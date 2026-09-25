import Foundation
import SQLite3

struct BackgroundSecurityJob: Sendable {
    let session: String
    let turn: String
    let revision: Int64
}

/// Independent WAL queue. No model call holds a database transaction or evidence writer lock.
actor BackgroundSecurityQueue {
    private var db: OpaquePointer?
    private var source: OpaquePointer?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    private var streamSource = false

    init(url: URL, evidenceURL: URL) throws {
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              sqlite3_open_v2(evidenceURL.path, &source, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            sqlite3_close(db); sqlite3_close(source)
            throw NSError(domain: "BackgroundSecurity", code: 1, userInfo: [NSLocalizedDescriptionKey: "无法打开后台安全队列"])
        }
        sqlite3_busy_timeout(db, 2000); sqlite3_busy_timeout(source, 2000)
        let schema = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS jobs(session TEXT,turn TEXT,revision INTEGER,done INTEGER DEFAULT 0,
          attempts INTEGER DEFAULT 0,not_before REAL DEFAULT 0,error TEXT,report BLOB,
          updated REAL DEFAULT 0,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY,session TEXT,turn TEXT);
        INSERT OR IGNORE INTO cursor VALUES(1,'','');
        INSERT OR IGNORE INTO cursor VALUES(2,'','');
        CREATE TABLE IF NOT EXISTS behavior_jobs(session TEXT,turn TEXT,revision INTEGER,updated REAL,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS behavior_stream_progress(session TEXT,turn TEXT,position INTEGER,configuration TEXT,serviced REAL,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS behavior_reports(session TEXT,turn TEXT,revision INTEGER,
          configuration TEXT,report BLOB,updated REAL,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS behavior_failures(session TEXT,turn TEXT,revision INTEGER,
          not_before REAL,error TEXT,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS security_slice_results(session TEXT,turn TEXT,context TEXT,chunk TEXT,
          report BLOB,PRIMARY KEY(session,turn,context,chunk));
        CREATE TABLE IF NOT EXISTS security_slice_failures(session TEXT,turn TEXT,context TEXT,chunk TEXT,
          attempts INTEGER,not_before REAL,error TEXT,PRIMARY KEY(session,turn,context,chunk));
        CREATE TABLE IF NOT EXISTS security_slice_manifest(session TEXT,turn TEXT,revision INTEGER,context TEXT,chunk TEXT,
          PRIMARY KEY(session,turn,revision,context,chunk));
        CREATE INDEX IF NOT EXISTS security_manifest_chunk ON security_slice_manifest(chunk);
        CREATE TABLE IF NOT EXISTS security_turn_service(session TEXT,turn TEXT,serviced REAL,
          PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS security_stream_progress(session TEXT,turn TEXT,revision INTEGER,context TEXT,
          position INTEGER DEFAULT 0,finished INTEGER DEFAULT 0,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS security_stream_slices(chunk TEXT PRIMARY KEY,payload BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS security_stream_context(session TEXT,turn TEXT,purpose TEXT,agent TEXT,observed REAL,PRIMARY KEY(session,turn));
        CREATE TABLE IF NOT EXISTS security_queue_meta(key TEXT PRIMARY KEY,value TEXT);
        """
        guard sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 2) }
        var table: OpaquePointer?
        guard sqlite3_prepare_v2(source, "SELECT 1 FROM sqlite_master WHERE name='security_evidence_tasks'", -1, &table, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 20) }
        streamSource = sqlite3_step(table) == SQLITE_ROW
        sqlite3_finalize(table)
        if streamSource {
            // Keep saved reports, but do not compare old snapshot revisions with
            // independent evidence-stream revisions.
            let migration = """
            BEGIN IMMEDIATE;
            UPDATE jobs SET revision=0,done=0,attempts=0,not_before=0
              WHERE NOT EXISTS(SELECT 1 FROM security_queue_meta WHERE key='stream-v1');
            UPDATE behavior_jobs SET revision=0
              WHERE NOT EXISTS(SELECT 1 FROM security_queue_meta WHERE key='stream-v1');
            INSERT OR IGNORE INTO security_queue_meta VALUES('stream-v1','1');
            COMMIT;
            """
            guard sqlite3_exec(db, migration, nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 12) }
        }
    }
    deinit { sqlite3_close(db); sqlite3_close(source) }

    private func statement(_ sql: String, source read: Bool = false) throws -> OpaquePointer {
        var s: OpaquePointer?
        let handle = read ? source : db
        guard sqlite3_prepare_v2(handle, sql, -1, &s, nil) == SQLITE_OK, let s else {
            throw NSError(domain: "BackgroundSecurity", code: 3, userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(handle))])
        }
        return s
    }
    private func bind(_ text: String, _ index: Int32, _ s: OpaquePointer) { sqlite3_bind_text(s, index, text, -1, transient) }
    private func text(_ s: OpaquePointer, _ index: Int32) -> String { sqlite3_column_text(s, index).map { String(cString: $0) } ?? "" }
    private func done(_ s: OpaquePointer) throws {
        guard sqlite3_step(s) == SQLITE_DONE else { throw NSError(domain: "BackgroundSecurity", code: 4, userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db))]) }
    }

    // Cursor walks projection metadata only. At end-of-table it wraps once so
    // tasks already seen can be revisited for a newer projection revision.
    func discover() throws {
        if streamSource { try discoverRecentJobs() }
        let c = try statement("SELECT session,turn FROM cursor WHERE id=1"); defer { sqlite3_finalize(c) }
        guard sqlite3_step(c) == SQLITE_ROW else { return }
        var cursorSession = text(c, 0), cursorTurn = text(c, 1)
        let sourceTable = streamSource ? "security_evidence_tasks" : "task_snapshot_projection"
        let dateColumn = streamSource ? "updated" : "generated_at"
        let discoverySQL = "SELECT session_id,turn_id,revision,\(dateColumn) FROM \(sourceTable) WHERE (session_id,turn_id)>(?,?) ORDER BY session_id,turn_id LIMIT 25"
        let s = try statement(discoverySQL, source: true)
        defer { sqlite3_finalize(s) }; bind(cursorSession, 1, s); bind(cursorTurn, 2, s)
        var last = ("", "")
        var found = false
        while sqlite3_step(s) == SQLITE_ROW {
            found = true
            last = (text(s, 0), text(s, 1))
            let q = try statement("INSERT INTO jobs(session,turn,revision,updated) VALUES(?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,attempts=0,not_before=0,error=NULL,updated=excluded.updated WHERE excluded.revision>jobs.revision")
            defer { sqlite3_finalize(q) }
            bind(last.0, 1, q); bind(last.1, 2, q); sqlite3_bind_int64(q, 3, sqlite3_column_int64(s, 2)); sqlite3_bind_double(q, 4, sqlite3_column_double(s, 3)); try done(q)
        }
        if !found && (!cursorSession.isEmpty || !cursorTurn.isEmpty) {
            // End reached: wrap back to the beginning. Existing successful
            // jobs are left untouched unless the projection revision changed.
            cursorSession = ""; cursorTurn = ""
            let wrap = try statement(discoverySQL, source: true)
            defer { sqlite3_finalize(wrap) }; bind("", 1, wrap); bind("", 2, wrap)
            while sqlite3_step(wrap) == SQLITE_ROW {
                last = (text(wrap, 0), text(wrap, 1))
                let q = try statement("INSERT INTO jobs(session,turn,revision,updated) VALUES(?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,attempts=0,not_before=0,error=NULL,updated=excluded.updated WHERE excluded.revision>jobs.revision")
                defer { sqlite3_finalize(q) }
                bind(last.0, 1, q); bind(last.1, 2, q); sqlite3_bind_int64(q, 3, sqlite3_column_int64(wrap, 2)); sqlite3_bind_double(q, 4, sqlite3_column_double(wrap, 3)); try done(q)
            }
        }
        let u = try statement("UPDATE cursor SET session=?,turn=? WHERE id=1"); defer { sqlite3_finalize(u) }
        bind(last.0, 1, u); bind(last.1, 2, u); try done(u)
    }

    func next(now: Date = Date()) throws -> BackgroundSecurityJob? {
        let historyTurn = try nextHistoryTurn(key: "ai-dispatch")
        let s = try statement("SELECT j.session,j.turn,j.revision FROM jobs j LEFT JOIN security_turn_service s ON s.session=j.session AND s.turn=j.turn WHERE revision>done AND attempts<3 AND not_before<=? ORDER BY CASE WHEN (updated>=? AND updated<=?) THEN \(historyTurn ? 1 : 0) ELSE \(historyTurn ? 0 : 1) END,COALESCE(s.serviced,0),updated ASC LIMIT 1")
        defer { sqlite3_finalize(s) }; sqlite3_bind_double(s, 1, now.timeIntervalSince1970)
        sqlite3_bind_double(s, 2, now.addingTimeInterval(-120).timeIntervalSince1970)
        sqlite3_bind_double(s, 3, now.addingTimeInterval(30).timeIntervalSince1970)
        guard sqlite3_step(s) == SQLITE_ROW else { return nil }
        return BackgroundSecurityJob(session: text(s, 0), turn: text(s, 1), revision: sqlite3_column_int64(s, 2))
    }

    private func nextHistoryTurn(key: String) throws -> Bool {
        let read = try statement("SELECT value FROM security_queue_meta WHERE key=?")
        defer { sqlite3_finalize(read) }; bind(key, 1, read)
        let value = sqlite3_step(read) == SQLITE_ROW ? (Int(text(read, 0)) ?? 0) : 0
        let write = try statement("INSERT INTO security_queue_meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        defer { sqlite3_finalize(write) }; bind(key, 1, write); bind(String((value + 1) % 4), 2, write); try done(write)
        return value % 4 == 3
    }

    private func discoverRecentJobs() throws {
        let s = try statement("SELECT session_id,turn_id,revision,updated FROM security_evidence_tasks WHERE updated>=? ORDER BY updated DESC LIMIT 25", source: true)
        defer { sqlite3_finalize(s) }; sqlite3_bind_double(s, 1, Date().addingTimeInterval(-120).timeIntervalSince1970)
        while sqlite3_step(s) == SQLITE_ROW {
            let q = try statement("INSERT INTO jobs(session,turn,revision,updated) VALUES(?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,attempts=0,not_before=0,error=NULL,updated=excluded.updated WHERE excluded.revision>jobs.revision")
            defer { sqlite3_finalize(q) }; bind(text(s, 0), 1, q); bind(text(s, 1), 2, q)
            sqlite3_bind_int64(q, 3, sqlite3_column_int64(s, 2)); sqlite3_bind_double(q, 4, sqlite3_column_double(s, 3)); try done(q)
        }
    }

    func snapshot(_ job: BackgroundSecurityJob) throws -> AgentTaskSnapshot? {
        let s = try statement("SELECT payload FROM task_snapshot_projection WHERE session_id=? AND turn_id=? AND revision=? AND length(payload)<=16777216", source: true)
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
        guard sqlite3_step(s) == SQLITE_ROW, let bytes = sqlite3_column_blob(s, 0) else { return nil }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AgentTaskSnapshot.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 0))))
    }

    func usesEvidenceStream() -> Bool { streamSource }

    /// One event per preparation quantum. No task-sized JSON is fetched or decoded.
    /// Cursor + manifest are committed together, so interruption safely replays.
    func prepareInputStep(_ job: BackgroundSecurityJob, context: String) throws {
        guard streamSource else { return }
        let version = try statement("SELECT revision FROM security_evidence_tasks WHERE session_id=? AND turn_id=?", source: true)
        defer { sqlite3_finalize(version) }
        bind(job.session, 1, version); bind(job.turn, 2, version)
        guard sqlite3_step(version) == SQLITE_ROW, sqlite3_column_int64(version, 0) >= job.revision else {
            throw NSError(domain: "BackgroundSecurity", code: 14, userInfo: [NSLocalizedDescriptionKey: "源事件版本已更新，等待队列刷新"])
        }
        let read = try statement("SELECT revision,context,position,finished FROM security_stream_progress WHERE session=? AND turn=?")
        defer { sqlite3_finalize(read) }; bind(job.session, 1, read); bind(job.turn, 2, read)
        let exists = sqlite3_step(read) == SQLITE_ROW
        let same = exists && sqlite3_column_int64(read, 0) == job.revision && text(read, 1) == context
        let resumable = exists && sqlite3_column_int64(read, 0) <= job.revision && text(read, 1) == context
        if same && sqlite3_column_int(read, 3) == 1 { return }
        let position = resumable ? sqlite3_column_int64(read, 2) : 0
        let input = try statement("""
          SELECT i.position,e.payload FROM security_evidence_inputs i JOIN evidence_records e ON e.evidence_key=i.evidence_key
          WHERE i.session_id=? AND i.turn_id=? AND i.position>? AND i.position<=? ORDER BY i.position LIMIT 1
          """, source: true)
        defer { sqlite3_finalize(input) }
        bind(job.session, 1, input); bind(job.turn, 2, input); sqlite3_bind_int64(input, 3, position)
        sqlite3_bind_int64(input, 4, job.revision)
        let step = sqlite3_step(input)
        guard step == SQLITE_ROW || step == SQLITE_DONE else { throw NSError(domain: "BackgroundSecurity", code: 15) }
        let finished = step == SQLITE_DONE
        var slices: [SecurityAnalysisSlice] = []
        var taskEvent: GuardEvent?
        var next = position
        if !finished {
            guard let bytes = sqlite3_column_blob(input, 1) else { throw NSError(domain: "BackgroundSecurity", code: 16) }
            let eventDecoder = JSONDecoder(); eventDecoder.dateDecodingStrategy = .iso8601
            let event = try eventDecoder.decode(GuardEvent.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(input, 1))))
            taskEvent = event
            slices = SecurityAnalysisSlices.build([event])
            next = sqlite3_column_int64(input, 0)
        }
        guard sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 17) }
        do {
            if let event = taskEvent, let purpose = event.userIntent, !purpose.isEmpty {
                let meta = try statement("INSERT INTO security_stream_context VALUES(?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET purpose=excluded.purpose,agent=excluded.agent,observed=excluded.observed WHERE excluded.observed<security_stream_context.observed")
                defer { sqlite3_finalize(meta) }; bind(job.session, 1, meta); bind(job.turn, 2, meta)
                bind(String(purpose.prefix(1500)), 3, meta); bind(event.agent ?? "unknown", 4, meta)
                sqlite3_bind_double(meta, 5, event.ts.timeIntervalSince1970); try done(meta)
            }
            if resumable && !same {
                let advance = try statement("UPDATE security_slice_manifest SET revision=? WHERE session=? AND turn=?")
                defer { sqlite3_finalize(advance) }; sqlite3_bind_int64(advance, 1, job.revision)
                bind(job.session, 2, advance); bind(job.turn, 3, advance); try done(advance)
            } else if !same {
                let clear = try statement("DELETE FROM security_slice_manifest WHERE session=? AND turn=?")
                defer { sqlite3_finalize(clear) }; bind(job.session, 1, clear); bind(job.turn, 2, clear); try done(clear)
                // Old findings remain visible until replaced, but progress is not reused.
            }
            for slice in slices {
                let data = try encoder.encode(slice)
                let payload = try statement("INSERT OR IGNORE INTO security_stream_slices VALUES(?,?)")
                defer { sqlite3_finalize(payload) }; bind(slice.id, 1, payload)
                _ = data.withUnsafeBytes { sqlite3_bind_blob(payload, 2, $0.baseAddress, Int32(data.count), transient) }; try done(payload)
                let manifest = try statement("INSERT OR IGNORE INTO security_slice_manifest VALUES(?,?,?,?,?)")
                defer { sqlite3_finalize(manifest) }; bind(job.session, 1, manifest); bind(job.turn, 2, manifest)
                sqlite3_bind_int64(manifest, 3, job.revision); bind(context, 4, manifest); bind(slice.id, 5, manifest); try done(manifest)
            }
            let cursor = try statement("INSERT INTO security_stream_progress VALUES(?,?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,context=excluded.context,position=excluded.position,finished=excluded.finished")
            defer { sqlite3_finalize(cursor) }
            bind(job.session, 1, cursor); bind(job.turn, 2, cursor); sqlite3_bind_int64(cursor, 3, job.revision)
            bind(context, 4, cursor); sqlite3_bind_int64(cursor, 5, next); sqlite3_bind_int(cursor, 6, finished ? 1 : 0); try done(cursor)
            guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 18) }
        } catch { sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    func preparationFinished(_ job: BackgroundSecurityJob) throws -> Bool {
        guard streamSource else { return true }
        let s = try statement("SELECT finished FROM security_stream_progress WHERE session=? AND turn=? AND revision=?")
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
        return sqlite3_step(s) == SQLITE_ROW && sqlite3_column_int(s, 0) == 1
    }

    func taskDescription(_ job: BackgroundSecurityJob) throws -> String {
        let s = try statement("SELECT purpose FROM security_stream_context WHERE session=? AND turn=?")
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s)
        return sqlite3_step(s) == SQLITE_ROW ? text(s, 0) : "任务描述尚未采集或尚未处理；不可据此推断用户未授权"
    }

    func pendingSlices(_ job: BackgroundSecurityJob, context: String, limit: Int = 2) throws -> [SecurityAnalysisSlice] {
        let s = try statement("""
          SELECT p.payload FROM security_slice_manifest m JOIN security_stream_slices p ON p.chunk=m.chunk
          LEFT JOIN security_slice_results r ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk
          LEFT JOIN security_slice_failures f ON f.session=m.session AND f.turn=m.turn AND f.context=m.context AND f.chunk=m.chunk
          WHERE m.session=? AND m.turn=? AND m.revision=? AND m.context=? AND r.chunk IS NULL
          AND (f.attempts IS NULL OR (f.attempts<3 AND f.not_before<=?)) ORDER BY m.chunk LIMIT ?
          """)
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s)
        sqlite3_bind_int64(s, 3, job.revision); bind(context, 4, s)
        sqlite3_bind_double(s, 5, Date().timeIntervalSince1970); sqlite3_bind_int(s, 6, Int32(max(1, min(limit, 2))))
        var slices: [SecurityAnalysisSlice] = []
        while sqlite3_step(s) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(s, 0) else { continue }
            slices.append(try decoder.decode(SecurityAnalysisSlice.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 0)))))
        }
        return slices
    }

    func failSlice(_ job: BackgroundSecurityJob, context: String, chunk: String, message: String) throws {
        let s = try statement("INSERT INTO security_slice_failures VALUES(?,?,?,?,1,?,?) ON CONFLICT(session,turn,context,chunk) DO UPDATE SET attempts=attempts+1,not_before=excluded.not_before+60*MIN(attempts,10),error=excluded.error")
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s)
        bind(context, 3, s); bind(chunk, 4, s); sqlite3_bind_double(s, 5, Date().addingTimeInterval(60).timeIntervalSince1970)
        bind(String(message.prefix(1000)), 6, s); try done(s)
    }

    func failedSliceCount(_ job: BackgroundSecurityJob) throws -> Int {
        let s = try statement("SELECT count(*) FROM security_slice_manifest m JOIN security_slice_failures f ON f.session=m.session AND f.turn=m.turn AND f.context=m.context AND f.chunk=m.chunk LEFT JOIN security_slice_results r ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk WHERE m.session=? AND m.turn=? AND m.revision=? AND r.chunk IS NULL")
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
        return sqlite3_step(s) == SQLITE_ROW ? Int(sqlite3_column_int(s, 0)) : 0
    }

    func assembledReport(_ job: BackgroundSecurityJob) throws -> HistoricalSecurityAnalysis {
        let s = try statement("""
          SELECT r.report FROM security_slice_manifest m JOIN security_slice_results r
          ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk
          WHERE m.session=? AND m.turn=? AND m.revision=? ORDER BY m.chunk
          """)
        defer { sqlite3_finalize(s) }; bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
        var findings: [String: AIHistoricalFinding] = [:], rules: [String: AIRuleExamination] = [:]
        var model: String?
        while sqlite3_step(s) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(s, 0) else { continue }
            let report = try decoder.decode(HistoricalSecurityAnalysis.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 0))))
            for finding in report.findings { findings[finding.id] = finding }
            for rule in report.rules { rules[rule.id] = rule }
            model = report.model
        }
        return HistoricalSecurityAnalysis(findings: findings.values.sorted { $0.id < $1.id }, rules: rules.values.sorted { $0.id < $1.id }, generatedAt: ISO8601DateFormatter().string(from: Date()), model: model, examinationPasses: 2)
    }

    func complete(_ job: BackgroundSecurityJob, report: HistoricalSecurityAnalysis) throws {
        if try !preparationFinished(job) {
            throw NSError(domain: "BackgroundSecurity", code: 13, userInfo: [NSLocalizedDescriptionKey: "还有源事件未分段，不能标记完成"])
        }
        let coverage = try sliceCoverage(job)
        guard coverage.total > 0 && coverage.completed == coverage.total else {
            throw NSError(domain: "BackgroundSecurity", code: 11, userInfo: [NSLocalizedDescriptionKey: "分段清单未完成，不能将任务标记为已检查"])
        }
        let data = try encoder.encode(report)
        let s = try statement("UPDATE jobs SET done=?,report=?,attempts=0,error=NULL,updated=? WHERE session=? AND turn=? AND revision=?")
        defer { sqlite3_finalize(s) }; sqlite3_bind_int64(s, 1, job.revision)
        _ = data.withUnsafeBytes { sqlite3_bind_blob(s, 2, $0.baseAddress, Int32(data.count), transient) }
        sqlite3_bind_double(s, 3, Date().timeIntervalSince1970)
        bind(job.session, 4, s); bind(job.turn, 5, s); sqlite3_bind_int64(s, 6, job.revision); try done(s)
        guard sqlite3_changes(db) == 1 else { throw NSError(domain: "BackgroundSecurity", code: 5, userInfo: [NSLocalizedDescriptionKey: "任务版本已更新，旧结果不覆盖新任务"] ) }
        // Prepared content is a temporary spool, not another permanent raw archive.
        let cleanup = try statement("""
          DELETE FROM security_stream_slices WHERE chunk IN
          (SELECT chunk FROM security_slice_manifest WHERE session=? AND turn=?)
          AND NOT EXISTS(SELECT 1 FROM security_slice_manifest m LEFT JOIN security_slice_results r
            ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk
            WHERE m.chunk=security_stream_slices.chunk AND r.chunk IS NULL)
          """)
        defer { sqlite3_finalize(cleanup) }; bind(job.session, 1, cleanup); bind(job.turn, 2, cleanup); try done(cleanup)
    }

    func fail(_ job: BackgroundSecurityJob, message: String, now: Date = Date()) throws {
        let current = try statement("SELECT attempts FROM jobs WHERE session=? AND turn=? AND revision=?")
        bind(job.session, 1, current); bind(job.turn, 2, current); sqlite3_bind_int64(current, 3, job.revision)
        let attempts = sqlite3_step(current) == SQLITE_ROW ? sqlite3_column_int(current, 0) + 1 : 1
        sqlite3_finalize(current)
        let delay = min(3600.0, 60.0 * pow(2.0, Double(min(attempts - 1, 6))))
        let s = try statement("UPDATE jobs SET attempts=?,not_before=?,error=? WHERE session=? AND turn=? AND revision=?")
        defer { sqlite3_finalize(s) }; sqlite3_bind_int(s, 1, attempts); sqlite3_bind_double(s, 2, now.addingTimeInterval(delay).timeIntervalSince1970)
        bind(String(message.prefix(1000)), 3, s); bind(job.session, 4, s); bind(job.turn, 5, s); sqlite3_bind_int64(s, 6, job.revision); try done(s)
    }

    func status() throws -> (completed: Int, pending: Int, failed: Int) {
        let s = try statement("""
          SELECT SUM(done=revision),SUM(done<revision),SUM(done<revision AND (attempts>=3 OR EXISTS(
            SELECT 1 FROM security_slice_manifest m JOIN security_slice_failures f
            ON f.session=m.session AND f.turn=m.turn AND f.context=m.context AND f.chunk=m.chunk
            LEFT JOIN security_slice_results r ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk
            WHERE m.session=jobs.session AND m.turn=jobs.turn AND m.revision=jobs.revision AND f.attempts>=3 AND r.chunk IS NULL)))
          FROM jobs WHERE revision>0
          """)
        defer { sqlite3_finalize(s) }; guard sqlite3_step(s) == SQLITE_ROW else { return (0,0,0) }
        return (Int(sqlite3_column_int(s,0)),Int(sqlite3_column_int(s,1)),Int(sqlite3_column_int(s,2)))
    }

    func activateAnalysisContext(_ context: String) throws {
        let read = try statement("SELECT value FROM security_queue_meta WHERE key='analysis-context'")
        defer { sqlite3_finalize(read) }
        if sqlite3_step(read) == SQLITE_ROW && text(read, 0) == context { return }
        guard sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 21) }
        do {
            guard sqlite3_exec(db, "UPDATE jobs SET done=0,attempts=0,not_before=0", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 22) }
            let write = try statement("INSERT INTO security_queue_meta VALUES('analysis-context',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            defer { sqlite3_finalize(write) }; bind(context, 1, write); try done(write)
            guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 23) }
        } catch { sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    func sliceReport(_ job: BackgroundSecurityJob, context: String, chunk: String) throws -> HistoricalSecurityAnalysis? {
        let s = try statement("SELECT report FROM security_slice_results WHERE session=? AND turn=? AND context=? AND chunk=?")
        defer { sqlite3_finalize(s) }
        bind(job.session, 1, s); bind(job.turn, 2, s); bind(context, 3, s); bind(chunk, 4, s)
        guard sqlite3_step(s) == SQLITE_ROW, let bytes = sqlite3_column_blob(s, 0) else { return nil }
        return try decoder.decode(HistoricalSecurityAnalysis.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 0))))
    }

    func registerSlices(_ job: BackgroundSecurityJob, context: String, chunks: [String]) throws {
        guard sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 9) }
        do {
            let remove = try statement("DELETE FROM security_slice_manifest WHERE session=? AND turn=?")
            bind(job.session, 1, remove); bind(job.turn, 2, remove)
            defer { sqlite3_finalize(remove) }; try done(remove)
            for chunk in Set(chunks) {
                let s = try statement("INSERT INTO security_slice_manifest VALUES(?,?,?,?,?)")
                defer { sqlite3_finalize(s) }
                bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
                bind(context, 4, s); bind(chunk, 5, s); try done(s)
            }
            guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 10) }
        } catch { sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    func sliceCoverage(_ job: BackgroundSecurityJob) throws -> (total: Int, completed: Int) {
        let s = try statement("SELECT count(*),count(r.chunk) FROM security_slice_manifest m LEFT JOIN security_slice_results r ON r.session=m.session AND r.turn=m.turn AND r.context=m.context AND r.chunk=m.chunk WHERE m.session=? AND m.turn=? AND m.revision=?")
        defer { sqlite3_finalize(s) }
        bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_int64(s, 3, job.revision)
        guard sqlite3_step(s) == SQLITE_ROW else { return (0, 0) }
        return (Int(sqlite3_column_int(s, 0)), Int(sqlite3_column_int(s, 1)))
    }

    func yieldJob(_ job: BackgroundSecurityJob) throws {
        let s = try statement("INSERT INTO security_turn_service VALUES(?,?,?) ON CONFLICT(session,turn) DO UPDATE SET serviced=excluded.serviced")
        defer { sqlite3_finalize(s) }
        bind(job.session, 1, s); bind(job.turn, 2, s); sqlite3_bind_double(s, 3, Date().timeIntervalSince1970)
        try done(s)
    }

    func saveSlice(_ job: BackgroundSecurityJob, context: String, chunk: String, report: HistoricalSecurityAnalysis) throws {
        let data = try encoder.encode(report)
        let s = try statement("INSERT OR REPLACE INTO security_slice_results VALUES(?,?,?,?,?)")
        defer { sqlite3_finalize(s) }
        bind(job.session, 1, s); bind(job.turn, 2, s); bind(context, 3, s); bind(chunk, 4, s)
        _ = data.withUnsafeBytes { sqlite3_bind_blob(s, 5, $0.baseAddress, Int32(data.count), transient) }; try done(s)
    }

    func saveProgress(_ job: BackgroundSecurityJob, report: HistoricalSecurityAnalysis) throws {
        let data = try encoder.encode(report)
        let s = try statement("UPDATE jobs SET report=? WHERE session=? AND turn=? AND revision=?")
        defer { sqlite3_finalize(s) }
        _ = data.withUnsafeBytes { sqlite3_bind_blob(s, 1, $0.baseAddress, Int32(data.count), transient) }
        bind(job.session, 2, s); bind(job.turn, 3, s); sqlite3_bind_int64(s, 4, job.revision); try done(s)
    }

    func behaviorStep(domains: Set<String>) throws -> Bool {
        try discoverBehaviorJobs()
        let configuration = "\(streamSource ? "stream-v1|" : "")v\(LocalBehaviorAnalysis.version)|" + domains.sorted().joined(separator: "|")
        let historyTurn = try nextHistoryTurn(key: "local-dispatch")
        let s = try statement("""
          SELECT j.session,j.turn,j.revision FROM behavior_jobs j
          LEFT JOIN behavior_reports r ON r.session=j.session AND r.turn=j.turn
          LEFT JOIN behavior_failures f ON f.session=j.session AND f.turn=j.turn AND f.revision=j.revision
          LEFT JOIN behavior_stream_progress p ON p.session=j.session AND p.turn=j.turn
          WHERE (r.revision IS NULL OR r.revision<j.revision OR r.configuration<>?)
          AND (f.not_before IS NULL OR f.not_before<=?)
          ORDER BY CASE WHEN j.updated>=? AND j.updated<=? THEN \(historyTurn ? 1 : 0) ELSE \(historyTurn ? 0 : 1) END,
          COALESCE(p.serviced,0),j.updated ASC LIMIT 1
          """)
        defer { sqlite3_finalize(s) }
        bind(configuration, 1, s); sqlite3_bind_double(s, 2, Date().timeIntervalSince1970)
        sqlite3_bind_double(s, 3, Date().addingTimeInterval(-120).timeIntervalSince1970)
        sqlite3_bind_double(s, 4, Date().addingTimeInterval(30).timeIntervalSince1970)
        guard sqlite3_step(s) == SQLITE_ROW else { return false }
        let job = BackgroundSecurityJob(session: text(s, 0), turn: text(s, 1), revision: sqlite3_column_int64(s, 2))
        do {
            if streamSource {
                try processBehaviorEvent(job, configuration: configuration, domains: domains)
                return true
            }
            guard let snapshot = try snapshot(job) else { throw NSError(domain: "LocalBehavior", code: 1, userInfo: [NSLocalizedDescriptionKey: "快照已更新或超过读取预算，稍后重试"] ) }
            let report = LocalBehaviorAnalysis.report(events: snapshot.sourceEvents, reportedDomains: domains)
            let data = try encoder.encode(report)
            let write = try statement("INSERT INTO behavior_reports VALUES(?,?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,configuration=excluded.configuration,report=excluded.report,updated=excluded.updated WHERE excluded.revision>=behavior_reports.revision")
            defer { sqlite3_finalize(write) }
            bind(job.session, 1, write); bind(job.turn, 2, write); sqlite3_bind_int64(write, 3, job.revision)
            bind(configuration, 4, write)
            _ = data.withUnsafeBytes { sqlite3_bind_blob(write, 5, $0.baseAddress, Int32(data.count), transient) }
            sqlite3_bind_double(write, 6, Date().timeIntervalSince1970); try done(write)
        } catch {
            let failure = try statement("INSERT INTO behavior_failures VALUES(?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,not_before=excluded.not_before,error=excluded.error")
            defer { sqlite3_finalize(failure) }
            bind(job.session, 1, failure); bind(job.turn, 2, failure); sqlite3_bind_int64(failure, 3, job.revision)
            sqlite3_bind_double(failure, 4, Date().addingTimeInterval(300).timeIntervalSince1970)
            bind(error.localizedDescription, 5, failure); try done(failure)
        }
        return true
    }

    private func discoverBehaviorJobs() throws {
        let table = streamSource ? "security_evidence_tasks" : "task_snapshot_projection"
        let date = streamSource ? "updated" : "generated_at"
        if streamSource {
            let recent = try statement("SELECT session_id,turn_id,revision,updated FROM security_evidence_tasks ORDER BY updated DESC LIMIT 50", source: true)
            defer { sqlite3_finalize(recent) }
            while sqlite3_step(recent) == SQLITE_ROW { try admitBehaviorJob(recent) }
        }
        let cursor = try statement("SELECT session,turn FROM cursor WHERE id=2")
        defer { sqlite3_finalize(cursor) }; guard sqlite3_step(cursor) == SQLITE_ROW else { return }
        let s = try statement("SELECT session_id,turn_id,revision,\(date) FROM \(table) WHERE (session_id,turn_id)>(?,?) ORDER BY session_id,turn_id LIMIT 25", source: true)
        defer { sqlite3_finalize(s) }; bind(text(cursor, 0), 1, s); bind(text(cursor, 1), 2, s)
        var last = ("", "")
        while sqlite3_step(s) == SQLITE_ROW {
            last = (text(s, 0), text(s, 1))
            try admitBehaviorJob(s)
        }
        let update = try statement("UPDATE cursor SET session=?,turn=? WHERE id=2")
        defer { sqlite3_finalize(update) }; bind(last.0, 1, update); bind(last.1, 2, update); try done(update)
    }

    private func admitBehaviorJob(_ sourceRow: OpaquePointer) throws {
        let q = try statement("INSERT INTO behavior_jobs VALUES(?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,updated=excluded.updated WHERE excluded.revision>behavior_jobs.revision")
        defer { sqlite3_finalize(q) }; bind(text(sourceRow, 0), 1, q); bind(text(sourceRow, 1), 2, q)
        sqlite3_bind_int64(q, 3, sqlite3_column_int64(sourceRow, 2)); sqlite3_bind_double(q, 4, sqlite3_column_double(sourceRow, 3)); try done(q)
    }

    private func processBehaviorEvent(_ job: BackgroundSecurityJob, configuration: String, domains: Set<String>) throws {
        let progress = try statement("SELECT position,configuration FROM behavior_stream_progress WHERE session=? AND turn=?")
        defer { sqlite3_finalize(progress) }; bind(job.session, 1, progress); bind(job.turn, 2, progress)
        let same = sqlite3_step(progress) == SQLITE_ROW && text(progress, 1) == configuration
        var position = same ? sqlite3_column_int64(progress, 0) : 0
        let input = try statement("SELECT i.position,e.payload FROM security_evidence_inputs i JOIN evidence_records e ON e.evidence_key=i.evidence_key WHERE i.session_id=? AND i.turn_id=? AND i.position>? AND i.position<=? ORDER BY i.position LIMIT 1", source: true)
        defer { sqlite3_finalize(input) }; bind(job.session, 1, input); bind(job.turn, 2, input)
        sqlite3_bind_int64(input, 3, position); sqlite3_bind_int64(input, 4, job.revision)
        let step = sqlite3_step(input)
        guard step == SQLITE_ROW || step == SQLITE_DONE else { throw NSError(domain: "BackgroundSecurity", code: 24) }
        let finished = step == SQLITE_DONE
        var events: [GuardEvent] = []
        let eventDecoder = JSONDecoder(); eventDecoder.dateDecodingStrategy = .iso8601
        if !finished, let bytes = sqlite3_column_blob(input, 1) {
            let event = try eventDecoder.decode(GuardEvent.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(input, 1))))
            events.append(event); position = sqlite3_column_int64(input, 0)
            // Match the latest available counterpart by native call ID and task,
            // not by temporal proximity. Later returns revise the same finding.
            if event.kind == "tool", let callID = event.toolCallId, !callID.isEmpty,
               event.op == "call" || event.op == "result" {
                let counterpart = try statement("SELECT e.payload FROM security_evidence_inputs i JOIN evidence_records e ON e.evidence_key=i.evidence_key WHERE i.session_id=? AND i.turn_id=? AND i.tool_call_id=? AND i.operation=? AND i.position<=? ORDER BY i.position DESC LIMIT 1", source: true)
                defer { sqlite3_finalize(counterpart) }; bind(job.session, 1, counterpart); bind(job.turn, 2, counterpart)
                bind(callID, 3, counterpart); bind(event.op == "call" ? "result" : "call", 4, counterpart)
                sqlite3_bind_int64(counterpart, 5, job.revision)
                if sqlite3_step(counterpart) == SQLITE_ROW, let body = sqlite3_column_blob(counterpart, 0) {
                    events.append(try eventDecoder.decode(GuardEvent.self, from: Data(bytes: body, count: Int(sqlite3_column_bytes(counterpart, 0)))))
                }
            }
        }
        let found = LocalBehaviorAnalysis.report(events: events, reportedDomains: domains)
        var findings: [String: AIHistoricalFinding] = [:]
        if same {
            let prior = try statement("SELECT report FROM behavior_reports WHERE session=? AND turn=?")
            defer { sqlite3_finalize(prior) }; bind(job.session, 1, prior); bind(job.turn, 2, prior)
            if sqlite3_step(prior) == SQLITE_ROW, let bytes = sqlite3_column_blob(prior, 0) {
                let report = try decoder.decode(HistoricalSecurityAnalysis.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(prior, 0))))
                for item in report.findings { findings[item.id] = item }
            }
        }
        let purpose = try taskDescription(job)
        for var item in found.findings {
            if item.taskTitle == nil && !purpose.hasPrefix("任务描述尚未") { item.taskTitle = String(purpose.prefix(160)) }
            findings[item.id] = item
        }
        let report = HistoricalSecurityAnalysis(findings: findings.values.sorted { $0.id < $1.id }, rules: [], generatedAt: found.generatedAt, model: found.model, examinationPasses: 0)
        let data = try encoder.encode(report)
        guard sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 25) }
        do {
            if let event = events.first, let purpose = event.userIntent, !purpose.isEmpty {
                let meta = try statement("INSERT INTO security_stream_context VALUES(?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET purpose=excluded.purpose,agent=excluded.agent,observed=excluded.observed WHERE excluded.observed<security_stream_context.observed")
                defer { sqlite3_finalize(meta) }; bind(job.session, 1, meta); bind(job.turn, 2, meta)
                bind(String(purpose.prefix(1500)), 3, meta); bind(event.agent ?? "unknown", 4, meta)
                sqlite3_bind_double(meta, 5, event.ts.timeIntervalSince1970); try done(meta)
            }
            let write = try statement("INSERT INTO behavior_reports VALUES(?,?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET revision=excluded.revision,configuration=excluded.configuration,report=excluded.report,updated=excluded.updated")
            defer { sqlite3_finalize(write) }; bind(job.session, 1, write); bind(job.turn, 2, write)
            sqlite3_bind_int64(write, 3, finished ? job.revision : 0); bind(configuration, 4, write)
            _ = data.withUnsafeBytes { sqlite3_bind_blob(write, 5, $0.baseAddress, Int32(data.count), transient) }
            sqlite3_bind_double(write, 6, Date().timeIntervalSince1970); try done(write)
            let cursor = try statement("INSERT INTO behavior_stream_progress VALUES(?,?,?,?,?) ON CONFLICT(session,turn) DO UPDATE SET position=excluded.position,configuration=excluded.configuration,serviced=excluded.serviced")
            defer { sqlite3_finalize(cursor) }; bind(job.session, 1, cursor); bind(job.turn, 2, cursor)
            sqlite3_bind_int64(cursor, 3, position); bind(configuration, 4, cursor); sqlite3_bind_double(cursor, 5, Date().timeIntervalSince1970); try done(cursor)
            guard sqlite3_exec(db, "COMMIT", nil, nil, nil) == SQLITE_OK else { throw NSError(domain: "BackgroundSecurity", code: 26) }
        } catch { sqlite3_exec(db, "ROLLBACK", nil, nil, nil); throw error }
    }

    func behaviorStatus() throws -> (known: Int, projected: Int, checked: Int) {
        let known = try statement("SELECT count(*) FROM task_summary", source: true)
        defer { sqlite3_finalize(known) }; _ = sqlite3_step(known)
        let checked = try statement("SELECT count(*),sum(r.revision=j.revision) FROM behavior_jobs j LEFT JOIN behavior_reports r ON r.session=j.session AND r.turn=j.turn")
        defer { sqlite3_finalize(checked) }; _ = sqlite3_step(checked)
        return (Int(sqlite3_column_int(known, 0)), Int(sqlite3_column_int(checked, 0)), Int(sqlite3_column_int(checked, 1)))
    }

    func behaviorReports(limit: Int = 50) throws -> HistoricalSecurityAnalysis {
        let s = try statement("SELECT report FROM behavior_reports WHERE json_array_length(CAST(report AS TEXT),'$.findings')>0 ORDER BY updated DESC LIMIT ?")
        defer { sqlite3_finalize(s) }; sqlite3_bind_int(s, 1, Int32(max(1, min(limit, 1000))))
        var findings: [AIHistoricalFinding] = []
        while sqlite3_step(s) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(s, 0) else { continue }
            let report = try decoder.decode(HistoricalSecurityAnalysis.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 0))))
            findings += report.findings
        }
        return HistoricalSecurityAnalysis(findings: findings, rules: [], generatedAt: nil, model: "本地行为检测", examinationPasses: 0)
    }

    func recentReports() throws -> HistoricalSecurityAnalysis {
        let s = try statement("SELECT session,turn,report FROM jobs WHERE report IS NOT NULL ORDER BY updated DESC LIMIT 20")
        defer { sqlite3_finalize(s) }
        var findings: [AIHistoricalFinding] = []; var rules: [AIRuleExamination] = []
        var latestTime: String?; var latestModel: String?
        while sqlite3_step(s) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(s, 2) else { continue }
            let report = try decoder.decode(HistoricalSecurityAnalysis.self, from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(s, 2))))
            if latestTime == nil { latestTime = report.generatedAt; latestModel = report.model }
            let prefix = "\(text(s,0))|\(text(s,1))|"
            findings += report.findings.map { f in
                var item = AIHistoricalFinding(id: prefix + f.id, title: f.title, severity: f.severity, summary: f.summary, recommendedAction: f.recommendedAction, evidenceEventIds: f.evidenceEventIds, ruleId: f.ruleId, llmSelfExamine: f.llmSelfExamine)
                item.agentName = f.agentName; item.taskTitle = f.taskTitle; item.observedAt = f.observedAt ?? report.generatedAt
                return item
            }
            for rule in report.rules where !rules.contains(where: { $0.id == rule.id }) { rules.append(rule) }
        }
        return HistoricalSecurityAnalysis(findings: findings, rules: rules, generatedAt: latestTime, model: latestModel, examinationPasses: 2)
    }
}
