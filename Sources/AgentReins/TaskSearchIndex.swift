import Foundation
import SQLite3
import CryptoKit

struct TaskAggregateGroup: Codable, Sendable {
    let value: String
    let tasks: Int
    let occurrences: Int
    let inputTokens: Int
    let outputTokens: Int
}

struct TaskAggregates: Codable, Sendable {
    struct RankedTask: Codable, Sendable, Identifiable {
        let sessionID: String
        let turnID: String
        let title: String
        let agent: String
        let inputTokens: Int
        let outputTokens: Int
        var id: String { "\(sessionID)\u{0}\(turnID)" }
        var totalTokens: Int { inputTokens + outputTokens }
    }
    let topTokenTasks: [RankedTask]
    let agents: [TaskAggregateGroup]
    let repeatedTools: [TaskAggregateGroup]
    let modelInputAddresses: [TaskAggregateGroup]
    var taskCount: Int { agents.reduce(0) { $0 + $1.tasks } }
}

struct TaskSearchHit: Identifiable, Sendable {
    let task: StoredTaskSummary
    let excerpt: String
    let revision: Int64
    var isMemoryWriteMatch: Bool = false
    var id: String { task.id }
}

/// Rebuildable task-level search in its own SQLite file. Index writes cannot
/// hold the evidence log's WAL writer; the evidence-side outbox is acknowledged
/// only after this file commits. Replays replace the same task revision.
final class TaskSearchIndex: @unchecked Sendable {
    private var handle: OpaquePointer?
    private let lock = NSLock()
    private(set) var newlyCreated = true

    init(evidenceURL: URL) throws {
        let url = evidenceURL.deletingPathExtension().appendingPathExtension("search.sqlite3")
        guard sqlite3_open_v2(url.path, &handle,
                              SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                              nil) == SQLITE_OK else { throw failure("open search database") }
        try execute("PRAGMA journal_mode=WAL")
        try execute("PRAGMA synchronous=NORMAL")
        try execute("PRAGMA busy_timeout=2000")
        try execute("""
            CREATE TABLE IF NOT EXISTS task_search_meta(
              id INTEGER PRIMARY KEY,session_id TEXT NOT NULL,turn_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,title TEXT,started_at REAL NOT NULL,last_at REAL NOT NULL,
              event_count INTEGER NOT NULL,revision INTEGER NOT NULL,
              evidence_flags INTEGER NOT NULL,address_in_model_input INTEGER NOT NULL,
              address_excerpt TEXT,
              UNIQUE(session_id,turn_id))
            """)
        // A search index can survive an app update independently of evidence.
        var columns: OpaquePointer?
        if sqlite3_prepare_v2(handle, "PRAGMA table_info(task_search_meta)", -1, &columns, nil) == SQLITE_OK {
            var hasExcerpt = false
            while sqlite3_step(columns) == SQLITE_ROW {
                if let name = sqlite3_column_text(columns, 1), String(cString: name) == "address_excerpt" {
                    hasExcerpt = true
                }
            }
            sqlite3_finalize(columns)
            if !hasExcerpt { try execute("ALTER TABLE task_search_meta ADD COLUMN address_excerpt TEXT") }
        }
        try execute("CREATE INDEX IF NOT EXISTS task_search_time ON task_search_meta(last_at DESC,id)")
        try execute("CREATE INDEX IF NOT EXISTS task_search_agent_time ON task_search_meta(agent_id,last_at DESC,id)")
        try execute("CREATE VIRTUAL TABLE IF NOT EXISTS task_search_fts USING fts5(content, tokenize='trigram')")
        try execute("CREATE TABLE IF NOT EXISTS task_metrics(task_id INTEGER PRIMARY KEY,input_tokens INTEGER NOT NULL,output_tokens INTEGER NOT NULL)")
        try execute("CREATE TABLE IF NOT EXISTS task_facts(task_id INTEGER NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,label TEXT NOT NULL,evidence_id TEXT NOT NULL,PRIMARY KEY(task_id,kind,value,evidence_id)) WITHOUT ROWID")
        try execute("CREATE INDEX IF NOT EXISTS task_facts_kind_value ON task_facts(kind,value,task_id)")
        try execute("CREATE TABLE IF NOT EXISTS task_aggregate_version(version INTEGER PRIMARY KEY)")
        // Existing indexed snapshots are re-projected in bounded backfill slices.
        try execute("CREATE TABLE IF NOT EXISTS task_search_control(id INTEGER PRIMARY KEY CHECK(id=1),backfill_initialized INTEGER NOT NULL)")
        try execute("INSERT OR IGNORE INTO task_search_control VALUES(1,0)")
        try execute("UPDATE task_search_control SET backfill_initialized=0 WHERE NOT EXISTS(SELECT 1 FROM task_aggregate_version WHERE version=2)")
        try execute("INSERT OR IGNORE INTO task_aggregate_version VALUES(2)")
        var state: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT backfill_initialized FROM task_search_control WHERE id=1", -1, &state, nil) == SQLITE_OK else { throw failure("read rebuild state") }
        defer { sqlite3_finalize(state) }
        guard sqlite3_step(state) == SQLITE_ROW else { throw failure("read rebuild state") }
        newlyCreated = sqlite3_column_int(state, 0) == 0
    }

    deinit { sqlite3_close(handle) }

    func confirmBackfillInitialized() throws {
        lock.lock(); defer { lock.unlock() }
        try execute("UPDATE task_search_control SET backfill_initialized=1 WHERE id=1")
        newlyCreated = false
    }

    func upsert(snapshot: AgentTaskSnapshot, revision: Int64) throws {
        let body = try JSONEncoder().encode(snapshot)
        let flags = Self.flags(snapshot)
        let addressExcerpt = snapshot.outboundRequests.compactMap { request -> String? in
            guard let match = Self.addressPattern.firstMatch(in: request.body,
                range: NSRange(request.body.startIndex..., in: request.body)),
                let range = Range(match.range, in: request.body) else { return nil }
            let start = request.body.index(range.lowerBound, offsetBy: -100,
                limitedBy: request.body.startIndex) ?? request.body.startIndex
            let end = request.body.index(range.upperBound, offsetBy: 200,
                limitedBy: request.body.endIndex) ?? request.body.endIndex
            return String(request.body[start..<end])
        }.first
        lock.lock(); defer { lock.unlock() }
        try execute("BEGIN IMMEDIATE")
        do {
            var lookup: OpaquePointer?
            let lookupSQL = "SELECT id,revision FROM task_search_meta WHERE session_id=? AND turn_id=?"
            guard sqlite3_prepare_v2(handle, lookupSQL, -1, &lookup, nil) == SQLITE_OK else { throw failure("prepare search lookup") }
            bind(snapshot.task.sessionID, at: 1, to: lookup)
            bind(snapshot.task.turnID ?? "unattributed", at: 2, to: lookup)
            let existing = sqlite3_step(lookup) == SQLITE_ROW
                ? (sqlite3_column_int64(lookup, 0), sqlite3_column_int64(lookup, 1)) : nil
            sqlite3_finalize(lookup)
            if let existing, existing.1 > revision { try execute("COMMIT"); return }

            var meta: OpaquePointer?
            let metaSQL = """
                INSERT INTO task_search_meta(session_id,turn_id,agent_id,title,started_at,last_at,
                  event_count,revision,evidence_flags,address_in_model_input,address_excerpt)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id,turn_id) DO UPDATE SET
                  agent_id=excluded.agent_id,title=excluded.title,started_at=excluded.started_at,
                  last_at=excluded.last_at,event_count=excluded.event_count,revision=excluded.revision,
                  evidence_flags=excluded.evidence_flags,address_in_model_input=excluded.address_in_model_input,
                  address_excerpt=excluded.address_excerpt
                """
            guard sqlite3_prepare_v2(handle, metaSQL, -1, &meta, nil) == SQLITE_OK else { throw failure("prepare search meta") }
            bind(snapshot.task.sessionID, at: 1, to: meta)
            bind(snapshot.task.turnID ?? "unattributed", at: 2, to: meta)
            bind(snapshot.task.agentID, at: 3, to: meta)
            bindOptional(snapshot.conversation.userInputs.first, at: 4, to: meta)
            sqlite3_bind_double(meta, 5, snapshot.task.startedAt?.timeIntervalSince1970 ?? snapshot.generatedAt.timeIntervalSince1970)
            sqlite3_bind_double(meta, 6, snapshot.task.endedAt?.timeIntervalSince1970 ?? snapshot.generatedAt.timeIntervalSince1970)
            sqlite3_bind_int(meta, 7, Int32(snapshot.capture.eventCount))
            sqlite3_bind_int64(meta, 8, revision)
            sqlite3_bind_int(meta, 9, Int32(flags))
            sqlite3_bind_int(meta, 10, addressExcerpt == nil ? 0 : 1)
            bindOptional(addressExcerpt, at: 11, to: meta)
            guard sqlite3_step(meta) == SQLITE_DONE else { sqlite3_finalize(meta); throw failure("write search meta") }
            sqlite3_finalize(meta)

            let rowID: Int64
            if let existing { rowID = existing.0 }
            else { rowID = sqlite3_last_insert_rowid(handle) }
            if existing != nil {
                var remove: OpaquePointer?
                guard sqlite3_prepare_v2(handle, "DELETE FROM task_search_fts WHERE rowid=?", -1, &remove, nil) == SQLITE_OK else { throw failure("prepare search replace") }
                sqlite3_bind_int64(remove, 1, rowID)
                guard sqlite3_step(remove) == SQLITE_DONE else { sqlite3_finalize(remove); throw failure("replace search document") }
                sqlite3_finalize(remove)
            }
            var insert: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "INSERT INTO task_search_fts(rowid,content) VALUES(?,?)", -1, &insert, nil) == SQLITE_OK else { throw failure("prepare FTS document") }
            sqlite3_bind_int64(insert, 1, rowID)
            _ = body.withUnsafeBytes {
                sqlite3_bind_text(insert, 2, $0.baseAddress?.assumingMemoryBound(to: CChar.self),
                                  Int32(body.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard sqlite3_step(insert) == SQLITE_DONE else { sqlite3_finalize(insert); throw failure("index task document") }
            sqlite3_finalize(insert)
            try execute("INSERT OR REPLACE INTO task_metrics VALUES(\(rowID),\(max(0, snapshot.metrics.inputTokens)),\(max(0, snapshot.metrics.outputTokens)))")
            try execute("DELETE FROM task_facts WHERE task_id=\(rowID)")
            var fact: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "INSERT OR IGNORE INTO task_facts VALUES(?,?,?,?,?)", -1, &fact, nil) == SQLITE_OK else { throw failure("prepare facts") }
            defer { sqlite3_finalize(fact) }
            func saveFact(_ kind: String, _ value: String, _ label: String, _ evidence: String) throws {
                sqlite3_bind_int64(fact, 1, rowID)
                bind(kind, at: 2, to: fact); bind(value, at: 3, to: fact)
                bind(label, at: 4, to: fact); bind(evidence, at: 5, to: fact)
                guard sqlite3_step(fact) == SQLITE_DONE else { throw failure("write fact") }
                sqlite3_reset(fact); sqlite3_clear_bindings(fact)
            }
            for tool in snapshot.activities.tools {
                // Exact name and arguments identify repetition candidates;
                // equality alone does not establish wasted work.
                let signature = Data((tool.toolName + "\u{0}" + (tool.arguments ?? "")).utf8)
                let digest = SHA256.hash(data: signature).map { String(format: "%02x", $0) }.joined()
                try saveFact("tool", digest, tool.toolName, tool.callID)
            }
            for request in snapshot.outboundRequests {
                for match in Self.addressPattern.matches(in: request.body, range: NSRange(request.body.startIndex..., in: request.body)) {
                    if let range = Range(match.range, in: request.body) {
                        let address = String(request.body[range])
                        try saveFact("model_address", address, address, request.eventID)
                    }
                }
            }
            // Structured lineage index: an IP is a memory-write hit only when
            // it appears in the committed memory content/diff, not merely in
            // a prompt or some unrelated event from the same task.
            for write in snapshot.analysis.memoryCommits {
                guard let content = write.contentDiff else { continue }
                for match in Self.ipPattern.matches(in: content, range: NSRange(content.startIndex..., in: content)) {
                    guard let range = Range(match.range, in: content) else { continue }
                    let address = String(content[range])
                    guard IPGeolocationStore.isIPAddress(address) else { continue }
                    let label = "\(write.observedAt.formatted(date: .abbreviated, time: .standard)) · \(write.storagePath ?? "记忆路径未采集") · \(write.changeKind.rawValue)"
                    try saveFact("memory_address", address, label, write.commitId)
                }
            }
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
    }

    func indexedTaskCount() throws -> Int {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM task_search_meta", -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare indexed task count")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw failure("read indexed task count") }
        return Int(sqlite3_column_int64(statement, 0))
    }

    func searchMemoryAddress(_ address: String, limit: Int = 100) throws -> [TaskSearchHit] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
            SELECT m.session_id,m.turn_id,m.agent_id,m.title,m.started_at,m.last_at,
                   m.event_count,m.revision,f.label
            FROM task_facts f JOIN task_search_meta m ON m.id=f.task_id
            WHERE f.kind='memory_address' AND f.value=?
            GROUP BY m.id ORDER BY m.last_at DESC,m.id DESC LIMIT ?
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory lineage search") }
        defer { sqlite3_finalize(statement) }
        bind(address, at: 1, to: statement)
        sqlite3_bind_int(statement, 2, Int32(max(1, min(limit, 500))))
        var result: [TaskSearchHit] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let session = column(statement, 0), let turn = column(statement, 1),
                  let agent = column(statement, 2) else { continue }
            let task = StoredTaskSummary(sessionID: session, turnID: turn, agentID: agent,
                title: column(statement, 3),
                startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 4)),
                lastObservedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)),
                eventCount: Int(sqlite3_column_int64(statement, 6)))
            result.append(TaskSearchHit(task: task, excerpt: column(statement, 8) ?? "",
                                        revision: sqlite3_column_int64(statement, 7), isMemoryWriteMatch: true))
        }
        return result
    }

    func search(_ plan: HistoryQueryUnderstanding, limit: Int = 30) throws -> [TaskSearchHit] {
        lock.lock(); defer { lock.unlock() }
        let terms = plan.searchTerms.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.unicodeScalars.count >= 3 }
        let fts = !terms.isEmpty
        var predicates: [String] = []
        if plan.agent != nil { predicates.append("m.agent_id=?") }
        if let start = Self.day(plan.startDate) { predicates.append("m.last_at>=\(start.timeIntervalSince1970)") }
        if let end = Self.day(plan.endDate) { predicates.append("m.last_at<\(end.timeIntervalSince1970)") }
        if let kind = plan.evidenceKind, let flag = Self.flag(for: kind) {
            predicates.append("(m.evidence_flags & \(flag))!=0")
        }
        if plan.requiresAddressInModelInput { predicates.append("m.address_in_model_input=1") }
        if fts { predicates.append("task_search_fts MATCH ?") }
        else if let short = plan.searchTerms.first, !short.isEmpty { predicates.append("m.title LIKE ?") }
        let sql = """
            SELECT m.session_id,m.turn_id,m.agent_id,m.title,m.started_at,m.last_at,
                   m.event_count,m.revision,\(fts ? "snippet(task_search_fts,0,'[',']','…',18)" : "COALESCE(m.address_excerpt,m.title,'')")
            FROM task_search_meta m
            \(fts ? "JOIN task_search_fts ON task_search_fts.rowid=m.id" : "")
            \(predicates.isEmpty ? "" : "WHERE " + predicates.joined(separator: " AND "))
            ORDER BY m.last_at DESC,m.id DESC LIMIT ?
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare task search") }
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        if let agent = plan.agent { bind(agent, at: index, to: statement); index += 1 }
        if fts {
            let expression = terms.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: " OR ")
            bind(expression, at: index, to: statement); index += 1
        } else if let short = plan.searchTerms.first, !short.isEmpty {
            bind("%\(short)%", at: index, to: statement); index += 1
        }
        sqlite3_bind_int(statement, index, Int32(max(1, min(limit, 100))))
        var result: [TaskSearchHit] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let session = column(statement, 0), let turn = column(statement, 1),
                  let agent = column(statement, 2) else { continue }
            let task = StoredTaskSummary(sessionID: session, turnID: turn, agentID: agent,
                title: column(statement, 3),
                startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 4)),
                lastObservedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)),
                eventCount: Int(sqlite3_column_int64(statement, 6)))
            result.append(TaskSearchHit(task: task, excerpt: column(statement, 8) ?? "",
                                        revision: sqlite3_column_int64(statement, 7)))
        }
        return result
    }

    /// Aggregate all indexed tasks matching the same filters as search. No
    /// pagination limit is applied before COUNT/SUM/GROUP BY.
    func aggregate(_ plan: HistoryQueryUnderstanding) throws -> TaskAggregates {
        lock.lock(); defer { lock.unlock() }
        var conditions: [String] = []
        var bindings: [String] = []
        if let agent = plan.agent { conditions.append("m.agent_id=?"); bindings.append(agent) }
        if let start = Self.day(plan.startDate) { conditions.append("m.last_at>=\(start.timeIntervalSince1970)") }
        if let end = Self.day(plan.endDate) { conditions.append("m.last_at<\(end.timeIntervalSince1970)") }
        if let kind = plan.evidenceKind, let flag = Self.flag(for: kind) { conditions.append("(m.evidence_flags & \(flag))!=0") }
        if plan.requiresAddressInModelInput { conditions.append("m.address_in_model_input=1") }
        let terms = plan.searchTerms.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { $0.unicodeScalars.count >= 3 }
        if !terms.isEmpty {
            conditions.append("m.id IN (SELECT rowid FROM task_search_fts WHERE task_search_fts MATCH ?)")
            bindings.append(terms.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: " OR "))
        } else if let short = plan.searchTerms.first, !short.isEmpty {
            conditions.append("m.title LIKE ?"); bindings.append("%\(short)%")
        }
        let matched = "SELECT m.* FROM task_search_meta m" + (conditions.isEmpty ? "" : " WHERE " + conditions.joined(separator: " AND "))
        func groups(_ sql: String) throws -> [TaskAggregateGroup] {
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "WITH matched AS (\(matched)) " + sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare aggregate") }
            defer { sqlite3_finalize(statement) }
            for (offset, value) in bindings.enumerated() { bind(value, at: Int32(offset + 1), to: statement) }
            var result: [TaskAggregateGroup] = []
            var step = sqlite3_step(statement)
            while step == SQLITE_ROW {
                result.append(TaskAggregateGroup(value: column(statement, 0) ?? "",
                    tasks: Int(sqlite3_column_int64(statement, 1)), occurrences: Int(sqlite3_column_int64(statement, 2)),
                    inputTokens: Int(sqlite3_column_int64(statement, 3)), outputTokens: Int(sqlite3_column_int64(statement, 4))))
                step = sqlite3_step(statement)
            }
            guard step == SQLITE_DONE else { throw failure("aggregate") }
            return result
        }
        try execute("BEGIN")
        do {
            let agents = try groups("SELECT m.agent_id,COUNT(*),0,COALESCE(SUM(t.input_tokens),0),COALESCE(SUM(t.output_tokens),0) FROM matched m LEFT JOIN task_metrics t ON t.task_id=m.id GROUP BY m.agent_id ORDER BY SUM(t.input_tokens+t.output_tokens) DESC")
            let tools = try groups("SELECT MIN(f.label),COUNT(DISTINCT f.task_id),COUNT(*),0,0 FROM matched m JOIN task_facts f ON f.task_id=m.id WHERE f.kind='tool' GROUP BY f.value HAVING COUNT(*)>1 ORDER BY COUNT(*) DESC LIMIT 100")
            let addresses = try groups("SELECT f.value,COUNT(DISTINCT f.task_id),COUNT(*),0,0 FROM matched m JOIN task_facts f ON f.task_id=m.id WHERE f.kind='model_address' GROUP BY f.value ORDER BY COUNT(*) DESC LIMIT 100")
            var ranking: OpaquePointer?
            let rankingSQL = "WITH matched AS (\(matched)) SELECT m.session_id,m.turn_id,COALESCE(m.title,'任务描述未采集'),m.agent_id,t.input_tokens,t.output_tokens FROM matched m JOIN task_metrics t ON t.task_id=m.id ORDER BY (t.input_tokens+t.output_tokens) DESC,m.session_id,m.turn_id LIMIT 10"
            guard sqlite3_prepare_v2(handle, rankingSQL, -1, &ranking, nil) == SQLITE_OK else { throw failure("prepare task ranking") }
            defer { sqlite3_finalize(ranking) }
            for (offset, value) in bindings.enumerated() { bind(value, at: Int32(offset + 1), to: ranking) }
            var ranked: [TaskAggregates.RankedTask] = []
            var step = sqlite3_step(ranking)
            while step == SQLITE_ROW {
                ranked.append(.init(sessionID: column(ranking, 0) ?? "", turnID: column(ranking, 1) ?? "",
                    title: column(ranking, 2) ?? "", agent: column(ranking, 3) ?? "",
                    inputTokens: Int(sqlite3_column_int64(ranking, 4)), outputTokens: Int(sqlite3_column_int64(ranking, 5))))
                step = sqlite3_step(ranking)
            }
            guard step == SQLITE_DONE else { throw failure("read task ranking") }
            try execute("COMMIT")
            return TaskAggregates(topTokenTasks: ranked, agents: agents, repeatedTools: tools, modelInputAddresses: addresses)
        } catch { try? execute("ROLLBACK"); throw error }
    }

    private static func flags(_ snapshot: AgentTaskSnapshot) -> Int {
        var value = 0
        if !snapshot.outboundRequests.isEmpty { value |= 1 }
        if !snapshot.activities.tools.isEmpty { value |= 2 }
        if !snapshot.activities.memory.isEmpty { value |= 4 }
        if !snapshot.activities.network.isEmpty { value |= 8 }
        if !snapshot.activities.files.isEmpty { value |= 16 }
        return value
    }

    private static func flag(for kind: String) -> Int? {
        ["model": 1, "tool": 2, "memory": 4, "network": 8, "file": 16][kind]
    }

    private static func day(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.isLenient = false
        return formatter.date(from: value)
    }

    private static let addressPattern = try! NSRegularExpression(
        pattern: #"\b(?:\d{1,3}\.){3}\d{1,3}\b|https?://[A-Za-z0-9.-]+"#)
    private static let ipPattern = try! NSRegularExpression(pattern: #"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"#)

    private func bind(_ value: String, at index: Int32, to statement: OpaquePointer?) {
        value.withCString { _ = sqlite3_bind_text(statement, index, $0, -1,
            unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
    }

    private func bindOptional(_ value: String?, at index: Int32, to statement: OpaquePointer?) {
        if let value { bind(value, at: index, to: statement) }
        else { sqlite3_bind_null(statement, index) }
    }

    private func column(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        sqlite3_column_text(statement, index).map { String(cString: $0) }
    }

    private func execute(_ sql: String) throws {
        var error: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(handle, sql, nil, nil, &error) == SQLITE_OK else {
            let detail = error.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(error)
            throw NSError(domain: "TaskSearchIndex", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "\(sql.prefix(80)): \(detail)"])
        }
    }

    private func failure(_ action: String) -> NSError {
        NSError(domain: "TaskSearchIndex", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "\(action): \(String(cString: sqlite3_errmsg(handle)))"])
    }
}
