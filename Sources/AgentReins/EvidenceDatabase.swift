import CryptoKit
import Foundation
import SQLite3

struct SourceCheckpoint: Equatable, Sendable {
    let source: String
    let stream: String
    let offset: Int64
    let fingerprint: String?
    let updatedAt: Date
}

struct RawEvidenceRecord: Sendable {
    let source: String
    let stream: String
    let offsetStart: Int64
    let offsetEnd: Int64
    let fingerprint: String?
    let observedAt: Date
    let payload: Data
}

struct CollectorHealthRecord: Equatable, Sendable {
    enum State: String, Sendable { case healthy, degraded, failed }

    let source: String
    let state: State
    let lastSuccess: Date?
    let lagSeconds: Double?
    let accepted: Int
    let malformed: Int
    let dropped: Int
    let detail: String?
}

/// Durable local evidence spine. WAL keeps ingestion transactional without
/// blocking readers, and stable evidence keys make replay idempotent.
final class EvidenceDatabase: @unchecked Sendable {
    private var handle: OpaquePointer?
    private let lock = NSLock()
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(url: URL = EvidenceDatabase.defaultURL()) throws {
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        guard sqlite3_open_v2(url.path, &handle,
                              SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                              nil) == SQLITE_OK else {
            throw failure("open")
        }
        try execute("PRAGMA journal_mode=WAL")
        try execute("PRAGMA synchronous=NORMAL")
        try execute("PRAGMA busy_timeout=5000")
        try execute("PRAGMA foreign_keys=ON")
        try execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
              evidence_key TEXT PRIMARY KEY,
              event_id TEXT NOT NULL,
              source TEXT NOT NULL,
              observed_at REAL NOT NULL,
              payload BLOB NOT NULL,
              payload_sha256 TEXT NOT NULL,
              collector_version INTEGER NOT NULL DEFAULT 1,
              ingested_at REAL NOT NULL
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS evidence_time ON evidence_records(observed_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS raw_evidence (
              evidence_key TEXT PRIMARY KEY, source TEXT NOT NULL, stream TEXT NOT NULL,
              offset_start INTEGER NOT NULL, offset_end INTEGER NOT NULL, fingerprint TEXT,
              observed_at REAL NOT NULL, payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL
              , previous_hash TEXT, record_hash TEXT
            ) WITHOUT ROWID
            """)
        try addColumnIfMissing(table: "raw_evidence", column: "previous_hash", definition: "TEXT")
        try addColumnIfMissing(table: "raw_evidence", column: "record_hash", definition: "TEXT")
        try execute("""
            CREATE TABLE IF NOT EXISTS source_checkpoints (
              source TEXT NOT NULL,
              stream TEXT NOT NULL,
              byte_offset INTEGER NOT NULL,
              fingerprint TEXT,
              updated_at REAL NOT NULL,
              PRIMARY KEY(source, stream)
            ) WITHOUT ROWID
            """)
        try execute("""
            CREATE TABLE IF NOT EXISTS collector_health (
              source TEXT PRIMARY KEY,
              state TEXT NOT NULL,
              last_success REAL,
              lag_seconds REAL,
              accepted INTEGER NOT NULL,
              malformed INTEGER NOT NULL,
              dropped INTEGER NOT NULL,
              detail TEXT,
              updated_at REAL NOT NULL
            ) WITHOUT ROWID
            """)
        try execute("""
            CREATE TABLE IF NOT EXISTS forensic_assessments (
              assessment_id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL,
              turn_id TEXT NOT NULL,
              agent TEXT NOT NULL,
              assessment_type TEXT NOT NULL,
              rule_version INTEGER NOT NULL,
              confidence TEXT NOT NULL,
              generated_at REAL NOT NULL,
              evidence_event_ids BLOB NOT NULL,
              payload BLOB NOT NULL,
              payload_sha256 TEXT NOT NULL
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS forensic_turn ON forensic_assessments(session_id,turn_id,generated_at DESC)")
    }

    deinit { sqlite3_close(handle) }

    static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("AgentGuard/evidence.sqlite3")
    }

    static func openRecovering(url: URL = defaultURL()) throws -> EvidenceDatabase {
        let backupURL = url.appendingPathExtension("backup")
        do {
            let database = try EvidenceDatabase(url: url)
            guard try database.verifyIntegrity() else {
                throw NSError(domain: "AgentReins.EvidenceDatabase", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "Raw evidence integrity verification failed"])
            }
            let temporary = backupURL.appendingPathExtension("new")
            try? FileManager.default.removeItem(at: temporary)
            try database.backup(to: temporary)
            if FileManager.default.fileExists(atPath: backupURL.path) { try FileManager.default.removeItem(at: backupURL) }
            try FileManager.default.moveItem(at: temporary, to: backupURL)
            return database
        } catch {
            guard FileManager.default.fileExists(atPath: backupURL.path) else { throw error }
            let quarantined = url.appendingPathExtension("corrupt-\(Int(Date().timeIntervalSince1970))")
            if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.moveItem(at: url, to: quarantined) }
            for suffix in ["-wal", "-shm"] { try? FileManager.default.removeItem(atPath: url.path + suffix) }
            try FileManager.default.copyItem(at: backupURL, to: url)
            return try EvidenceDatabase(url: url)
        }
    }

    func append(_ events: [GuardEvent]) throws {
        guard !events.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = "INSERT OR IGNORE INTO evidence_records(evidence_key,event_id,source,observed_at,payload,payload_sha256,ingested_at) VALUES(?,?,?,?,?,?,?)"
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare append") }
            defer { sqlite3_finalize(statement) }
            for event in events {
                let payload = try encoder.encode(event)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind("\(event.id.uuidString):\(digest)", at: 1, to: statement)
                bind(event.id.uuidString, at: 2, to: statement)
                bind(event.source ?? "unknown", at: 3, to: statement)
                sqlite3_bind_double(statement, 4, event.ts.timeIntervalSince1970)
                _ = payload.withUnsafeBytes { bytes in
                    sqlite3_bind_blob(statement, 5, bytes.baseAddress, Int32(payload.count), SQLITE_TRANSIENT)
                }
                bind(digest, at: 6, to: statement)
                sqlite3_bind_double(statement, 7, Date().timeIntervalSince1970)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("append") }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch {
            try? executeUnlocked("ROLLBACK")
            throw error
        }
    }

    func appendRaw(_ records: [RawEvidenceRecord]) throws {
        guard !records.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = "INSERT OR IGNORE INTO raw_evidence(evidence_key,source,stream,offset_start,offset_end,fingerprint,observed_at,payload,payload_sha256,previous_hash,record_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare raw") }
            defer { sqlite3_finalize(statement) }
            var previousHash = try lastRawHashUnlocked()
            for record in records {
                let digest = SHA256.hash(data: record.payload).map { String(format: "%02x", $0) }.joined()
                let chainMaterial = "\(previousHash ?? "GENESIS")|\(record.source)|\(record.stream)|\(record.offsetStart)|\(record.offsetEnd)|\(digest)"
                let recordHash = SHA256.hash(data: Data(chainMaterial.utf8)).map { String(format: "%02x", $0) }.joined()
                bind("\(record.source):\(record.stream):\(record.offsetStart):\(record.offsetEnd):\(digest)", at: 1, to: statement)
                bind(record.source, at: 2, to: statement); bind(record.stream, at: 3, to: statement)
                sqlite3_bind_int64(statement, 4, record.offsetStart); sqlite3_bind_int64(statement, 5, record.offsetEnd)
                bindOptional(record.fingerprint, at: 6, to: statement)
                sqlite3_bind_double(statement, 7, record.observedAt.timeIntervalSince1970)
                _ = record.payload.withUnsafeBytes { sqlite3_bind_blob(statement, 8, $0.baseAddress, Int32(record.payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 9, to: statement)
                bindOptional(previousHash, at: 10, to: statement); bind(recordHash, at: 11, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("append raw") }
                if sqlite3_changes(handle) > 0 { previousHash = recordHash }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func rawRecordCount() throws -> Int {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT count(*) FROM raw_evidence", -1, &statement, nil) == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW else { throw failure("raw count") }
        defer { sqlite3_finalize(statement) }
        return Int(sqlite3_column_int64(statement, 0))
    }

    func upsertAssessments(_ records: [ForensicAssessmentRecord]) throws {
        guard !records.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = """
              INSERT INTO forensic_assessments(assessment_id,session_id,turn_id,agent,assessment_type,
              rule_version,confidence,generated_at,evidence_event_ids,payload,payload_sha256)
              VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(assessment_id) DO UPDATE SET
              confidence=excluded.confidence,generated_at=excluded.generated_at,
              evidence_event_ids=excluded.evidence_event_ids,payload=excluded.payload,payload_sha256=excluded.payload_sha256
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare assessment") }
            defer { sqlite3_finalize(statement) }
            for record in records {
                let references = try encoder.encode(record.evidenceEventIds)
                let digest = SHA256.hash(data: record.payload).map { String(format: "%02x", $0) }.joined()
                bind(record.assessmentId, at: 1, to: statement); bind(record.sessionId, at: 2, to: statement)
                bind(record.turnId, at: 3, to: statement); bind(record.agent, at: 4, to: statement)
                bind(record.kind.rawValue, at: 5, to: statement); sqlite3_bind_int(statement, 6, Int32(record.ruleVersion))
                bind(record.confidence.rawValue, at: 7, to: statement)
                sqlite3_bind_double(statement, 8, record.generatedAt.timeIntervalSince1970)
                _ = references.withUnsafeBytes { sqlite3_bind_blob(statement, 9, $0.baseAddress, Int32(references.count), SQLITE_TRANSIENT) }
                _ = record.payload.withUnsafeBytes { sqlite3_bind_blob(statement, 10, $0.baseAddress, Int32(record.payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 11, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert assessment") }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func assessments(sessionId: String, turnId: String) throws -> [ForensicAssessmentRecord] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT assessment_id,agent,assessment_type,rule_version,confidence,generated_at,evidence_event_ids,payload FROM forensic_assessments WHERE session_id=? AND turn_id=? ORDER BY assessment_type"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare assessment read") }
        defer { sqlite3_finalize(statement) }
        bind(sessionId, at: 1, to: statement); bind(turnId, at: 2, to: statement)
        var result: [ForensicAssessmentRecord] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let id = text(statement, 0), let agent = text(statement, 1), let rawKind = text(statement, 2),
                  let kind = ForensicAssessmentKind(rawValue: rawKind), let rawConfidence = text(statement, 4),
                  let confidence = EvidenceConfidence(rawValue: rawConfidence),
                  let referenceBytes = sqlite3_column_blob(statement, 6), let payloadBytes = sqlite3_column_blob(statement, 7) else { continue }
            let references = Data(bytes: referenceBytes, count: Int(sqlite3_column_bytes(statement, 6)))
            let payload = Data(bytes: payloadBytes, count: Int(sqlite3_column_bytes(statement, 7)))
            let ids = (try? decoder.decode([String].self, from: references)) ?? []
            result.append(ForensicAssessmentRecord(assessmentId: id, sessionId: sessionId, turnId: turnId,
                agent: agent, kind: kind, ruleVersion: Int(sqlite3_column_int(statement, 3)), confidence: confidence,
                generatedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)), evidenceEventIds: ids,
                payload: payload))
        }
        return result
    }

    func verifyIntegrity() throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT source,stream,offset_start,offset_end,payload_sha256,previous_hash,record_hash FROM raw_evidence WHERE record_hash IS NOT NULL ORDER BY observed_at,evidence_key"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("integrity prepare") }
        defer { sqlite3_finalize(statement) }
        var hashes = Set<String>()
        var links: [String: String] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let source = text(statement, 0), let stream = text(statement, 1),
                  let digest = text(statement, 4), let storedHash = text(statement, 6) else { return false }
            let storedPrevious = text(statement, 5)
            let material = "\(storedPrevious ?? "GENESIS")|\(source)|\(stream)|\(sqlite3_column_int64(statement, 2))|\(sqlite3_column_int64(statement, 3))|\(digest)"
            let computed = SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
            guard computed == storedHash else { return false }
            guard hashes.insert(storedHash).inserted else { return false }
            let key = storedPrevious ?? "GENESIS"
            guard links[key] == nil else { return false }
            links[key] = storedHash
        }
        if hashes.isEmpty { return true }
        var visited = Set<String>(), cursor = links["GENESIS"]
        while let hash = cursor, visited.insert(hash).inserted { cursor = links[hash] }
        return visited == hashes
    }

    func backup(to destination: URL) throws {
        lock.lock(); defer { lock.unlock() }
        var target: OpaquePointer?
        guard sqlite3_open(destination.path, &target) == SQLITE_OK else { throw failure("backup open") }
        defer { sqlite3_close(target) }
        guard let backup = sqlite3_backup_init(target, "main", handle, "main") else { throw failure("backup init") }
        defer { sqlite3_backup_finish(backup) }
        guard sqlite3_backup_step(backup, -1) == SQLITE_DONE else { throw failure("backup") }
    }

    func recent(limit: Int) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT payload FROM evidence_records ORDER BY observed_at DESC, ingested_at DESC LIMIT ?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare read") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int(statement, 1, Int32(limit))
        var result: [GuardEvent] = []
        var ids = Set<UUID>()
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let event = try? decoder.decode(GuardEvent.self, from: data), ids.insert(event.id).inserted {
                result.append(event)
            }
        }
        return result
    }

    func saveCheckpoint(_ checkpoint: SourceCheckpoint) throws {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          INSERT INTO source_checkpoints(source,stream,byte_offset,fingerprint,updated_at) VALUES(?,?,?,?,?)
          ON CONFLICT(source,stream) DO UPDATE SET byte_offset=excluded.byte_offset,
          fingerprint=excluded.fingerprint,updated_at=excluded.updated_at
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare checkpoint") }
        defer { sqlite3_finalize(statement) }
        bind(checkpoint.source, at: 1, to: statement)
        bind(checkpoint.stream, at: 2, to: statement)
        sqlite3_bind_int64(statement, 3, checkpoint.offset)
        bindOptional(checkpoint.fingerprint, at: 4, to: statement)
        sqlite3_bind_double(statement, 5, checkpoint.updatedAt.timeIntervalSince1970)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("checkpoint") }
    }

    func checkpoint(source: String, stream: String) throws -> SourceCheckpoint? {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT byte_offset,fingerprint,updated_at FROM source_checkpoints WHERE source=? AND stream=?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare checkpoint read") }
        defer { sqlite3_finalize(statement) }
        bind(source, at: 1, to: statement); bind(stream, at: 2, to: statement)
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return SourceCheckpoint(source: source, stream: stream, offset: sqlite3_column_int64(statement, 0),
                                fingerprint: text(statement, 1),
                                updatedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 2)))
    }

    func checkpoints(source: String) throws -> [String: UInt64] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT stream,byte_offset FROM source_checkpoints WHERE source=?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare checkpoints") }
        defer { sqlite3_finalize(statement) }
        bind(source, at: 1, to: statement)
        var result: [String: UInt64] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            if let stream = text(statement, 0) { result[stream] = UInt64(max(0, sqlite3_column_int64(statement, 1))) }
        }
        return result
    }

    func updateHealth(_ record: CollectorHealthRecord) throws {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          INSERT INTO collector_health(source,state,last_success,lag_seconds,accepted,malformed,dropped,detail,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,
          last_success=excluded.last_success,lag_seconds=excluded.lag_seconds,accepted=excluded.accepted,
          malformed=excluded.malformed,dropped=excluded.dropped,detail=excluded.detail,updated_at=excluded.updated_at
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare health") }
        defer { sqlite3_finalize(statement) }
        bind(record.source, at: 1, to: statement); bind(record.state.rawValue, at: 2, to: statement)
        bindOptional(record.lastSuccess?.timeIntervalSince1970, at: 3, to: statement)
        bindOptional(record.lagSeconds, at: 4, to: statement)
        sqlite3_bind_int(statement, 5, Int32(record.accepted)); sqlite3_bind_int(statement, 6, Int32(record.malformed))
        sqlite3_bind_int(statement, 7, Int32(record.dropped)); bindOptional(record.detail, at: 8, to: statement)
        sqlite3_bind_double(statement, 9, Date().timeIntervalSince1970)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("health") }
    }

    func healthRecords() throws -> [CollectorHealthRecord] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT source,state,last_success,lag_seconds,accepted,malformed,dropped,detail FROM collector_health ORDER BY source"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare health read") }
        defer { sqlite3_finalize(statement) }
        var records: [CollectorHealthRecord] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let source = text(statement, 0), let rawState = text(statement, 1),
                  let state = CollectorHealthRecord.State(rawValue: rawState) else { continue }
            records.append(CollectorHealthRecord(source: source, state: state,
                lastSuccess: sqlite3_column_type(statement, 2) == SQLITE_NULL ? nil : Date(timeIntervalSince1970: sqlite3_column_double(statement, 2)),
                lagSeconds: sqlite3_column_type(statement, 3) == SQLITE_NULL ? nil : sqlite3_column_double(statement, 3),
                accepted: Int(sqlite3_column_int(statement, 4)), malformed: Int(sqlite3_column_int(statement, 5)),
                dropped: Int(sqlite3_column_int(statement, 6)), detail: text(statement, 7)))
        }
        return records
    }

    func journalMode() throws -> String {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "PRAGMA journal_mode", -1, &statement, nil) == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW, let mode = text(statement, 0) else { throw failure("journal mode") }
        defer { sqlite3_finalize(statement) }
        return mode
    }

    private func execute(_ sql: String) throws { lock.lock(); defer { lock.unlock() }; try executeUnlocked(sql) }
    private func executeUnlocked(_ sql: String) throws {
        guard sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else { throw failure(sql) }
    }
    private func lastRawHashUnlocked() throws -> String? {
        var statement: OpaquePointer?
        let sql = "SELECT r.record_hash FROM raw_evidence r LEFT JOIN raw_evidence n ON n.previous_hash=r.record_hash WHERE r.record_hash IS NOT NULL AND n.record_hash IS NULL LIMIT 1"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("last hash") }
        defer { sqlite3_finalize(statement) }
        return sqlite3_step(statement) == SQLITE_ROW ? text(statement, 0) : nil
    }
    private func addColumnIfMissing(table: String, column: String, definition: String) throws {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "PRAGMA table_info(\(table))", -1, &statement, nil) == SQLITE_OK else { throw failure("table info") }
        var found = false
        while sqlite3_step(statement) == SQLITE_ROW { if text(statement, 1) == column { found = true } }
        sqlite3_finalize(statement)
        if !found { try execute("ALTER TABLE \(table) ADD COLUMN \(column) \(definition)") }
    }
    private func bind(_ value: String, at index: Int32, to statement: OpaquePointer?) {
        sqlite3_bind_text(statement, index, value, -1, SQLITE_TRANSIENT)
    }
    private func bindOptional(_ value: String?, at index: Int32, to statement: OpaquePointer?) {
        if let value { bind(value, at: index, to: statement) } else { sqlite3_bind_null(statement, index) }
    }
    private func bindOptional(_ value: Double?, at index: Int32, to statement: OpaquePointer?) {
        if let value { sqlite3_bind_double(statement, index, value) } else { sqlite3_bind_null(statement, index) }
    }
    private func text(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        sqlite3_column_text(statement, index).map { String(cString: $0) }
    }
    private func failure(_ operation: String) -> NSError {
        NSError(domain: "AgentReins.EvidenceDatabase", code: Int(sqlite3_errcode(handle)),
                userInfo: [NSLocalizedDescriptionKey: "\(operation): \(String(cString: sqlite3_errmsg(handle)))"])
    }
}

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
