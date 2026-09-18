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
        // Hash-chain tail lookup happens on every raw append. Without these
        // indexes the self-join scanned the complete raw table and blocked the
        // UI once the local evidence store reached hundreds of megabytes.
        try execute("CREATE INDEX IF NOT EXISTS raw_evidence_previous_hash ON raw_evidence(previous_hash)")
        try execute("CREATE INDEX IF NOT EXISTS raw_evidence_record_hash ON raw_evidence(record_hash)")
        try addColumnIfMissing(table: "raw_evidence", column: "previous_hash", definition: "TEXT")
        try addColumnIfMissing(table: "raw_evidence", column: "record_hash", definition: "TEXT")
        try execute("""
            CREATE TABLE IF NOT EXISTS raw_chain_state (
              singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
              record_hash TEXT NOT NULL
            ) WITHOUT ROWID
            """)
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
        try execute("""
            CREATE TABLE IF NOT EXISTS model_route_evidence (
              route_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, turn_id TEXT NOT NULL,
              agent TEXT NOT NULL, destination TEXT NOT NULL, classification TEXT NOT NULL,
              confidence TEXT NOT NULL, identity_status TEXT NOT NULL,
              first_observed_at REAL NOT NULL, last_observed_at REAL NOT NULL,
              payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS model_route_turn ON model_route_evidence(session_id,turn_id,last_observed_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS model_route_destination ON model_route_evidence(destination,last_observed_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS memory_commits (
              commit_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, turn_id TEXT NOT NULL,
              agent TEXT NOT NULL, storage_path TEXT, risk TEXT NOT NULL,
              confidence TEXT NOT NULL, observed_at REAL NOT NULL,
              payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS memory_commit_turn ON memory_commits(session_id,turn_id,observed_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS memory_commit_agent ON memory_commits(agent,observed_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS agent_event_stream (
              event_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              agent_id TEXT NOT NULL,
              session_id TEXT NOT NULL,
              turn_id TEXT,
              sequence INTEGER NOT NULL,
              occurred_at REAL NOT NULL,
              observed_at REAL NOT NULL,
              source TEXT NOT NULL,
              confidence TEXT NOT NULL,
              payload BLOB NOT NULL,
              payload_sha256 TEXT NOT NULL,
              UNIQUE(session_id, sequence)
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS agent_event_project_time ON agent_event_stream(project_id,occurred_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS agent_event_session_sequence ON agent_event_stream(session_id,sequence)")
        try execute("""
            CREATE TABLE IF NOT EXISTS code_change_index (
              change_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, agent_id TEXT NOT NULL,
              session_id TEXT NOT NULL, turn_id TEXT, path TEXT NOT NULL, operation TEXT NOT NULL,
              started_at REAL NOT NULL, last_observed_at REAL NOT NULL, attribution TEXT NOT NULL,
              payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL
            )
            """)
        try execute("CREATE INDEX IF NOT EXISTS code_change_project_time ON code_change_index(project_id,last_observed_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS code_change_project_path ON code_change_index(project_id,path,last_observed_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS code_change_session_turn ON code_change_index(session_id,turn_id,last_observed_at)")
        try execute("""
            CREATE TABLE IF NOT EXISTS change_set_index (
              change_set_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, title TEXT NOT NULL,
              started_at REAL NOT NULL, last_activity_at REAL NOT NULL, state TEXT NOT NULL,
              confidence TEXT NOT NULL, payload BLOB NOT NULL, payload_sha256 TEXT NOT NULL
            )
            """)
        try execute("CREATE INDEX IF NOT EXISTS change_set_project_time ON change_set_index(project_id,last_activity_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS requirement_documents (
              document_id TEXT PRIMARY KEY, change_set_id TEXT NOT NULL, version INTEGER NOT NULL,
              generated_at REAL NOT NULL, model TEXT NOT NULL, payload BLOB NOT NULL,
              payload_sha256 TEXT NOT NULL, UNIQUE(change_set_id,version)
            )
            """)
        try execute("CREATE INDEX IF NOT EXISTS requirement_document_change_set ON requirement_documents(change_set_id,version DESC)")
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
            scheduleMaintenance(database: database, backupURL: backupURL)
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

    /// Explicit, potentially expensive integrity audit. This is invoked by a
    /// user action or scheduled maintenance, never on the live startup path.
    static func verifyAndRecover(url: URL = defaultURL()) throws -> EvidenceDatabase {
        let backupURL = url.appendingPathExtension("backup")
        do {
            let database = try EvidenceDatabase(url: url)
            if try database.verifyIntegrity() { return database }
        } catch {
            // Continue to the same quarantined recovery path below.
        }
        guard FileManager.default.fileExists(atPath: backupURL.path) else {
            throw NSError(domain: "AgentReins.EvidenceDatabase", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Integrity failed and no verified backup is available"])
        }
        let quarantined = url.appendingPathExtension("corrupt-\(Int(Date().timeIntervalSince1970))")
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.moveItem(at: url, to: quarantined) }
        for suffix in ["-wal", "-shm"] { try? FileManager.default.removeItem(atPath: url.path + suffix) }
        try FileManager.default.copyItem(at: backupURL, to: url)
        let recovered = try EvidenceDatabase(url: url)
        guard try recovered.verifyIntegrity() else {
            throw NSError(domain: "AgentReins.EvidenceDatabase", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "The evidence backup also failed integrity verification"])
        }
        return recovered
    }

    /// Full hash-chain verification and a 100+ MB SQLite backup are important
    /// maintenance operations, not launch work. Run them at most weekly and
    /// only after the app has been idle long enough to establish live capture.
    private static func scheduleMaintenance(database: EvidenceDatabase, backupURL: URL) {
        let modified = (try? backupURL.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        guard modified.map({ Date().timeIntervalSince($0) > 7 * 86_400 }) ?? true else { return }
        DispatchQueue.global(qos: .background).asyncAfter(deadline: .now() + 300) {
            guard (try? database.verifyIntegrity()) == true else { return }
            let temporary = backupURL.appendingPathExtension("new")
            try? FileManager.default.removeItem(at: temporary)
            guard (try? database.backup(to: temporary)) != nil else { return }
            if FileManager.default.fileExists(atPath: backupURL.path) {
                try? FileManager.default.removeItem(at: backupURL)
            }
            try? FileManager.default.moveItem(at: temporary, to: backupURL)
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
            if let previousHash {
                try setRawHashUnlocked(previousHash)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    /// Appends canonical Agent events atomically. The `(session_id, sequence)`
    /// constraint makes replay idempotent and turns competing payloads for one
    /// sequence into a visible capture error instead of silently rewriting
    /// evidence.
    func appendAgentEvents(_ events: [AgentEventEnvelope]) throws {
        guard !events.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = """
              INSERT OR IGNORE INTO agent_event_stream(event_id,project_id,agent_id,session_id,
              turn_id,sequence,occurred_at,observed_at,source,confidence,payload,payload_sha256)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
                throw failure("prepare agent event append")
            }
            defer { sqlite3_finalize(statement) }
            for event in events {
                let payload = try encoder.encode(event)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind(event.id, at: 1, to: statement)
                bind(event.projectID, at: 2, to: statement)
                bind(event.agentID, at: 3, to: statement)
                bind(event.sessionID, at: 4, to: statement)
                bindOptional(event.turnID, at: 5, to: statement)
                sqlite3_bind_int64(statement, 6, Int64(event.sequence))
                sqlite3_bind_double(statement, 7, event.occurredAt.timeIntervalSince1970)
                sqlite3_bind_double(statement, 8, event.observedAt.timeIntervalSince1970)
                bind(event.source.rawValue, at: 9, to: statement)
                bind(event.confidence.rawValue, at: 10, to: statement)
                _ = payload.withUnsafeBytes {
                    sqlite3_bind_blob(statement, 11, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT)
                }
                bind(digest, at: 12, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("append agent event") }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch {
            try? executeUnlocked("ROLLBACK")
            throw error
        }
    }

    func agentEvents(projectID: String, limit: Int = 2_000) throws -> [AgentEventEnvelope] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          SELECT payload FROM agent_event_stream WHERE project_id=?
          ORDER BY occurred_at ASC, session_id ASC, sequence ASC LIMIT ?
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare agent event read")
        }
        defer { sqlite3_finalize(statement) }
        bind(projectID, at: 1, to: statement)
        sqlite3_bind_int(statement, 2, Int32(max(1, min(limit, 20_000))))
        var events: [AgentEventEnvelope] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let event = try? decoder.decode(AgentEventEnvelope.self, from: payload) {
                events.append(event)
            }
        }
        return events
    }

    /// On-demand compatibility read used only when a project has no canonical
    /// event stream yet. It reconstructs the selected project rather than
    /// loading historical evidence during application startup.
    func legacyProjectEvents(projectID: String, limit: Int = 5_000) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let root = URL(fileURLWithPath: projectID).standardizedFileURL.path
        let prefix = root.hasSuffix("/") ? root + "%" : root + "/%"
        let sql = """
          SELECT payload FROM (
            SELECT payload, observed_at, ingested_at FROM evidence_records
            WHERE json_extract(CAST(payload AS TEXT), '$.sessionId') IS NOT NULL
              AND (json_extract(CAST(payload AS TEXT), '$.path')=?
                   OR json_extract(CAST(payload AS TEXT), '$.path') LIKE ?)
            ORDER BY observed_at DESC, ingested_at DESC LIMIT ?
          ) ORDER BY observed_at ASC, ingested_at ASC
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare legacy project event read")
        }
        defer { sqlite3_finalize(statement) }
        bind(root, at: 1, to: statement); bind(prefix, at: 2, to: statement)
        sqlite3_bind_int(statement, 3, Int32(max(1, min(limit, 20_000))))
        var result: [GuardEvent] = []; var ids = Set<UUID>()
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let event = try? decoder.decode(GuardEvent.self, from: data), ids.insert(event.id).inserted {
                result.append(event)
            }
        }
        return result
    }

    func agentEvents(sessionID: String) throws -> [AgentEventEnvelope] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT payload FROM agent_event_stream WHERE session_id=? ORDER BY sequence ASC"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare session agent event read")
        }
        defer { sqlite3_finalize(statement) }
        bind(sessionID, at: 1, to: statement)
        var events: [AgentEventEnvelope] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let event = try? decoder.decode(AgentEventEnvelope.self, from: payload) {
                events.append(event)
            }
        }
        return events
    }

    func nextAgentEventSequence(sessionID: String) throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT COALESCE(MAX(sequence),0)+1 FROM agent_event_stream WHERE session_id=?"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare next agent event sequence")
        }
        defer { sqlite3_finalize(statement) }
        bind(sessionID, at: 1, to: statement)
        guard sqlite3_step(statement) == SQLITE_ROW else { throw failure("read next agent event sequence") }
        return UInt64(max(1, sqlite3_column_int64(statement, 0)))
    }

    func upsertCodeChanges(_ changes: [IndexedCodeChange]) throws {
        guard !changes.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = """
              INSERT INTO code_change_index(change_id,project_id,agent_id,session_id,turn_id,path,
              operation,started_at,last_observed_at,attribution,payload,payload_sha256)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(change_id) DO UPDATE SET
              last_observed_at=excluded.last_observed_at,attribution=excluded.attribution,
              payload=excluded.payload,payload_sha256=excluded.payload_sha256
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
                throw failure("prepare code change upsert")
            }
            defer { sqlite3_finalize(statement) }
            for change in changes {
                let payload = try encoder.encode(change)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind(change.id, at: 1, to: statement); bind(change.projectID, at: 2, to: statement)
                bind(change.agentID, at: 3, to: statement); bind(change.sessionID, at: 4, to: statement)
                bindOptional(change.turnID, at: 5, to: statement); bind(change.path, at: 6, to: statement)
                bind(change.operation.rawValue, at: 7, to: statement)
                sqlite3_bind_double(statement, 8, change.startedAt.timeIntervalSince1970)
                sqlite3_bind_double(statement, 9, change.lastObservedAt.timeIntervalSince1970)
                bind(change.attribution.rawValue, at: 10, to: statement)
                _ = payload.withUnsafeBytes { sqlite3_bind_blob(statement, 11, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 12, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert code change") }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func codeChanges(projectID: String, path: String? = nil, limit: Int = 2_000) throws -> [IndexedCodeChange] {
        lock.lock(); defer { lock.unlock() }
        let sql = path == nil
            ? "SELECT payload FROM code_change_index WHERE project_id=? ORDER BY last_observed_at DESC LIMIT ?"
            : "SELECT payload FROM code_change_index WHERE project_id=? AND path=? ORDER BY last_observed_at DESC LIMIT ?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare code change read")
        }
        defer { sqlite3_finalize(statement) }
        bind(projectID, at: 1, to: statement)
        if let path { bind(path, at: 2, to: statement); sqlite3_bind_int(statement, 3, Int32(max(1, min(limit, 20_000)))) }
        else { sqlite3_bind_int(statement, 2, Int32(max(1, min(limit, 20_000)))) }
        var result: [IndexedCodeChange] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let value = try? decoder.decode(IndexedCodeChange.self, from: payload) { result.append(value) }
        }
        return result
    }

    func replaceChangeSets(projectID: String, values: [IndexedChangeSet]) throws {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var deletion: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "DELETE FROM change_set_index WHERE project_id=?", -1,
                                     &deletion, nil) == SQLITE_OK else { throw failure("prepare change set replacement") }
            bind(projectID, at: 1, to: deletion)
            guard sqlite3_step(deletion) == SQLITE_DONE else { sqlite3_finalize(deletion); throw failure("delete change sets") }
            sqlite3_finalize(deletion)
            let sql = """
              INSERT INTO change_set_index(change_set_id,project_id,title,started_at,last_activity_at,
              state,confidence,payload,payload_sha256) VALUES(?,?,?,?,?,?,?,?,?)
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
                throw failure("prepare change set insert")
            }
            defer { sqlite3_finalize(statement) }
            for value in values {
                let payload = try encoder.encode(value)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind(value.id, at: 1, to: statement); bind(value.projectID, at: 2, to: statement)
                bind(value.title, at: 3, to: statement)
                sqlite3_bind_double(statement, 4, value.startedAt.timeIntervalSince1970)
                sqlite3_bind_double(statement, 5, value.lastActivityAt.timeIntervalSince1970)
                bind(value.state.rawValue, at: 6, to: statement)
                bind(value.groupingConfidence.rawValue, at: 7, to: statement)
                _ = payload.withUnsafeBytes { sqlite3_bind_blob(statement, 8, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 9, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("insert change set") }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func changeSets(projectID: String, limit: Int = 500) throws -> [IndexedChangeSet] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT payload FROM change_set_index WHERE project_id=? ORDER BY last_activity_at DESC LIMIT ?"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare change set read")
        }
        defer { sqlite3_finalize(statement) }
        bind(projectID, at: 1, to: statement); sqlite3_bind_int(statement, 2, Int32(max(1, min(limit, 5_000))))
        var result: [IndexedChangeSet] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let value = try? decoder.decode(IndexedChangeSet.self, from: payload) { result.append(value) }
        }
        return result
    }

    func upsertRequirementDocument(_ value: GeneratedRequirementDocument) throws {
        lock.lock(); defer { lock.unlock() }
        let payload = try encoder.encode(value)
        let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let sql = """
          INSERT INTO requirement_documents(document_id,change_set_id,version,generated_at,model,payload,payload_sha256)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(document_id) DO UPDATE SET
          generated_at=excluded.generated_at,model=excluded.model,payload=excluded.payload,
          payload_sha256=excluded.payload_sha256
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare requirement document upsert")
        }
        defer { sqlite3_finalize(statement) }
        bind(value.id, at: 1, to: statement); bind(value.changeSetID, at: 2, to: statement)
        sqlite3_bind_int(statement, 3, Int32(value.version))
        sqlite3_bind_double(statement, 4, value.generatedAt.timeIntervalSince1970)
        bind(value.model, at: 5, to: statement)
        _ = payload.withUnsafeBytes { sqlite3_bind_blob(statement, 6, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT) }
        bind(digest, at: 7, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert requirement document") }
    }

    func requirementDocuments(changeSetID: String) throws -> [GeneratedRequirementDocument] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT payload FROM requirement_documents WHERE change_set_id=? ORDER BY version DESC"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare requirement document read")
        }
        defer { sqlite3_finalize(statement) }
        bind(changeSetID, at: 1, to: statement)
        var result: [GeneratedRequirementDocument] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let value = try? decoder.decode(GeneratedRequirementDocument.self, from: data) { result.append(value) }
        }
        return result
    }

    func rawRecordCount() throws -> Int {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT count(*) FROM raw_evidence", -1, &statement, nil) == SQLITE_OK,
              sqlite3_step(statement) == SQLITE_ROW else { throw failure("raw count") }
        defer { sqlite3_finalize(statement) }
        return Int(sqlite3_column_int64(statement, 0))
    }

    func rawRecords(source: String) throws -> [RawEvidenceRecord] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          SELECT source,stream,offset_start,offset_end,fingerprint,observed_at,payload
          FROM raw_evidence WHERE source=? ORDER BY stream,offset_start,observed_at
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare raw read")
        }
        defer { sqlite3_finalize(statement) }
        bind(source, at: 1, to: statement)
        var records: [RawEvidenceRecord] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let storedSource = text(statement, 0), let stream = text(statement, 1),
                  let bytes = sqlite3_column_blob(statement, 6) else {
                throw failure("decode raw read")
            }
            records.append(RawEvidenceRecord(source: storedSource, stream: stream,
                offsetStart: sqlite3_column_int64(statement, 2),
                offsetEnd: sqlite3_column_int64(statement, 3), fingerprint: text(statement, 4),
                observedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)),
                payload: Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 6)))))
        }
        return records
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

    func replaceModelRoutes(_ records: [ModelRouteEvidence], turns: [(sessionId: String, turnId: String)]) throws {
        guard !turns.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var deleteStatement: OpaquePointer?
            guard sqlite3_prepare_v2(handle,
                "DELETE FROM model_route_evidence WHERE session_id=? AND turn_id=?", -1,
                &deleteStatement, nil) == SQLITE_OK else { throw failure("prepare model route replacement") }
            defer { sqlite3_finalize(deleteStatement) }
            for turn in turns {
                bind(turn.sessionId, at: 1, to: deleteStatement)
                bind(turn.turnId, at: 2, to: deleteStatement)
                guard sqlite3_step(deleteStatement) == SQLITE_DONE else { throw failure("replace model routes") }
                sqlite3_reset(deleteStatement); sqlite3_clear_bindings(deleteStatement)
            }
            let sql = """
              INSERT INTO model_route_evidence(route_id,session_id,turn_id,agent,destination,
              classification,confidence,identity_status,first_observed_at,last_observed_at,payload,payload_sha256)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(route_id) DO UPDATE SET
              classification=excluded.classification,confidence=excluded.confidence,
              identity_status=excluded.identity_status,last_observed_at=excluded.last_observed_at,
              payload=excluded.payload,payload_sha256=excluded.payload_sha256
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare model route") }
            defer { sqlite3_finalize(statement) }
            for record in records {
                let payload = try encoder.encode(record)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind(record.routeId, at: 1, to: statement); bind(record.sessionId, at: 2, to: statement)
                bind(record.turnId, at: 3, to: statement); bind(record.agent, at: 4, to: statement)
                bind(record.destination, at: 5, to: statement); bind(record.classification.rawValue, at: 6, to: statement)
                bind(record.confidence.rawValue, at: 7, to: statement); bind(record.identityStatus, at: 8, to: statement)
                sqlite3_bind_double(statement, 9, record.firstObservedAt.timeIntervalSince1970)
                sqlite3_bind_double(statement, 10, record.lastObservedAt.timeIntervalSince1970)
                _ = payload.withUnsafeBytes { sqlite3_bind_blob(statement, 11, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 12, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert model route") }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func upsertModelRoutes(_ records: [ModelRouteEvidence]) throws {
        let turns = Array(Set(records.map { "\($0.sessionId)\u{0}\($0.turnId)" })).compactMap { key -> (String, String)? in
            let parts = key.split(separator: "\u{0}", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { return nil }
            return (String(parts[0]), String(parts[1]))
        }
        try replaceModelRoutes(records, turns: turns)
    }

    func modelRoutes(sessionId: String, turnId: String) throws -> [ModelRouteEvidence] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT payload FROM model_route_evidence WHERE session_id=? AND turn_id=? ORDER BY last_observed_at DESC"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare model route read") }
        defer { sqlite3_finalize(statement) }
        bind(sessionId, at: 1, to: statement); bind(turnId, at: 2, to: statement)
        var result: [ModelRouteEvidence] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let route = try? decoder.decode(ModelRouteEvidence.self, from: payload) { result.append(route) }
        }
        return result
    }

    func upsertMemoryCommits(_ records: [MemoryCommitEvidence]) throws {
        guard !records.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let sql = """
              INSERT INTO memory_commits(commit_id,session_id,turn_id,agent,storage_path,risk,
              confidence,observed_at,payload,payload_sha256) VALUES(?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(commit_id) DO UPDATE SET risk=excluded.risk,confidence=excluded.confidence,
              payload=excluded.payload,payload_sha256=excluded.payload_sha256
              """
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory commit") }
            defer { sqlite3_finalize(statement) }
            for record in records {
                let payload = try encoder.encode(record)
                let digest = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
                bind(record.commitId, at: 1, to: statement); bind(record.sessionId, at: 2, to: statement)
                bind(record.turnId, at: 3, to: statement); bind(record.agent, at: 4, to: statement)
                bindOptional(record.storagePath, at: 5, to: statement); bind(record.risk, at: 6, to: statement)
                bind(record.confidence.rawValue, at: 7, to: statement)
                sqlite3_bind_double(statement, 8, record.observedAt.timeIntervalSince1970)
                _ = payload.withUnsafeBytes { sqlite3_bind_blob(statement, 9, $0.baseAddress, Int32(payload.count), SQLITE_TRANSIENT) }
                bind(digest, at: 10, to: statement)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert memory commit") }
                sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func memoryCommits(sessionId: String, turnId: String) throws -> [MemoryCommitEvidence] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT payload FROM memory_commits WHERE session_id=? AND turn_id=? ORDER BY observed_at DESC"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory commit read") }
        defer { sqlite3_finalize(statement) }
        bind(sessionId, at: 1, to: statement); bind(turnId, at: 2, to: statement)
        var result: [MemoryCommitEvidence] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let record = try? decoder.decode(MemoryCommitEvidence.self, from: payload) { result.append(record) }
        }
        return result
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

    func historicalSecurityCandidates(limit: Int) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
        WITH candidates AS (
          SELECT payload, observed_at, ingested_at,
                 ROW_NUMBER() OVER (
                   PARTITION BY COALESCE(json_extract(CAST(payload AS TEXT), '$.agent'), 'unknown')
                   ORDER BY observed_at DESC, ingested_at DESC
                 ) AS agent_rank
          FROM evidence_records
          WHERE source LIKE 'agentsight:%' OR source='tool-intent' OR source='policy-engine'
             OR source='external-content-security' OR source='lsof-network'
        )
        SELECT payload FROM candidates WHERE agent_rank <= ?
        ORDER BY observed_at DESC, ingested_at DESC
        """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare security history") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int(statement, 1, Int32(max(1, limit / 5)))
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

    /// Bounded project history used by the project supervisor. Reading is
    /// explicit and incremental: each known session contributes at most the
    /// requested number of newest records.
    func projectEvidence(sessionIDs: [String], limitPerSession: Int = 500) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        guard !sessionIDs.isEmpty else { return [] }
        let sql = "SELECT payload FROM evidence_records WHERE json_extract(CAST(payload AS TEXT), '$.sessionId')=? ORDER BY observed_at DESC, ingested_at DESC LIMIT ?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare project history")
        }
        defer { sqlite3_finalize(statement) }
        var result: [GuardEvent] = []
        var ids = Set<UUID>()
        for sessionID in Set(sessionIDs) {
            sqlite3_reset(statement); sqlite3_clear_bindings(statement)
            bind(sessionID, at: 1, to: statement)
            sqlite3_bind_int(statement, 2, Int32(max(1, limitPerSession)))
            while sqlite3_step(statement) == SQLITE_ROW {
                guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
                let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
                if let event = try? decoder.decode(GuardEvent.self, from: data), ids.insert(event.id).inserted {
                    result.append(event)
                }
            }
        }
        return result.sorted { $0.ts > $1.ts }
    }

    // MARK: - History review

    /// Distinct collectors with row counts, for the history filter picker.
    func historySources() throws -> [(source: String, count: Int)] {
        lock.lock(); defer { lock.unlock() }
        let sql = "SELECT source, COUNT(*) FROM evidence_records GROUP BY source ORDER BY 2 DESC"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare sources") }
        defer { sqlite3_finalize(statement) }
        var result: [(String, Int)] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let text = sqlite3_column_text(statement, 0) else { continue }
            result.append((String(cString: text), Int(sqlite3_column_int64(statement, 1))))
        }
        return result
    }

    private func historyWhere(since: TimeInterval?, source: String?, keyword: String?) -> (sql: String, binds: [String]) {
        var clauses: [String] = []
        var binds: [String] = []
        // Placeholder order matters: since -> source -> keyword. Numeric binds
        // are appended by the caller after these text binds.
        if let since {
            clauses.append("observed_at >= ?")
            binds.append(String(format: "%.3f", since))
        }
        if let source, !source.isEmpty {
            clauses.append("source = ?")
            binds.append(source)
        }
        if let keyword, !keyword.isEmpty {
            clauses.append("payload LIKE ?")
            binds.append("%\(keyword)%")
        }
        return (clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND "), binds)
    }

    func historyCount(since: TimeInterval?, source: String?, keyword: String?) throws -> Int {
        lock.lock(); defer { lock.unlock() }
        let whereClause = historyWhere(since: since, source: source, keyword: keyword)
        let sql = "SELECT COUNT(*) FROM evidence_records \(whereClause.sql)"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare history count") }
        defer { sqlite3_finalize(statement) }
        for (index, value) in whereClause.binds.enumerated() {
            bind(value, at: Int32(index + 1), to: statement)
        }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw failure("history count") }
        return Int(sqlite3_column_int64(statement, 0))
    }

    /// Ordered newest-first. Mirrors `recent` decoding: rows whose payload
    /// does not decode into a GuardEvent are skipped.
    func history(since: TimeInterval?, source: String?, keyword: String?,
                 limit: Int, offset: Int) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let whereClause = historyWhere(since: since, source: source, keyword: keyword)
        let sql = "SELECT payload FROM evidence_records \(whereClause.sql) " +
            "ORDER BY observed_at DESC, ingested_at DESC LIMIT ? OFFSET ?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare history") }
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        for value in whereClause.binds {
            bind(value, at: index, to: statement)
            index += 1
        }
        sqlite3_bind_int(statement, index, Int32(limit)); index += 1
        sqlite3_bind_int(statement, index, Int32(offset))
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

    func events(sessionId: String) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          SELECT payload FROM evidence_records
          WHERE json_extract(CAST(payload AS TEXT), '$.sessionId') = ?
          ORDER BY observed_at ASC, ingested_at ASC
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare session read")
        }
        defer { sqlite3_finalize(statement) }
        bind(sessionId, at: 1, to: statement)
        var result: [GuardEvent] = []
        var ids = Set<UUID>()
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            let event = try decoder.decode(GuardEvent.self, from: data)
            if ids.insert(event.id).inserted {
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
        let stateSQL = "SELECT record_hash FROM raw_chain_state WHERE singleton=1"
        guard sqlite3_prepare_v2(handle, stateSQL, -1, &statement, nil) == SQLITE_OK else { throw failure("last hash state") }
        if sqlite3_step(statement) == SQLITE_ROW {
            let value = text(statement, 0)
            sqlite3_finalize(statement)
            return value
        }
        sqlite3_finalize(statement)
        statement = nil

        // One-time migration for stores created before raw_chain_state. The
        // discovered head is persisted by appendRaw in the same transaction;
        // all subsequent live writes use the constant-time lookup above.
        let sql = "SELECT r.record_hash FROM raw_evidence r LEFT JOIN raw_evidence n ON n.previous_hash=r.record_hash WHERE r.record_hash IS NOT NULL AND n.record_hash IS NULL LIMIT 1"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("last hash") }
        defer { sqlite3_finalize(statement) }
        return sqlite3_step(statement) == SQLITE_ROW ? text(statement, 0) : nil
    }

    private func setRawHashUnlocked(_ hash: String) throws {
        var statement: OpaquePointer?
        let sql = "INSERT INTO raw_chain_state(singleton,record_hash) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET record_hash=excluded.record_hash"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare chain head") }
        defer { sqlite3_finalize(statement) }
        bind(hash, at: 1, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("save chain head") }
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
