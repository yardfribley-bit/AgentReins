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

struct EvidenceParseJob: Sendable {
    let key: String
    let token: String
    let event: GuardEvent
}

struct EvidenceAnalysisJob: Sendable {
    let sessionID: String
    let turnID: String
    let revision: Int64
    let token: String
}

struct TaskSearchJob: Sendable {
    let sessionID: String
    let turnID: String
    let revision: Int64
}

struct AuditOutboxJob: Sendable {
    let sessionID: String
    let turnID: String
    let revision: Int64
    let token: String
    let snapshot: AgentTaskSnapshot
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
    private static let registryLock = NSLock()
    private final class WeakDatabase {
        weak var value: EvidenceDatabase?
        init(_ value: EvidenceDatabase) { self.value = value }
    }
    private static var registry: [String: WeakDatabase] = [:]

    /// One writable connection per database in this process. Independent read
    /// connections still serve task views without joining the writer backlog.
    static func shared(url: URL = defaultURL()) throws -> EvidenceDatabase {
        let canonical = url.standardizedFileURL.resolvingSymlinksInPath()
        registryLock.lock(); defer { registryLock.unlock() }
        if let existing = registry[canonical.path]?.value { return existing }
        let database = try openRecovering(url: canonical)
        registry[canonical.path] = WeakDatabase(database)
        return database
    }

    private var handle: OpaquePointer?
    private var readConnection: EvidenceReadConnection?
    private let lock = NSRecursiveLock()
    private var auditUploadEnabled = false
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(url: URL = EvidenceDatabase.defaultURL()) throws {
        encoder = JSONEncoder()
        // Content hashes are persistent identities; dictionary key order must
        // not turn an identical record into a new evidence revision on replay.
        encoder.outputFormatting = [.sortedKeys]
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
        try execute("CREATE INDEX IF NOT EXISTS evidence_event_lookup ON evidence_records(event_id,ingested_at DESC)")
        try execute("""
            CREATE TABLE IF NOT EXISTS evidence_parse_jobs(
              evidence_key TEXT PRIMARY KEY REFERENCES evidence_records(evidence_key),
              state TEXT NOT NULL DEFAULT 'pending', token TEXT,
              lease_until REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
              not_before REAL NOT NULL DEFAULT 0, last_error TEXT
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS evidence_parse_ready ON evidence_parse_jobs(state,not_before,lease_until)")
        try execute("CREATE TABLE IF NOT EXISTS evidence_parse_order(position INTEGER PRIMARY KEY AUTOINCREMENT,evidence_key TEXT NOT NULL UNIQUE REFERENCES evidence_parse_jobs(evidence_key),partition_key TEXT NOT NULL)")
        try execute("CREATE INDEX IF NOT EXISTS evidence_parse_partition ON evidence_parse_order(partition_key,position)")
        try execute("""
            CREATE TABLE IF NOT EXISTS evidence_analysis_jobs(
              session_id TEXT NOT NULL,turn_id TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,
              completed_revision INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'pending',
              token TEXT,lease_until REAL NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,
              not_before REAL NOT NULL DEFAULT 0,last_error TEXT,
              PRIMARY KEY(session_id,turn_id)
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS evidence_analysis_ready ON evidence_analysis_jobs(state,not_before,lease_until)")
        try execute("CREATE TABLE IF NOT EXISTS task_snapshot_projection(session_id TEXT NOT NULL,turn_id TEXT NOT NULL,revision INTEGER NOT NULL,payload BLOB NOT NULL,generated_at REAL NOT NULL,PRIMARY KEY(session_id,turn_id)) WITHOUT ROWID")
        try execute("CREATE TABLE IF NOT EXISTS task_search_jobs(session_id TEXT NOT NULL,turn_id TEXT NOT NULL,revision INTEGER NOT NULL,completed_revision INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'pending',PRIMARY KEY(session_id,turn_id)) WITHOUT ROWID")
        try addColumnIfMissing(table: "task_search_jobs", column: "state", definition: "TEXT NOT NULL DEFAULT 'pending'")
        try execute("CREATE INDEX IF NOT EXISTS task_search_ready ON task_search_jobs(state,session_id,turn_id)")
        try execute("CREATE TABLE IF NOT EXISTS task_search_backfill(id INTEGER PRIMARY KEY CHECK(id=1),session_id TEXT NOT NULL,turn_id TEXT NOT NULL,complete INTEGER NOT NULL)")
        try execute("INSERT OR IGNORE INTO task_search_backfill VALUES(1,'','',0)")
        try execute("""
            CREATE TABLE IF NOT EXISTS audit_upload_outbox(
              session_id TEXT NOT NULL,turn_id TEXT NOT NULL,revision INTEGER NOT NULL,
              completed_revision INTEGER NOT NULL DEFAULT 0,state TEXT NOT NULL DEFAULT 'pending',
              token TEXT,lease_until REAL NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,
              not_before REAL NOT NULL DEFAULT 0,last_error TEXT,receipt_id TEXT,
              PRIMARY KEY(session_id,turn_id)
            ) WITHOUT ROWID
            """)
        try execute("CREATE INDEX IF NOT EXISTS audit_upload_ready ON audit_upload_outbox(state,not_before,lease_until)")
        try execute("CREATE TABLE IF NOT EXISTS evidence_pipeline_migrations(version INTEGER PRIMARY KEY)")
        // Existing queue positions are established once, atomically. Subsequent
        // admissions allocate monotonic positions in the evidence transaction.
        try execute("BEGIN IMMEDIATE")
        do {
            var migration: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "SELECT 1 FROM evidence_pipeline_migrations WHERE version=1", -1, &migration, nil) == SQLITE_OK else { throw failure("read pipeline migration") }
            let migrated = sqlite3_step(migration) == SQLITE_ROW
            sqlite3_finalize(migration)
            if !migrated {
            try execute("""
                INSERT OR IGNORE INTO evidence_parse_order(evidence_key,partition_key)
                SELECT j.evidence_key,
                  json_array(COALESCE(json_extract(CAST(e.payload AS TEXT),'$.agent'),'unknown'),
                    COALESCE(json_extract(CAST(e.payload AS TEXT),'$.sessionId'),e.source))
                FROM evidence_parse_jobs j CROSS JOIN evidence_records e ON e.evidence_key=j.evidence_key
                ORDER BY e.ingested_at,j.evidence_key
                """)
            try execute("INSERT OR IGNORE INTO evidence_pipeline_migrations VALUES(1)")
            }
            try execute("COMMIT")
        } catch { try? execute("ROLLBACK"); throw error }
        try execute("""
            CREATE TRIGGER IF NOT EXISTS evidence_parse_admission AFTER INSERT ON evidence_parse_jobs
            BEGIN
              INSERT INTO evidence_parse_order(evidence_key,partition_key)
              SELECT NEW.evidence_key,
                json_array(COALESCE(json_extract(CAST(payload AS TEXT),'$.agent'),'unknown'),
                  COALESCE(json_extract(CAST(payload AS TEXT),'$.sessionId'),source))
              FROM evidence_records WHERE evidence_key=NEW.evidence_key;
            END
            """)
        // Session detail used to scan and JSON-decode every historical record.
        // Security consumes immutable evidence positions, not task-sized JSON.
        // Historical admissions are backfilled by a bounded worker, never at startup.
        try execute("CREATE TABLE IF NOT EXISTS security_evidence_inputs(position INTEGER PRIMARY KEY AUTOINCREMENT,evidence_key TEXT NOT NULL UNIQUE,session_id TEXT NOT NULL,turn_id TEXT NOT NULL,tool_call_id TEXT,operation TEXT)")
        try addColumnIfMissing(table: "security_evidence_inputs", column: "tool_call_id", definition: "TEXT")
        try addColumnIfMissing(table: "security_evidence_inputs", column: "operation", definition: "TEXT")
        try execute("CREATE INDEX IF NOT EXISTS security_input_task ON security_evidence_inputs(session_id,turn_id,position)")
        try execute("CREATE INDEX IF NOT EXISTS security_input_call ON security_evidence_inputs(session_id,turn_id,tool_call_id,operation,position)")
        try execute("CREATE TABLE IF NOT EXISTS security_evidence_tasks(session_id TEXT NOT NULL,turn_id TEXT NOT NULL,revision INTEGER NOT NULL,updated REAL NOT NULL,PRIMARY KEY(session_id,turn_id)) WITHOUT ROWID")
        try execute("CREATE INDEX IF NOT EXISTS security_tasks_activity ON security_evidence_tasks(updated DESC)")
        try execute("CREATE TABLE IF NOT EXISTS security_input_backfill(id INTEGER PRIMARY KEY,last_position INTEGER NOT NULL)")
        try execute("INSERT OR IGNORE INTO security_input_backfill VALUES(1,0)")
        try execute("""
            CREATE TRIGGER IF NOT EXISTS security_input_revision AFTER INSERT ON security_evidence_inputs
            BEGIN
              INSERT INTO security_evidence_tasks SELECT NEW.session_id,NEW.turn_id,NEW.position,observed_at
                FROM evidence_records WHERE evidence_key=NEW.evidence_key
              ON CONFLICT(session_id,turn_id) DO UPDATE SET revision=MAX(revision,excluded.revision),updated=MAX(updated,excluded.updated);
            END
            """)
        // Security input admission is intentionally performed by the durable
        // processor in small batches, outside the hot evidence write path.
        // A trigger here would JSON-decode every event while the Agent is live.
        // SQLite can use this expression index for the existing session query.
        try execute("""
            CREATE INDEX IF NOT EXISTS evidence_session_time ON evidence_records(
              json_extract(CAST(payload AS TEXT), '$.sessionId'), observed_at, ingested_at
            )
            """)
        try execute("""
            CREATE INDEX IF NOT EXISTS evidence_task_time ON evidence_records(
              json_extract(CAST(payload AS TEXT), '$.sessionId'),
              json_extract(CAST(payload AS TEXT), '$.turnId'), observed_at, ingested_at
            )
            """)
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
        try execute("CREATE TABLE IF NOT EXISTS memory_commit_addresses(address TEXT NOT NULL,commit_id TEXT NOT NULL,session_id TEXT NOT NULL,turn_id TEXT NOT NULL,observed_at REAL NOT NULL,storage_path TEXT,confidence TEXT NOT NULL,PRIMARY KEY(address,commit_id)) WITHOUT ROWID")
        try execute("CREATE INDEX IF NOT EXISTS memory_address_time ON memory_commit_addresses(address,observed_at DESC)")
        try execute("CREATE VIRTUAL TABLE IF NOT EXISTS memory_commit_fts USING fts5(commit_id UNINDEXED,content,tokenize='trigram')")
        try backfillMemorySearchIndexIfNeeded()
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
        try execute("CREATE TABLE IF NOT EXISTS dirty_code_sessions(project_id TEXT NOT NULL, session_id TEXT NOT NULL, PRIMARY KEY(project_id,session_id)) WITHOUT ROWID")
        try execute("CREATE INDEX IF NOT EXISTS agent_event_project_time ON agent_event_stream(project_id,occurred_at DESC)")
        try execute("CREATE INDEX IF NOT EXISTS agent_event_session_sequence ON agent_event_stream(session_id,sequence)")
        try execute("CREATE INDEX IF NOT EXISTS agent_event_task_sequence ON agent_event_stream(session_id,turn_id,sequence)")
        try execute("CREATE TABLE IF NOT EXISTS task_summary(session_id TEXT NOT NULL,turn_id TEXT NOT NULL,agent_id TEXT NOT NULL,started_at REAL NOT NULL,last_at REAL NOT NULL,event_count INTEGER NOT NULL,title TEXT,title_checked INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(session_id,turn_id)) WITHOUT ROWID")
        try addColumnIfMissing(table: "task_summary", column: "title", definition: "TEXT")
        try addColumnIfMissing(table: "task_summary", column: "title_checked", definition: "INTEGER NOT NULL DEFAULT 0")
        try execute("CREATE INDEX IF NOT EXISTS task_summary_time ON task_summary(last_at DESC,session_id,turn_id)")
        try execute("CREATE INDEX IF NOT EXISTS task_summary_agent_time ON task_summary(agent_id,last_at DESC,session_id,turn_id)")
        try execute("CREATE INDEX IF NOT EXISTS task_summary_title_pending ON task_summary(session_id,turn_id) WHERE title_checked=0")
        try execute("CREATE TABLE IF NOT EXISTS task_summary_version(version INTEGER PRIMARY KEY)")
        try execute("CREATE TABLE IF NOT EXISTS task_summary_backfill_state(id INTEGER PRIMARY KEY CHECK(id=1),last_session_id TEXT NOT NULL,last_turn_id TEXT NOT NULL,completed INTEGER NOT NULL)")
        try execute("INSERT OR IGNORE INTO task_summary_backfill_state VALUES(1,'','',0)")
        try execute("CREATE TABLE IF NOT EXISTS collector_parser_state(source TEXT NOT NULL,stream TEXT NOT NULL,state BLOB NOT NULL,PRIMARY KEY(source,stream)) WITHOUT ROWID")
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
        readConnection = try EvidenceReadConnection(url: url)
    }

    deinit { readConnection = nil; sqlite3_close(handle) }

    static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("AgentGuard/evidence.sqlite3")
    }

    func setAuditUploadEnabled(_ enabled: Bool) {
        lock.lock(); defer { lock.unlock() }
        auditUploadEnabled = enabled
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

    /// Checkpoints may advance only after all three durable representations succeed.
    /// Each write is idempotent; interruption before the checkpoint replays safely.
    func persistCollected(raw: [RawEvidenceRecord], events: [GuardEvent],
                          checkpoints: [SourceCheckpoint] = [],
                          parserStates: [(source: String, stream: String, state: Data)] = []) throws {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            try appendRaw(raw, withinTransaction: true)
            try append(events, withinTransaction: true)
            for state in parserStates {
                try saveParserState(source: state.source, stream: state.stream, state: state.state)
            }
            for checkpoint in checkpoints { try saveCheckpoint(checkpoint) }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func parserStates(source: String) throws -> [String: Data] {
        lock.lock(); defer { lock.unlock() }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT stream,state FROM collector_parser_state WHERE source=?", -1, &stmt, nil) == SQLITE_OK else { throw failure("parser state") }
        defer { sqlite3_finalize(stmt) }
        bind(source, at: 1, to: stmt)
        var result: [String: Data] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let stream = text(stmt, 0), let bytes = sqlite3_column_blob(stmt, 1) {
                result[stream] = Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, 1)))
            }
        }
        return result
    }

    func saveParserState(source: String, stream: String, state: Data) throws {
        lock.lock(); defer { lock.unlock() }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "INSERT OR REPLACE INTO collector_parser_state VALUES(?,?,?)", -1, &stmt, nil) == SQLITE_OK else { throw failure("save parser state") }
        defer { sqlite3_finalize(stmt) }
        bind(source, at: 1, to: stmt); bind(stream, at: 2, to: stmt)
        _ = state.withUnsafeBytes { sqlite3_bind_blob(stmt, 3, $0.baseAddress, Int32(state.count), SQLITE_TRANSIENT) }
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw failure("save parser state") }
    }

    func append(_ events: [GuardEvent]) throws {
        try append(events, withinTransaction: false)
    }

    /// Metadata-only bounded catch-up; payloads remain in the evidence store.
    func advanceSecurityInputIndex(limit: Int = 25) throws {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            let count = max(1, min(limit, 100))
            // Admit a bounded recent window independently of the historical cursor.
            // Existing keys are removed before reading and decoding their bodies.
            try executeUnlocked("""
                INSERT OR IGNORE INTO security_evidence_inputs(evidence_key,session_id,turn_id,tool_call_id,operation)
                SELECT o.evidence_key,json_extract(CAST(e.payload AS TEXT),'$.sessionId'),json_extract(CAST(e.payload AS TEXT),'$.turnId'),json_extract(CAST(e.payload AS TEXT),'$.toolCallId'),json_extract(CAST(e.payload AS TEXT),'$.op')
                FROM (SELECT evidence_key FROM (SELECT evidence_key,position FROM evidence_parse_order ORDER BY position DESC LIMIT 100) recent
                  WHERE NOT EXISTS(SELECT 1 FROM security_evidence_inputs i WHERE i.evidence_key=recent.evidence_key)
                  ORDER BY position DESC LIMIT \(count)) o
                JOIN evidence_records e ON e.evidence_key=o.evidence_key
                WHERE e.observed_at>=unixepoch()-120
                  AND json_extract(CAST(e.payload AS TEXT),'$.sessionId') IS NOT NULL
                  AND json_extract(CAST(e.payload AS TEXT),'$.turnId') IS NOT NULL
                """)
            try executeUnlocked("""
                INSERT OR IGNORE INTO security_evidence_inputs(evidence_key,session_id,turn_id,tool_call_id,operation)
                SELECT o.evidence_key,json_extract(CAST(e.payload AS TEXT),'$.sessionId'),json_extract(CAST(e.payload AS TEXT),'$.turnId'),json_extract(CAST(e.payload AS TEXT),'$.toolCallId'),json_extract(CAST(e.payload AS TEXT),'$.op')
                FROM (SELECT position,evidence_key FROM evidence_parse_order
                  WHERE position>(SELECT last_position FROM security_input_backfill WHERE id=1)
                  ORDER BY position LIMIT \(count)) o
                JOIN evidence_records e ON e.evidence_key=o.evidence_key
                WHERE json_extract(CAST(e.payload AS TEXT),'$.sessionId') IS NOT NULL
                  AND json_extract(CAST(e.payload AS TEXT),'$.turnId') IS NOT NULL
                """)
            try executeUnlocked("""
                UPDATE security_input_backfill SET last_position=COALESCE((SELECT MAX(position) FROM
                (SELECT position FROM evidence_parse_order WHERE position>last_position ORDER BY position LIMIT \(count))),last_position)
                WHERE id=1
                """)
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    private func append(_ events: [GuardEvent], withinTransaction: Bool) throws {
        guard !events.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        if !withinTransaction { try executeUnlocked("BEGIN IMMEDIATE") }
        do {
            let sql = "INSERT OR IGNORE INTO evidence_records(evidence_key,event_id,source,observed_at,payload,payload_sha256,ingested_at) VALUES(?,?,?,?,?,?,?)"
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare append") }
            defer { sqlite3_finalize(statement) }
            var work: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "INSERT OR IGNORE INTO evidence_parse_jobs(evidence_key) VALUES(?)", -1, &work, nil) == SQLITE_OK else { throw failure("prepare durable parse work") }
            defer { sqlite3_finalize(work) }
            for event in events {
                let payload = try encoder.encode(event)
                let digits = Array("0123456789abcdef".utf8)
                var hex = [UInt8](); hex.reserveCapacity(64)
                for byte in SHA256.hash(data: payload) {
                    hex.append(digits[Int(byte >> 4)]); hex.append(digits[Int(byte & 15)])
                }
                let digest = String(decoding: hex, as: UTF8.self)
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
                if sqlite3_changes(handle) > 0 {
                    bind("\(event.id.uuidString):\(digest)", at: 1, to: work)
                    guard sqlite3_step(work) == SQLITE_DONE else { throw failure("register parse work") }
                    sqlite3_reset(work); sqlite3_clear_bindings(work)
                }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            if !withinTransaction { try executeUnlocked("COMMIT") }
        } catch {
            if !withinTransaction { try? executeUnlocked("ROLLBACK") }
            throw error
        }
    }

    /// One record per lease bounds the number of large bodies resident at once.
    /// A single worker owns sequence allocation; expired leases are fenced at commit.
    func claimParseJob(now: Date = Date(), leaseSeconds: TimeInterval = 60) throws -> EvidenceParseJob? {
        lock.lock(); defer { lock.unlock() }
        do {
            var row: OpaquePointer?
            let sql = """
                WITH heads AS MATERIALIZED (
                  SELECT ordering.partition_key,MIN(ordering.position) AS position
                  FROM evidence_parse_jobs unfinished
                  JOIN evidence_parse_order ordering ON ordering.evidence_key=unfinished.evidence_key
                  WHERE unfinished.state!='done'
                  GROUP BY ordering.partition_key
                )
                SELECT j.evidence_key,e.payload FROM heads
                CROSS JOIN evidence_parse_order ordering ON ordering.position=heads.position
                CROSS JOIN evidence_parse_jobs j ON j.evidence_key=ordering.evidence_key
                JOIN evidence_records e ON e.evidence_key=j.evidence_key
                WHERE ((j.state='pending' AND j.not_before<=?)
                   OR (j.state='running' AND j.lease_until<=?))
                ORDER BY ordering.position LIMIT 1
                """
            guard sqlite3_prepare_v2(handle, sql, -1, &row, nil) == SQLITE_OK else { throw failure("prepare parse claim") }
            defer { if row != nil { sqlite3_finalize(row) } }
            sqlite3_bind_double(row, 1, now.timeIntervalSince1970)
            sqlite3_bind_double(row, 2, now.timeIntervalSince1970)
            let step = sqlite3_step(row)
            if step == SQLITE_DONE { return nil }
            guard step == SQLITE_ROW, let key = text(row, 0),
                  let bytes = sqlite3_column_blob(row, 1) else { throw failure("read parse work") }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(row, 1)))
            // Selection and JSON decoding must not hold SQLite's writer lease.
            sqlite3_finalize(row); row = nil
            let decoded = Result { try decoder.decode(GuardEvent.self, from: data) }
            try executeUnlocked("BEGIN IMMEDIATE")
            let token = UUID().uuidString
            var claim: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "UPDATE evidence_parse_jobs SET state='running',token=?,lease_until=?,attempts=attempts+1 WHERE evidence_key=? AND ((state='pending' AND not_before<=?) OR (state='running' AND lease_until<=?))", -1, &claim, nil) == SQLITE_OK else { throw failure("prepare lease") }
            defer { sqlite3_finalize(claim) }
            bind(token, at: 1, to: claim)
            sqlite3_bind_double(claim, 2, now.addingTimeInterval(leaseSeconds).timeIntervalSince1970)
            bind(key, at: 3, to: claim)
            sqlite3_bind_double(claim, 4, now.timeIntervalSince1970)
            sqlite3_bind_double(claim, 5, now.timeIntervalSince1970)
            guard sqlite3_step(claim) == SQLITE_DONE else { throw failure("claim parse work") }
            // Another process may have leased this record after our selection.
            guard sqlite3_changes(handle) == 1 else {
                try executeUnlocked("COMMIT")
                return nil
            }
            // Invalid persisted JSON is isolated without blocking other records.
            switch decoded {
            case .success(let event):
                try executeUnlocked("COMMIT")
                return EvidenceParseJob(key: key, token: token, event: event)
            case .failure:
                var quarantine: OpaquePointer?
                guard sqlite3_prepare_v2(handle, "UPDATE evidence_parse_jobs SET state='isolated',last_error='Invalid evidence JSON',token=NULL WHERE evidence_key=?", -1, &quarantine, nil) == SQLITE_OK else { throw failure("prepare quarantine") }
                defer { sqlite3_finalize(quarantine) }
                bind(key, at: 1, to: quarantine)
                guard sqlite3_step(quarantine) == SQLITE_DONE else { throw failure("quarantine evidence") }
                try executeUnlocked("COMMIT")
                return nil
            }
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func retryParseJob(_ job: EvidenceParseJob, message: String) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = """
            UPDATE evidence_parse_jobs SET state=CASE WHEN attempts>=8 THEN 'isolated' ELSE 'pending' END,
            not_before=?+MIN(300,5*(1<<MIN(attempts,6))),token=NULL,last_error=?
            WHERE evidence_key=? AND token=? AND state='running'
            """
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare parse retry") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, Date().timeIntervalSince1970)
        bind(String(message.prefix(512)), at: 2, to: statement)
        bind(job.key, at: 3, to: statement); bind(job.token, at: 4, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("schedule parse retry") }
    }

    func appendRaw(_ records: [RawEvidenceRecord]) throws {
        try appendRaw(records, withinTransaction: false)
    }

    private func appendRaw(_ records: [RawEvidenceRecord], withinTransaction: Bool) throws {
        guard !records.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        if !withinTransaction { try executeUnlocked("BEGIN IMMEDIATE") }
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
            if !withinTransaction { try executeUnlocked("COMMIT") }
        } catch {
            if !withinTransaction { try? executeUnlocked("ROLLBACK") }
            throw error
        }
    }

    /// Appends canonical Agent events atomically. The `(session_id, sequence)`
    /// constraint makes replay idempotent and turns competing payloads for one
    /// sequence into a visible capture error instead of silently rewriting
    /// evidence.
    @discardableResult
    func appendAgentEvents(_ events: [AgentEventEnvelope], completing job: EvidenceParseJob? = nil) throws -> [AgentEventEnvelope] {
        guard !events.isEmpty || job != nil else { return [] }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        var inserted: [AgentEventEnvelope] = []
        do {
            if let job {
                var check: OpaquePointer?
                guard sqlite3_prepare_v2(handle, "SELECT 1 FROM evidence_parse_jobs WHERE evidence_key=? AND token=? AND state='running' AND lease_until>?", -1, &check, nil) == SQLITE_OK else { throw failure("prepare lease fence") }
                defer { sqlite3_finalize(check) }
                bind(job.key, at: 1, to: check); bind(job.token, at: 2, to: check)
                sqlite3_bind_double(check, 3, Date().timeIntervalSince1970)
                guard sqlite3_step(check) == SQLITE_ROW else { throw failure("expired parse lease") }
            }
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
                if sqlite3_changes(handle) > 0 {
                    inserted.append(event)
                } else if job != nil {
                    // A concurrent canonical writer may have taken this sequence.
                    // Never acknowledge durable work after INSERT OR IGNORE hid it.
                    throw failure("canonical event conflict; retry parse work")
                }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            // Persist invalidation in the same transaction as evidence so a
            // restart cannot lose deferred indexing work.
            var summary: OpaquePointer?
            let summarySQL = "INSERT INTO task_summary(session_id,turn_id,agent_id,started_at,last_at,event_count,title,title_checked) VALUES(?,?,?,?,?,1,?,1) ON CONFLICT(session_id,turn_id) DO UPDATE SET agent_id=excluded.agent_id,started_at=MIN(started_at,excluded.started_at),last_at=MAX(last_at,excluded.last_at),event_count=event_count+1,title=COALESCE(task_summary.title,excluded.title)"
            guard sqlite3_prepare_v2(handle, summarySQL, -1, &summary, nil) == SQLITE_OK else { throw failure("prepare task summary") }
            defer { sqlite3_finalize(summary) }
            for event in inserted {
                guard let turn = event.turnID else { continue }
                bind(event.sessionID, at: 1, to: summary); bind(turn, at: 2, to: summary)
                bind(event.agentID, at: 3, to: summary)
                sqlite3_bind_double(summary, 4, event.occurredAt.timeIntervalSince1970)
                sqlite3_bind_double(summary, 5, event.occurredAt.timeIntervalSince1970)
                if case let .userPrompt(prompt) = event.payload {
                    bind(prompt.rawText, at: 6, to: summary)
                } else {
                    sqlite3_bind_null(summary, 6)
                }
                guard sqlite3_step(summary) == SQLITE_DONE else { throw failure("update task summary") }
                sqlite3_reset(summary); sqlite3_clear_bindings(summary)
            }
            var dirty: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "INSERT OR IGNORE INTO dirty_code_sessions VALUES(?,?)", -1, &dirty, nil) == SQLITE_OK else {
                throw failure("prepare index invalidation")
            }
            defer { sqlite3_finalize(dirty) }
            for event in inserted where CodeChangeIndexer.needsRefresh([event]) {
                bind(event.projectID, at: 1, to: dirty)
                bind(event.sessionID, at: 2, to: dirty)
                guard sqlite3_step(dirty) == SQLITE_DONE else { throw failure("invalidate code index") }
                sqlite3_reset(dirty); sqlite3_clear_bindings(dirty)
            }
            var analysis: OpaquePointer?
            let analysisSQL = "INSERT INTO evidence_analysis_jobs(session_id,turn_id) VALUES(?,?) ON CONFLICT(session_id,turn_id) DO UPDATE SET revision=revision+1,state='pending',not_before=0,last_error=NULL"
            guard sqlite3_prepare_v2(handle, analysisSQL, -1, &analysis, nil) == SQLITE_OK else { throw failure("prepare analysis work") }
            defer { sqlite3_finalize(analysis) }
            for key in Set(inserted.compactMap { event -> String? in
                guard let turn = event.turnID else { return nil }
                return "\(event.sessionID)\u{0}\(turn)"
            }) {
                let parts = key.split(separator: "\u{0}", maxSplits: 1, omittingEmptySubsequences: false)
                bind(String(parts[0]), at: 1, to: analysis); bind(String(parts[1]), at: 2, to: analysis)
                guard sqlite3_step(analysis) == SQLITE_DONE else { throw failure("register analysis work") }
                sqlite3_reset(analysis); sqlite3_clear_bindings(analysis)
            }
            // When enterprise upload is enabled, its outbox is invalidated in
            // the same commit as canonical evidence. Local-only installs do
            // not accumulate work that no consumer can ever drain.
            if auditUploadEnabled {
                var outbox: OpaquePointer?
                let outboxSQL = """
                  INSERT INTO audit_upload_outbox(session_id,turn_id,revision)
                  SELECT session_id,turn_id,revision FROM evidence_analysis_jobs
                  WHERE session_id=? AND turn_id=?
                  ON CONFLICT(session_id,turn_id) DO UPDATE SET
                    revision=excluded.revision,state='pending',token=NULL,lease_until=0,
                    not_before=0,last_error=NULL
                  """
                guard sqlite3_prepare_v2(handle, outboxSQL, -1, &outbox, nil) == SQLITE_OK else { throw failure("prepare audit outbox") }
                defer { sqlite3_finalize(outbox) }
                for key in Set(inserted.compactMap { event -> String? in
                    guard let turn = event.turnID else { return nil }
                    return "\(event.sessionID)\u{0}\(turn)"
                }) {
                    let parts = key.split(separator: "\u{0}", maxSplits: 1, omittingEmptySubsequences: false)
                    bind(String(parts[0]), at: 1, to: outbox); bind(String(parts[1]), at: 2, to: outbox)
                    guard sqlite3_step(outbox) == SQLITE_DONE else { throw failure("register audit outbox") }
                    sqlite3_reset(outbox); sqlite3_clear_bindings(outbox)
                }
            }
            if let job {
                var ack: OpaquePointer?
                guard sqlite3_prepare_v2(handle, "UPDATE evidence_parse_jobs SET state='done',token=NULL,last_error=NULL WHERE evidence_key=? AND token=?", -1, &ack, nil) == SQLITE_OK else { throw failure("prepare parse confirmation") }
                defer { sqlite3_finalize(ack) }
                bind(job.key, at: 1, to: ack); bind(job.token, at: 2, to: ack)
                guard sqlite3_step(ack) == SQLITE_DONE else { throw failure("confirm parse work") }
            }
            try executeUnlocked("COMMIT")
            return inserted
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

    func dirtyCodeSessions(projectID: String) throws -> [String] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT session_id FROM dirty_code_sessions WHERE project_id=?", -1, &statement, nil) == SQLITE_OK else { throw failure("read dirty indexes") }
        defer { sqlite3_finalize(statement) }
        bind(projectID, at: 1, to: statement)
        var sessions: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if let id = text(statement, 0) { sessions.append(id) }
        }
        return sessions
    }

    func clearDirtyCodeSession(projectID: String, sessionID: String) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "DELETE FROM dirty_code_sessions WHERE project_id=? AND session_id=?", -1, &statement, nil) == SQLITE_OK else { throw failure("clear dirty index") }
        defer { sqlite3_finalize(statement) }
        bind(projectID, at: 1, to: statement); bind(sessionID, at: 2, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("clear dirty index") }
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

    func recentTasks(limit: Int, before: Date? = nil, offset: Int = 0,
                     after cursor: StoredTaskSummary? = nil) throws -> [StoredTaskSummary] {
        if let readConnection {
            return try readConnection.recentTasks(limit: limit, before: before, offset: offset, after: cursor)
        }
        lock.lock(); defer { lock.unlock() }
        let cursorClause = cursor == nil ? "" :
            "AND (last_at < ? OR (last_at = ? AND (session_id,turn_id) > (?,?)))"
        let sql = """
          WITH recent AS (
            SELECT * FROM task_summary WHERE last_at < ? \(cursorClause)
            ORDER BY last_at DESC, session_id, turn_id LIMIT ? OFFSET ?
          )
          SELECT recent.session_id, recent.turn_id, recent.agent_id,
                 recent.started_at, recent.last_at, recent.event_count,
                 (SELECT json_extract(CAST(prompt.payload AS TEXT), '$.payload.userPrompt._0.rawText')
                  FROM agent_event_stream AS prompt
                  WHERE prompt.session_id = recent.session_id AND prompt.turn_id = recent.turn_id
                    AND json_type(CAST(prompt.payload AS TEXT), '$.payload.userPrompt') IS NOT NULL
                  ORDER BY prompt.sequence ASC LIMIT 1)
          FROM recent ORDER BY recent.last_at DESC, recent.session_id, recent.turn_id
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare recent tasks")
        }
        defer { sqlite3_finalize(statement) }
        var bindIndex: Int32 = 1
        sqlite3_bind_double(statement, bindIndex, before?.timeIntervalSince1970 ?? Date.distantFuture.timeIntervalSince1970)
        bindIndex += 1
        if let cursor {
            sqlite3_bind_double(statement, bindIndex, cursor.lastObservedAt.timeIntervalSince1970); bindIndex += 1
            sqlite3_bind_double(statement, bindIndex, cursor.lastObservedAt.timeIntervalSince1970); bindIndex += 1
            bind(cursor.sessionID, at: bindIndex, to: statement); bindIndex += 1
            bind(cursor.turnID, at: bindIndex, to: statement); bindIndex += 1
        }
        sqlite3_bind_int(statement, bindIndex, Int32(max(1, min(limit, 200)))); bindIndex += 1
        sqlite3_bind_int(statement, bindIndex, Int32(max(0, offset)))
        var result: [StoredTaskSummary] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let sessionID = text(statement, 0),
                  let turnID = text(statement, 1),
                  let agentID = text(statement, 2) else { continue }
            result.append(StoredTaskSummary(sessionID: sessionID, turnID: turnID,
                agentID: agentID, title: text(statement, 6),
                startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 3)),
                lastObservedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 4)),
                eventCount: Int(sqlite3_column_int64(statement, 5))))
        }
        return result
    }

    /// Incrementally materialize summaries for pre-existing events. A bounded
    /// batch runs as a short transaction and stores its cursor atomically, so
    /// history queries never initiate a whole-database GROUP BY.
    @discardableResult
    func backfillTaskSummaries(limit: Int = 25) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var version: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "SELECT 1 FROM task_summary_version WHERE version=1", -1, &version, nil) == SQLITE_OK else { throw failure("prepare task summary version") }
            let alreadyComplete = sqlite3_step(version) == SQLITE_ROW
            sqlite3_finalize(version)
            if alreadyComplete {
                try executeUnlocked("UPDATE task_summary_backfill_state SET completed=1 WHERE id=1")
                try executeUnlocked("COMMIT")
                return true
            }
            var state: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "SELECT last_session_id,last_turn_id,completed FROM task_summary_backfill_state WHERE id=1", -1, &state, nil) == SQLITE_OK else { throw failure("prepare task summary backfill state") }
            defer { sqlite3_finalize(state) }
            guard sqlite3_step(state) == SQLITE_ROW,
                  let lastSession = text(state, 0), let lastTurn = text(state, 1) else { throw failure("read task summary backfill state") }
            if sqlite3_column_int(state, 2) != 0 {
                try executeUnlocked("COMMIT")
                return true
            }
            var cursor: OpaquePointer?
            let cursorSQL = "SELECT session_id,turn_id FROM agent_event_stream WHERE turn_id IS NOT NULL AND (session_id,turn_id)>(?,?) GROUP BY session_id,turn_id ORDER BY session_id,turn_id LIMIT ?"
            guard sqlite3_prepare_v2(handle, cursorSQL, -1, &cursor, nil) == SQLITE_OK else { throw failure("prepare task summary backfill page") }
            defer { sqlite3_finalize(cursor) }
            bind(lastSession, at: 1, to: cursor); bind(lastTurn, at: 2, to: cursor)
            sqlite3_bind_int(cursor, 3, Int32(max(1, min(limit, 100))))
            var keys: [(String, String)] = []
            while sqlite3_step(cursor) == SQLITE_ROW {
                if let session = text(cursor, 0), let turn = text(cursor, 1) { keys.append((session, turn)) }
            }
            if keys.isEmpty {
                try executeUnlocked("INSERT OR IGNORE INTO task_summary_version VALUES(1)")
                try executeUnlocked("UPDATE task_summary_backfill_state SET completed=1 WHERE id=1")
                try executeUnlocked("COMMIT")
                return true
            }
            var aggregate: OpaquePointer?
            let aggregateSQL = "SELECT MAX(agent_id),MIN(occurred_at),MAX(occurred_at),COUNT(*) FROM agent_event_stream WHERE session_id=? AND turn_id=?"
            guard sqlite3_prepare_v2(handle, aggregateSQL, -1, &aggregate, nil) == SQLITE_OK else { throw failure("prepare task summary aggregate") }
            defer { sqlite3_finalize(aggregate) }
            var write: OpaquePointer?
            let writeSQL = "INSERT OR REPLACE INTO task_summary(session_id,turn_id,agent_id,started_at,last_at,event_count) VALUES(?,?,?,?,?,?)"
            guard sqlite3_prepare_v2(handle, writeSQL, -1, &write, nil) == SQLITE_OK else { throw failure("prepare task summary backfill write") }
            defer { sqlite3_finalize(write) }
            for (session, turn) in keys {
                bind(session, at: 1, to: aggregate); bind(turn, at: 2, to: aggregate)
                guard sqlite3_step(aggregate) == SQLITE_ROW, let agent = text(aggregate, 0) else { throw failure("aggregate task summary") }
                bind(session, at: 1, to: write); bind(turn, at: 2, to: write); bind(agent, at: 3, to: write)
                sqlite3_bind_double(write, 4, sqlite3_column_double(aggregate, 1))
                sqlite3_bind_double(write, 5, sqlite3_column_double(aggregate, 2))
                sqlite3_bind_int64(write, 6, sqlite3_column_int64(aggregate, 3))
                guard sqlite3_step(write) == SQLITE_DONE else { throw failure("write task summary") }
                sqlite3_reset(aggregate); sqlite3_clear_bindings(aggregate)
                sqlite3_reset(write); sqlite3_clear_bindings(write)
            }
            let last = keys[keys.count - 1]
            var update: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "UPDATE task_summary_backfill_state SET last_session_id=?,last_turn_id=? WHERE id=1", -1, &update, nil) == SQLITE_OK else { throw failure("prepare task summary cursor") }
            bind(last.0, at: 1, to: update); bind(last.1, at: 2, to: update)
            guard sqlite3_step(update) == SQLITE_DONE else { sqlite3_finalize(update); throw failure("save task summary cursor") }
            sqlite3_finalize(update)
            try executeUnlocked("COMMIT")
            return false
        } catch {
            try? executeUnlocked("ROLLBACK")
            throw error
        }
    }

    /// Legacy summaries gained a materialized title after their original
    /// creation. Fill it once in bounded idle batches; a task with no captured
    /// user prompt is marked checked so it is never scanned again.
    @discardableResult
    func backfillTaskTitles(limit: Int = 25) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var select: OpaquePointer?
            let sql = "SELECT session_id,turn_id FROM task_summary WHERE title_checked=0 ORDER BY session_id,turn_id LIMIT ?"
            guard sqlite3_prepare_v2(handle, sql, -1, &select, nil) == SQLITE_OK else { throw failure("prepare title backfill") }
            defer { sqlite3_finalize(select) }
            sqlite3_bind_int(select, 1, Int32(max(1, min(limit, 100))))
            var keys: [(String, String)] = []
            while sqlite3_step(select) == SQLITE_ROW {
                if let session = text(select, 0), let turn = text(select, 1) { keys.append((session, turn)) }
            }
            if keys.isEmpty { try executeUnlocked("COMMIT"); return true }
            var update: OpaquePointer?
            let updateSQL = """
                UPDATE task_summary SET title=COALESCE(title,(
                  SELECT json_extract(CAST(prompt.payload AS TEXT),'$.payload.userPrompt._0.rawText')
                  FROM agent_event_stream prompt
                  WHERE prompt.session_id=task_summary.session_id AND prompt.turn_id=task_summary.turn_id
                    AND json_type(CAST(prompt.payload AS TEXT),'$.payload.userPrompt') IS NOT NULL
                  ORDER BY prompt.sequence LIMIT 1)),title_checked=1
                WHERE session_id=? AND turn_id=?
                """
            guard sqlite3_prepare_v2(handle, updateSQL, -1, &update, nil) == SQLITE_OK else { throw failure("prepare title backfill update") }
            defer { sqlite3_finalize(update) }
            for (session, turn) in keys {
                bind(session, at: 1, to: update); bind(turn, at: 2, to: update)
                guard sqlite3_step(update) == SQLITE_DONE else { throw failure("backfill title") }
                sqlite3_reset(update); sqlite3_clear_bindings(update)
            }
            try executeUnlocked("COMMIT")
            return keys.count < max(1, min(limit, 100))
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
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

    func claimAnalysisJob(now: Date = Date(), leaseSeconds: TimeInterval = 120) throws -> EvidenceAnalysisJob? {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var row: OpaquePointer?
            let sql = "SELECT session_id,turn_id,revision FROM evidence_analysis_jobs WHERE (state='pending' AND not_before<=?) OR (state='running' AND lease_until<=?) ORDER BY not_before,session_id,turn_id LIMIT 1"
            guard sqlite3_prepare_v2(handle, sql, -1, &row, nil) == SQLITE_OK else { throw failure("prepare analysis claim") }
            defer { sqlite3_finalize(row) }
            sqlite3_bind_double(row, 1, now.timeIntervalSince1970); sqlite3_bind_double(row, 2, now.timeIntervalSince1970)
            let step = sqlite3_step(row)
            if step == SQLITE_DONE { try executeUnlocked("COMMIT"); return nil }
            guard step == SQLITE_ROW, let session = text(row, 0), let turn = text(row, 1) else { throw failure("read analysis work") }
            let revision = sqlite3_column_int64(row, 2), token = UUID().uuidString
            var claim: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "UPDATE evidence_analysis_jobs SET state='running',token=?,lease_until=?,attempts=attempts+1 WHERE session_id=? AND turn_id=? AND revision=?", -1, &claim, nil) == SQLITE_OK else { throw failure("prepare analysis lease") }
            defer { sqlite3_finalize(claim) }
            bind(token, at: 1, to: claim); sqlite3_bind_double(claim, 2, now.addingTimeInterval(leaseSeconds).timeIntervalSince1970)
            bind(session, at: 3, to: claim); bind(turn, at: 4, to: claim); sqlite3_bind_int64(claim, 5, revision)
            guard sqlite3_step(claim) == SQLITE_DONE, sqlite3_changes(handle) == 1 else { throw failure("claim analysis work") }
            try executeUnlocked("COMMIT")
            return EvidenceAnalysisJob(sessionID: session, turnID: turn, revision: revision, token: token)
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    /// Schedules only legacy tasks that have a materialized history summary but
    /// no analysis work yet. This runs in bounded batches while the app is idle;
    /// unlike live event admission it deliberately creates no upload outbox row.
    @discardableResult
    func enqueueHistoricalAnalysisJobs(limit: Int = 25) throws -> Int {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var statement: OpaquePointer?
            let sql = """
              INSERT OR IGNORE INTO evidence_analysis_jobs(session_id,turn_id)
              SELECT s.session_id,s.turn_id FROM task_summary s
              LEFT JOIN evidence_analysis_jobs j
                ON j.session_id=s.session_id AND j.turn_id=s.turn_id
              WHERE j.session_id IS NULL
              ORDER BY s.session_id,s.turn_id LIMIT ?
              """
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare historical analysis admission") }
            defer { sqlite3_finalize(statement) }
            sqlite3_bind_int(statement, 1, Int32(max(1, min(limit, 100))))
            guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("enqueue historical analysis") }
            let inserted = Int(sqlite3_changes(handle))
            try executeUnlocked("COMMIT")
            return inserted
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func retryAnalysisJob(_ job: EvidenceAnalysisJob, message: String) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "UPDATE evidence_analysis_jobs SET state=CASE WHEN attempts>=8 THEN 'isolated' ELSE 'pending' END,not_before=?+MIN(300,5*(1<<MIN(attempts,6))),token=NULL,last_error=? WHERE session_id=? AND turn_id=? AND revision=? AND token=?"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare analysis retry") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, Date().timeIntervalSince1970); bind(String(message.prefix(512)), at: 2, to: statement)
        bind(job.sessionID, at: 3, to: statement); bind(job.turnID, at: 4, to: statement)
        sqlite3_bind_int64(statement, 5, job.revision); bind(job.token, at: 6, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("retry analysis work") }
    }

    func completeAnalysisJob(_ job: EvidenceAnalysisJob,
                             assessments: [ForensicAssessmentRecord],
                             routes: [ModelRouteEvidence],
                             memory: [MemoryCommitEvidence],
                             snapshot: AgentTaskSnapshot) throws {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            try upsertAssessments(assessments)
            try replaceModelRoutes(routes, turns: [(job.sessionID, job.turnID)])
            try upsertMemoryCommits(memory)
            let snapshotPayload = try encoder.encode(snapshot)
            var projection: OpaquePointer?
            let projectionSQL = "INSERT INTO task_snapshot_projection VALUES(?,?,?,?,?) ON CONFLICT(session_id,turn_id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,generated_at=excluded.generated_at WHERE excluded.revision>=revision"
            guard sqlite3_prepare_v2(handle, projectionSQL, -1, &projection, nil) == SQLITE_OK else { throw failure("prepare task projection") }
            defer { sqlite3_finalize(projection) }
            bind(job.sessionID, at: 1, to: projection); bind(job.turnID, at: 2, to: projection)
            sqlite3_bind_int64(projection, 3, job.revision)
            _ = snapshotPayload.withUnsafeBytes { sqlite3_bind_blob(projection, 4, $0.baseAddress, Int32(snapshotPayload.count), SQLITE_TRANSIENT) }
            sqlite3_bind_double(projection, 5, Date().timeIntervalSince1970)
            guard sqlite3_step(projection) == SQLITE_DONE else { throw failure("write task projection") }
            var searchJob: OpaquePointer?
            let searchSQL = "INSERT INTO task_search_jobs(session_id,turn_id,revision) VALUES(?,?,?) ON CONFLICT(session_id,turn_id) DO UPDATE SET revision=MAX(revision,excluded.revision),state='pending'"
            guard sqlite3_prepare_v2(handle, searchSQL, -1, &searchJob, nil) == SQLITE_OK else { throw failure("prepare search work") }
            defer { sqlite3_finalize(searchJob) }
            bind(job.sessionID, at: 1, to: searchJob); bind(job.turnID, at: 2, to: searchJob)
            sqlite3_bind_int64(searchJob, 3, job.revision)
            guard sqlite3_step(searchJob) == SQLITE_DONE else { throw failure("register search work") }
            var ack: OpaquePointer?
            let sql = "UPDATE evidence_analysis_jobs SET state='done',completed_revision=revision,token=NULL,last_error=NULL WHERE session_id=? AND turn_id=? AND revision=? AND token=? AND state='running' AND lease_until>?"
            guard sqlite3_prepare_v2(handle, sql, -1, &ack, nil) == SQLITE_OK else { throw failure("prepare analysis confirmation") }
            defer { sqlite3_finalize(ack) }
            bind(job.sessionID, at: 1, to: ack); bind(job.turnID, at: 2, to: ack)
            sqlite3_bind_int64(ack, 3, job.revision); bind(job.token, at: 4, to: ack); sqlite3_bind_double(ack, 5, Date().timeIntervalSince1970)
            guard sqlite3_step(ack) == SQLITE_DONE, sqlite3_changes(handle) == 1 else { throw failure("stale analysis lease") }
            try executeUnlocked("COMMIT")
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func taskSnapshot(sessionID: String, turnID: String) throws -> AgentTaskSnapshot? {
        guard let readConnection else {
            throw NSError(domain: "EvidenceDatabase", code: Int(SQLITE_MISUSE),
                          userInfo: [NSLocalizedDescriptionKey: "task detail read connection unavailable"])
        }
        return try readConnection.taskSnapshot(sessionID: sessionID, turnID: turnID)
    }

    func nextTaskSearchJob() throws -> TaskSearchJob? {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT session_id,turn_id,revision FROM task_search_jobs WHERE state='pending' AND completed_revision<revision ORDER BY session_id,turn_id LIMIT 1"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare next task search work") }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
              let session = text(statement, 0), let turn = text(statement, 1) else { return nil }
        return TaskSearchJob(sessionID: session, turnID: turn, revision: sqlite3_column_int64(statement, 2))
    }

    func restartTaskSearchBackfill() throws {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("UPDATE task_search_backfill SET session_id='',turn_id='',complete=0 WHERE id=1")
    }

    func completeTaskSearchJob(_ job: TaskSearchJob) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "UPDATE task_search_jobs SET completed_revision=?,state='done' WHERE session_id=? AND turn_id=? AND revision=? AND completed_revision<?"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare search completion") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, job.revision)
        bind(job.sessionID, at: 2, to: statement); bind(job.turnID, at: 3, to: statement)
        sqlite3_bind_int64(statement, 4, job.revision); sqlite3_bind_int64(statement, 5, job.revision)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("complete search work") }
        // A newer revision can be admitted while this one is indexed. Its job
        // remains pending and the index is advanced again on the next slice.
    }

    @discardableResult
    func enqueueTaskSearchBackfill(limit: Int = 25) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("BEGIN IMMEDIATE")
        do {
            var state: OpaquePointer?
            guard sqlite3_prepare_v2(handle, "SELECT session_id,turn_id,complete FROM task_search_backfill WHERE id=1", -1, &state, nil) == SQLITE_OK else { throw failure("prepare search backfill cursor") }
            defer { sqlite3_finalize(state) }
            guard sqlite3_step(state) == SQLITE_ROW,
                  let session = text(state, 0), let turn = text(state, 1) else { throw failure("read search backfill cursor") }
            if sqlite3_column_int(state, 2) != 0 { try executeUnlocked("COMMIT"); return true }
            var rows: OpaquePointer?
            let sql = "SELECT session_id,turn_id,revision FROM task_snapshot_projection WHERE (session_id,turn_id)>(?,?) ORDER BY session_id,turn_id LIMIT ?"
            guard sqlite3_prepare_v2(handle, sql, -1, &rows, nil) == SQLITE_OK else { throw failure("prepare search backfill page") }
            defer { sqlite3_finalize(rows) }
            bind(session, at: 1, to: rows); bind(turn, at: 2, to: rows)
            sqlite3_bind_int(rows, 3, Int32(max(1, min(limit, 100))))
            var page: [TaskSearchJob] = []
            while sqlite3_step(rows) == SQLITE_ROW {
                if let session = text(rows, 0), let turn = text(rows, 1) {
                    page.append(TaskSearchJob(sessionID: session, turnID: turn,
                        revision: sqlite3_column_int64(rows, 2)))
                }
            }
            var insert: OpaquePointer?
            let insertSQL = "INSERT INTO task_search_jobs(session_id,turn_id,revision) VALUES(?,?,?) ON CONFLICT(session_id,turn_id) DO UPDATE SET revision=MAX(revision,excluded.revision),completed_revision=0,state='pending'"
            guard sqlite3_prepare_v2(handle, insertSQL, -1, &insert, nil) == SQLITE_OK else { throw failure("prepare search backfill insert") }
            defer { sqlite3_finalize(insert) }
            for job in page {
                bind(job.sessionID, at: 1, to: insert); bind(job.turnID, at: 2, to: insert)
                sqlite3_bind_int64(insert, 3, job.revision)
                guard sqlite3_step(insert) == SQLITE_DONE else { throw failure("backfill search job") }
                sqlite3_reset(insert); sqlite3_clear_bindings(insert)
            }
            if let last = page.last {
                var update: OpaquePointer?
                guard sqlite3_prepare_v2(handle, "UPDATE task_search_backfill SET session_id=?,turn_id=? WHERE id=1", -1, &update, nil) == SQLITE_OK else { throw failure("prepare search backfill update") }
                bind(last.sessionID, at: 1, to: update); bind(last.turnID, at: 2, to: update)
                guard sqlite3_step(update) == SQLITE_DONE else { sqlite3_finalize(update); throw failure("save search backfill cursor") }
                sqlite3_finalize(update)
            }
            let complete = page.count < max(1, min(limit, 100))
            if complete { try executeUnlocked("UPDATE task_search_backfill SET complete=1 WHERE id=1") }
            try executeUnlocked("COMMIT")
            return complete
        } catch { try? executeUnlocked("ROLLBACK"); throw error }
    }

    func claimAuditUploadJob(now: Date = Date(), leaseSeconds: TimeInterval = 180) throws -> AuditOutboxJob? {
        lock.lock()
        var claimed: (session: String, turn: String, revision: Int64, token: String)?
        do {
            try executeUnlocked("BEGIN IMMEDIATE")
            var row: OpaquePointer?
            let sql = """
              SELECT o.session_id,o.turn_id,o.revision
              FROM audit_upload_outbox o
              WHERE ((o.state='pending' AND o.not_before<=?) OR
                     (o.state='running' AND o.lease_until<=?))
                AND EXISTS (SELECT 1 FROM task_snapshot_projection p
                  WHERE p.session_id=o.session_id AND p.turn_id=o.turn_id AND p.revision>=o.revision)
              ORDER BY o.not_before,o.session_id,o.turn_id LIMIT 1
              """
            guard sqlite3_prepare_v2(handle, sql, -1, &row, nil) == SQLITE_OK else { throw failure("prepare audit outbox claim") }
            defer { sqlite3_finalize(row) }
            sqlite3_bind_double(row, 1, now.timeIntervalSince1970)
            sqlite3_bind_double(row, 2, now.timeIntervalSince1970)
            let step = sqlite3_step(row)
            if step == SQLITE_ROW {
                guard let session = text(row, 0), let turn = text(row, 1) else { throw failure("read audit outbox") }
                let revision = sqlite3_column_int64(row, 2), token = UUID().uuidString
                var claim: OpaquePointer?
                let claimSQL = "UPDATE audit_upload_outbox SET state='running',token=?,lease_until=?,attempts=attempts+1 WHERE session_id=? AND turn_id=? AND revision=?"
                guard sqlite3_prepare_v2(handle, claimSQL, -1, &claim, nil) == SQLITE_OK else { throw failure("prepare audit outbox lease") }
                defer { sqlite3_finalize(claim) }
                bind(token, at: 1, to: claim)
                sqlite3_bind_double(claim, 2, now.addingTimeInterval(leaseSeconds).timeIntervalSince1970)
                bind(session, at: 3, to: claim); bind(turn, at: 4, to: claim)
                sqlite3_bind_int64(claim, 5, revision)
                guard sqlite3_step(claim) == SQLITE_DONE, sqlite3_changes(handle) == 1 else { throw failure("claim audit outbox") }
                claimed = (session, turn, revision, token)
            } else if step != SQLITE_DONE { throw failure("read audit outbox") }
            try executeUnlocked("COMMIT")
        } catch {
            try? executeUnlocked("ROLLBACK")
            lock.unlock()
            throw error
        }
        lock.unlock()
        guard let claimed else { return nil }
        guard let snapshot = try taskSnapshot(sessionID: claimed.session, turnID: claimed.turn) else {
            throw failure("claimed audit snapshot missing")
        }
        return AuditOutboxJob(sessionID: claimed.session, turnID: claimed.turn,
                              revision: claimed.revision, token: claimed.token, snapshot: snapshot)
    }

    func retryAuditUploadJob(_ job: AuditOutboxJob, message: String,
                             retryAfter: TimeInterval? = nil) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "UPDATE audit_upload_outbox SET state='pending',not_before=?+CASE WHEN ?>=0 THEN ? ELSE MIN(300,5*(1<<MIN(attempts,6))) END,token=NULL,lease_until=0,last_error=? WHERE session_id=? AND turn_id=? AND revision=? AND token=?"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare audit outbox retry") }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, Date().timeIntervalSince1970)
        let serverDelay = retryAfter.map { max(1, min(3600, $0)) } ?? -1
        sqlite3_bind_double(statement, 2, serverDelay); sqlite3_bind_double(statement, 3, serverDelay)
        bind(String(message.prefix(512)), at: 4, to: statement)
        bind(job.sessionID, at: 5, to: statement); bind(job.turnID, at: 6, to: statement)
        sqlite3_bind_int64(statement, 7, job.revision); bind(job.token, at: 8, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("retry audit outbox") }
    }

    func completeAuditUploadJob(_ job: AuditOutboxJob, receiptID: String?) throws {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "UPDATE audit_upload_outbox SET state='done',completed_revision=revision,token=NULL,lease_until=0,last_error=NULL,receipt_id=? WHERE session_id=? AND turn_id=? AND revision=? AND token=? AND state='running'"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare audit outbox confirmation") }
        defer { sqlite3_finalize(statement) }
        bindOptional(receiptID, at: 1, to: statement)
        bind(job.sessionID, at: 2, to: statement); bind(job.turnID, at: 3, to: statement)
        sqlite3_bind_int64(statement, 4, job.revision); bind(job.token, at: 5, to: statement)
        guard sqlite3_step(statement) == SQLITE_DONE, sqlite3_changes(handle) == 1 else { throw failure("stale audit outbox lease") }
    }

    func upsertAssessments(_ records: [ForensicAssessmentRecord]) throws {
        guard !records.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("SAVEPOINT assessment_write")
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
            try executeUnlocked("RELEASE assessment_write")
        } catch { try? executeUnlocked("ROLLBACK TO assessment_write"); try? executeUnlocked("RELEASE assessment_write"); throw error }
    }

    func replaceModelRoutes(_ records: [ModelRouteEvidence], turns: [(sessionId: String, turnId: String)]) throws {
        guard !turns.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try executeUnlocked("SAVEPOINT model_route_write")
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
            try executeUnlocked("RELEASE model_route_write")
        } catch { try? executeUnlocked("ROLLBACK TO model_route_write"); try? executeUnlocked("RELEASE model_route_write"); throw error }
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
        try executeUnlocked("SAVEPOINT memory_commit_write")
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
                try indexMemoryCommitAddresses(record)
                try indexMemoryCommitText(record)
            }
            try executeUnlocked("RELEASE memory_commit_write")
        } catch { try? executeUnlocked("ROLLBACK TO memory_commit_write"); try? executeUnlocked("RELEASE memory_commit_write"); throw error }
    }

    /// Exact-IP lookup over normalized memory-write evidence. This intentionally
    /// avoids scanning source JSON or requiring a task snapshot projection.
    func searchMemoryCommits(address: String, limit: Int = 500) throws -> [MemoryCommitEvidence] {
        lock.lock(); defer { lock.unlock() }
        let sql = """
            SELECT c.payload FROM memory_commit_addresses a
            JOIN memory_commits c ON c.commit_id=a.commit_id
            WHERE a.address=? ORDER BY a.observed_at DESC LIMIT ?
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory address lookup") }
        defer { sqlite3_finalize(statement) }
        bind(address, at: 1, to: statement); sqlite3_bind_int(statement, 2, Int32(max(1, min(limit, 5_000))))
        var result: [MemoryCommitEvidence] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let record = try? decoder.decode(MemoryCommitEvidence.self, from: payload) { result.append(record) }
        }
        return result
    }

    func searchMemoryCommits(terms: [String], agent: String?, startDate: String?, endDate: String?,
                             limit: Int = 100) throws -> [MemoryCommitEvidence] {
        lock.lock(); defer { lock.unlock() }
        let usable = terms.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.unicodeScalars.count >= 3 }
        var clauses: [String] = []
        if agent != nil { clauses.append("m.agent=?") }
        if let start = startDate.flatMap(Self.historyDate) { clauses.append("m.observed_at>=\(start.timeIntervalSince1970)") }
        if let end = endDate.flatMap(Self.historyDate) { clauses.append("m.observed_at<\(end.timeIntervalSince1970)") }
        if !usable.isEmpty { clauses.append("memory_commit_fts MATCH ?") }
        let sql = """
            SELECT m.payload FROM memory_commits m
            \(usable.isEmpty ? "" : "JOIN memory_commit_fts ON memory_commit_fts.commit_id=m.commit_id")
            \(clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND "))
            ORDER BY m.observed_at DESC LIMIT ?
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory history search") }
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        if let agent { bind(agent, at: index, to: statement); index += 1 }
        if !usable.isEmpty {
            let expression = usable.map { "\"\($0.replacingOccurrences(of: "\"", with: "\"\""))\"" }.joined(separator: " OR ")
            bind(expression, at: index, to: statement); index += 1
        }
        sqlite3_bind_int(statement, index, Int32(max(1, min(limit, 500))))
        var result: [MemoryCommitEvidence] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let record = try? decoder.decode(MemoryCommitEvidence.self, from: payload) { result.append(record) }
        }
        return result
    }

    private static func historyDate(_ value: String) -> Date? {
        let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd"; formatter.isLenient = false
        return formatter.date(from: value)
    }

    private func backfillMemorySearchIndexIfNeeded() throws {
        var check: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT 1 FROM evidence_pipeline_migrations WHERE version=3", -1, &check, nil) == SQLITE_OK else { throw failure("prepare memory search migration check") }
        let done = sqlite3_step(check) == SQLITE_ROW
        sqlite3_finalize(check)
        guard !done else { return }
        var rows: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT payload FROM memory_commits", -1, &rows, nil) == SQLITE_OK else { throw failure("prepare memory search migration") }
        defer { sqlite3_finalize(rows) }
        var records: [MemoryCommitEvidence] = []
        while sqlite3_step(rows) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(rows, 0) else { continue }
            let payload = Data(bytes: bytes, count: Int(sqlite3_column_bytes(rows, 0)))
            if let record = try? decoder.decode(MemoryCommitEvidence.self, from: payload) { records.append(record) }
        }
        for record in records {
            try indexMemoryCommitAddresses(record)
            try indexMemoryCommitText(record)
        }
        var migration: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "INSERT OR IGNORE INTO evidence_pipeline_migrations(version) VALUES(3)", -1, &migration, nil) == SQLITE_OK else { throw failure("prepare memory search migration marker") }
        defer { sqlite3_finalize(migration) }
        guard sqlite3_step(migration) == SQLITE_DONE else { throw failure("save memory search migration marker") }
    }

    private func indexMemoryCommitAddresses(_ record: MemoryCommitEvidence) throws {
        var remove: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "DELETE FROM memory_commit_addresses WHERE commit_id=?", -1, &remove, nil) == SQLITE_OK else { throw failure("prepare memory address refresh") }
        bind(record.commitId, at: 1, to: remove)
        guard sqlite3_step(remove) == SQLITE_DONE else { sqlite3_finalize(remove); throw failure("refresh memory address facts") }
        sqlite3_finalize(remove)
        guard let content = record.contentDiff else { return }
        let regex = try! NSRegularExpression(pattern: #"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"#)
        let values = regex.matches(in: content, range: NSRange(content.startIndex..., in: content)).compactMap { match -> String? in
            guard let range = Range(match.range, in: content) else { return nil }
            let address = String(content[range])
            return IPGeolocationStore.isIPAddress(address) ? address : nil
        }
        guard !values.isEmpty else { return }
        let sql = "INSERT OR IGNORE INTO memory_commit_addresses(address,commit_id,session_id,turn_id,observed_at,storage_path,confidence) VALUES(?,?,?,?,?,?,?)"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare memory address index") }
        defer { sqlite3_finalize(statement) }
        for address in Set(values) {
            bind(address, at: 1, to: statement); bind(record.commitId, at: 2, to: statement)
            bind(record.sessionId, at: 3, to: statement); bind(record.turnId, at: 4, to: statement)
            sqlite3_bind_double(statement, 5, record.observedAt.timeIntervalSince1970)
            bindOptional(record.storagePath, at: 6, to: statement); bind(record.confidence.rawValue, at: 7, to: statement)
            guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("index memory address") }
            sqlite3_reset(statement); sqlite3_clear_bindings(statement)
        }
    }

    private func indexMemoryCommitText(_ record: MemoryCommitEvidence) throws {
        var remove: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "DELETE FROM memory_commit_fts WHERE commit_id=?", -1, &remove, nil) == SQLITE_OK else { throw failure("prepare memory text refresh") }
        bind(record.commitId, at: 1, to: remove)
        guard sqlite3_step(remove) == SQLITE_DONE else { sqlite3_finalize(remove); throw failure("refresh memory text facts") }
        sqlite3_finalize(remove)
        var insert: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "INSERT INTO memory_commit_fts(commit_id,content) VALUES(?,?)", -1, &insert, nil) == SQLITE_OK else { throw failure("prepare memory text index") }
        defer { sqlite3_finalize(insert) }
        bind(record.commitId, at: 1, to: insert)
        bind([record.storagePath ?? "", record.summary, record.contentDiff ?? ""].joined(separator: "\n"), at: 2, to: insert)
        guard sqlite3_step(insert) == SQLITE_DONE else { throw failure("index memory text") }
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
        let sql = "SELECT source,stream,offset_start,offset_end,payload_sha256,previous_hash,record_hash,payload FROM raw_evidence WHERE record_hash IS NOT NULL ORDER BY observed_at,evidence_key"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("integrity prepare") }
        defer { sqlite3_finalize(statement) }
        var hashes = Set<String>()
        var links: [String: String] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let source = text(statement, 0), let stream = text(statement, 1),
                  let digest = text(statement, 4), let storedHash = text(statement, 6) else { return false }
            let storedPrevious = text(statement, 5)
            let length = Int(sqlite3_column_bytes(statement, 7))
            let payload = sqlite3_column_blob(statement, 7).map { Data(bytes: $0, count: length) } ?? Data()
            guard SHA256.hash(data: payload).map({ String(format: "%02x", $0) }).joined() == digest else { return false }
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

    func recentSecurityReviewEvidence(limit: Int) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        // Limit before decoding/filtering: opening the UI never sorts every raw JSON payload.
        let sql = "SELECT payload FROM evidence_records ORDER BY observed_at DESC LIMIT ?"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare bounded security review")
        }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int(statement, 1, Int32(min(max(limit, 1), 500)))
        var result: [GuardEvent] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            if let event = try? decoder.decode(GuardEvent.self, from: data) { result.append(event) }
        }
        return result
    }

    func securityEvidence(ids: [String]) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT payload FROM evidence_records WHERE event_id=? ORDER BY ingested_at DESC LIMIT 1", -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare security evidence lookup")
        }
        defer { sqlite3_finalize(statement) }
        var result: [GuardEvent] = []
        for id in Set(ids.compactMap { UUID(uuidString: $0)?.uuidString }).sorted().prefix(200) {
            bind(id, at: 1, to: statement)
            if sqlite3_step(statement) == SQLITE_ROW, let bytes = sqlite3_column_blob(statement, 0) {
                let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
                if let event = try? decoder.decode(GuardEvent.self, from: data) { result.append(event) }
            }
            sqlite3_reset(statement); sqlite3_clear_bindings(statement)
        }
        return result.sorted { $0.ts < $1.ts }
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

    func events(sessionId: String, turnID: String? = nil) throws -> [GuardEvent] {
        guard let readConnection else {
            throw NSError(domain: "EvidenceDatabase", code: Int(SQLITE_MISUSE),
                          userInfo: [NSLocalizedDescriptionKey: "task event read connection unavailable"])
        }
        return try readConnection.events(sessionID: sessionId, turnID: turnID)
    }

    /// Read only the next prompt timestamp, never another task's request body.
    func nextPromptDate(sessionID: String, turnID: String, after: Date) throws -> Date? {
        guard let readConnection else {
            throw NSError(domain: "EvidenceDatabase", code: Int(SQLITE_MISUSE),
                          userInfo: [NSLocalizedDescriptionKey: "prompt boundary read connection unavailable"])
        }
        return try readConnection.nextPromptDate(sessionID: sessionID, turnID: turnID, after: after)
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

    // UI callbacks enqueue a coalesced health snapshot; they never wait for
    // SQLite's writer lock. Evidence admission remains on the durable pipeline.
    private let healthWriteQueue = DispatchQueue(label: "com.agentspec.evidence.health", qos: .utility)
    private let pendingHealthLock = NSLock()
    private var pendingHealth: [String: CollectorHealthRecord] = [:]
    private var healthWriteScheduled = false

    func enqueueHealth(_ record: CollectorHealthRecord) {
        pendingHealthLock.lock()
        pendingHealth[record.source] = record
        let schedule = !healthWriteScheduled
        healthWriteScheduled = true
        pendingHealthLock.unlock()
        guard schedule else { return }
        healthWriteQueue.async { [self] in
            while true {
                pendingHealthLock.lock()
                let batch = Array(pendingHealth.values)
                pendingHealth.removeAll()
                if batch.isEmpty { healthWriteScheduled = false }
                pendingHealthLock.unlock()
                guard !batch.isEmpty else { return }
                for record in batch { try? updateHealth(record) }
            }
        }
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
