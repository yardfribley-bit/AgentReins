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
    }

    deinit { sqlite3_close(handle) }

    static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("AgentGuard/evidence.sqlite3")
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
