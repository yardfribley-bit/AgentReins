import CryptoKit
import Foundation
import SQLite3

/// Only the currently observed/restored live working set. No history import.
/// Bodies and recovery metadata commit together; unchanged bodies are untouched.
final class RealtimeCheckpointDatabase: @unchecked Sendable {
    private struct Metadata: Codable {
        let version: Int
        let savedAt: Date
        let readTaskIDs: [String]
        let coverageTruncated: Bool
    }
    static func location(for checkpoint: URL) -> URL { checkpoint.appendingPathExtension("sqlite3") }
    private var handle: OpaquePointer?
    private var revisions: [UUID: UUID] = [:]
    private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    init(url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard sqlite3_open_v2(url.path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else { throw failure("open") }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        sqlite3_busy_timeout(handle, 5000)
        try execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        try execute("CREATE TABLE IF NOT EXISTS live_events(event_id TEXT PRIMARY KEY, revision TEXT NOT NULL, body BLOB NOT NULL, sha256 TEXT NOT NULL, raw_bytes INTEGER NOT NULL, ts REAL NOT NULL, session TEXT, turn TEXT); CREATE INDEX IF NOT EXISTS live_task ON live_events(session,turn,ts); CREATE TABLE IF NOT EXISTS live_metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL);")
        let statement = try prepare("SELECT event_id,revision FROM live_events")
        defer { sqlite3_finalize(statement) }
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let id = text(statement, 0).flatMap(UUID.init(uuidString:)), let revision = text(statement, 1).flatMap(UUID.init(uuidString:)) else { throw failure("invalid identity") }
            revisions[id] = revision
        }
    }
    deinit { sqlite3_close(handle) }
    private func failure(_ operation: String) -> NSError {
        NSError(domain: "AgentReins.LiveDatabase", code: 1, userInfo: [NSLocalizedDescriptionKey: "实时恢复数据库 \(operation)：\(handle.map { String(cString: sqlite3_errmsg($0)) } ?? "unavailable")"])
    }
    private func execute(_ sql: String) throws { guard sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else { throw failure("transaction") } }
    private func prepare(_ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw failure("prepare") }
        return statement
    }
    private func text(_ statement: OpaquePointer, _ index: Int32) -> String? { sqlite3_column_text(statement, index).map { String(cString: $0) } }
    private func bind(_ value: String?, _ index: Int32, _ statement: OpaquePointer) {
        if let value { sqlite3_bind_text(statement, index, value, -1, transient) } else { sqlite3_bind_null(statement, index) }
    }
    private func bind(_ value: Data, _ index: Int32, _ statement: OpaquePointer) {
        _ = value.withUnsafeBytes { sqlite3_bind_blob(statement, index, $0.baseAddress, Int32(value.count), transient) }
    }
    private func bytes(_ statement: OpaquePointer, _ index: Int32) throws -> Data {
        let size = Int(sqlite3_column_bytes(statement, index))
        guard size > 0, size <= 257 * 1024 * 1024, let pointer = sqlite3_column_blob(statement, index) else { throw failure("invalid body size") }
        return Data(bytes: pointer, count: size)
    }
    private func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    func load() throws -> RealtimeActiveCheckpoint? {
        let meta = try prepare("SELECT value FROM live_metadata WHERE key='snapshot'")
        defer { sqlite3_finalize(meta) }
        let result = sqlite3_step(meta)
        if result == SQLITE_DONE { return nil }
        guard result == SQLITE_ROW else { throw failure("metadata read") }
        let metadata = try JSONDecoder().decode(Metadata.self, from: bytes(meta, 0))
        guard metadata.version == 1 else { throw failure("unsupported version") }
        let statement = try prepare("SELECT event_id,body,sha256,raw_bytes FROM live_events ORDER BY ts,event_id")
        defer { sqlite3_finalize(statement) }
        var events: [GuardEvent] = []
        var status = sqlite3_step(statement)
        while status == SQLITE_ROW {
            let compressed = try bytes(statement, 1)
            let rawSize = Int(sqlite3_column_int64(statement, 3))
            guard rawSize > 0, rawSize <= 256 * 1024 * 1024, hash(compressed) == text(statement, 2) else { throw failure("body checksum") }
            let data = try (compressed as NSData).decompressed(using: .lzfse) as Data
            guard data.count == rawSize else { throw failure("decompressed size") }
            let event = try JSONDecoder().decode(GuardEvent.self, from: data)
            guard event.id.uuidString == text(statement, 0) else { throw failure("event identity") }
            events.append(event); status = sqlite3_step(statement)
        }
        guard status == SQLITE_DONE else { throw failure("body read") }
        return RealtimeActiveCheckpoint(version: 1, savedAt: metadata.savedAt, events: events,
            readTaskIDs: metadata.readTaskIDs, coverageTruncated: metadata.coverageTruncated)
    }
    func save(records: [RealtimeLiveEvidenceBuffer.Record], readTaskIDs: [String], coverageTruncated: Bool, savedAt: Date) throws -> RealtimeActiveCheckpoint.Writer.SaveMetrics {
        let desired = Dictionary(records.map { ($0.id, $0.revision) }, uniquingKeysWith: { _, last in last })
        guard desired.count == records.count else { throw failure("duplicate event identity") }
        let changed = records.filter { revisions[$0.id] != $0.revision }
        let removed = Set(revisions.keys).subtracting(desired.keys)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let metadata = try encoder.encode(Metadata(version: 1, savedAt: savedAt, readTaskIDs: readTaskIDs, coverageTruncated: coverageTruncated))
        try execute("BEGIN IMMEDIATE")
        do {
            let insert = try prepare("INSERT INTO live_events(event_id,revision,body,sha256,raw_bytes,ts,session,turn) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET revision=excluded.revision,body=excluded.body,sha256=excluded.sha256,raw_bytes=excluded.raw_bytes,ts=excluded.ts,session=excluded.session,turn=excluded.turn")
            defer { sqlite3_finalize(insert) }
            for record in changed {
                let event = try record.read()
                guard event.id == record.id else { throw failure("event identity") }
                let data = try encoder.encode(event)
                guard data.count <= 256 * 1024 * 1024 else { throw failure("event exceeds 256 MiB") }
                let compressed = try (data as NSData).compressed(using: .lzfse) as Data
                sqlite3_reset(insert); sqlite3_clear_bindings(insert)
                bind(record.id.uuidString, 1, insert); bind(record.revision.uuidString, 2, insert)
                bind(compressed, 3, insert); bind(hash(compressed), 4, insert)
                sqlite3_bind_int64(insert, 5, Int64(data.count)); sqlite3_bind_double(insert, 6, record.ts.timeIntervalSince1970)
                bind(record.session, 7, insert); bind(record.turn, 8, insert)
                guard sqlite3_step(insert) == SQLITE_DONE else { throw failure("event write") }
            }
            if !removed.isEmpty {
                let delete = try prepare("DELETE FROM live_events WHERE event_id=?")
                defer { sqlite3_finalize(delete) }
                for id in removed {
                    sqlite3_reset(delete); sqlite3_clear_bindings(delete); bind(id.uuidString, 1, delete)
                    guard sqlite3_step(delete) == SQLITE_DONE else { throw failure("event removal") }
                }
            }
            let update = try prepare("INSERT INTO live_metadata(key,value) VALUES('snapshot',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            defer { sqlite3_finalize(update) }
            bind(metadata, 1, update)
            guard sqlite3_step(update) == SQLITE_DONE else { throw failure("metadata write") }
            try execute("COMMIT")
            revisions = desired
            var metrics = RealtimeActiveCheckpoint.Writer.SaveMetrics()
            metrics.serializedEvents = changed.count; metrics.reusedEvents = records.count - changed.count
            return metrics
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }
}
