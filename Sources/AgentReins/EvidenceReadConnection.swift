import Foundation
import SQLite3

/// A dedicated read-only SQLite connection for task details. WAL lets these
/// long JSON reads proceed without taking the writer's Swift lock or opening a
/// write transaction. One reader is deliberately bounded; a pool can follow
/// once query concurrency is measured.
final class EvidenceReadConnection: @unchecked Sendable {
    private var handle: OpaquePointer?
    private let lock = NSLock()
    private let decoder: JSONDecoder

    init(url: URL) throws {
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard sqlite3_open_v2(url.path, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            throw failure("open read-only connection")
        }
        sqlite3_busy_timeout(handle, 2_000)
        guard sqlite3_exec(handle, "PRAGMA query_only=ON", nil, nil, nil) == SQLITE_OK else {
            throw failure("enable read-only mode")
        }
    }

    deinit { sqlite3_close(handle) }

    func recentTasks(limit: Int, before: Date?, offset: Int,
                     after cursor: StoredTaskSummary?) throws -> [StoredTaskSummary] {
        lock.lock(); defer { lock.unlock() }
        let cursorClause = cursor == nil ? "" :
            "AND (last_at < ? OR (last_at = ? AND (session_id,turn_id) > (?,?)))"
        let sql = """
            SELECT session_id,turn_id,agent_id,started_at,last_at,event_count,
                   COALESCE(title, (SELECT json_extract(CAST(prompt.payload AS TEXT),
                       '$.payload.userPrompt._0.rawText') FROM agent_event_stream prompt
                       WHERE prompt.session_id=task_summary.session_id
                         AND prompt.turn_id=task_summary.turn_id
                         AND json_type(CAST(prompt.payload AS TEXT),'$.payload.userPrompt') IS NOT NULL
                       ORDER BY prompt.sequence LIMIT 1))
            FROM task_summary WHERE last_at < ? \(cursorClause)
            ORDER BY last_at DESC,session_id,turn_id LIMIT ? OFFSET ?
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare read-only task page")
        }
        defer { sqlite3_finalize(statement) }
        var index: Int32 = 1
        sqlite3_bind_double(statement, index, before?.timeIntervalSince1970 ?? Date.distantFuture.timeIntervalSince1970)
        index += 1
        if let cursor {
            sqlite3_bind_double(statement, index, cursor.lastObservedAt.timeIntervalSince1970); index += 1
            sqlite3_bind_double(statement, index, cursor.lastObservedAt.timeIntervalSince1970); index += 1
            bind(cursor.sessionID, at: index, to: statement); index += 1
            bind(cursor.turnID, at: index, to: statement); index += 1
        }
        sqlite3_bind_int(statement, index, Int32(max(1, min(limit, 200)))); index += 1
        sqlite3_bind_int(statement, index, Int32(max(0, offset)))
        var result: [StoredTaskSummary] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let sessionID = columnText(statement, 0), let turnID = columnText(statement, 1),
                  let agentID = columnText(statement, 2) else { continue }
            result.append(StoredTaskSummary(sessionID: sessionID, turnID: turnID,
                agentID: agentID, title: columnText(statement, 6),
                startedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 3)),
                lastObservedAt: Date(timeIntervalSince1970: sqlite3_column_double(statement, 4)),
                eventCount: Int(sqlite3_column_int64(statement, 5))))
        }
        return result
    }

    private func columnText(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        sqlite3_column_text(statement, index).map { String(cString: $0) }
    }

    func taskSnapshot(sessionID: String, turnID: String) throws -> AgentTaskSnapshot? {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT payload FROM task_snapshot_projection WHERE session_id=? AND turn_id=?", -1, &statement, nil) == SQLITE_OK else {
            throw failure("prepare task projection read")
        }
        defer { sqlite3_finalize(statement) }
        bind(sessionID, at: 1, to: statement); bind(turnID, at: 2, to: statement)
        guard sqlite3_step(statement) == SQLITE_ROW, let bytes = sqlite3_column_blob(statement, 0) else { return nil }
        return try decoder.decode(AgentTaskSnapshot.self,
            from: Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0))))
    }

    func events(sessionID: String, turnID: String?) throws -> [GuardEvent] {
        lock.lock(); defer { lock.unlock() }
        let turnFilter = turnID == nil ? "" : (turnID == "unattributed"
            ? "AND json_extract(CAST(payload AS TEXT), '$.turnId') IS NULL"
            : "AND json_extract(CAST(payload AS TEXT), '$.turnId') = ?")
        let sql = """
          SELECT payload FROM evidence_records
          WHERE json_extract(CAST(payload AS TEXT), '$.sessionId') = ?
          \(turnFilter)
          ORDER BY observed_at ASC, ingested_at ASC
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare session detail read") }
        defer { sqlite3_finalize(statement) }
        bind(sessionID, at: 1, to: statement)
        if let turnID, turnID != "unattributed" { bind(turnID, at: 2, to: statement) }
        var rows: [GuardEvent] = []
        var ids = Set<UUID>()
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let bytes = sqlite3_column_blob(statement, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
            let event = try decoder.decode(GuardEvent.self, from: data)
            if ids.insert(event.id).inserted { rows.append(event) }
        }
        return rows
    }

    func nextPromptDate(sessionID: String, turnID: String, after: Date) throws -> Date? {
        lock.lock(); defer { lock.unlock() }
        let sql = """
          SELECT MIN(observed_at) FROM evidence_records
          WHERE json_extract(CAST(payload AS TEXT), '$.sessionId') = ? AND observed_at > ?
            AND json_extract(CAST(payload AS TEXT), '$.turnId') != ?
            AND json_extract(CAST(payload AS TEXT), '$.kind') = 'model'
            AND json_extract(CAST(payload AS TEXT), '$.op') = 'prompt'
          """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare prompt boundary") }
        defer { sqlite3_finalize(statement) }
        bind(sessionID, at: 1, to: statement)
        sqlite3_bind_double(statement, 2, after.timeIntervalSince1970)
        bind(turnID, at: 3, to: statement)
        guard sqlite3_step(statement) == SQLITE_ROW, sqlite3_column_type(statement, 0) != SQLITE_NULL else { return nil }
        return Date(timeIntervalSince1970: sqlite3_column_double(statement, 0))
    }

    private func bind(_ value: String, at index: Int32, to statement: OpaquePointer?) {
        value.withCString { _ = sqlite3_bind_text(statement, index, $0, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
    }

    private func failure(_ operation: String) -> NSError {
        NSError(domain: "EvidenceReadConnection", code: Int(sqlite3_errcode(handle)),
                userInfo: [NSLocalizedDescriptionKey: "\(operation): \(handle.map { String(cString: sqlite3_errmsg($0)) } ?? "SQLite unavailable")"])
    }
}
