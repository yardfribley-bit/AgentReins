import AgentReinsVerify
import Foundation
import SQLite3

/// Join keys and short excerpts for tool-call cards. The Claude/Codex jsonl stays
/// where the agent wrote it; this file does not store the log body.
final class SessionJoinIndex {
    static let excerptLimit = SessionVerification.excerptLimit

    let url: URL
    private var handle: OpaquePointer?
    private let lock = NSLock()

    static func url(beside databaseURL: URL) -> URL {
        databaseURL.deletingLastPathComponent().appendingPathComponent("session-join-index.sqlite3")
    }

    init(url: URL) throws {
        self.url = url
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard sqlite3_open_v2(url.path, &handle, SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            throw NSError(domain: "AgentReins.SessionJoin", code: 1, userInfo: [NSLocalizedDescriptionKey: "打不开会话核对索引"])
        }
        try exec("""
            CREATE TABLE IF NOT EXISTS session_join_calls (
              call_id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL,
              agent TEXT NOT NULL,
              source_path TEXT NOT NULL,
              source_offset INTEGER NOT NULL,
              observed_at REAL NOT NULL,
              pid INTEGER,
              tool_name TEXT NOT NULL,
              arguments_excerpt TEXT NOT NULL,
              reasoning_excerpt TEXT NOT NULL,
              reasoning_truncated INTEGER NOT NULL,
              arguments_truncated INTEGER NOT NULL,
              claimed_paths TEXT NOT NULL,
              claims_edit INTEGER NOT NULL
            )
            """)
        try exec("CREATE INDEX IF NOT EXISTS session_join_time ON session_join_calls(observed_at)")
        try exec("""
            CREATE TABLE IF NOT EXISTS session_join_verdicts (
              call_id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL,
              status TEXT NOT NULL,
              labels TEXT NOT NULL,
              effect_ids TEXT NOT NULL,
              paths TEXT NOT NULL,
              observed_at REAL NOT NULL
            )
            """)
    }

    deinit { sqlite3_close(handle) }

    func upsert(_ calls: [ParsedToolCall]) throws {
        guard !calls.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try exec("BEGIN IMMEDIATE")
        do {
            var statement: OpaquePointer?
            let sql = """
                INSERT INTO session_join_calls(call_id,session_id,agent,source_path,source_offset,observed_at,pid,tool_name,arguments_excerpt,reasoning_excerpt,reasoning_truncated,arguments_truncated,claimed_paths,claims_edit)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(call_id) DO UPDATE SET
                  session_id=excluded.session_id, agent=excluded.agent, source_path=excluded.source_path,
                  source_offset=excluded.source_offset, observed_at=excluded.observed_at, pid=excluded.pid,
                  tool_name=excluded.tool_name, arguments_excerpt=excluded.arguments_excerpt,
                  reasoning_excerpt=excluded.reasoning_excerpt, reasoning_truncated=excluded.reasoning_truncated,
                  arguments_truncated=excluded.arguments_truncated, claimed_paths=excluded.claimed_paths,
                  claims_edit=excluded.claims_edit
                """
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare join upsert") }
            defer { sqlite3_finalize(statement) }
            for call in calls {
                bind(call.id, 1, statement)
                bind(call.sessionId, 2, statement)
                bind(call.agent, 3, statement)
                bind(call.sourcePath, 4, statement)
                sqlite3_bind_int64(statement, 5, Int64(call.sourceOffset))
                sqlite3_bind_double(statement, 6, call.timestamp.timeIntervalSince1970)
                if let pid = call.pid { sqlite3_bind_int(statement, 7, pid) } else { sqlite3_bind_null(statement, 7) }
                bind(call.toolName, 8, statement)
                bind(call.arguments, 9, statement)
                bind(call.reasoning, 10, statement)
                sqlite3_bind_int(statement, 11, call.reasoningTruncated ? 1 : 0)
                sqlite3_bind_int(statement, 12, call.argumentsTruncated ? 1 : 0)
                let paths = (try? JSONSerialization.data(withJSONObject: call.claimedPaths)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
                bind(paths, 13, statement)
                sqlite3_bind_int(statement, 14, call.claimsEdit ? 1 : 0)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("upsert join") }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            try exec("COMMIT")
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    func calls() throws -> [ParsedToolCall] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        let sql = "SELECT call_id,session_id,agent,source_path,source_offset,observed_at,pid,tool_name,arguments_excerpt,reasoning_excerpt,reasoning_truncated,arguments_truncated,claimed_paths,claims_edit FROM session_join_calls ORDER BY observed_at, call_id"
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("read join") }
        defer { sqlite3_finalize(statement) }
        var rows: [ParsedToolCall] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let id = text(statement, 0), let session = text(statement, 1), let agent = text(statement, 2),
                  let source = text(statement, 3), let tool = text(statement, 7), let arguments = text(statement, 8),
                  let reasoning = text(statement, 9) else { continue }
            let paths = (text(statement, 12)?.data(using: .utf8)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String] } ?? []
            rows.append(ParsedToolCall(
                id: id, callId: id, sessionId: session, agent: agent, sourcePath: source,
                sourceOffset: Int(sqlite3_column_int64(statement, 4)),
                timestamp: Date(timeIntervalSince1970: sqlite3_column_double(statement, 5)),
                pid: sqlite3_column_type(statement, 6) == SQLITE_NULL ? nil : sqlite3_column_int(statement, 6),
                reasoning: reasoning, reasoningTruncated: sqlite3_column_int(statement, 10) == 1,
                toolName: tool, arguments: arguments, argumentsTruncated: sqlite3_column_int(statement, 11) == 1,
                claimedPaths: paths, claimsEdit: sqlite3_column_int(statement, 13) == 1))
        }
        return rows
    }

    /// Mismatch labels and the host row ids they point at. No diff body and no log text.
    func saveVerdicts(_ cards: [ToolCallCard]) throws {
        guard !cards.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        try exec("BEGIN IMMEDIATE")
        do {
            var statement: OpaquePointer?
            let sql = """
                INSERT INTO session_join_verdicts(call_id,session_id,status,labels,effect_ids,paths,observed_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(call_id) DO UPDATE SET
                  session_id=excluded.session_id, status=excluded.status, labels=excluded.labels,
                  effect_ids=excluded.effect_ids, paths=excluded.paths, observed_at=excluded.observed_at
                """
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw failure("prepare verdict") }
            defer { sqlite3_finalize(statement) }
            for card in cards {
                let labels = card.mismatches.map(\.label).joined(separator: ",")
                let effectIDs = (try? JSONSerialization.data(withJSONObject: card.happened.map(\.id))).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
                let paths = card.happened.compactMap(\.path)
                let pathText = (try? JSONSerialization.data(withJSONObject: paths)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
                bind(card.id, 1, statement)
                bind(card.sessionId, 2, statement)
                bind(card.status, 3, statement)
                bind(labels, 4, statement)
                bind(effectIDs, 5, statement)
                bind(pathText, 6, statement)
                sqlite3_bind_double(statement, 7, card.timestamp.timeIntervalSince1970)
                guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("save verdict") }
                sqlite3_reset(statement)
                sqlite3_clear_bindings(statement)
            }
            try exec("COMMIT")
        } catch {
            try? exec("ROLLBACK")
            throw error
        }
    }

    func verdictLabels() throws -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT call_id, labels, effect_ids FROM session_join_verdicts", -1, &statement, nil) == SQLITE_OK else { throw failure("read verdicts") }
        defer { sqlite3_finalize(statement) }
        var rows: [String: String] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            if let id = text(statement, 0) { rows[id] = (text(statement, 1) ?? "") + "|" + (text(statement, 2) ?? "") }
        }
        return rows
    }

    func deleteOlder(than cutoff: Date) throws -> Int {
        lock.lock(); defer { lock.unlock() }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "DELETE FROM session_join_calls WHERE observed_at < ?", -1, &statement, nil) == SQLITE_OK else {
            throw failure("prune join")
        }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, cutoff.timeIntervalSince1970)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("prune join") }
        return Int(sqlite3_changes(handle))
    }

    private func exec(_ sql: String) throws {
        guard sqlite3_exec(handle, sql, nil, nil, nil) == SQLITE_OK else { throw failure(sql) }
    }

    private func bind(_ value: String, _ index: Int32, _ statement: OpaquePointer?) {
        sqlite3_bind_text(statement, index, value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
    }

    private func text(_ statement: OpaquePointer?, _ index: Int32) -> String? {
        sqlite3_column_text(statement, index).map { String(cString: $0) }
    }

    private func failure(_ operation: String) -> NSError {
        NSError(domain: "AgentReins.SessionJoin", code: Int(sqlite3_errcode(handle)),
                userInfo: [NSLocalizedDescriptionKey: "\(operation): \(String(cString: sqlite3_errmsg(handle)))"])
    }
}
