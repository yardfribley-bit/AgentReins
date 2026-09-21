import CryptoKit
import Foundation
import SQLite3
import SwiftUI

/// Read-only native adapter for ZCode's local session database, structured
/// runtime log, and pre-encryption Model I/O records. Credentials, cookies,
/// and private keys are deliberately outside the projected event boundary.
@MainActor
final class ZCodeSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var databaseFingerprint: String?
    private var logOffsets: [String: UInt64] = [:]
    private var seen = Set<UUID>()
    private let queue = DispatchQueue(label: "com.agentspec.zcodesight", qos: .utility)
    private let evidenceDatabase = try? EvidenceDatabase()
    private var accepted = 0
    private var malformed = 0

    nonisolated static var root: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".zcode")
    }
    nonisolated static var sessionDatabaseURL: URL { root.appendingPathComponent("cli/db/db.sqlite") }
    nonisolated static var logRootURL: URL { root.appendingPathComponent("cli/log") }
    nonisolated static var modelIORootURL: URL { root.appendingPathComponent("cli/rollout") }

    func start() {
        guard timer == nil else { return }
        if let saved = try? evidenceDatabase?.checkpoints(source: "zcode") { logOffsets = saved }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        let previousFingerprint = databaseFingerprint
        let previousOffsets = logOffsets
        let evidenceDatabase = evidenceDatabase
        queue.async { [weak self] in
            let fingerprint = Self.sqliteFingerprint(Self.sessionDatabaseURL)
            let snapshot = fingerprint == previousFingerprint ? nil : Self.readLatestDatabase()
            let logs = Self.readLogs(previousOffsets: previousOffsets)
            let modelIO = Self.readModelIO(previousOffsets: previousOffsets)
            let raw = (snapshot.map { [$0.rawEvidence] } ?? []) + logs.raw + modelIO.raw
            var rawWriteFailed = false
            do { try evidenceDatabase?.appendRaw(raw) } catch { rawWriteFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                self.databaseFingerprint = fingerprint
                let databaseAvailable = FileManager.default.fileExists(atPath: Self.sessionDatabaseURL.path)
                let available = databaseAvailable || modelIO.available
                if self.connected != available { self.connected = available }
                if rawWriteFailed { self.malformed += 1 }
                self.malformed += logs.malformed + modelIO.malformed
                let projected = (snapshot?.events ?? []) + logs.events + modelIO.events
                let fresh = projected.filter { self.seen.insert($0.id).inserted }
                self.accepted += fresh.count
                if !fresh.isEmpty { self.lastUpdate = Date(); self.onEvents?(fresh) }
                for (stream, offset) in logs.offsets {
                    self.logOffsets[stream] = offset
                    try? self.evidenceDatabase?.saveCheckpoint(SourceCheckpoint(
                        source: "zcode", stream: stream, offset: Int64(offset),
                        fingerprint: nil, updatedAt: Date()))
                }
                for (stream, offset) in modelIO.offsets {
                    self.logOffsets[stream] = offset
                    try? self.evidenceDatabase?.saveCheckpoint(SourceCheckpoint(
                        source: "zcode", stream: stream, offset: Int64(offset),
                        fingerprint: nil, updatedAt: Date()))
                }
                try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                    source: "zcode", state: !available ? .failed : self.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: available ? Date() : nil, lagSeconds: nil,
                    accepted: self.accepted, malformed: self.malformed, dropped: 0,
                    detail: modelIO.available
                        ? "ZCode pre-encryption Model I/O, session SQLite, and runtime log connected"
                        : databaseAvailable
                            ? "ZCode session SQLite and runtime log connected; no native Model I/O record found"
                            : "ZCode local evidence is unavailable"))
            }
        }
    }

    struct Snapshot {
        let rawEvidence: RawEvidenceRecord
        let events: [GuardEvent]
    }

    nonisolated static func readLatestDatabase(url: URL? = nil) -> Snapshot? {
        let url = url ?? sessionDatabaseURL
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              let db else { return nil }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 1_000)
        guard let sessionRow = rows(db, sql: """
            SELECT id,directory,title,time_created,time_updated,trace_id
            FROM session ORDER BY time_updated DESC LIMIT 1
            """).first, let sessionID = sessionRow[0] else { return nil }
        let workspace = sessionRow[1] ?? "-"
        let messageRows = rows(db, sql: """
            SELECT id,time_created,data FROM message
            WHERE session_id=? ORDER BY time_created DESC LIMIT 80
            """, bind: sessionID).reversed()
        guard !messageRows.isEmpty else { return nil }
        let latestUserTime = messageRows.last(where: { row in
            guard let data = row[2], let object = dictionary(data) else { return false }
            return object["role"] as? String == "user"
        }).flatMap { Int64($0[1] ?? "") } ?? 0
        let selectedMessages = messageRows.filter { (Int64($0[1] ?? "") ?? 0) >= latestUserTime }
        let messageIDs = selectedMessages.compactMap { $0[0] }
        let partRows = messageIDs.flatMap { messageID in
            rows(db, sql: """
                SELECT id,message_id,time_created,data FROM part
                WHERE message_id=? ORDER BY time_created,sequence,id
                """, bind: messageID)
        }
        let toolRows = rows(db, sql: """
            SELECT tool_call_id,tool_name,status,started_at,completed_at,exit_code,
                   output_bytes,retry_count,error_message,turn_id
            FROM tool_usage WHERE session_id=? AND started_at>=? ORDER BY started_at
            """, binds: [sessionID, String(latestUserTime)])
        let usageRows = rows(db, sql: """
            SELECT turn_id,status,started_at,completed_at,model_request_count,model_retry_count,
                   tool_call_count,tool_error_count,input_tokens,output_tokens,reasoning_tokens,
                   cache_read_input_tokens
            FROM turn_usage WHERE session_id=? AND started_at>=? ORDER BY started_at
            """, binds: [sessionID, String(latestUserTime)])
        var envelope: [String: Any] = [:]
        envelope["schema"] = "zcode-local-v1"
        envelope["session"] = jsonValues(sessionRow)
        envelope["messages"] = selectedMessages.map(jsonValues)
        envelope["parts"] = partRows.map(jsonValues)
        envelope["toolUsage"] = toolRows.map(jsonValues)
        envelope["turnUsage"] = usageRows.map(jsonValues)
        guard let raw = try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]) else { return nil }
        let observed = date(milliseconds: Int64(sessionRow[4] ?? "")) ?? Date()
        let record = RawEvidenceRecord(source: "zcode", stream: "zcode-session:\(sessionID)",
            offsetStart: 0, offsetEnd: Int64(raw.count), fingerprint: digest(raw),
            observedAt: observed, payload: raw)
        return Snapshot(rawEvidence: record,
            events: project(sessionID: sessionID, workspace: workspace,
                messages: Array(selectedMessages), parts: partRows,
                toolRows: toolRows, usageRows: usageRows))
    }

    nonisolated static func project(sessionID: String, workspace: String,
                                    messages: [[String?]], parts: [[String?]],
                                    toolRows: [[String?]], usageRows: [[String?]]) -> [GuardEvent] {
        let partsByMessage = Dictionary(grouping: parts, by: { $0[1] ?? "" })
        var events: [GuardEvent] = []
        var activeTurn: String?
        var model: String?
        var provider: String?
        for row in messages {
            guard let messageID = row[0], let raw = row[2], let object = dictionary(raw) else { continue }
            let timestamp = date(milliseconds: Int64(row[1] ?? "")) ?? Date()
            let role = object["role"] as? String ?? "unknown"
            let anchor = object["anchor"] as? [String: Any]
            let turn = anchor?["turnId"] as? String ?? activeTurn
            if let turn { activeTurn = turn }
            let selection = object["modelSelection"] as? [String: Any]
            model = selection?["modelId"] as? String ?? object["modelId"] as? String ?? model
            provider = selection?["providerId"] as? String ?? object["providerId"] as? String ?? provider
            let messageParts = partsByMessage[messageID] ?? []
            let decodedParts = messageParts.compactMap { $0[3].flatMap(dictionary) }
            if role == "user" {
                let metadata = object["metadata"] as? [String: Any]
                let input = metadata?["inputIntent"] as? [String: Any]
                let prompt = input?["text"] as? String ?? text(from: decodedParts)
                if let prompt, !prompt.isEmpty {
                    events.append(event("\(messageID):prompt", kind: "model", op: "prompt", action: "sent",
                        timestamp: timestamp, session: sessionID, turn: turn, workspace: workspace,
                        userIntent: prompt, modelPrompt: prompt, model: model, provider: provider))
                }
                if let context = object["contextSnapshot"] as? [String: Any] {
                    let tools = object["tools"] as? [String: Any] ?? [:]
                    let captured = json(["contextSnapshot": context, "availableTools": tools])
                    events.append(event("\(messageID):context", kind: "context", op: "context_prepared",
                        action: "observed", timestamp: timestamp, session: sessionID, turn: turn,
                        workspace: workspace, command: captured, modelPrompt: captured,
                        model: model, provider: provider))
                }
            } else if role == "assistant" {
                let response = text(from: decodedParts)
                let reasoning = decodedParts.filter {
                    ["thinking", "reasoning"].contains(($0["type"] as? String ?? "").lowercased())
                }.compactMap { $0["text"] as? String ?? $0["thinking"] as? String ?? $0["reasoning"] as? String }
                    .joined(separator: "\n")
                let tokens = object["tokens"] as? [String: Any]
                let cache = tokens?["cache"] as? [String: Any]
                if !reasoning.isEmpty {
                    events.append(event("\(messageID):reasoning", kind: "model", op: "reasoning_summary",
                        action: "captured", timestamp: timestamp, session: sessionID, turn: turn,
                        workspace: workspace,
                        command: json(["capturedCharacters": reasoning.count,
                                       "recordedCharacters": reasoning.count,
                                       "truncated": false,
                                       "sha256": digest(Data(reasoning.utf8))]),
                        modelReasoning: reasoning, model: model, provider: provider,
                        reasoningTokens: int(tokens?["reasoning"])))
                }
                events.append(event("\(messageID):response", kind: "model", op: "response", action: "received",
                    timestamp: timestamp, session: sessionID, turn: turn, workspace: workspace,
                    modelReasoning: nil,
                    modelResponse: response, model: model, provider: provider,
                    inputTokens: int(tokens?["input"]), outputTokens: int(tokens?["output"]),
                    cachedTokens: int(cache?["read"]), reasoningTokens: int(tokens?["reasoning"])))
                events += toolPartEvents(decodedParts, messageID: messageID, timestamp: timestamp,
                    session: sessionID, turn: turn, workspace: workspace, model: model, provider: provider)
            }
        }
        for row in toolRows {
            guard let callID = row[0], let name = row[1] else { continue }
            let status = row[2] ?? "running"
            let timestamp = date(milliseconds: Int64(row[3] ?? "")) ?? Date()
            var resultPayload: [String: Any] = [
                "outputBytes": Int(row[6] ?? "0") ?? 0,
                "retryCount": Int(row[7] ?? "0") ?? 0
            ]
            resultPayload["error"] = row[8] ?? NSNull()
            let result = json(resultPayload)
            events.append(event("tool-usage:\(callID):\(status)", kind: "tool", op: "result",
                action: status, timestamp: timestamp, session: sessionID, turn: row[9] ?? activeTurn,
                workspace: workspace, command: result, modelResponse: result,
                toolCallId: callID, toolName: name, model: model, provider: provider))
        }
        for row in usageRows {
            guard let turn = row[0] else { continue }
            let timestamp = date(milliseconds: Int64(row[2] ?? "")) ?? Date()
            events.append(event("usage:\(turn):\(row[1] ?? "unknown")", kind: "model", op: "usage",
                action: row[1] ?? "observed", timestamp: timestamp, session: sessionID, turn: turn,
                workspace: workspace, command: json(["modelRequests": Int(row[4] ?? "0") ?? 0,
                    "modelRetries": Int(row[5] ?? "0") ?? 0, "toolCalls": Int(row[6] ?? "0") ?? 0,
                    "toolErrors": Int(row[7] ?? "0") ?? 0]), model: model, provider: provider,
                inputTokens: Int(row[8] ?? ""), outputTokens: Int(row[9] ?? ""),
                cachedTokens: Int(row[11] ?? ""), reasoningTokens: Int(row[10] ?? "")))
        }
        return events
    }

    nonisolated static func parseLog(_ data: Data, sourcePath: String) -> (events: [GuardEvent], malformed: Int) {
        var events: [GuardEvent] = [], malformed = 0
        for bytes in data.split(separator: 0x0A) {
            guard let object = try? JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else {
                malformed += 1; continue
            }
            let name = object["event"] as? String ?? ""
            let context = object["context"] as? [String: Any] ?? [:]
            let session = object["sessionId"] as? String ?? "zcode-runtime"
            let turn = object["turnId"] as? String
            let timestamp = ISO8601DateFormatter().date(from: object["timestamp"] as? String ?? "") ?? Date()
            let workspace = context["workingDirectory"] as? String ?? context["workspacePath"] as? String ?? "-"
            if name == "bootstrap.app.startup.runtime_config.completed" {
                let safe = context.filter { !["apiKey", "token", "password", "authorization"].contains($0.key) }
                events.append(event("\(sourcePath):\(timestamp.timeIntervalSince1970):runtime", kind: "context",
                    op: "runtime_config", action: "observed", timestamp: timestamp, session: session,
                    turn: turn, workspace: workspace, command: json(safe), modelPrompt: json(safe),
                    model: context["model"] as? String, provider: nil))
            } else if name.hasPrefix("mcp.server.") {
                let server = context["mcpServerName"] as? String ?? "unknown-mcp"
                let action = name.hasSuffix("failed") ? "failed" : name.hasSuffix("connected") ? "completed" : "requested"
                let callID = context["mcpConnectionId"] as? String ?? "\(session):\(server)"
                events.append(event("\(sourcePath):\(timestamp.timeIntervalSince1970):\(name):\(callID)",
                    kind: "tool", op: name, action: action, timestamp: timestamp, session: session,
                    turn: turn, workspace: workspace, command: json(context), toolCallId: callID,
                    toolName: "mcp:\(server)", model: nil, provider: nil))
            }
        }
        return (events, malformed)
    }

    private nonisolated static func readLogs(previousOffsets: [String: UInt64])
        -> (events: [GuardEvent], raw: [RawEvidenceRecord], offsets: [String: UInt64], malformed: Int) {
        let files = (try? FileManager.default.contentsOfDirectory(at: logRootURL,
            includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])) ?? []
        var events: [GuardEvent] = [], raw: [RawEvidenceRecord] = [], offsets: [String: UInt64] = [:], malformed = 0
        for url in files.filter({ $0.pathExtension == "jsonl" }).sorted(by: { $0.lastPathComponent > $1.lastPathComponent }).prefix(1) {
            guard let record = RawLogCapture.capture(url: url, source: "zcode",
                previousOffset: previousOffsets[url.path], maximumInitialBytes: 512 * 1_024) else { continue }
            raw.append(record); offsets[url.path] = RawLogCapture.safeCheckpoint(for: record)
            let parsed = parseLog(record.payload, sourcePath: url.path)
            events += parsed.events; malformed += parsed.malformed
        }
        return (events, raw, offsets, malformed)
    }

    private nonisolated static func readModelIO(previousOffsets: [String: UInt64])
        -> (events: [GuardEvent], raw: [RawEvidenceRecord], offsets: [String: UInt64], malformed: Int,
            available: Bool) {
        let files = (try? FileManager.default.contentsOfDirectory(at: modelIORootURL,
            includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles])) ?? []
        let modelIOFiles = files.filter { $0.lastPathComponent.hasPrefix("model-io-") && $0.pathExtension == "jsonl" }
        var events: [GuardEvent] = [], raw: [RawEvidenceRecord] = [], offsets: [String: UInt64] = [:], malformed = 0
        for url in modelIOFiles {
            guard let record = RawLogCapture.capture(url: url, source: "zcode-model-io",
                previousOffset: previousOffsets[url.path], maximumInitialBytes: 64 * 1_024 * 1_024) else { continue }
            raw.append(record); offsets[url.path] = RawLogCapture.safeCheckpoint(for: record)
            for line in record.payload.split(separator: 0x0A) {
                guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                      object["type"] as? String == "model_io" else { malformed += 1; continue }
                let projected = modelIOEvents(object, sourcePath: url.path)
                if projected.isEmpty { malformed += 1 } else { events += projected }
            }
        }
        return (events, raw, offsets, malformed, !modelIOFiles.isEmpty)
    }

    nonisolated static func modelIOEvents(_ object: [String: Any], sourcePath: String) -> [GuardEvent] {
        guard let requestID = object["requestId"] as? String,
              let request = object["request"] as? [String: Any] else { return [] }
        let session = object["sessionId"] as? String ?? "zcode-model-io"
        let turn = object["turnId"] as? String
        let trace = object["traceId"] as? String
        let started = ISO8601DateFormatter().date(from: object["startedAt"] as? String ?? "") ?? Date()
        let completed = ISO8601DateFormatter().date(from: object["completedAt"] as? String ?? "") ?? started
        let modelInfo = object["model"] as? [String: Any] ?? [:]
        let model = modelInfo["modelId"] as? String
        let provider = modelInfo["providerId"] as? String
        let body = request["body"] ?? request["messages"] ?? [:]
        let prompt = json(body)
        let messages = request["messages"] as? [[String: Any]]
        let intent = messages?.last(where: { $0["role"] as? String == "user" })
            .flatMap { messageText($0["content"]) }
        let requestMeta = json([
            "capture": "ZCode pre-encryption Model I/O",
            "requestId": requestID,
            "traceId": trace ?? "",
            "messageCount": request["messageCount"] ?? -1,
            "toolNames": request["toolNames"] ?? [],
            "bodyBytes": prompt?.utf8.count ?? 0
        ])
        var result = [GuardEvent(id: uuid("model-io:\(requestID):request"), kind: "model",
            ruleId: "zcode_model_io_request", path: sourcePath, command: requestMeta,
            agent: "zcode", op: "network_prompt", severity: "info", ts: started,
            action: "captured_pre_encryption", sessionId: session, traceId: trace, turnId: turn,
            userIntent: intent, modelPrompt: prompt, model: [provider, model].compactMap { $0 }.joined(separator: "/"),
            source: "agentsight:zcode-model-io", attributionConfidence: .confirmed,
            attributionMethod: "ZCode native Model I/O record captured before TLS encryption",
            remotePort: 443, remoteDomain: "zcode.z.ai")]
        if let response = object["response"] as? [String: Any] {
            let usage = response["usage"] as? [String: Any] ?? [:]
            result.append(GuardEvent(id: uuid("model-io:\(requestID):response"), kind: "model",
                ruleId: "zcode_model_io_response", path: sourcePath, command: requestMeta,
                agent: "zcode", op: "network_response", severity: "info", ts: completed,
                action: object["error"] == nil ? "received" : "failed", sessionId: session,
                traceId: trace, turnId: turn, userIntent: intent,
                modelReasoning: response["reasoningText"] as? String,
                modelResponse: response["text"] as? String,
                model: [provider, model].compactMap { $0 }.joined(separator: "/"),
                inputTokens: int(usage["inputTokens"] ?? usage["input_tokens"]),
                outputTokens: int(usage["outputTokens"] ?? usage["output_tokens"]),
                cachedTokens: int(usage["cacheReadTokens"] ?? usage["cacheReadInputTokens"] ?? usage["cached_tokens"]),
                reasoningTokens: int(usage["reasoningTokens"] ?? usage["reasoning_tokens"]),
                source: "agentsight:zcode-model-io", attributionConfidence: .confirmed,
                attributionMethod: "ZCode native Model I/O response record",
                remotePort: 443, remoteDomain: "zcode.z.ai"))
        }
        return result
    }

    private nonisolated static func messageText(_ value: Any?) -> String? {
        if let text = value as? String { return text }
        if let parts = value as? [[String: Any]] {
            return parts.compactMap { $0["text"] as? String }.joined(separator: "\n")
        }
        return nil
    }

    private nonisolated static func toolPartEvents(_ parts: [[String: Any]], messageID: String,
        timestamp: Date, session: String, turn: String?, workspace: String,
        model: String?, provider: String?) -> [GuardEvent] {
        parts.enumerated().compactMap { index, part in
            let type = (part["type"] as? String ?? "").lowercased()
            guard ["tool", "tool-use", "tool_use", "tool-call", "tool_call"].contains(type) else { return nil }
            let state = part["state"] as? [String: Any] ?? [:]
            let callID = part["callID"] as? String ?? part["id"] as? String
                ?? part["toolCallId"] as? String ?? "\(messageID):\(index)"
            let name = part["name"] as? String ?? part["tool"] as? String ?? "unknown_tool"
            let arguments = json(state["input"] ?? part["input"] ?? part["arguments"] ?? [:])
            let status = state["status"] as? String ?? "requested"
            return event("\(messageID):tool:\(callID)", kind: "tool", op: "call", action: "requested",
                timestamp: timestamp, session: session, turn: turn, workspace: workspace,
                command: arguments, modelResponse: json(state["output"] ?? [:]),
                toolCallId: callID, toolName: name, model: model, provider: provider,
                selfReportedStatus: status)
        }
    }

    private nonisolated static func event(_ id: String, kind: String, op: String, action: String,
        timestamp: Date, session: String, turn: String?, workspace: String, command: String? = nil,
        userIntent: String? = nil, modelReasoning: String? = nil, modelPrompt: String? = nil,
        modelResponse: String? = nil, toolCallId: String? = nil, toolName: String? = nil,
        model: String?, provider: String?, inputTokens: Int? = nil, outputTokens: Int? = nil,
        cachedTokens: Int? = nil, reasoningTokens: Int? = nil,
        selfReportedStatus: String? = nil) -> GuardEvent {
        GuardEvent(id: uuid(id), kind: kind, ruleId: "zcode_\(op)", path: workspace,
            command: command, agent: "zcode", op: op, severity: "info", ts: timestamp,
            action: action, sessionId: session, traceId: nil, turnId: turn, toolCallId: toolCallId,
            userIntent: userIntent, modelReasoning: modelReasoning, modelPrompt: modelPrompt,
            modelResponse: modelResponse, toolName: toolName,
            model: [provider, model].compactMap { $0 }.joined(separator: "/"),
            inputTokens: inputTokens, outputTokens: outputTokens, cachedTokens: cachedTokens,
            reasoningTokens: reasoningTokens,
            source: "agentsight:zcode-self-reported-v1", attributionConfidence: .unknown,
            attributionMethod: ["ZCode self-reported SQLite/structured JSONL evidence",
                                selfReportedStatus.map { "reported status=\($0)" }]
                .compactMap { $0 }.joined(separator: "; "))
    }

    private nonisolated static func sqliteFingerprint(_ url: URL) -> String? {
        [url, URL(fileURLWithPath: url.path + "-wal")].compactMap { candidate -> String? in
            guard let values = try? candidate.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]) else { return nil }
            return "\(candidate.lastPathComponent):\(values.fileSize ?? -1):\(values.contentModificationDate?.timeIntervalSince1970 ?? 0)"
        }.joined(separator: "|")
    }
    private nonisolated static func rows(_ db: OpaquePointer, sql: String, bind: String? = nil,
                                         binds: [String] = []) -> [[String?]] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { return [] }
        defer { sqlite3_finalize(statement) }
        let values = bind.map { [$0] } ?? binds
        for (index, value) in values.enumerated() {
            sqlite3_bind_text(statement, Int32(index + 1), value, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
        var result: [[String?]] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            result.append((0..<sqlite3_column_count(statement)).map { column in
                sqlite3_column_text(statement, column).map { String(cString: $0) }
            })
        }
        return result
    }
    private nonisolated static func dictionary(_ value: String) -> [String: Any]? {
        value.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }
    private nonisolated static func jsonValues(_ row: [String?]) -> [Any] {
        row.map { value -> Any in value ?? NSNull() }
    }
    private nonisolated static func json(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    private nonisolated static func text(from parts: [[String: Any]]) -> String? {
        let value = parts.filter { ($0["type"] as? String ?? "") == "text" }
            .compactMap { $0["text"] as? String }.joined(separator: "\n")
        return value.isEmpty ? nil : value
    }
    private nonisolated static func int(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let string = value as? String { return Int(string) }
        return nil
    }
    private nonisolated static func date(milliseconds: Int64?) -> Date? {
        milliseconds.map { Date(timeIntervalSince1970: Double($0) / 1_000) }
    }
    private nonisolated static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    private nonisolated static func uuid(_ value: String) -> UUID {
        let bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            (bytes[6] & 0x0F) | 0x50, bytes[7], (bytes[8] & 0x3F) | 0x80, bytes[9], bytes[10],
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
