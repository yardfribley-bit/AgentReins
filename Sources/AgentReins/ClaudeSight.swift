import CryptoKit
import Foundation
import SwiftUI

enum ClaudeSightError: LocalizedError {
    case databaseUnavailable

    var errorDescription: String? {
        "Claude Code 本地证据数据库不可用"
    }
}

struct ClaudeProjectionState: Sendable {
    var currentTurn: [String: String] = [:]
    var turnByUUID: [String: String] = [:]
    var toolNames: [String: String] = [:]
    var sessionContext: [String: [String: String]] = [:]
    var emittedContextSignatures: [String: String] = [:]
}

private struct ClaudeSessionContextProjection {
    let state: ClaudeProjectionState
    let event: GuardEvent?
}

private struct ClaudeAttachmentProjection {
    let type: String
    let metadata: String
    let context: String?
}

/// Native, read-only Claude Code adapter. It tails only the most recently
/// changed local project JSONL and preserves raw evidence before projection.
@MainActor
final class ClaudeSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var fileSizes: [String: UInt64] = [:]
    private var seen = Set<UUID>()
    private let queue = DispatchQueue(label: "com.agentspec.claudesight", qos: .utility)
    private let database = try? EvidenceDatabase()
    private var accepted = 0
    private var malformed = 0
    private var isInitialPoll = true
    private var isPolling = false
    private var projectionStates: [String: ClaudeProjectionState] = [:]
    private let projectionRecoveryKey = "agr_claude_projection_recovery_v1"

    func start() {
        guard timer == nil else { return }
        if let saved = try? database?.checkpoints(source: "claude") { fileSizes = saved }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        guard !isPolling else { return }
        isPolling = true
        let root = ("~/.claude/projects" as NSString).expandingTildeInPath
        let previous = fileSizes
        let database = database
        let baselineOtherStreams = isInitialPoll
        let previousStates = projectionStates
        let shouldRecover = isInitialPoll && !UserDefaults.standard.bool(forKey: projectionRecoveryKey)
        queue.async { [weak self] in
            var recovered: [GuardEvent] = []
            var recoveryError: String?
            if shouldRecover {
                do {
                    guard let database else { throw ClaudeSightError.databaseUnavailable }
                    recovered = Self.recoverProjection(from: try database.rawRecords(source: "claude"))
                    try database.append(recovered)
                } catch {
                    recoveryError = error.localizedDescription
                }
            }
            let batch = Self.readRecentStateful(root: root, previousSizes: previous,
                baselineOtherStreams: baselineOtherStreams, previousStates: previousStates)
            var writeFailed = false
            do { try database?.appendRaw(batch.raw) } catch { writeFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                let available = FileManager.default.fileExists(atPath: root)
                self.isPolling = false
                if available { self.isInitialPoll = false }
                if self.connected != available { self.connected = available }
                self.malformed += batch.malformed + (writeFailed || recoveryError != nil ? 1 : 0)
                self.projectionStates = batch.states
                let fresh = Self.deduplicated(recovered + batch.events)
                    .filter { self.seen.insert($0.id).inserted }
                self.accepted += fresh.count
                if !fresh.isEmpty { self.lastUpdate = Date(); self.onEvents?(fresh) }
                if shouldRecover && recoveryError == nil {
                    UserDefaults.standard.set(true, forKey: self.projectionRecoveryKey)
                }
                for (stream, offset) in batch.sizes {
                    self.fileSizes[stream] = offset
                }
                let checkpoints = batch.sizes.map { stream, offset in
                    SourceCheckpoint(source: "claude", stream: stream, offset: Int64(offset),
                                     fingerprint: nil, updatedAt: Date())
                }
                let detail = recoveryError.map { "Claude Code 投影恢复失败：\($0)" } ??
                    (available ? "Claude Code local session evidence connected" :
                        "Claude Code project evidence directory is unavailable")
                let health = CollectorHealthRecord(source: "claude",
                    state: !available ? .failed : self.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: available ? Date() : nil, lagSeconds: nil, accepted: self.accepted,
                    malformed: self.malformed, dropped: 0,
                    detail: detail)
                self.queue.async { [weak self] in
                    guard let database else {
                        DispatchQueue.main.async { self?.malformed += 1 }
                        return
                    }
                    var persistenceFailed = false
                    for checkpoint in checkpoints {
                        do { try database.saveCheckpoint(checkpoint) }
                        catch { persistenceFailed = true }
                    }
                    do { try database.updateHealth(health) }
                    catch { persistenceFailed = true }
                    if persistenceFailed {
                        DispatchQueue.main.async { self?.malformed += 1 }
                    }
                }
            }
        }
    }

    nonisolated static func readRecent(root: String, previousSizes: [String: UInt64],
                                      baselineOtherStreams: Bool)
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], malformed: Int) {
        let batch = readRecentStateful(root: root, previousSizes: previousSizes,
            baselineOtherStreams: baselineOtherStreams, previousStates: [:])
        return (batch.events, batch.sizes, batch.raw, batch.malformed)
    }

    private nonisolated static func readRecentStateful(root: String, previousSizes: [String: UInt64],
        baselineOtherStreams: Bool, previousStates: [String: ClaudeProjectionState])
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], malformed: Int,
            states: [String: ClaudeProjectionState]) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]) else {
            return ([], [:], [], 0, previousStates)
        }
        var files: [(URL, Date, UInt64)] = []
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let size = UInt64(values?.fileSize ?? 0)
            if previousSizes[url.path] != size {
                files.append((url, values?.contentModificationDate ?? .distantPast, size))
            }
        }
        guard let item = files.max(by: { $0.1 < $1.1 }) else {
            return ([], [:], [], 0, previousStates)
        }
        var sizes = baselineOtherStreams
            ? Dictionary(uniqueKeysWithValues: files.map { ($0.0.path, $0.2) }) : [:]
        guard let raw = RawLogCapture.capture(url: item.0, source: "claude",
            previousOffset: previousSizes[item.0.path], maximumInitialBytes: 512 * 1_024)
        else { return ([], sizes, [], 1, previousStates) }
        let priorOffset = previousSizes[item.0.path]
        var state = priorOffset.map { $0 <= item.2 } == false ? ClaudeProjectionState() : previousStates[item.0.path]
        if state == nil, raw.offsetStart > 0,
           let bootstrap = bootstrapData(url: item.0, beforeOffset: UInt64(raw.offsetStart)) {
            state = parseWithState(bootstrap, sourcePath: item.0.path,
                                   initialState: ClaudeProjectionState()).state
        }
        let startsAtLineBoundary = raw.offsetStart == 0 || priorOffset == UInt64(raw.offsetStart)
        let payload = completeProjectionLines(raw.payload, startsAtLineBoundary: startsAtLineBoundary)
        let parsed = parseWithState(payload, sourcePath: item.0.path,
                                    initialState: state ?? ClaudeProjectionState())
        sizes[item.0.path] = RawLogCapture.safeCheckpoint(for: raw)
        var states = previousStates
        states[item.0.path] = parsed.state
        return (parsed.events, sizes, [raw], parsed.malformed, states)
    }

    nonisolated static func parse(_ data: Data, sourcePath: String = "claude.jsonl")
        -> (events: [GuardEvent], malformed: Int) {
        let parsed = parseWithState(data, sourcePath: sourcePath, initialState: ClaudeProjectionState())
        return (parsed.events, parsed.malformed)
    }

    nonisolated static func parseIncrement(_ data: Data, sourcePath: String,
        state: ClaudeProjectionState)
        -> (events: [GuardEvent], malformed: Int, state: ClaudeProjectionState) {
        parseWithState(data, sourcePath: sourcePath, initialState: state)
    }

    nonisolated static func recoverProjection(from records: [RawEvidenceRecord]) -> [GuardEvent] {
        var states: [String: ClaudeProjectionState] = [:]
        var events: [GuardEvent] = []
        let ordered = records.sorted {
            $0.stream == $1.stream ? $0.offsetStart < $1.offsetStart : $0.stream < $1.stream
        }
        for record in ordered {
            let parsed = parseWithState(record.payload, sourcePath: record.stream,
                initialState: states[record.stream] ?? ClaudeProjectionState())
            states[record.stream] = parsed.state
            events.append(contentsOf: parsed.events)
        }
        return deduplicated(events)
    }

    private nonisolated static func parseWithState(_ data: Data, sourcePath: String,
        initialState: ClaudeProjectionState)
        -> (events: [GuardEvent], malformed: Int, state: ClaudeProjectionState) {
        var events: [GuardEvent] = [], malformed = 0
        var state = initialState
        for line in data.split(separator: 0x0A) {
            guard let row = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
                malformed += 1; continue
            }
            let type = row["type"] as? String ?? "unknown"
            let session = row["sessionId"] as? String ?? row["session_id"] as? String ?? "claude-local"
            state = stateCapturingSession(row: row, type: type, session: session, state: state)
            let timestamp = date(row["timestamp"])
            let parentTurn = (row["parentUuid"] as? String).flatMap { state.turnByUUID[$0] }
            let message = row["message"] as? [String: Any]
            let contents = message?["content"] as? [[String: Any]] ?? []
            let isToolResult = contents.contains { $0["type"] as? String == "tool_result" }
            if type == "user", !isToolResult, let text = userText(message?["content"]), !text.isEmpty {
                guard let timestamp else { malformed += 1; continue }
                let turn = row["promptId"] as? String ?? row["uuid"] as? String ?? UUID().uuidString
                state.currentTurn[session] = turn
                if let uuid = row["uuid"] as? String { state.turnByUUID[uuid] = turn }
                events.append(event(row, identity: row["uuid"] as? String, suffix: "prompt",
                    kind: "model", op: "prompt", action: "sent",
                    timestamp: timestamp, session: session, turn: turn, userIntent: bounded(text),
                    modelPrompt: bounded(text), sourcePath: sourcePath))
                let context = sessionContextProjection(row: row, timestamp: timestamp, session: session,
                    turn: turn, state: state, sourcePath: sourcePath)
                state = context.state
                if let event = context.event { events.append(event) }
                continue
            }
            let turn = parentTurn ?? state.currentTurn[session]
            if let uuid = row["uuid"] as? String, let turn { state.turnByUUID[uuid] = turn }
            if let timestamp, let turn {
                let context = sessionContextProjection(row: row, timestamp: timestamp, session: session,
                    turn: turn, state: state, sourcePath: sourcePath)
                state = context.state
                if let event = context.event { events.append(event) }
            }
            let model = message?["model"] as? String
            let usage = message?["usage"] as? [String: Any]
            let messageID = message?["id"] as? String ?? row["requestId"] as? String
            if type == "assistant" {
                guard let timestamp else { malformed += 1; continue }
                let text = contents.filter { $0["type"] as? String == "text" }
                    .compactMap { $0["text"] as? String }.joined(separator: "\n")
                let thinking = contents.filter { $0["type"] as? String == "thinking" }
                    .compactMap { $0["thinking"] as? String }.joined(separator: "\n")
                if !text.isEmpty {
                    events.append(event(row, identity: messageID, suffix: "response",
                        kind: "model", op: "response",
                        action: message?["stop_reason"] as? String ?? "received", timestamp: timestamp,
                        session: session, turn: turn, modelResponse: bounded(text), model: model,
                        sourcePath: sourcePath))
                }
                if !thinking.isEmpty {
                    events.append(reasoningEvent(row: row, timestamp: timestamp, session: session,
                                                 turn: turn, model: model, reasoning: thinking,
                                                 sourcePath: sourcePath, messageID: messageID))
                }
                if usage != nil {
                    events.append(usageEvent(row: row, timestamp: timestamp, session: session,
                                             turn: turn, model: model, usage: usage,
                                             sourcePath: sourcePath, messageID: messageID))
                }
            }
            let hasToolEvidence = contents.contains {
                ["tool_use", "tool_result"].contains($0["type"] as? String ?? "")
            }
            if hasToolEvidence, timestamp == nil { malformed += 1; continue }
            for content in contents {
                if content["type"] as? String == "tool_use", let callID = content["id"] as? String,
                   let timestamp {
                    let name = content["name"] as? String ?? "unknown_tool"
                    state.toolNames[callID] = name
                    let arguments = json(content["input"]).map(bounded)
                    events.append(event(row, identity: "\(session):\(callID)", suffix: "call",
                        kind: "tool", op: "call",
                        action: "requested", command: arguments, timestamp: timestamp, session: session,
                        turn: turn, toolCallId: callID, toolName: name, model: model,
                        codeFindings: CodeSecurityScanner.scanGenerated(toolName: name, arguments: arguments),
                        sourcePath: sourcePath))
                } else if content["type"] as? String == "tool_result",
                          let callID = content["tool_use_id"] as? String, let timestamp {
                    events.append(event(row, identity: "\(session):\(callID)", suffix: "result",
                        kind: "tool", op: "result",
                        action: (content["is_error"] as? Bool) == true ? "failed" : "completed",
                        timestamp: timestamp, session: session, turn: turn, toolCallId: callID,
                        modelResponse: string(content["content"]), toolName: state.toolNames[callID],
                        sourcePath: sourcePath))
                }
            }
            if type == "attachment", shouldProjectAttachment(row["attachment"]) {
                guard let timestamp else { malformed += 1; continue }
                let attachment = attachmentProjection(row["attachment"])
                events.append(event(row, identity: row["uuid"] as? String, suffix: "attachment",
                    kind: "context", op: "attachment", action: "observed", command: attachment.metadata,
                    timestamp: timestamp, session: session, turn: turn,
                    modelPrompt: attachment.context, toolName: "claude.attachment.\(attachment.type)",
                    sourcePath: sourcePath))
            }
            if type == "system", let subtype = row["subtype"] as? String {
                guard let timestamp else { malformed += 1; continue }
                events.append(systemEvent(row: row, subtype: subtype, timestamp: timestamp,
                                          session: session, turn: turn, sourcePath: sourcePath))
            }
        }
        return (deduplicated(events), malformed, state)
    }

    private nonisolated static func reasoningEvent(row: [String: Any], timestamp: Date,
        session: String, turn: String?, model: String?, reasoning: String,
        sourcePath: String, messageID: String?) -> GuardEvent {
        let rawID = messageID ?? row["uuid"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        return GuardEvent(id: deterministicUUID("\(rawID):reasoning"), kind: "model",
            ruleId: "claude_reasoning", path: row["cwd"] as? String ?? sourcePath,
            command: nil, agent: "claude-code", op: "reasoning_summary", severity: "info",
            ts: timestamp, action: "captured", sessionId: session, turnId: turn,
            modelReasoning: bounded(reasoning), model: model, source: "agentsight:claude-local",
            attributionConfidence: .confirmed,
            attributionMethod: "Claude Code native project JSONL")
    }

    private nonisolated static func usageEvent(row: [String: Any], timestamp: Date,
        session: String, turn: String?, model: String?, usage: [String: Any]?,
        sourcePath: String, messageID: String?) -> GuardEvent {
        let rawID = messageID ?? row["uuid"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        let cacheCreation = int(usage?["cache_creation_input_tokens"])
        let cacheRead = int(usage?["cache_read_input_tokens"])
        let uncached = int(usage?["input_tokens"])
        let totalInput = [uncached, cacheCreation, cacheRead].compactMap { $0 }.reduce(0, +)
        let details = usage?["output_tokens_details"] as? [String: Any]
        let metadata = selectedJSON(usage, keys: ["cache_creation_input_tokens", "cache_read_input_tokens",
            "cache_creation", "server_tool_use", "service_tier", "speed", "inference_geo"])
        return GuardEvent(id: deterministicUUID("\(rawID):usage"), kind: "model",
            ruleId: "claude_usage", path: row["cwd"] as? String ?? sourcePath,
            command: metadata, agent: "claude-code", op: "usage", severity: "info",
            ts: timestamp, action: "reported", sessionId: session,
            traceId: (row["message"] as? [String: Any])?["id"] as? String, turnId: turn,
            model: model, inputTokens: totalInput > 0 ? totalInput : nil,
            outputTokens: int(usage?["output_tokens"]),
            cachedTokens: cacheRead, reasoningTokens: int(details?["thinking_tokens"]),
            source: "agentsight:claude-local", attributionConfidence: .confirmed,
            attributionMethod: "Claude Code native project JSONL")
    }

    private nonisolated static func systemEvent(row: [String: Any], subtype: String,
        timestamp: Date, session: String, turn: String?, sourcePath: String) -> GuardEvent {
        let rawID = row["uuid"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        var fields = row.filter {
            ["subtype", "entrypoint", "gitBranch", "version", "userType", "slug",
             "isSidechain", "durationMs", "messageCount", "stopReason", "compactMetadata"].contains($0.key)
        }
        if let content = row["content"] as? String { fields["content"] = bounded(content) }
        let operation = subtype == "compact_boundary" ? "context_compaction" : "session_metadata"
        return GuardEvent(id: deterministicUUID("\(rawID):system:\(subtype)"), kind: "context",
            ruleId: "claude_\(operation)", path: row["cwd"] as? String ?? sourcePath,
            command: json(fields), agent: "claude-code", op: operation, severity: "info",
            ts: timestamp, action: "observed", sessionId: session, turnId: turn,
            toolName: "claude.system.\(subtype)", source: "agentsight:claude-local",
            attributionConfidence: .confirmed,
            attributionMethod: "Claude Code native project JSONL")
    }

    private nonisolated static func event(_ row: [String: Any], identity: String?, suffix: String,
        kind: String, op: String,
        action: String, command: String? = nil, timestamp: Date, session: String, turn: String? = nil,
        toolCallId: String? = nil, userIntent: String? = nil, modelPrompt: String? = nil,
        modelResponse: String? = nil, toolName: String? = nil, model: String? = nil,
        inputTokens: Int? = nil, outputTokens: Int? = nil, cachedTokens: Int? = nil,
        codeFindings: [CodeFinding]? = nil, sourcePath: String) -> GuardEvent {
        let rawID = identity ?? row["uuid"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        return GuardEvent(id: deterministicUUID("\(rawID):\(suffix)"), kind: kind, ruleId: "claude_\(op)",
            path: row["cwd"] as? String ?? sourcePath, command: command, agent: "claude-code", op: op,
            severity: "info", ts: timestamp, action: action, sessionId: session,
            traceId: (row["message"] as? [String: Any])?["id"] as? String, turnId: turn,
            toolCallId: toolCallId, userIntent: userIntent, modelPrompt: modelPrompt,
            modelResponse: modelResponse, toolName: toolName, model: model,
            inputTokens: inputTokens, outputTokens: outputTokens, cachedTokens: cachedTokens,
            codeFindings: codeFindings?.isEmpty == false ? codeFindings : nil,
            source: "agentsight:claude-local", attributionConfidence: .confirmed,
            attributionMethod: "Claude Code native project JSONL")
    }

    private nonisolated static func userText(_ value: Any?) -> String? {
        if let text = value as? String { return text }
        return (value as? [[String: Any]])?.filter { $0["type"] as? String == "text" }
            .compactMap { $0["text"] as? String }.joined(separator: "\n")
    }
    private nonisolated static func stateCapturingSession(row: [String: Any], type: String,
        session: String, state: ClaudeProjectionState) -> ClaudeProjectionState {
        var next = state
        var values = next.sessionContext[session] ?? [:]
        if type == "permission-mode", let value = row["permissionMode"] as? String {
            values["permission_mode"] = value
        }
        if type == "mode", let value = row["mode"] as? String { values["mode"] = value }
        if let value = row["effort"] as? String { values["effort"] = value }
        if let value = row["perTurnEffort"] as? String { values["turn_effort"] = value }
        if type == "bridge-session", let value = row["bridgeSessionId"] as? String {
            values["bridge_session"] = value
        }
        if !values.isEmpty { next.sessionContext[session] = values }
        return next
    }

    private nonisolated static func sessionContextProjection(row: [String: Any], timestamp: Date,
        session: String, turn: String, state: ClaudeProjectionState,
        sourcePath: String) -> ClaudeSessionContextProjection {
        guard let values = state.sessionContext[session], let payload = json(values) else {
            return ClaudeSessionContextProjection(state: state, event: nil)
        }
        let key = "\(session):\(turn)"
        guard state.emittedContextSignatures[key] != payload else {
            return ClaudeSessionContextProjection(state: state, event: nil)
        }
        var next = state
        next.emittedContextSignatures[key] = payload
        let event = GuardEvent(id: deterministicUUID("\(key):context:\(payload)"), kind: "context",
            ruleId: "claude_turn_context", path: row["cwd"] as? String ?? sourcePath,
            command: payload, agent: "claude-code", op: "turn_context", severity: "info",
            ts: timestamp, action: "observed", sessionId: session, turnId: turn,
            toolName: "claude.turn_context", source: "agentsight:claude-local",
            attributionConfidence: .confirmed,
            attributionMethod: "Claude Code native project JSONL")
        return ClaudeSessionContextProjection(state: next, event: event)
    }

    private nonisolated static func shouldProjectAttachment(_ value: Any?) -> Bool {
        guard let item = value as? [String: Any], let type = item["type"] as? String else { return false }
        let meaningful: Set<String> = [
            "agent_listing_delta", "auto_mode", "command_permissions", "compact_file_reference",
            "date_change", "deferred_tools_delta", "deferred_tools_record", "edited_text_file",
            "environment", "file", "hook_system_message", "instructions", "invoked_skills",
            "mcp_instructions_delta", "model", "prompt_snapshot", "remote_session_change",
            "session_context", "skill_listing"
        ]
        return meaningful.contains(type)
    }

    private nonisolated static func attachmentProjection(_ value: Any?) -> ClaudeAttachmentProjection {
        guard let item = value as? [String: Any] else {
            return ClaudeAttachmentProjection(type: "unknown", metadata: "{}", context: nil)
        }
        let type = item["type"] as? String ?? "unknown"
        let metadataKeys = ["type", "filename", "displayPath", "url", "hookName", "scope", "model",
                            "names", "tools", "skills", "files", "changed", "addedLines", "commit"]
        let contextKeys = ["systemPrompt", "prompt", "context", "text", "content", "snippet"]
        let metadata = selectedJSON(item, keys: metadataKeys) ?? "{\"type\":\"\(type)\"}"
        let context = selectedJSON(item, keys: contextKeys)
        return ClaudeAttachmentProjection(type: type, metadata: metadata, context: context)
    }

    private nonisolated static func selectedJSON(_ value: [String: Any]?, keys: [String]) -> String? {
        guard let value else { return nil }
        let selected = value.filter { keys.contains($0.key) }
        return selected.isEmpty ? nil : json(selected)
    }

    private nonisolated static func completeProjectionLines(_ data: Data,
        startsAtLineBoundary: Bool) -> Data {
        guard !startsAtLineBoundary else { return data }
        guard let newline = data.firstIndex(of: 0x0A) else { return Data() }
        return Data(data[data.index(after: newline)...])
    }

    private nonisolated static func bootstrapData(url: URL, beforeOffset: UInt64) -> Data? {
        let maximumBytes: UInt64 = 2 * 1_024 * 1_024
        let start = beforeOffset > maximumBytes ? beforeOffset - maximumBytes : 0
        guard beforeOffset > start, let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: start)
            guard let data = try handle.read(upToCount: Int(beforeOffset - start)) else { return nil }
            return completeProjectionLines(data, startsAtLineBoundary: start == 0)
        } catch {
            return nil
        }
    }

    private nonisolated static func deduplicated(_ events: [GuardEvent]) -> [GuardEvent] {
        var result: [GuardEvent] = []
        var indexes: [UUID: Int] = [:]
        for event in events {
            if let index = indexes[event.id] {
                result[index] = event
            } else {
                indexes[event.id] = result.count
                result.append(event)
            }
        }
        return result
    }
    private nonisolated static func date(_ value: Any?) -> Date? {
        guard let text = value as? String else { return nil }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: text) ?? ISO8601DateFormatter().date(from: text)
    }
    private nonisolated static func int(_ value: Any?) -> Int? { (value as? NSNumber)?.intValue }
    private nonisolated static func json(_ value: Any?) -> String? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    private nonisolated static func string(_ value: Any?) -> String? {
        if let text = value as? String { return bounded(text) }
        return json(value).map(bounded)
    }
    private nonisolated static func bounded(_ value: String) -> String { String(value.prefix(512_000)) }
    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        let bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            (bytes[6] & 0x0F) | 0x50, bytes[7], (bytes[8] & 0x3F) | 0x80, bytes[9], bytes[10],
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
