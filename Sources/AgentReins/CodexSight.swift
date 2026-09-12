import Foundation
import SwiftUI
import CryptoKit

/// Compatibility adapter for Codex's local rollout records. OpenAI does not
/// document this JSONL layout as a stable public API, so parsing is defensive
/// and every projected event retains a source label that states this boundary.
@MainActor
final class CodexSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var seen = Set<UUID>()
    private var fileSizes: [String: UInt64] = [:]
    private let evidenceDatabase = try? EvidenceDatabase()
    private var acceptedEvents = 0
    private var collectionFailures = 0
    private var malformedRows = 0
    private var partialRows = 0
    private let queue = DispatchQueue(label: "com.agentspec.codexsight", qos: .utility)

    func start() {
        guard timer == nil else { return }
        if fileSizes.isEmpty, let saved = try? evidenceDatabase?.checkpoints(source: "codex") {
            fileSizes = saved
        }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        let root = ("~/.codex/sessions" as NSString).expandingTildeInPath
        let previousSizes = fileSizes
        let database = evidenceDatabase
        queue.async { [weak self] in
            let batch = Self.readLiveEvents(root: root, previousSizes: previousSizes)
            let malformed = batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).malformedRows }
            let partial = batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).trailingPartialRows }
            var rawWriteFailed = false
            do { try database?.appendRaw(batch.raw) } catch { rawWriteFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                let isConnected = FileManager.default.fileExists(atPath: root)
                if self.connected != isConnected { self.connected = isConnected }
                self.fileSizes.merge(batch.sizes) { _, new in new }
                let fresh = batch.events.filter { self.seen.insert($0.id).inserted }
                self.collectionFailures += batch.rawFailures
                self.malformedRows += malformed
                self.partialRows += partial
                if rawWriteFailed { self.collectionFailures += 1 }
                self.acceptedEvents += fresh.count
                if !fresh.isEmpty {
                    self.onEvents?(fresh)
                    self.lastUpdate = Date()
                }
                // Advance only after delivery. A crash between delivery and this
                // checkpoint causes a safe idempotent replay, never silent loss.
                for (stream, offset) in batch.sizes {
                    try? self.evidenceDatabase?.saveCheckpoint(SourceCheckpoint(
                        source: "codex", stream: stream, offset: Int64(offset),
                        fingerprint: nil, updatedAt: Date()))
                }
                let state: CollectorHealthRecord.State = !self.connected ? .failed : self.collectionFailures + self.malformedRows > 0 ? .degraded : .healthy
                try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                    source: "codex", state: state, lastSuccess: self.connected ? Date() : nil,
                    lagSeconds: nil, accepted: self.acceptedEvents,
                    malformed: self.collectionFailures + self.malformedRows, dropped: self.partialRows,
                    detail: !self.connected ? "Codex session directory is unavailable" : self.collectionFailures > 0 || self.malformedRows > 0 ? "Raw read/write or malformed JSONL evidence detected" : self.partialRows > 0 ? "A trailing partial row is buffered for the next poll" : nil))
            }
        }
    }

    private nonisolated static func readLiveEvents(root: String, previousSizes: [String: UInt64])
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], rawFailures: Int) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]) else { return ([], [:], [], 1) }
        let cutoff = Date().addingTimeInterval(-7 * 86_400)
        var files: [(URL, Date, UInt64)] = []
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let mtime = values?.contentModificationDate ?? .distantPast
            let size = UInt64(values?.fileSize ?? 0)
            if mtime >= cutoff, previousSizes[url.path] != size { files.append((url, mtime, size)) }
        }
        var sizes: [String: UInt64] = [:]
        var raw: [RawEvidenceRecord] = []
        // One latest rollout at startup, then byte-level increments only.
        let events = files.sorted { $0.1 > $1.1 }.prefix(1).flatMap { item -> [GuardEvent] in
            let (url, _, size) = item
            let previous = previousSizes[url.path]
            if let record = RawLogCapture.capture(url: url, source: "codex", previousOffset: previous) {
                raw.append(record); sizes[url.path] = RawLogCapture.safeCheckpoint(for: record)
            } else { sizes[url.path] = size }
            let start = previous.map { min($0, size) > 64 * 1_024 ? min($0, size) - 64 * 1_024 : 0 }
                ?? (size > 512 * 1_024 ? size - 512 * 1_024 : 0)
            return parseSession(url, liveStartOffset: start)
        }
        return (events, sizes, raw, max(0, sizes.count - raw.count))
    }

    nonisolated static func parseSession(_ url: URL, fullHistory: Bool = false) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: fullHistory) else { return [] }
        return parseSessionText(text, url: url)
    }

    private nonisolated static func parseSession(_ url: URL, liveStartOffset: UInt64) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: false, startOffset: liveStartOffset) else { return [] }
        return parseSessionText(text, url: url)
    }

    private nonisolated static func parseSessionText(_ text: String, url: URL) -> [GuardEvent] {
        let lines = text.split(whereSeparator: \.isNewline)
        var session = url.deletingPathExtension().lastPathComponent
        var workspace = "-"
        var model: String?
        var currentTurn: String?
        var lastIntent: String?
        var toolNames: [String: String] = [:]
        var result: [GuardEvent] = []

        if let first = lines.first, let row = dictionary(first), let payload = row["payload"] as? [String: Any] {
            session = payload["id"] as? String ?? payload["session_id"] as? String ?? session
            workspace = payload["cwd"] as? String ?? workspace
        }

        for line in lines {
            guard let row = dictionary(line), let payload = row["payload"] as? [String: Any] else { continue }
            let type = row["type"] as? String ?? ""
            let payloadType = payload["type"] as? String ?? ""
            let timestamp = date(row["timestamp"])
            let timestampKey = row["timestamp"] as? String ?? String(timestamp.timeIntervalSince1970)

            if type == "session_meta", let base = payload["base_instructions"] as? [String: Any],
               let instructions = base["text"] as? String, !instructions.isEmpty {
                let provenance = jsonString(base["provenance"]) ?? "unknown"
                result.append(event(identity: "\(session):base-instructions", kind: "context",
                    rule: "codex_base_instructions", workspace: workspace, op: "base_instructions",
                    timestamp: timestamp, action: "captured", session: session, trace: nil, turn: nil,
                    intent: nil, prompt: String(instructions.prefix(128_000)), response: nil,
                    toolCallId: nil, toolName: "codex.base_instructions", command: provenance, model: model))
                continue
            }

            if type == "turn_context" {
                currentTurn = payload["turn_id"] as? String ?? currentTurn
                workspace = payload["cwd"] as? String ?? workspace
                model = payload["model"] as? String ?? model
                let context = selectedJSON(payload, keys: ["cwd", "current_date", "timezone", "model", "effort",
                    "approval_policy", "sandbox_policy", "permission_profile", "active_permission_profile",
                    "collaboration_mode", "workspace_roots", "realtime_active"])
                result.append(event(identity: "\(session):\(currentTurn ?? timestampKey):turn-context", kind: "context",
                    rule: "codex_turn_context", workspace: workspace, op: "turn_context", timestamp: timestamp,
                    action: "captured", session: session, trace: nil, turn: currentTurn, intent: lastIntent,
                    prompt: nil, response: nil, toolCallId: nil, toolName: "codex.turn_context",
                    command: context, model: model))
                continue
            }
            if type == "compacted" {
                let replacement = payload["replacement_history"] as? [Any] ?? []
                let guardian = payload["guardian_history"] as? [Any] ?? []
                let metadata: [String: Any] = [
                    "window_number": payload["window_number"] ?? NSNull(),
                    "previous_window_id": payload["previous_window_id"] ?? NSNull(),
                    "window_id": payload["window_id"] ?? NSNull(),
                    "compaction_response_id": payload["compaction_response_id"] ?? NSNull(),
                    "replacement_history_items": replacement.count,
                    "replacement_history_bytes": jsonByteCount(replacement),
                    "guardian_history_items": guardian.count,
                    "guardian_history_bytes": jsonByteCount(guardian)
                ]
                result.append(event(identity: "\(session):\(payload["window_id"] as? String ?? timestampKey):compaction",
                    kind: "context", rule: "codex_context_compaction", workspace: workspace,
                    op: "context_compaction", timestamp: timestamp, action: "captured", session: session,
                    trace: payload["compaction_response_id"] as? String, turn: currentTurn, intent: lastIntent,
                    prompt: nil, response: nil, toolCallId: nil, toolName: "codex.compaction",
                    command: jsonString(metadata), model: model))
                continue
            }
            if type == "world_state" {
                let state = payload["state"] as? [String: Any] ?? [:]
                let summary: [String: Any] = ["full": payload["full"] ?? false,
                    "state_keys": state.keys.sorted(), "state_bytes": jsonByteCount(state)]
                result.append(event(identity: "\(session):\(currentTurn ?? "none"):\(timestampKey):world-state",
                    kind: "context", rule: "codex_world_state", workspace: workspace, op: "world_state",
                    timestamp: timestamp, action: "captured", session: session, trace: nil, turn: currentTurn,
                    intent: lastIntent, prompt: nil, response: nil, toolCallId: nil,
                    toolName: "codex.world_state", command: jsonString(summary), model: model))
                continue
            }
            if type == "event_msg", payloadType == "task_started" {
                currentTurn = payload["turn_id"] as? String ?? currentTurn
                continue
            }
            if type == "event_msg", payloadType == "item_completed",
               let item = payload["item"] as? [String: Any], item["type"] as? String == "UserMessage",
               let content = textContent(item["content"]) {
                let turn = payload["turn_id"] as? String ?? currentTurn ?? item["id"] as? String
                currentTurn = turn
                lastIntent = cleanUserIntent(content)
                result.append(event(identity: "\(session):\(turn ?? "none"):\(item["id"] as? String ?? timestampKey):prompt", kind: "model",
                    rule: "codex_model_prompt", workspace: workspace, op: "prompt", timestamp: timestamp,
                    action: "sent", session: session, trace: nil, turn: turn, intent: lastIntent,
                    prompt: String(content.prefix(64_000)), response: nil, toolCallId: nil,
                    toolName: nil, command: nil, model: model))
                let attachments = (item["content"] as? [[String: Any]] ?? []).filter {
                    ($0["type"] as? String) != "text" && ($0["type"] as? String) != "input_text"
                }
                if !attachments.isEmpty {
                    let kinds = attachments.compactMap { $0["type"] as? String }
                    result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):attachments",
                        kind: "context", rule: "codex_attachment", workspace: workspace, op: "attachment",
                        timestamp: timestamp, action: "captured", session: session, trace: nil, turn: turn,
                        intent: lastIntent, prompt: nil, response: nil, toolCallId: nil,
                        toolName: "codex.attachment", command: jsonString(["count": attachments.count, "types": kinds]),
                        model: model))
                }
                continue
            }
            if type == "response_item", payloadType == "message", payload["role"] as? String == "developer",
               let content = textContent(payload["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(payload["id"] as? String ?? timestampKey):developer",
                    kind: "context", rule: "codex_developer_instructions", workspace: workspace,
                    op: "developer_instructions", timestamp: timestamp, action: "captured", session: session,
                    trace: nil, turn: turn, intent: lastIntent, prompt: String(content.prefix(128_000)),
                    response: nil, toolCallId: nil, toolName: "codex.developer_instructions",
                    command: nil, model: model))
                continue
            }
            if type == "response_item", payloadType == "reasoning" {
                let summary = recursiveText(payload["summary"])
                if let summary {
                    let turn = metadataTurn(payload) ?? currentTurn
                    result.append(event(identity: "\(session):\(turn ?? "none"):\(payload["id"] as? String ?? timestampKey):reasoning",
                        kind: "model", rule: "codex_reasoning_summary", workspace: workspace,
                        op: "reasoning_summary", timestamp: timestamp, action: "captured", session: session,
                        trace: nil, turn: turn, intent: lastIntent, prompt: nil, response: nil,
                        toolCallId: nil, toolName: nil, command: nil, model: model,
                        reasoning: String(summary.prefix(64_000))))
                }
                continue
            }
            if type == "response_item", payloadType == "message", payload["role"] as? String == "assistant",
               let content = textContent(payload["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):response", kind: "model",
                    rule: "codex_model_response", workspace: workspace, op: "response", timestamp: timestamp,
                    action: payload["phase"] as? String ?? "received", session: session, trace: nil, turn: turn, intent: lastIntent,
                    prompt: nil, response: String(content.prefix(64_000)), toolCallId: nil,
                    toolName: nil, command: nil, model: model))
                continue
            }
            if type == "token_usage_record", let usage = payload["usage"] as? [String: Any] {
                let turn = payload["turn_id"] as? String ?? currentTurn
                let trace = payload["response_id"] as? String
                result.append(event(identity: "\(session):\(turn ?? "none"):\(trace ?? "none"):\(timestampKey):usage", kind: "model",
                    rule: "codex_model_usage", workspace: workspace, op: "usage", timestamp: timestamp,
                    action: "reported", session: session, trace: trace, turn: turn, intent: lastIntent,
                    prompt: nil, response: nil, toolCallId: nil, toolName: nil, command: nil, model: model,
                    inputTokens: int(usage["input_tokens"]), outputTokens: int(usage["output_tokens"]),
                    cachedTokens: int(usage["cached_input_tokens"]), reasoningTokens: int(usage["reasoning_output_tokens"])))
                continue
            }
            guard type == "response_item", ["custom_tool_call", "function_call", "custom_tool_call_output", "function_call_output"].contains(payloadType) else { continue }
            let isOutput = payloadType.hasSuffix("output")
            let callId = payload["call_id"] as? String
            let namespace = payload["namespace"] as? String
            let recordedName = payload["name"] as? String
            let qualifiedName = [namespace, recordedName].compactMap { $0 }.joined(separator: namespace == nil ? "" : "__")
            if !isOutput, let callId { toolNames[callId] = qualifiedName.isEmpty ? "unknown_tool" : qualifiedName }
            let name = nonEmpty(qualifiedName) ?? callId.flatMap { toolNames[$0] } ?? "unknown_tool"
            let command = isOutput ? nil : (payload["input"] as? String ?? payload["arguments"] as? String)
            let output = isOutput ? recursiveText(payload["output"]) : nil
            let turn = metadataTurn(payload) ?? currentTurn
            result.append(event(identity: "\(session):\(turn ?? "none"):\(callId ?? "none"):\(payloadType):\(timestampKey)",
                kind: "tool", rule: "codex_\(payloadType)", workspace: workspace,
                op: isOutput ? "result" : "call", timestamp: timestamp,
                action: isOutput ? "completed" : "requested", session: session, trace: nil,
                turn: turn, intent: isOutput ? nil : lastIntent, prompt: nil, response: output,
                toolCallId: callId, toolName: name, command: command, model: model))
        }
        return result
    }

    private nonisolated static func event(identity: String, kind: String, rule: String, workspace: String,
        op: String, timestamp: Date, action: String, session: String, trace: String?, turn: String?,
        intent: String?, prompt: String?, response: String?, toolCallId: String?, toolName: String?,
        command: String?, model: String?, inputTokens: Int? = nil, outputTokens: Int? = nil,
        cachedTokens: Int? = nil, reasoningTokens: Int? = nil, reasoning: String? = nil) -> GuardEvent {
        GuardEvent(id: deterministicUUID(identity), kind: kind, ruleId: rule, path: workspace,
            command: command, agent: "codex", op: op, severity: "info", ts: timestamp,
            action: action, sessionId: session, traceId: trace, turnId: turn,
            toolCallId: toolCallId, userIntent: intent,
            modelDecision: op == "call" ? "The model selected \(toolName ?? "a tool")" : nil,
            modelReasoning: reasoning, modelPrompt: prompt, modelResponse: response, toolName: toolName, model: model,
            inputTokens: inputTokens, outputTokens: outputTokens, cachedTokens: cachedTokens,
            reasoningTokens: reasoningTokens, source: "agentsight:codex-local-compat")
    }

    private nonisolated static func dictionary(_ line: Substring) -> [String: Any]? {
        guard let data = String(line).data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    /// Keep startup bounded even when a long-running Codex task has produced a
    /// multi-megabyte rollout. The first record carries session metadata; recent
    /// records carry the active turns that the live monitor needs.
    private nonisolated static func sessionText(_ url: URL, fullHistory: Bool, startOffset: UInt64? = nil) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if fullHistory {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        if let startOffset {
            try? handle.seek(toOffset: 0)
            let first = handle.readData(ofLength: 64 * 1_024)
            try? handle.seek(toOffset: min(startOffset, size))
            var tail = handle.readDataToEndOfFile()
            if startOffset > 0, let newline = tail.firstIndex(of: 0x0A) {
                tail = tail.suffix(from: tail.index(after: newline))
            }
            guard let headText = String(data: first, encoding: .utf8),
                  let tailText = String(data: tail, encoding: .utf8) else { return nil }
            let firstLine = headText.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            return firstLine + "\n" + tailText
        }
        let tailBytes: UInt64 = 512 * 1_024
        guard size > tailBytes else {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        try? handle.seek(toOffset: 0)
        let first = handle.readData(ofLength: 64 * 1_024)
        try? handle.seek(toOffset: size - tailBytes)
        var tail = handle.readDataToEndOfFile()
        if let newline = tail.firstIndex(of: 0x0A) { tail = tail.suffix(from: tail.index(after: newline)) }
        guard let headText = String(data: first, encoding: .utf8),
              let tailText = String(data: tail, encoding: .utf8) else { return nil }
        let firstLine = headText.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        return firstLine + "\n" + tailText
    }

    private nonisolated static func textContent(_ value: Any?) -> String? {
        guard let items = value as? [[String: Any]] else { return nil }
        return nonEmpty(items.compactMap { $0["text"] as? String }.joined(separator: "\n"))
    }

    private nonisolated static func recursiveText(_ value: Any?) -> String? {
        if let value = value as? String { return nonEmpty(value) }
        if let items = value as? [[String: Any]] {
            return nonEmpty(items.compactMap { item in
                (item["text"] as? String) ?? (item["summary_text"] as? String)
            }.joined(separator: "\n"))
        }
        return nil
    }

    private nonisolated static func selectedJSON(_ object: [String: Any], keys: [String]) -> String? {
        jsonString(Dictionary(uniqueKeysWithValues: keys.compactMap { key in object[key].map { (key, $0) } }))
    }

    private nonisolated static func jsonString(_ value: Any?) -> String? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private nonisolated static func jsonByteCount(_ value: Any) -> Int {
        (try? JSONSerialization.data(withJSONObject: value)).map(\.count) ?? 0
    }

    private nonisolated static func metadataTurn(_ payload: [String: Any]) -> String? {
        (payload["internal_chat_message_metadata_passthrough"] as? [String: Any])?["turn_id"] as? String
    }

    private nonisolated static func cleanUserIntent(_ value: String) -> String {
        if let range = value.range(of: #"(?s)## My request:\s*(.*)$"#, options: .regularExpression) {
            return String(value[range]).replacingOccurrences(of: #"(?s)^## My request:\s*"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private nonisolated static func date(_ value: Any?) -> Date {
        guard let string = value as? String else { return Date() }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string) ?? ISO8601DateFormatter().date(from: string) ?? Date()
    }

    private nonisolated static func nonEmpty(_ value: String) -> String? {
        value.isEmpty ? nil : value
    }

    private nonisolated static func int(_ value: Any?) -> Int? {
        (value as? NSNumber)?.intValue ?? (value as? String).flatMap(Int.init)
    }

    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        let hex = SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        return UUID(uuidString: "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))")!
    }
}
