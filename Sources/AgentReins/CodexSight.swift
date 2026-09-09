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
    @Published private(set) var historyRestoring = false
    @Published private(set) var historyProgress = 0.0
    @Published private(set) var historyFileCount = 0
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var seen = Set<UUID>()
    private var lastPoll = Date.distantPast
    private let queue = DispatchQueue(label: "com.agentspec.codexsight", qos: .utility)

    func start() {
        guard timer == nil else { return }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func restoreHistory() {
        guard !historyRestoring else { return }
        let root = ("~/.codex/sessions" as NSString).expandingTildeInPath
        historyRestoring = true
        historyProgress = 0
        queue.async { [weak self] in
            let files = Self.sessionFiles(root: root)
            var restored: [GuardEvent] = []
            for (index, url) in files.enumerated() {
                restored.append(contentsOf: Self.parseSession(url, fullHistory: true))
                DispatchQueue.main.async {
                    self?.historyProgress = files.isEmpty ? 1 : Double(index + 1) / Double(files.count)
                }
            }
            DispatchQueue.main.async {
                guard let self else { return }
                let fresh = restored.filter { self.seen.insert($0.id).inserted }
                self.onEvents?(fresh)
                self.historyFileCount = files.count
                self.historyRestoring = false
                self.historyProgress = 1
            }
        }
    }

    private func poll() {
        let root = ("~/.codex/sessions" as NSString).expandingTildeInPath
        let changedAfter = lastPoll
        lastPoll = Date()
        queue.async { [weak self] in
            let events = Self.readRecentEvents(root: root, changedAfter: changedAfter)
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = FileManager.default.fileExists(atPath: root)
                let fresh = events.filter { self.seen.insert($0.id).inserted }
                if !fresh.isEmpty {
                    self.onEvents?(fresh)
                    self.lastUpdate = Date()
                }
            }
        }
    }

    nonisolated static func readRecentEvents(root: String, changedAfter: Date) -> [GuardEvent] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey]) else { return [] }
        let cutoff = Date().addingTimeInterval(-7 * 86_400)
        var files: [(URL, Date)] = []
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let mtime = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            if mtime >= cutoff && mtime >= changedAfter { files.append((url, mtime)) }
        }
        return files.sorted { $0.1 > $1.1 }.prefix(2).flatMap { parseSession($0.0) }
    }

    private nonisolated static func sessionFiles(root: String) -> [URL] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey]) else { return [] }
        var files: [(URL, Date)] = []
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            files.append((url, date))
        }
        return files.sorted { $0.1 > $1.1 }.map(\.0)
    }

    nonisolated static func parseSession(_ url: URL, fullHistory: Bool = false) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: fullHistory) else { return [] }
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

            if type == "turn_context" {
                currentTurn = payload["turn_id"] as? String ?? currentTurn
                workspace = payload["cwd"] as? String ?? workspace
                model = payload["model"] as? String ?? model
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
                continue
            }
            if type == "response_item", payloadType == "message", payload["role"] as? String == "assistant",
               let content = textContent(payload["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):response", kind: "model",
                    rule: "codex_model_response", workspace: workspace, op: "response", timestamp: timestamp,
                    action: "received", session: session, trace: nil, turn: turn, intent: lastIntent,
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
        cachedTokens: Int? = nil, reasoningTokens: Int? = nil) -> GuardEvent {
        GuardEvent(id: deterministicUUID(identity), kind: kind, ruleId: rule, path: workspace,
            command: command, agent: "codex", op: op, severity: "info", ts: timestamp,
            action: action, sessionId: session, traceId: trace, turnId: turn,
            toolCallId: toolCallId, userIntent: intent,
            modelDecision: op == "call" ? "The model selected \(toolName ?? "a tool")" : nil,
            modelPrompt: prompt, modelResponse: response, toolName: toolName, model: model,
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
    private nonisolated static func sessionText(_ url: URL, fullHistory: Bool) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if fullHistory {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
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
        if let items = value as? [[String: Any]] { return textContent(items) }
        return nil
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
