import Foundation
import SwiftUI
import CryptoKit

/// AgentSight 的 WorkBuddy-native 数据源：读取本地会话事件并投影成统一 GuardEvent。
/// macOS 无 eBPF record，因此这里使用 AgentSight 推荐的 agent-native session fallback。
@MainActor
final class WorkBuddySight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var historyRestoring = false
    @Published private(set) var historyProgress = 0.0
    @Published private(set) var historyFileCount = 0
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var seen = Set<UUID>()
    private var lastPoll = Date.distantPast
    private var fileSizes: [String: UInt64] = [:]
    private let evidenceDatabase = try? EvidenceDatabase()
    private var lastHealthPersist = Date.distantPast
    private var acceptedEvents = 0
    private var collectionFailures = 0
    private var malformedRows = 0
    private var partialRows = 0
    private let queue = DispatchQueue(label: "com.agentspec.workbuddysight", qos: .utility)

    func start() {
        guard timer == nil else { return }
        if fileSizes.isEmpty, let saved = try? evidenceDatabase?.checkpoints(source: "workbuddy") {
            fileSizes = saved
        }
        poll()
        // Keep the live monitor responsive while avoiding a permanent busy loop.
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func restoreHistory() {
        guard !historyRestoring else { return }
        let root = ("~/.workbuddy/projects" as NSString).expandingTildeInPath
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
        let root = ("~/.workbuddy/projects" as NSString).expandingTildeInPath
        let changedAfter = lastPoll
        let previousSizes = fileSizes
        lastPoll = Date()
        queue.async { [weak self] in
            let batch = Self.readRecentEvents(root: root, changedAfter: changedAfter,
                                              previousSizes: previousSizes)
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = FileManager.default.fileExists(atPath: root)
                self.fileSizes.merge(batch.sizes) { _, new in new }
                let fresh = batch.events.filter { self.seen.insert($0.id).inserted }
                self.collectionFailures += batch.rawFailures
                self.malformedRows += batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).malformedRows }
                self.partialRows += batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).trailingPartialRows }
                do { try self.evidenceDatabase?.appendRaw(batch.raw) }
                catch { self.collectionFailures += 1 }
                self.acceptedEvents += fresh.count
                if !fresh.isEmpty {
                    self.onEvents?(fresh)
                    self.lastUpdate = Date()
                }
                // Delivery precedes checkpointing so interruption can only
                // replay stable IDs; it cannot acknowledge unseen evidence.
                for (stream, offset) in batch.sizes {
                    try? self.evidenceDatabase?.saveCheckpoint(SourceCheckpoint(
                        source: "workbuddy", stream: stream, offset: Int64(offset),
                        fingerprint: nil, updatedAt: Date()))
                }
                if Date().timeIntervalSince(self.lastHealthPersist) >= 10 || !self.connected {
                    self.lastHealthPersist = Date()
                    let state: CollectorHealthRecord.State = !self.connected ? .failed : self.collectionFailures + self.malformedRows > 0 ? .degraded : .healthy
                    try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                        source: "workbuddy", state: state, lastSuccess: self.connected ? Date() : nil,
                        lagSeconds: nil, accepted: self.acceptedEvents,
                        malformed: self.collectionFailures + self.malformedRows, dropped: self.partialRows,
                        detail: !self.connected ? "WorkBuddy session directory is unavailable" : self.collectionFailures > 0 || self.malformedRows > 0 ? "Raw read/write or malformed JSONL evidence detected" : self.partialRows > 0 ? "A trailing partial row is buffered for the next poll" : nil))
                }
            }
        }
    }

    private nonisolated static func readRecentEvents(root: String, changedAfter: Date,
                                                     previousSizes: [String: UInt64])
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
            if mtime >= cutoff && (mtime >= changedAfter || previousSizes[url.path] != size) {
                files.append((url, mtime, size))
            }
        }
        let selected = files.sorted { $0.1 > $1.1 }.prefix(4)
        let raw = selected.compactMap { RawLogCapture.capture(url: $0.0, source: "workbuddy", previousOffset: previousSizes[$0.0.path]) }
        var sizes = Dictionary(uniqueKeysWithValues: selected.map { ($0.0.path, $0.2) })
        for record in raw { sizes[record.stream] = RawLogCapture.safeCheckpoint(for: record) }
        return (selected.flatMap { parseSession($0.0) },
                sizes, raw,
                max(0, selected.count - raw.count))
    }

    nonisolated static func parseSession(_ url: URL, fullHistory: Bool = false) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: fullHistory) else { return [] }
        var lastIntent: [String: String] = [:]
        var lastReasoning: [String: String] = [:]
        var currentTurn: [String: String] = [:]
        var toolNames: [String: String] = [:]
        var result: [GuardEvent] = []
        // 启动时只读取活跃窗口；完整历史已在 EventStore，避免重复解析巨型会话。
        let lines = text.split(whereSeparator: \.isNewline)
        for line in fullHistory ? ArraySlice(lines) : lines.suffix(400) {
            guard let data = String(line).data(using: .utf8),
                  let row = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = row["id"] as? String else { continue }
            // WorkBuddy may reuse the same row id for parallel tool calls. Include the
            // call identity and timestamp so no call silently disappears.
            let identity = [rawId, row["type"] as? String, row["callId"] as? String,
                            String(describing: row["timestamp"] ?? "")].compactMap { $0 }.joined(separator: ":")
            let id = deterministicUUID(identity)
            let session = row["sessionId"] as? String ?? url.deletingPathExtension().lastPathComponent
            let type = row["type"] as? String ?? ""
            if type == "message", row["role"] as? String == "user", let intent = textContent(row["content"]) {
                let readableIntent = cleanUserIntent(intent)
                lastIntent[session] = String(readableIntent.prefix(1_000))
                currentTurn[session] = rawId
                let provider = row["providerData"] as? [String: Any] ?? [:]
                result.append(GuardEvent(id: id, kind: "model", ruleId: "agentsight_model_prompt",
                    path: row["cwd"] as? String ?? "-", command: nil, agent: "workbuddy", op: "prompt",
                    severity: "info", ts: date(row["timestamp"]), action: "sent", sessionId: session,
                    traceId: provider["traceId"] as? String, turnId: rawId, userIntent: String(readableIntent.prefix(1_000)),
                    modelPrompt: String(intent.prefix(64_000)), model: provider["model"] as? String,
                    source: "agentsight:workbuddy-local"))
                continue
            }
            if type == "message", row["role"] as? String == "assistant", let response = textContent(row["content"]) {
                let provider = row["providerData"] as? [String: Any] ?? [:]
                let rawAgent = provider["agent"] as? String
                let agent = (rawAgent == nil || rawAgent == "cli") ? "workbuddy" : rawAgent!
                result.append(GuardEvent(id: id, kind: "model", ruleId: "agentsight_model_response",
                    path: row["cwd"] as? String ?? "-", command: nil, agent: agent, op: "response",
                    severity: "info", ts: date(row["timestamp"]), action: row["status"] as? String ?? "received",
                    sessionId: session, traceId: provider["traceId"] as? String,
                    turnId: currentTurn[session],
                    userIntent: lastIntent[session], modelResponse: String(response.prefix(64_000)),
                    model: provider["requestModelName"] as? String ?? provider["model"] as? String,
                    source: "agentsight:workbuddy-local"))
                continue
            }
            if type == "reasoning" {
                if let reasoning = recursiveText(row["content"] ?? row["rawContent"]) {
                    lastReasoning[session] = String(reasoning.prefix(8_000))
                }
                continue
            }
            guard type == "function_call" || type == "function_call_result" else { continue }
            let provider = row["providerData"] as? [String: Any] ?? [:]
            let usage = (provider["rawUsage"] as? [String: Any]) ?? (row["message"] as? [String: Any])?["usage"] as? [String: Any] ?? [:]
            let callId = row["callId"] as? String
            let recordedName = row["name"] as? String
            if type == "function_call", let callId, let recordedName { toolNames[callId] = recordedName }
            let name = recordedName ?? callId.flatMap { toolNames[$0] } ?? "unknown_tool"
            let args = row["arguments"] as? String
            let status = row["status"] as? String
            let timestamp = date(row["timestamp"])
            let rawAgent = provider["agent"] as? String
            let agent = (rawAgent == nil || rawAgent == "cli") ? "workbuddy" : rawAgent!
            let model = provider["requestModelName"] as? String ?? provider["model"] as? String
            let toolOutput = type == "function_call_result" ? recursiveText(row["output"] ?? provider["toolResult"]) : nil
            let command = type == "function_call" ? "\(name)(\(String((args ?? "").prefix(4_000))))" : nil
            let generatedCodeFindings = type == "function_call"
                ? CodeSecurityScanner.scanGenerated(toolName: name, arguments: args) : []
            result.append(GuardEvent(id: id, kind: "tool", ruleId: "agentsight_\(type)", path: row["cwd"] as? String ?? "-",
                command: command, agent: agent, op: type == "function_call" ? "call" : "result", severity: "info",
                ts: timestamp, action: status ?? (type == "function_call" ? "requested" : "completed"),
                sessionId: session, traceId: provider["traceId"] as? String, turnId: currentTurn[session], toolCallId: callId,
                userIntent: type == "function_call" ? lastIntent[session] : nil,
                modelDecision: type == "function_call" ? "The model selected \(name)" : nil,
                modelReasoning: type == "function_call" ? (provider["reasoning"] as? String ?? lastReasoning[session]) : nil,
                modelResponse: toolOutput.map { String($0.prefix(16_000)) },
                toolName: name, model: model,
                inputTokens: intValue(usage["prompt_tokens"] ?? usage["input_tokens"]),
                outputTokens: intValue(usage["completion_tokens"] ?? usage["output_tokens"]),
                cachedTokens: [intValue(usage["cached_tokens"]), intValue(usage["cache_read_input_tokens"]),
                               intValue((usage["prompt_tokens_details"] as? [String: Any])?["cached_tokens"])].compactMap { $0 }.max(),
                reasoningTokens: intValue((usage["completion_tokens_details"] as? [String: Any])?["reasoning_tokens"] ?? usage["completion_thinking_tokens"]),
                codeFindings: generatedCodeFindings.isEmpty ? nil : generatedCodeFindings,
                source: "agentsight:workbuddy-local"))
        }
        return result
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

    private nonisolated static func sessionText(_ url: URL, fullHistory: Bool) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if fullHistory || size <= 512 * 1_024 {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        try? handle.seek(toOffset: size - 512 * 1_024)
        var data = handle.readDataToEndOfFile()
        if let newline = data.firstIndex(of: 0x0A) { data = data.suffix(from: data.index(after: newline)) }
        return String(data: data, encoding: .utf8)
    }

    private nonisolated static func textContent(_ value: Any?) -> String? {
        guard let items = value as? [[String: Any]] else { return nil }
        return items.compactMap { $0["text"] as? String }.joined(separator: "\n").nilIfEmpty
    }

    private nonisolated static func recursiveText(_ value: Any?) -> String? {
        var parts: [String] = []
        func walk(_ value: Any) {
            if let string = value as? String { parts.append(string); return }
            if let array = value as? [Any] { array.forEach(walk); return }
            if let dict = value as? [String: Any] {
                for key in ["text", "summary", "content", "reasoning"] {
                    if let nested = dict[key] { walk(nested) }
                }
            }
        }
        if let value { walk(value) }
        return parts.joined(separator: "\n").nilIfEmpty
    }

    /// WorkBuddy 会把系统注入块和用户原话放在同一 message 中；摘要只取用户真正输入，原文仍保存在 modelPrompt。
    private nonisolated static func cleanUserIntent(_ text: String) -> String {
        // WorkBuddy wraps the literal user request inside <user_query>; extract it
        // before removing the surrounding injected system context.
        if let match = text.range(of: #"(?s)<user_query>(.*?)</user_query>"#, options: .regularExpression) {
            let block = String(text[match])
            return block.replacingOccurrences(of: #"(?s)</?user_query>"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        var value = text
        let blockPatterns = [
            #"(?s)<system-reminder[^>]*>.*?</system-reminder>"#,
            #"(?s)<product_identity>.*?</product_identity>"#,
            #"(?s)<tone_and_style>.*?</tone_and_style>"#,
            #"(?s)<project_context>.*?</project_context>"#,
            #"(?s)<additional_data>.*?</additional_data>"#,
            #"(?s)<memory_and_skills_reminder>.*?</memory_and_skills_reminder>"#
        ]
        for pattern in blockPatterns {
            value = value.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
        }
        let cleaned = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? "The user request could not be separated from injected context" : cleaned
    }

    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        if let uuid = UUID(uuidString: value) { return uuid }
        let hex = SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        let formatted = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))"
        return UUID(uuidString: formatted)!
    }

    private nonisolated static func date(_ value: Any?) -> Date {
        guard let number = value as? NSNumber else { return Date() }
        let raw = number.doubleValue
        return Date(timeIntervalSince1970: raw > 10_000_000_000 ? raw / 1_000 : raw)
    }

    private nonisolated static func intValue(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let string = value as? String { return Int(string) }
        return nil
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
