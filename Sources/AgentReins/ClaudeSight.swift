import CryptoKit
import Foundation
import SwiftUI

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
        let root = ("~/.claude/projects" as NSString).expandingTildeInPath
        let previous = fileSizes
        let database = database
        queue.async { [weak self] in
            let batch = Self.readRecent(root: root, previousSizes: previous)
            var writeFailed = false
            do { try database?.appendRaw(batch.raw) } catch { writeFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                let available = FileManager.default.fileExists(atPath: root)
                if self.connected != available { self.connected = available }
                self.malformed += batch.malformed + (writeFailed ? 1 : 0)
                let fresh = batch.events.filter { self.seen.insert($0.id).inserted }
                self.accepted += fresh.count
                if !fresh.isEmpty { self.lastUpdate = Date(); self.onEvents?(fresh) }
                for (stream, offset) in batch.sizes {
                    self.fileSizes[stream] = offset
                    try? self.database?.saveCheckpoint(SourceCheckpoint(source: "claude", stream: stream,
                        offset: Int64(offset), fingerprint: nil, updatedAt: Date()))
                }
                try? self.database?.updateHealth(CollectorHealthRecord(source: "claude",
                    state: !available ? .failed : self.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: available ? Date() : nil, lagSeconds: nil, accepted: self.accepted,
                    malformed: self.malformed, dropped: 0,
                    detail: available ? "Claude Code local session evidence connected" :
                        "Claude Code project evidence directory is unavailable"))
            }
        }
    }

    private nonisolated static func readRecent(root: String, previousSizes: [String: UInt64])
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], malformed: Int) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]) else { return ([], [:], [], 0) }
        var files: [(URL, Date, UInt64)] = []
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let size = UInt64(values?.fileSize ?? 0)
            if previousSizes[url.path] != size {
                files.append((url, values?.contentModificationDate ?? .distantPast, size))
            }
        }
        guard let item = files.max(by: { $0.1 < $1.1 }) else { return ([], [:], [], 0) }
        guard let raw = RawLogCapture.capture(url: item.0, source: "claude", previousOffset: previousSizes[item.0.path])
        else { return ([], [item.0.path: item.2], [], 1) }
        let parsed = parse(raw.payload, sourcePath: item.0.path)
        return (parsed.events, [item.0.path: RawLogCapture.safeCheckpoint(for: raw)], [raw], parsed.malformed)
    }

    nonisolated static func parse(_ data: Data, sourcePath: String = "claude.jsonl")
        -> (events: [GuardEvent], malformed: Int) {
        var events: [GuardEvent] = [], malformed = 0
        var currentTurn: [String: String] = [:]
        var turnByUUID: [String: String] = [:]
        var toolNames: [String: String] = [:]
        for line in data.split(separator: 0x0A) {
            guard let row = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
                malformed += 1; continue
            }
            let type = row["type"] as? String ?? "unknown"
            let session = row["sessionId"] as? String ?? row["session_id"] as? String ?? "claude-local"
            let timestamp = date(row["timestamp"])
            let parentTurn = (row["parentUuid"] as? String).flatMap { turnByUUID[$0] }
            let message = row["message"] as? [String: Any]
            let contents = message?["content"] as? [[String: Any]] ?? []
            let isToolResult = contents.contains { $0["type"] as? String == "tool_result" }
            if type == "user", !isToolResult, let text = userText(message?["content"]), !text.isEmpty {
                let turn = row["promptId"] as? String ?? row["uuid"] as? String ?? UUID().uuidString
                currentTurn[session] = turn
                if let uuid = row["uuid"] as? String { turnByUUID[uuid] = turn }
                events.append(event(row, suffix: "prompt", kind: "model", op: "prompt", action: "sent",
                    timestamp: timestamp, session: session, turn: turn, userIntent: bounded(text),
                    modelPrompt: bounded(text), sourcePath: sourcePath))
                continue
            }
            let turn = parentTurn ?? currentTurn[session]
            if let uuid = row["uuid"] as? String, let turn { turnByUUID[uuid] = turn }
            let model = message?["model"] as? String
            let usage = message?["usage"] as? [String: Any]
            if type == "assistant" {
                let text = contents.filter { $0["type"] as? String == "text" }
                    .compactMap { $0["text"] as? String }.joined(separator: "\n")
                let thinkingBytes = contents.filter { $0["type"] as? String == "thinking" }
                    .compactMap { $0["thinking"] as? String }.reduce(0) { $0 + $1.utf8.count }
                if !text.isEmpty {
                    events.append(event(row, suffix: "response", kind: "model", op: "response",
                        action: message?["stop_reason"] as? String ?? "received", timestamp: timestamp,
                        session: session, turn: turn, modelResponse: bounded(text), model: model,
                        inputTokens: int(usage?["input_tokens"]), outputTokens: int(usage?["output_tokens"]),
                        cachedTokens: int(usage?["cache_read_input_tokens"]), sourcePath: sourcePath))
                } else if thinkingBytes > 0 {
                    events.append(event(row, suffix: "reasoning", kind: "context", op: "reasoning_observed",
                        action: "observed", command: "{\"captured_bytes\":\(thinkingBytes),\"content_exposed\":false}",
                        timestamp: timestamp, session: session, turn: turn, model: model, sourcePath: sourcePath))
                }
            }
            for content in contents {
                if content["type"] as? String == "tool_use", let callID = content["id"] as? String {
                    let name = content["name"] as? String ?? "unknown_tool"
                    toolNames[callID] = name
                    let arguments = json(content["input"]).map(bounded)
                    events.append(event(row, suffix: "call:\(callID)", kind: "tool", op: "call",
                        action: "requested", command: arguments, timestamp: timestamp, session: session,
                        turn: turn, toolCallId: callID, toolName: name, model: model,
                        codeFindings: CodeSecurityScanner.scanGenerated(toolName: name, arguments: arguments),
                        sourcePath: sourcePath))
                } else if content["type"] as? String == "tool_result",
                          let callID = content["tool_use_id"] as? String {
                    events.append(event(row, suffix: "result:\(callID)", kind: "tool", op: "result",
                        action: (content["is_error"] as? Bool) == true ? "failed" : "completed",
                        timestamp: timestamp, session: session, turn: turn, toolCallId: callID,
                        modelResponse: string(content["content"]), toolName: toolNames[callID],
                        sourcePath: sourcePath))
                }
            }
            if type == "attachment" {
                events.append(event(row, suffix: "attachment", kind: "context", op: "attachment",
                    action: "observed", command: attachmentSummary(row["attachment"]), timestamp: timestamp,
                    session: session, turn: turn, toolName: "claude.attachment", sourcePath: sourcePath))
            }
            if type == "permission-mode", let mode = row["permissionMode"] as? String {
                events.append(event(row, suffix: "permission", kind: "context", op: "turn_context",
                    action: "observed", command: "{\"permission_mode\":\"\(mode)\"}", timestamp: timestamp,
                    session: session, turn: turn, sourcePath: sourcePath))
            }
        }
        return (events, malformed)
    }

    private nonisolated static func event(_ row: [String: Any], suffix: String, kind: String, op: String,
        action: String, command: String? = nil, timestamp: Date, session: String, turn: String? = nil,
        toolCallId: String? = nil, userIntent: String? = nil, modelPrompt: String? = nil,
        modelResponse: String? = nil, toolName: String? = nil, model: String? = nil,
        inputTokens: Int? = nil, outputTokens: Int? = nil, cachedTokens: Int? = nil,
        codeFindings: [CodeFinding]? = nil, sourcePath: String) -> GuardEvent {
        let rawID = row["uuid"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        return GuardEvent(id: deterministicUUID("\(rawID):\(suffix)"), kind: kind, ruleId: "claude_\(op)",
            path: row["cwd"] as? String ?? sourcePath, command: command, agent: "claude", op: op,
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
    private nonisolated static func attachmentSummary(_ value: Any?) -> String {
        guard let item = value as? [String: Any] else { return "Attachment metadata observed" }
        return json(item.filter { ["type", "filePath", "filename", "mimeType"].contains($0.key) }) ??
            "Attachment metadata observed"
    }
    private nonisolated static func date(_ value: Any?) -> Date {
        guard let text = value as? String else { return Date() }
        return ISO8601DateFormatter().date(from: text) ?? Date()
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
