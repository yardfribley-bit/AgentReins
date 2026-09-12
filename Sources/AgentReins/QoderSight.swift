import CryptoKit
import Foundation
import SwiftUI

/// Native Qoder adapter for local project JSONL. Raw lines are retained before
/// projection; credentials are never copied from Qoder configuration files.
@MainActor
final class QoderSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var fileSizes: [String: UInt64] = [:]
    private var seen = Set<UUID>()
    private let queue = DispatchQueue(label: "com.agentspec.qodersight", qos: .utility)
    private let database = try? EvidenceDatabase()
    private var accepted = 0
    private var malformed = 0

    func start() {
        guard timer == nil else { return }
        if let saved = try? database?.checkpoints(source: "qoder") { fileSizes = saved }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        let root = ("~/.qoder/projects" as NSString).expandingTildeInPath
        let previous = fileSizes
        let database = self.database
        queue.async { [weak self] in
            let batch = Self.readRecent(root: root, previousSizes: previous)
            var rawWriteFailed = false
            do { try database?.appendRaw(batch.raw) } catch { rawWriteFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                let isConnected = FileManager.default.fileExists(atPath: root)
                if self.connected != isConnected { self.connected = isConnected }
                if rawWriteFailed { self.malformed += 1 }
                self.malformed += batch.malformed
                let fresh = batch.events.filter { self.seen.insert($0.id).inserted }
                self.accepted += fresh.count
                if !fresh.isEmpty { self.lastUpdate = Date(); self.onEvents?(fresh) }
                for (stream, offset) in batch.sizes {
                    self.fileSizes[stream] = offset
                    try? self.database?.saveCheckpoint(SourceCheckpoint(source: "qoder", stream: stream,
                        offset: Int64(offset), fingerprint: nil, updatedAt: Date()))
                }
                try? self.database?.updateHealth(CollectorHealthRecord(source: "qoder",
                    state: !self.connected ? .failed : self.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: self.connected ? Date() : nil, lagSeconds: nil, accepted: self.accepted,
                    malformed: self.malformed, dropped: 0,
                    detail: self.connected ? "Qoder local session evidence connected" : "Qoder project evidence directory is unavailable"))
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
        var events: [GuardEvent] = [], sizes: [String: UInt64] = [:], raw: [RawEvidenceRecord] = []
        var bad = 0
        for (url, _, size) in files.sorted(by: { $0.1 > $1.1 }).prefix(1) {
            let previous = previousSizes[url.path]
            guard let record = RawLogCapture.capture(url: url, source: "qoder", previousOffset: previous) else {
                sizes[url.path] = size; continue
            }
            raw.append(record)
            sizes[url.path] = RawLogCapture.safeCheckpoint(for: record)
            let parsed = parse(record.payload, sourcePath: url.path)
            events += parsed.events; bad += parsed.malformed
        }
        return (events, sizes, raw, bad)
    }

    nonisolated static func parse(_ data: Data, sourcePath: String = "qoder.jsonl")
        -> (events: [GuardEvent], malformed: Int) {
        var events: [GuardEvent] = [], malformed = 0
        var modelBySession: [String: String] = [:]
        var turnByUUID: [String: String] = [:]
        for line in data.split(separator: 0x0A) {
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any] else {
                malformed += 1; continue
            }
            let type = object["type"] as? String ?? "unknown"
            let session = object["sessionId"] as? String ?? "qoder-local"
            let timestamp = parseDate(object["timestamp"])
            if type == "runtime-config" {
                let model = object["model"] as? String
                if let model { modelBySession[session] = model }
                let context = jsonString(object.filter {
                    ["model", "contextWindow", "reasoningEffort", "generation"].contains($0.key)
                })
                events.append(event(object, suffix: "runtime", kind: "context", op: "runtime_config",
                    action: "observed", command: context, timestamp: timestamp, session: session,
                    modelPrompt: context, model: model, sourcePath: sourcePath))
                continue
            }
            if type == "workspace-directories" {
                let context = jsonString(["directories": object["directories"] ?? []])
                events.append(event(object, suffix: "workspace", kind: "context", op: "project_context",
                    action: "observed", command: context, timestamp: timestamp, session: session,
                    modelPrompt: context, model: modelBySession[session], sourcePath: sourcePath))
                continue
            }
            let prompt = object["promptId"] as? String
            let inheritedTurn = (object["parentUuid"] as? String).flatMap { turnByUUID[$0] }
            let turn = prompt ?? object["requestSetId"] as? String ?? inheritedTurn
            if let uuid = object["uuid"] as? String, let turn { turnByUUID[uuid] = turn }
            let message = object["message"] as? [String: Any]
            let contents = message?["content"] as? [[String: Any]] ?? []
            let model = message?["model"] as? String ?? modelBySession[session]
            let usage = message?["usage"] as? [String: Any]
            if type == "user", let human = object["humanInput"] as? [String: Any],
               let text = human["text"] as? String, !text.isEmpty {
                events.append(event(object, suffix: "prompt", kind: "model", op: "prompt", action: "sent",
                    timestamp: timestamp, session: session, turn: turn, userIntent: bounded(text),
                    modelPrompt: bounded(text), model: model, sourcePath: sourcePath))
            }
            if type == "assistant" {
                let text = contents.filter { $0["type"] as? String == "text" }
                    .compactMap { $0["text"] as? String }.joined(separator: "\n")
                let reasoning = contents.filter { $0["type"] as? String == "thinking" }
                    .compactMap { $0["thinking"] as? String }.joined(separator: "\n")
                if !text.isEmpty || !reasoning.isEmpty {
                    events.append(event(object, suffix: "response", kind: "model", op: "response",
                        action: message?["stop_reason"] as? String ?? "received", timestamp: timestamp,
                        session: session, turn: turn, modelReasoning: reasoning.isEmpty ? nil : bounded(reasoning),
                        modelResponse: text.isEmpty ? nil : bounded(text), model: model,
                        inputTokens: int(usage?["input_tokens"]), outputTokens: int(usage?["output_tokens"]),
                        cachedTokens: int(usage?["cache_read_input_tokens"]), sourcePath: sourcePath))
                }
            }
            for content in contents {
                let contentType = content["type"] as? String
                if contentType == "tool_use", let callID = content["id"] as? String {
                    let tool = content["name"] as? String ?? "unknown_tool"
                    let arguments = jsonString(content["input"]).map(bounded)
                    events.append(event(object, suffix: "call:\(callID)", kind: "tool", op: "call",
                        action: "requested", command: arguments, timestamp: timestamp, session: session,
                        turn: turn, toolCallId: callID, toolName: tool, model: model,
                        codeFindings: CodeSecurityScanner.scanGenerated(toolName: tool, arguments: arguments),
                        sourcePath: sourcePath))
                } else if contentType == "tool_result", let callID = content["tool_use_id"] as? String {
                    events.append(event(object, suffix: "result:\(callID)", kind: "tool", op: "result",
                        action: (content["is_error"] as? Bool) == true ? "failed" : "completed",
                        timestamp: timestamp, session: session, turn: turn, toolCallId: callID,
                        modelResponse: stringify(content["content"]), model: model, sourcePath: sourcePath))
                }
            }
            if type == "attachment", let attachment = object["attachment"] as? [String: Any] {
                let attachmentType = attachment["type"] as? String ?? "unknown"
                let capturedContext = jsonString(attachment).map(bounded)
                events.append(event(object, suffix: "attachment:\(attachmentType)", kind: "context",
                    op: "attachment", action: "observed", command: safeAttachmentSummary(attachment),
                    timestamp: timestamp, session: session, turn: turn,
                    modelPrompt: capturedContext, toolName: "qoder.\(attachmentType)", model: model,
                    sourcePath: sourcePath))
            }
        }
        return (events, malformed)
    }

    private nonisolated static func event(_ object: [String: Any], suffix: String, kind: String, op: String,
        action: String, command: String? = nil, timestamp: Date, session: String, turn: String? = nil,
        toolCallId: String? = nil, userIntent: String? = nil, modelReasoning: String? = nil,
        modelPrompt: String? = nil, modelResponse: String? = nil, toolName: String? = nil,
        model: String? = nil, inputTokens: Int? = nil, outputTokens: Int? = nil,
        cachedTokens: Int? = nil, codeFindings: [CodeFinding]? = nil, sourcePath: String) -> GuardEvent {
        let rawID = object["uuid"] as? String ?? object["promptId"] as? String ?? "\(session):\(timestamp.timeIntervalSince1970)"
        return GuardEvent(id: deterministicUUID("\(rawID):\(suffix)"), kind: kind, ruleId: "qoder_\(op)",
            path: object["cwd"] as? String ?? sourcePath, command: command, agent: "qoder", op: op,
            severity: "info", ts: timestamp, action: action, sessionId: session,
            traceId: object["requestSetId"] as? String, turnId: turn, toolCallId: toolCallId,
            userIntent: userIntent, modelReasoning: modelReasoning, modelPrompt: modelPrompt,
            modelResponse: modelResponse, toolName: toolName, model: model,
            inputTokens: inputTokens, outputTokens: outputTokens, cachedTokens: cachedTokens,
            codeFindings: codeFindings?.isEmpty == false ? codeFindings : nil,
            source: "agentsight:qoder-local", attributionConfidence: .confirmed,
            attributionMethod: "Qoder native project JSONL")
    }

    private nonisolated static func parseDate(_ value: Any?) -> Date {
        if let number = value as? NSNumber {
            let raw = number.doubleValue; return Date(timeIntervalSince1970: raw > 10_000_000_000 ? raw / 1_000 : raw)
        }
        if let text = value as? String, let date = ISO8601DateFormatter().date(from: text) { return date }
        return Date()
    }
    private nonisolated static func int(_ value: Any?) -> Int? { (value as? NSNumber)?.intValue }
    private nonisolated static func jsonString(_ value: Any?) -> String? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    private nonisolated static func stringify(_ value: Any?) -> String? {
        if let text = value as? String { return bounded(text) }
        return jsonString(value).map(bounded)
    }
    private nonisolated static func bounded(_ value: String) -> String { String(value.prefix(512_000)) }
    private nonisolated static func safeAttachmentSummary(_ value: [String: Any]) -> String {
        let allowed = ["type", "hookName", "hookEvent", "hookEventName", "exitCode", "durationMs", "skillCount"]
        return jsonString(value.filter { allowed.contains($0.key) }) ?? "{}"
    }
    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        let bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            (bytes[6] & 0x0F) | 0x50, (bytes[7]), (bytes[8] & 0x3F) | 0x80, bytes[9], bytes[10],
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
