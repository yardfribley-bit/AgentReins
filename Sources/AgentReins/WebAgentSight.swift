import CryptoKit
import Foundation
import SwiftUI

/// Reads browser-extension evidence delivered by the Native Messaging host.
/// The extension confirms tab-level provenance; derived OS joins remain inferred.
@MainActor
final class WebAgentSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var offset: UInt64 = 0
    private let queue = DispatchQueue(label: "com.agentspec.webagentsight", qos: .utility)
    private let evidenceDatabase = try? EvidenceDatabase()
    private let sourceURL: URL

    init(sourceURL: URL? = nil) {
        self.sourceURL = sourceURL ?? FileManager.default.urls(for: .applicationSupportDirectory,
                                                               in: .userDomainMask)[0]
            .appendingPathComponent("AgentGuard/web-agent-events.jsonl")
    }

    func start() {
        guard timer == nil else { return }
        if let saved = try? evidenceDatabase?.checkpoint(source: "web-agent", stream: sourceURL.path) {
            offset = UInt64(max(0, saved.offset))
        }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        let previousOffset = offset
        let url = sourceURL
        let database = evidenceDatabase
        queue.async { [weak self] in
            guard let self else { return }
            let modified = try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            let extensionActive = modified.map { Date().timeIntervalSince($0) < 90 } ?? false
            let record = RawLogCapture.capture(url: url, source: "web-agent", previousOffset: previousOffset)
            let events = record.map { Self.parse($0.payload) } ?? []
            let checkpoint = record.map(RawLogCapture.safeCheckpoint)
            var rawWriteFailed = false
            if let record {
                do { try database?.appendRaw([record]) } catch { rawWriteFailed = true }
            }
            DispatchQueue.main.async {
                if self.connected != extensionActive { self.connected = extensionActive }
                guard let record, let checkpoint else {
                    try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                        source: "web-agent", state: self.connected ? .healthy : .failed,
                        lastSuccess: self.connected ? Date() : nil, lagSeconds: nil,
                        accepted: 0, malformed: 0, dropped: 0,
                        detail: self.connected ? nil : "No Grok browser heartbeat in the last 90 seconds"))
                    return
                }
                do {
                    if rawWriteFailed { throw NSError(domain: "AgentReins.WebAgentSight", code: 1) }
                    if !events.isEmpty { self.onEvents?(events); self.lastUpdate = Date() }
                    self.offset = checkpoint
                    try self.evidenceDatabase?.saveCheckpoint(SourceCheckpoint(
                        source: "web-agent", stream: url.path, offset: Int64(checkpoint),
                        fingerprint: record.fingerprint, updatedAt: Date()))
                    try self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                        source: "web-agent", state: .healthy, lastSuccess: Date(), lagSeconds: 0,
                        accepted: events.count, malformed: 0, dropped: 0,
                        detail: "Grok browser evidence connected through Native Messaging"))
                } catch {
                    try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                        source: "web-agent", state: .degraded, lastSuccess: self.lastUpdate,
                        lagSeconds: nil, accepted: 0, malformed: 1, dropped: 0,
                        detail: error.localizedDescription))
                }
            }
        }
    }

    nonisolated static func parse(_ data: Data) -> [GuardEvent] {
        data.split(separator: 0x0A).compactMap { line in
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any],
                  object["schemaVersion"] as? Int == 1,
                  let eventType = object["eventType"] as? String,
                  let eventID = object["eventId"] as? String,
                  let url = object["url"] as? String,
                  URL(string: url)?.host?.lowercased() == "grok.com" else { return nil }
            let timestamp = (object["timestamp"] as? String).flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date()
            let session = object["sessionId"] as? String ?? "grok-web"
            let text = object["text"] as? String
            let mode = object["mode"] as? String ?? "unknown"
            let tab = object["tabId"].map { String(describing: $0) } ?? "unknown"
            let id = deterministicUUID(eventID)
            switch eventType {
            case "heartbeat":
                return nil
            case "prompt":
                return GuardEvent(id: id, kind: "model", ruleId: "web_grok_prompt", path: url,
                    command: nil, agent: "grok", op: "prompt", severity: "info", ts: timestamp,
                    action: "sent", sessionId: session, turnId: eventID, userIntent: text,
                    modelPrompt: text, model: "grok-imagine", source: "browser:grok-confirmed",
                    attributionConfidence: .confirmed, attributionMethod: "browser tab \(tab)",
                    remoteDomain: "grok.com")
            case "result", "response":
                return GuardEvent(id: id, kind: "model", ruleId: "web_grok_result", path: url,
                    command: nil, agent: "grok", op: "response", severity: "info", ts: timestamp,
                    action: "received", sessionId: session, turnId: object["turnId"] as? String,
                    modelResponse: text,
                    model: "grok-imagine", source: "browser:grok-confirmed",
                    attributionConfidence: .confirmed, attributionMethod: "browser tab \(tab)",
                    remoteDomain: "grok.com")
            case "upload":
                return GuardEvent(id: id, kind: "tool", ruleId: "web_grok_upload", path: url,
                    command: text, agent: "grok", op: "call", severity: "info", ts: timestamp,
                    action: "completed", sessionId: session, toolCallId: eventID,
                    modelDecision: "The web agent received local input files", toolName: "browser.upload",
                    source: "browser:grok-confirmed", attributionConfidence: .confirmed,
                    attributionMethod: "browser file input in tab \(tab)", remoteDomain: "grok.com")
            default:
                return GuardEvent(id: id, kind: "activity", ruleId: "web_grok_\(eventType)", path: url,
                    command: text ?? "Grok Imagine \(mode): \(eventType)", agent: "grok", op: eventType,
                    severity: "info", ts: timestamp, action: "observed", sessionId: session,
                    source: "browser:grok-confirmed", attributionConfidence: .confirmed,
                    attributionMethod: "browser tab \(tab)", remoteDomain: "grok.com")
            }
        }
    }

    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        let digest = SHA256.hash(data: Data(value.utf8))
        var bytes = Array(digest.prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x50
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
