import CryptoKit
import Foundation
import SQLite3
import SwiftUI

/// Read-only adapter for Cursor's local Composer database. Cursor does not
/// publish this schema as a stable API, so every event names the observed
/// schema version and keeps the original composer snapshot as raw evidence.
@MainActor
final class CursorSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var seen = Set<UUID>()
    private let queue = DispatchQueue(label: "com.agentspec.cursorsight", qos: .utility)
    private let evidenceDatabase = try? EvidenceDatabase()
    private var accepted = 0
    private var malformed = 0

    static var databaseURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Cursor/User/globalStorage/state.vscdb")
    }

    func start() {
        guard timer == nil else { return }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    private func poll() {
        let url = Self.databaseURL
        queue.async { [weak self] in
            let snapshots = Self.readLatest(url: url)
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = FileManager.default.fileExists(atPath: url.path)
                if snapshots == nil { self.malformed += 1 }
                let values = snapshots ?? []
                let raw = values.map(\.rawEvidence)
                do { try self.evidenceDatabase?.appendRaw(raw) } catch { self.malformed += 1 }
                let fresh = values.flatMap(\.events).filter { self.seen.insert($0.id).inserted }
                self.accepted += fresh.count
                if !fresh.isEmpty { self.lastUpdate = Date(); self.onEvents?(fresh) }
                try? self.evidenceDatabase?.updateHealth(CollectorHealthRecord(
                    source: "cursor", state: !self.connected ? .failed : self.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: self.connected ? Date() : nil, lagSeconds: nil, accepted: self.accepted,
                    malformed: self.malformed, dropped: 0,
                    detail: self.connected ? "Cursor Composer SQLite evidence connected (undocumented compatibility schema)" : "Cursor state.vscdb is unavailable"))
            }
        }
    }

    struct Snapshot {
        let rawEvidence: RawEvidenceRecord
        let events: [GuardEvent]
    }

    nonisolated static func readLatest(url: URL) -> [Snapshot]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
              let db else { return nil }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 1_000)
        // `isDraft` lives inside the JSON header in current Cursor builds; it is
        // not a composerHeaders column. Keep SQL limited to stable columns and
        // apply the draft check after decoding the compatibility payload.
        let headers = rows(db, sql: "SELECT composerId,lastUpdatedAt,value FROM composerHeaders WHERE isArchived=0 ORDER BY lastUpdatedAt DESC LIMIT 8")
        return headers.compactMap { row in
            guard let id = row[0], let updatedText = row[1], let updated = Int64(updatedText),
                  let header = row[2], let headerData = header.data(using: .utf8),
                  let headerObject = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
                  (headerObject["isDraft"] as? Bool) != true else { return nil }
            let composerText = scalar(db, sql: "SELECT value FROM cursorDiskKV WHERE key=? LIMIT 1", bind: "composerData:\(id)") ?? header
            let composer = dictionary(composerText) ?? headerObject
            let bubbleRows = rows(db, sql: "SELECT key,value FROM cursorDiskKV WHERE key GLOB ? ORDER BY rowid", bind: "bubbleId:\(id):*")
            let bubbles: [(String, [String: Any])] = bubbleRows.compactMap { item in
                guard let key = item[0], let value = item[1], let object = dictionary(value) else { return nil }
                return (key, object)
            }
            var content: [String: String] = [:]
            for (_, bubble) in bubbles {
                guard let tool = bubble["toolFormerData"] as? [String: Any],
                      let resultText = tool["result"] as? String, let result = dictionary(resultText) else { continue }
                for field in ["beforeContentId", "afterContentId"] {
                    guard let key = result[field] as? String, content[key] == nil else { continue }
                    content[key] = scalar(db, sql: "SELECT value FROM cursorDiskKV WHERE key=? LIMIT 1", bind: key)
                }
            }
            let envelope: [String: Any] = ["schema": "cursor-state-v3", "header": headerObject,
                "composer": composer, "bubbles": bubbles.map(\.1)]
            guard let raw = try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys]) else { return nil }
            let fingerprint = SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
            let observed = date(composer["lastUpdatedAt"] ?? updated) ?? Date()
            let rawRecord = RawEvidenceRecord(source: "cursor", stream: "cursor-composer:\(id)",
                offsetStart: 0, offsetEnd: updated, fingerprint: fingerprint, observedAt: observed, payload: raw)
            return Snapshot(rawEvidence: rawRecord,
                            events: project(composerId: id, composer: composer, bubbles: bubbles, content: content))
        }
    }

    nonisolated static func project(composerId: String, composer: [String: Any],
                                    bubbles: [(String, [String: Any])], content: [String: String]) -> [GuardEvent] {
        let workspace = ((composer["workspaceIdentifier"] as? [String: Any])?["uri"] as? [String: Any])?["fsPath"] as? String ?? "-"
        let configuredModel = (composer["modelConfig"] as? [String: Any])?["modelName"] as? String
        let context = composer["promptTokenBreakdown"] as? [String: Any]
        let ordered = bubbles.sorted { (date($0.1["createdAt"]) ?? .distantPast) < (date($1.1["createdAt"]) ?? .distantPast) }
        var events: [GuardEvent] = []
        var turn: String?
        var intent: String?

        if let context, let encoded = json(context) {
            events.append(event(id: "\(composerId):context", kind: "context", op: "prompt_breakdown",
                action: "captured", ts: date(composer["lastUpdatedAt"]) ?? Date(), session: composerId,
                turn: nil, workspace: workspace, command: encoded, prompt: encoded,
                model: configuredModel, inputTokens: number(context["totalUsedTokens"]),
                toolName: "cursor.prompt_token_breakdown"))
        }

        for (key, bubble) in ordered {
            let bubbleID = bubble["bubbleId"] as? String ?? key
            let type = number(bubble["type"]) ?? 0
            let timestamp = date(bubble["createdAt"]) ?? Date()
            if type == 1 {
                guard let text = bubble["text"] as? String, !text.isEmpty else { continue }
                turn = bubbleID; intent = text
                let model = ((bubble["modelInfo"] as? [String: Any])?["modelName"] as? String) ?? configuredModel
                events.append(event(id: "\(bubbleID):prompt", kind: "model", op: "prompt", action: "sent",
                    ts: timestamp, session: composerId, turn: turn, workspace: workspace,
                    intent: text, prompt: text, model: model, trace: bubble["requestId"] as? String))
                continue
            }
            guard type == 2 else { continue }
            if let tool = bubble["toolFormerData"] as? [String: Any], let name = tool["name"] as? String {
                let callID = tool["toolCallId"] as? String ?? bubbleID
                let params = tool["params"] as? String
                let result = tool["result"] as? String
                let status = tool["status"] as? String ?? "requested"
                events.append(event(id: "\(bubbleID):call", kind: "tool", op: "call", action: "requested",
                    ts: timestamp, session: composerId, turn: turn, workspace: workspace, intent: intent,
                    command: params, model: configuredModel, toolCallId: callID, toolName: name,
                    codeFindings: CodeSecurityScanner.scanGenerated(toolName: name, arguments: params)))
                events.append(event(id: "\(bubbleID):result", kind: "tool", op: "result", action: status,
                    ts: timestamp, session: composerId, turn: turn, workspace: workspace,
                    response: result, model: configuredModel, toolCallId: callID, toolName: name))

                if name.lowercased().contains("edit"), let result, let resultObject = dictionary(result),
                   let afterID = resultObject["afterContentId"] as? String {
                    let before = (resultObject["beforeContentId"] as? String).flatMap { content[$0] }
                    let after = content[afterID]
                    let paramsObject = params.flatMap(dictionary)
                    let path = paramsObject?["relativeWorkspacePath"] as? String ?? workspace
                    let findings = CodeSecurityScanner.scan(path: path, before: before, after: after)
                    events.append(event(id: "\(bubbleID):file", kind: "file", op: before?.isEmpty == false ? "modify" : "create",
                        action: "observed", ts: timestamp, session: composerId, turn: turn, workspace: path,
                        intent: intent, before: before, after: after, model: configuredModel,
                        toolCallId: callID, toolName: name, codeFindings: findings))
                }
                continue
            }
            if let text = bubble["text"] as? String, !text.isEmpty {
                events.append(event(id: "\(bubbleID):response", kind: "model", op: "response",
                    action: "received", ts: timestamp, session: composerId, turn: turn,
                    workspace: workspace, intent: intent, response: text, model: configuredModel))
            }
            if let thinking = bubble["thinking"] as? String, !thinking.isEmpty {
                events.append(event(id: "\(bubbleID):reasoning", kind: "model", op: "reasoning",
                    action: "captured", ts: timestamp, session: composerId, turn: turn,
                    workspace: workspace, reasoning: thinking, model: configuredModel))
            }
        }
        return events
    }

    private nonisolated static func event(id: String, kind: String, op: String, action: String,
        ts: Date, session: String, turn: String?, workspace: String, intent: String? = nil,
        command: String? = nil, prompt: String? = nil, reasoning: String? = nil, response: String? = nil,
        before: String? = nil, after: String? = nil, model: String? = nil, trace: String? = nil,
        inputTokens: Int? = nil, toolCallId: String? = nil, toolName: String? = nil,
        codeFindings: [CodeFinding] = []) -> GuardEvent {
        GuardEvent(id: uuid(id), kind: kind, ruleId: "cursor_\(op)", path: workspace,
            command: command, agent: "cursor", op: op,
            severity: codeFindings.contains { $0.severity == "critical" || $0.severity == "high" } ? "high" : "info",
            ts: ts, action: action, sessionId: session, traceId: trace, turnId: turn,
            toolCallId: toolCallId, userIntent: intent, modelReasoning: reasoning, modelPrompt: prompt,
            modelResponse: response, toolName: toolName, model: model,
            inputTokens: inputTokens, beforeContent: before, afterContent: after,
            codeFindings: codeFindings.isEmpty ? nil : codeFindings,
            source: "agentsight:cursor-state-v3", attributionConfidence: .confirmed,
            attributionMethod: "Cursor native Composer ID, Bubble ID, Request ID, and Tool Call ID")
    }

    private nonisolated static func rows(_ db: OpaquePointer, sql: String, bind: String? = nil) -> [[String?]] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(statement) }
        if let bind { sqlite3_bind_text(statement, 1, bind, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
        var result: [[String?]] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            result.append((0..<sqlite3_column_count(statement)).map { index in
                guard let value = sqlite3_column_text(statement, index) else { return nil }
                return String(cString: value)
            })
        }
        return result
    }
    private nonisolated static func scalar(_ db: OpaquePointer, sql: String, bind: String) -> String? {
        rows(db, sql: sql, bind: bind).first?.first ?? nil
    }
    private nonisolated static func dictionary(_ value: String) -> [String: Any]? {
        value.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    }
    private nonisolated static func json(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    private nonisolated static func number(_ value: Any?) -> Int? { (value as? NSNumber)?.intValue }
    private nonisolated static func date(_ value: Any?) -> Date? {
        if let n = value as? NSNumber { let raw = n.doubleValue; return Date(timeIntervalSince1970: raw > 10_000_000_000 ? raw / 1_000 : raw) }
        if let n = value as? Int64 { return Date(timeIntervalSince1970: Double(n) / 1_000) }
        if let text = value as? String { return ISO8601DateFormatter().date(from: text) }
        return nil
    }
    private nonisolated static func uuid(_ value: String) -> UUID {
        let bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            (bytes[6] & 0x0F) | 0x50, bytes[7], (bytes[8] & 0x3F) | 0x80, bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
