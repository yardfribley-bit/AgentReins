import Foundation
import CryptoKit

struct SecurityAnalysisSlice: Codable, Sendable {
    let id: String
    let evidence: [[String: String]]
    let eventIDs: Set<String>
}

enum SecurityAnalysisSlices {
    /// Cover every saved textual field, including the tail of large model and
    /// tool payloads. Offsets explicitly use Swift Character coordinates.
    static func build(_ events: [GuardEvent]) -> [SecurityAnalysisSlice] {
        var slices: [SecurityAnalysisSlice] = []
        var rows: [[String: String]] = []
        var size = 0
        func flush() {
            guard !rows.isEmpty else { return }
            let data = try! JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys])
            let id = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            slices.append(SecurityAnalysisSlice(id: id, evidence: rows, eventIDs: Set(rows.compactMap { $0["event_id"] })))
            rows = []; size = 0
        }
        for event in events.sorted(by: { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }) {
            let fields: [(String, String?)] = [
                ("user_intent", event.userIntent), ("command", event.command),
                ("model_prompt", event.modelPrompt), ("model_response", event.modelResponse),
                ("model_reasoning", event.modelReasoning), ("model_decision", event.modelDecision),
                ("before_content", event.beforeContent), ("after_content", event.afterContent),
                ("file_diff", event.fileDiff), ("path", event.path)]
            for (field, value) in fields {
                guard let value, !value.isEmpty else { continue }
                var start = value.startIndex
                var offset = 0
                let capturedCharacters = value.count
                while start < value.endIndex {
                    let end = value.index(start, offsetBy: 3000, limitedBy: value.endIndex) ?? value.endIndex
                    let part = String(value[start..<end])
                    let row = ["event_id": event.id.uuidString, "time": ISO8601DateFormatter().string(from: event.ts),
                        "agent": event.agent ?? "unknown", "kind": event.kind, "operation": event.op,
                        "tool": event.toolName ?? "", "tool_call_id": event.toolCallId ?? "",
                        "trace_id": event.traceId ?? "", "action": event.action,
                        "source": event.source ?? "unknown", "destination": event.remoteDomain ?? event.remoteHost ?? "",
                        "field": field, "character_offset": String(offset), "captured_field_characters": String(capturedCharacters),
                        "detail": part]
                    let bytes = (try? JSONSerialization.data(withJSONObject: row).count) ?? part.utf8.count
                    if size + bytes > 24000 || rows.count >= 16 { flush() }
                    rows.append(row); size += bytes
                    if end == value.endIndex { break }
                    let next = value.index(end, offsetBy: -160)
                    offset += value.distance(from: start, to: next); start = next
                }
            }
        }
        flush()
        return slices
    }
}
