import CryptoKit
import Foundation

/// WorkBuddy keeps the assembled model input in separate traces from its
/// session transcript. Anchor on one trace at the user prompt, then accept
/// continuation traces from the same worker within that turn's time boundary.
enum WorkBuddyTraceRequests {
    static func load(events: [GuardEvent], sessionEvents: [GuardEvent]? = nil,
                     root: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".workbuddy/traces")) -> [AgentOutboundRequestEvidence] {
        guard let prompt = events.first(where: { $0.agent == "workbuddy" && $0.op == "prompt" }),
              let enumerator = FileManager.default.enumerator(at: root,
                  includingPropertiesForKeys: [.contentModificationDateKey],
                  options: [.skipsHiddenFiles]) else { return [] }
        let earliest = prompt.ts.addingTimeInterval(-5)
        let turnEnd = events.filter { $0.turnId == prompt.turnId }.map(\.ts).max() ?? prompt.ts
        let nextPrompt = (sessionEvents ?? []).filter {
            $0.kind == "model" && $0.op == "prompt" &&
                $0.sessionId == prompt.sessionId && $0.ts > prompt.ts &&
                $0.turnId != prompt.turnId
        }.map(\.ts).min()
        let latest = min(turnEnd.addingTimeInterval(30), nextPrompt ?? .distantFuture)
        var candidates: [(traceID: String, path: String, workerPID: Int,
                          started: Date, spans: [[String: Any]])] = []
        for case let url as URL in enumerator where url.pathExtension == "json" &&
            url.lastPathComponent.hasPrefix("trace_") {
            guard let modified = try? url.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate,
                  modified >= earliest, modified <= latest,
                  let data = try? Data(contentsOf: url),
                  let document = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let trace = document["trace"] as? [String: Any],
                  let traceID = trace["traceId"] as? String,
                  let workerPID = trace["workerPid"] as? Int,
                  let started = (trace["startedAt"] as? String).flatMap(parseDate),
                  started >= earliest, started <= latest,
                  let spans = document["spans"] as? [[String: Any]],
                  spans.contains(where: { $0["type"] as? String == "generation" &&
                      ($0["toolInput"] as? String)?.isEmpty == false }) else { continue }
            candidates.append((traceID, url.path, workerPID, started, spans))
        }
        let anchors = candidates.filter { $0.started <= prompt.ts.addingTimeInterval(15) }
        guard anchors.count == 1, let workerPID = anchors.first?.workerPID else { return [] }
        return candidates.filter { $0.workerPID == workerPID }
            .sorted { $0.started < $1.started }.flatMap { candidate in
            candidate.spans.compactMap { span in
            guard span["type"] as? String == "generation",
                  let spanID = span["spanId"] as? String,
                  let body = span["toolInput"] as? String, !body.isEmpty,
                  let started = (span["startedAt"] as? String).flatMap(parseDate),
                  started >= earliest, started <= latest else { return nil }
            let bytes = Data(body.utf8)
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            return AgentOutboundRequestEvidence(
                id: "outbound:\(candidate.traceID):\(spanID)",
                eventID: "trace:\(candidate.traceID):\(spanID)",
                capturedAt: started, model: span["model"] as? String,
                destination: nil, traceID: candidate.traceID, requestID: spanID,
                userIntent: prompt.userIntent, body: body, bodyBytes: bytes.count,
                bodySHA256: digest, evidenceSource: "workbuddy-local-trace",
                sourceLocator: candidate.path,
                captureMode: .agentRecordedContext, completeness: .partial,
                confidence: .confirmed)
            }
        }
    }

    private static func parseDate(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }
}
