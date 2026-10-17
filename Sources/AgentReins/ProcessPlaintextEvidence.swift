import Foundation
import CryptoKit

/// Application-layer evidence, never inferred from a socket snapshot.
enum ProcessPlaintextEvidence {
    static let source = "agentsight:process-plaintext"
    static func project(_ data: Data) -> [GuardEvent]? {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              o["source"] as? String == "node-http-plaintext" else { return nil }
        guard let agent = o["agent"] as? String, ["workbuddy", "codex"].contains(agent),
              let stage = o["stage"] as? String else { return [] }
        if stage == "ready" { return [] }
        guard let flow = o["flow"] as? String, let pid = o["pid"] as? Int32,
              let time = o["observedAt"] as? String else { return [] }
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: time) else { return [] }
        let request = stage == "request"
        let truncated = o["truncated"] as? Bool ?? false
        var body: String?
        if stage != "error" {
            guard let encoded = o["bodyBase64"] as? String, let bytes = Data(base64Encoded: encoded),
                  let captured = o["capturedBytes"] as? Int, captured == bytes.count,
                  let observed = o["observedBytes"] as? Int, observed >= captured else { return [] }
            if !truncated {
                let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
                guard observed == captured, o["sha256"] as? String == hash else { return [] }
            }
            body = String(data: bytes, encoding: .utf8)
        }
        let headers = (o["headers"] as? [String: Any] ?? [:]).sorted { $0.key < $1.key }.map { [$0.key, String(describing: $0.value)] }
        let complete = o["complete"] as? Bool == true && !truncated
        var metadata: [String: Any] = ["headersCaptured": true, "capturePoint": "node_http_application_layer", "captureStage": stage,
            "bodyTruncated": truncated, "observedBytes": o["observedBytes"] ?? 0,
            "protocolComplete": complete, "requestPath": o["path"] ?? "", "method": o["method"] ?? "",
            "responseStatus": o["status"] ?? -1, "transportError": o["error"] ?? "none",
            "limitation": "launcher agent label; native task and process birth identity not established"]
        metadata[request ? "requestHeaders" : "responseHeaders"] = headers
        let command = String(decoding: (try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])) ?? Data(), as: UTF8.self)
        let hash = Array(SHA256.hash(data: Data("\(source):\(flow):\(stage)".utf8)).prefix(16))
        let id = hash.withUnsafeBytes { UUID(uuid: $0.load(as: uuid_t.self)) }
        return [GuardEvent(id: id, kind: "network", ruleId: "process_plaintext_\(stage)", path: "-", command: command,
            agent: agent, op: request ? "tool_service_request" : "tool_service_response", severity: stage == "error" ? "warning" : "info",
            ts: date, action: request ? "observed" : stage == "error" ? "failed" : complete ? "received_complete" : "received_partial",
            traceId: "process:\(flow)", modelPrompt: request ? body : nil, modelResponse: request ? nil : body,
            source: source, attributionConfidence: .unknown, attributionMethod: "instrumented process; task unassigned",
            processId: pid, parentProcessId: o["ppid"] as? Int32, remoteDomain: o["host"] as? String)]
    }
}
