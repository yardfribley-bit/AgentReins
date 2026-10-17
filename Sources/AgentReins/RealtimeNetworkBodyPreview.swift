import Foundation

/// Display-only bounded preview. Full evidence remains in the collector store.
/// Only the HTTPS body adapter establishes these fields, never a tool argument.
struct RealtimeNetworkBodyPreview: Encodable, Equatable {
    let requestHeaders: [[String]]?
    let responseHeaders: [[String]]?
    let requestComplete: Bool?
    let responseStatus: Int?
    let transportError: String?
    let securityAudit: NetworkSecurityAudit?
    let flow: String
    let request: String?
    let response: String?
    let requestBytes: Int?
    let responseBytes: Int?
    let toolInstructions: String?
    let reasoning: String?
    let responseComplete: Bool?
    let requestTruncated: Bool
    let responseTruncated: Bool
    let responseRepresentation: String

    init?(event: GuardEvent) {
        guard ["agentsight:workbuddy-network-body", ProcessPlaintextEvidence.source].contains(event.source ?? ""), let flow = event.traceId else { return nil }
        let metadata = event.command?.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        securityAudit = (metadata?["securityAudit"] as? [String: Any]).flatMap { try? JSONSerialization.data(withJSONObject: $0) }.flatMap { try? JSONDecoder().decode(NetworkSecurityAudit.self, from: $0) }
        let hasHeaders = metadata?["headersCaptured"] as? Bool == true
        requestHeaders = hasHeaders ? metadata?["requestHeaders"] as? [[String]] : nil
        responseHeaders = hasHeaders ? metadata?["responseHeaders"] as? [[String]] : nil
        requestComplete = metadata?["protocolComplete"] as? Bool
        let status = metadata?["responseStatus"] as? Int
        responseStatus = status.flatMap { $0 >= 100 ? $0 : nil }
        let error = metadata?["transportError"] as? String
        transportError = error == "none" ? nil : error
        self.flow = flow
        request = event.modelPrompt.map { String($0.prefix(16_000)) }
        response = event.modelResponse.map { String($0.prefix(16_000)) }
        requestBytes = event.modelPrompt?.utf8.count
        responseBytes = event.modelResponse?.utf8.count
        toolInstructions = event.modelDecision.map { String($0.prefix(16_000)) }
        reasoning = event.modelReasoning.map { String($0.prefix(16_000)) }
        responseComplete = event.action == "received_complete" ? true : event.action == "received_partial" ? false : nil
        requestTruncated = (event.modelPrompt?.count ?? 0) > 16_000 || (event.modelPrompt != nil && metadata?["bodyTruncated"] as? Bool == true)
        responseTruncated = (event.modelResponse?.count ?? 0) > 16_000 || (event.modelResponse != nil && metadata?["bodyTruncated"] as? Bool == true)
        responseRepresentation = event.kind == "model" ? "parsed_model_output" : "captured_response_body"
    }
}
