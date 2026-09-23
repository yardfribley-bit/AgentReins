import Foundation
import CryptoKit

struct WorkBuddyNetworkCaptureRecord: Codable, Equatable, Sendable {
    let observedAt: Date
    let host: String
    let path: String
    let method: String
    let httpVersion: String
    let contentEncoding: String?
    let declaredContentLength: Int?
    let capturedWireBodyBytes: Int
    let requestBodyBase64: String
    let requestSHA256: String
    let responseStatus: Int?
    let responseComplete: Bool
    let responseBodyBase64: String?
    let clientAddress: String?
    let remoteHost: String?
    let remotePort: Int?

    init(observedAt: Date, host: String, path: String, method: String, httpVersion: String,
         contentEncoding: String?, declaredContentLength: Int?, capturedWireBodyBytes: Int,
         requestBodyBase64: String, requestSHA256: String, responseStatus: Int?,
         responseComplete: Bool, responseBodyBase64: String?, clientAddress: String? = nil,
         remoteHost: String? = nil, remotePort: Int? = nil) {
        self.observedAt = observedAt
        self.host = host
        self.path = path
        self.method = method
        self.httpVersion = httpVersion
        self.contentEncoding = contentEncoding
        self.declaredContentLength = declaredContentLength
        self.capturedWireBodyBytes = capturedWireBodyBytes
        self.requestBodyBase64 = requestBodyBase64
        self.requestSHA256 = requestSHA256
        self.responseStatus = responseStatus
        self.responseComplete = responseComplete
        self.responseBodyBase64 = responseBodyBase64
        self.clientAddress = clientAddress
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }
}

enum WorkBuddyNetworkEvidence {
    static func project(_ record: WorkBuddyNetworkCaptureRecord) -> [GuardEvent] {
        guard record.host.lowercased() == "copilot.tencent.com",
              ["/v1/chat/completions", "/v2/chat/completions", "/v3/chat/completions",
               "/agenttool/v1/intent/recall"].contains(record.path),
              let requestData = Data(base64Encoded: record.requestBodyBase64),
              SHA256.hash(data: requestData).hex == record.requestSHA256.lowercased() else { return [] }

        let requestComplete = record.declaredContentLength.map { $0 == record.capturedWireBodyBytes } ?? false
        let isModelRoute = record.path != "/agenttool/v1/intent/recall"
        let requestObject = try? JSONSerialization.jsonObject(with: requestData) as? [String: Any]
        let intent = userIntent(in: requestObject)
        let model = requestObject?["model"] as? String
        let identity = String(record.requestSHA256.prefix(20))
        let session = "workbuddy-network:\(identity)"
        let metadata = json([
            "capture": "complete HTTPS request body",
            "requestPath": record.path,
            "httpVersion": record.httpVersion,
            "contentEncoding": record.contentEncoding ?? "identity",
            "declaredContentLength": record.declaredContentLength ?? -1,
            "capturedWireBodyBytes": record.capturedWireBodyBytes,
            "decodedBodyBytes": requestData.count,
            "requestSHA256": record.requestSHA256,
            "protocolComplete": requestComplete,
            "clientAddress": record.clientAddress ?? "not captured",
            "remoteHost": record.remoteHost ?? "not captured",
            "remotePort": record.remotePort ?? 443,
            "routeCorrelation": record.remoteHost == nil
                ? "domain captured; socket endpoint unavailable"
                : "request body and socket endpoint observed in the same HTTPS flow"
        ])
        let routeMethod = record.remoteHost == nil
            ? "complete HTTPS request body; declared and captured lengths match"
            : "complete HTTPS request body + same-flow domain/IP/socket endpoint"
        var events = [GuardEvent(
            id: uuid("\(identity):request"), kind: isModelRoute ? "model" : "network",
            ruleId: isModelRoute ? "workbuddy_network_request_body" : "workbuddy_memory_recall_request",
            path: ("~/.workbuddy" as NSString).expandingTildeInPath, command: metadata,
            agent: "workbuddy", op: isModelRoute ? "network_prompt" : "memory_recall",
            severity: "info", ts: record.observedAt,
            action: requestComplete ? "captured_complete" : "captured_partial", sessionId: session,
            traceId: "workbuddy-http:\(identity)", turnId: identity,
            userIntent: intent, modelPrompt: String(decoding: requestData, as: UTF8.self),
            model: model, source: "agentsight:workbuddy-network-body",
            attributionConfidence: .confirmed,
            attributionMethod: requestComplete ? routeMethod
                                               : "HTTPS request body captured without a matching declared length",
            localAddress: record.clientAddress, remoteHost: record.remoteHost,
            remotePort: record.remotePort ?? 443, remoteDomain: record.host)]

        if let encoded = record.responseBodyBase64, let responseData = Data(base64Encoded: encoded) {
            let parsed = parseResponse(responseData)
            events.append(GuardEvent(
                id: uuid("\(identity):response"), kind: isModelRoute ? "model" : "network",
                ruleId: isModelRoute ? "workbuddy_network_response_body" : "workbuddy_memory_recall_response",
                path: ("~/.workbuddy" as NSString).expandingTildeInPath, command: nil,
                agent: "workbuddy", op: isModelRoute ? "network_response" : "memory_recall_response",
                severity: "info", ts: record.observedAt,
                action: record.responseComplete ? "received_complete" : "received_partial",
                sessionId: session, traceId: "workbuddy-http:\(identity)",
                turnId: identity, userIntent: intent,
                modelReasoning: isModelRoute ? parsed.reasoning : nil,
                modelResponse: isModelRoute ? parsed.text : String(decoding: responseData, as: UTF8.self),
                model: isModelRoute ? parsed.model ?? model : nil,
                inputTokens: parsed.inputTokens, outputTokens: parsed.outputTokens,
                cachedTokens: parsed.cachedTokens, reasoningTokens: parsed.reasoningTokens,
                source: "agentsight:workbuddy-network-body", attributionConfidence: .confirmed,
                attributionMethod: record.responseComplete ? "complete HTTPS response boundary verified"
                                                           : "HTTPS response body captured without a complete boundary",
                localAddress: record.clientAddress, remoteHost: record.remoteHost,
                remotePort: record.remotePort ?? 443, remoteDomain: record.host))
        }
        return events
    }

    private static func userIntent(in object: [String: Any]?) -> String? {
        guard let messages = object?["messages"] as? [[String: Any]],
              let user = messages.last(where: { $0["role"] as? String == "user" }) else { return nil }
        let text: String
        if let value = user["content"] as? String { text = value }
        else if let parts = user["content"] as? [[String: Any]] {
            text = parts.compactMap { $0["text"] as? String }.joined(separator: "\n")
        } else { return nil }
        if let range = text.range(of: #"(?s)<user_query>(.*?)</user_query>"#, options: .regularExpression) {
            return String(text[range]).replacingOccurrences(of: #"(?s)</?user_query>"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private struct ParsedResponse {
        var text: String?
        var reasoning: String?
        var model: String?
        var inputTokens: Int?
        var outputTokens: Int?
        var cachedTokens: Int?
        var reasoningTokens: Int?
    }

    private static func parseResponse(_ data: Data) -> ParsedResponse {
        var result = ParsedResponse()
        let text = String(decoding: data, as: UTF8.self)
        let payloads = text.split(whereSeparator: \.isNewline).compactMap { line -> [String: Any]? in
            let value = line.hasPrefix("data:") ? line.dropFirst(5).trimmingCharacters(in: .whitespaces) : String(line)
            guard value != "[DONE]", let bytes = value.data(using: .utf8) else { return nil }
            return try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
        }
        var output: [String] = [], reasoning: [String] = []
        for payload in payloads {
            result.model = payload["model"] as? String ?? result.model
            if let choices = payload["choices"] as? [[String: Any]] {
                for choice in choices {
                    let value = choice["delta"] as? [String: Any] ?? choice["message"] as? [String: Any] ?? [:]
                    if let chunk = value["content"] as? String { output.append(chunk) }
                    if let chunk = value["reasoning_content"] as? String ?? value["reasoning"] as? String {
                        reasoning.append(chunk)
                    }
                }
            }
            if let usage = payload["usage"] as? [String: Any] {
                result.inputTokens = int(usage["prompt_tokens"] ?? usage["input_tokens"])
                result.outputTokens = int(usage["completion_tokens"] ?? usage["output_tokens"])
                let prompt = usage["prompt_tokens_details"] as? [String: Any]
                let completion = usage["completion_tokens_details"] as? [String: Any]
                result.cachedTokens = int(prompt?["cached_tokens"] ?? usage["cached_tokens"])
                result.reasoningTokens = int(completion?["reasoning_tokens"] ?? usage["completion_thinking_tokens"])
            }
        }
        result.text = output.joined().nilIfBlank
        result.reasoning = reasoning.joined().nilIfBlank
        return result
    }

    private static func int(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let string = value as? String { return Int(string) }
        return nil
    }

    private static func json(_ object: [String: Any]) -> String {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    private static func uuid(_ value: String) -> UUID {
        let hex = SHA256.hash(data: Data(value.utf8)).hex
        let formatted = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))"
        return UUID(uuidString: formatted)!
    }
}

private extension SHA256.Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

private extension String {
    var nilIfBlank: String? { trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : self }
}
