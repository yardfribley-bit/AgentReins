import Foundation
import CryptoKit

struct NetworkSecurityFinding: Codable, Equatable, Sendable {
    let rule: String
    let direction: String
    let severity: String
    let count: Int
    let characterOffset: Int
    let basis: String
    let status: String
    var label: String? = nil
    var recommendation: String? = nil
}
struct NetworkSecurityAudit: Codable, Equatable, Sendable {
    let version: String
    let findings: [NetworkSecurityFinding]
    let requestBytesInspected: Int
    let responseBytesInspected: Int?
    let scope: String
    let verdict: String
    var policyError: String? = nil
    var destinationHost: String? = nil
    var destinationPolicy: String? = nil
}

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
    let flowID: String?
    let captureStage: String?
    let transportError: String?
    let websiteParentFlow: String?
    let websiteURL: String?
    let securityAudit: NetworkSecurityAudit?
    let requestComplete: Bool?
    let requestHeaders: [[String]]?
    let responseHeaders: [[String]]?
    let responseSHA256: String?
    /// model, remote-tool, or local-target. Absent on captures made before this field.
    let accessHop: String?

    init(observedAt: Date, host: String, path: String, method: String, httpVersion: String,
         contentEncoding: String?, declaredContentLength: Int?, capturedWireBodyBytes: Int,
         requestBodyBase64: String, requestSHA256: String, responseStatus: Int?,
         responseComplete: Bool, responseBodyBase64: String?, clientAddress: String? = nil,
         remoteHost: String? = nil, remotePort: Int? = nil, flowID: String? = nil,
         captureStage: String? = nil, transportError: String? = nil,
         websiteParentFlow: String? = nil, websiteURL: String? = nil,
         requestComplete: Bool? = nil, requestHeaders: [[String]]? = nil,
         responseHeaders: [[String]]? = nil, responseSHA256: String? = nil, securityAudit: NetworkSecurityAudit? = nil,
         accessHop: String? = nil) {
        self.securityAudit = securityAudit
        self.requestComplete = requestComplete
        self.requestHeaders = requestHeaders
        self.responseHeaders = responseHeaders
        self.responseSHA256 = responseSHA256
        self.accessHop = accessHop
        self.websiteParentFlow = websiteParentFlow
        self.websiteURL = websiteURL
        self.flowID = flowID
        self.captureStage = captureStage
        self.transportError = transportError
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
    static func captureDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        let fraction = ISO8601DateFormatter(); fraction.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let whole = ISO8601DateFormatter(); whole.formatOptions = [.withInternetDateTime]
        decoder.dateDecodingStrategy = .custom { decoder in
            let text = try decoder.singleValueContainer().decode(String.self)
            guard let date = fraction.date(from: text) ?? whole.date(from: text) else {
                throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid capture timestamp"))
            }
            return date
        }
        return decoder
    }

    static func project(_ record: WorkBuddyNetworkCaptureRecord) -> [GuardEvent] {
        let website = record.websiteURL.flatMap(URL.init(string:))
        let isWebsite = record.websiteParentFlow?.isEmpty == false
            && ["http", "https"].contains(website?.scheme?.lowercased() ?? "")
            && website?.host?.lowercased() == record.host.lowercased()
            && website?.path == record.path
            && website?.user == nil && website?.password == nil
        let labeled = ["model", "remote-tool", "local-target"].contains(record.accessHop ?? "")
        let knownService = record.host.lowercased() == "copilot.tencent.com" &&
              (record.path.hasSuffix("/chat/completions") || record.path.contains("/agenttool/") || record.path.hasPrefix("/v2/videos/"))
        guard (isWebsite || labeled || knownService),
              let requestData = Data(base64Encoded: record.requestBodyBase64),
              SHA256.hash(data: requestData).hex == record.requestSHA256.lowercased() else { return [] }

        let requestComplete = (record.requestComplete ?? false) || (record.declaredContentLength.map { $0 == record.capturedWireBodyBytes } ?? (isWebsite && record.capturedWireBodyBytes == 0))
        let isModelRoute = !isWebsite && (record.accessHop == "model" || record.path.hasSuffix("/chat/completions"))
        let isMemoryRoute = !isWebsite && record.path == "/agenttool/v1/intent/recall"
        let requestObject = try? JSONSerialization.jsonObject(with: requestData) as? [String: Any]
        let intent = userIntent(in: requestObject)
        let model = requestObject?["model"] as? String
        let identity = record.flowID ?? String(record.requestSHA256.prefix(20))
        let session = "workbuddy-network:\(identity)"
        let metadata = json([
            "capture": requestComplete ? "complete HTTPS request body" : "HTTPS request body; completeness unconfirmed",
            "requestHeaders": record.requestHeaders ?? [],
            "responseHeaders": record.responseHeaders ?? [],
            "headersCaptured": record.requestHeaders != nil,
            "securityAudit": record.securityAudit.flatMap { try? JSONEncoder().encode($0) }.flatMap { try? JSONSerialization.jsonObject(with: $0) } ?? NSNull(),
            "responseSHA256": record.responseSHA256 ?? "not captured",
            "captureStage": record.captureStage ?? "legacy_response",
            "transportError": record.transportError ?? "none",
            "requestPath": record.path,
            "websiteURL": record.websiteURL ?? "not captured",
            "websiteParentFlow": record.websiteParentFlow ?? "not applicable",
            "websiteScope": isWebsite ? "exact URL requested through audited Agent WebFetch; redirects excluded" : "Agent service endpoint",
            "method": record.method,
            "responseStatus": record.responseStatus ?? -1,
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
        if let expected = record.responseSHA256, let encoded = record.responseBodyBase64 {
            guard let data = Data(base64Encoded: encoded), SHA256.hash(data: data).hex == expected.lowercased() else { return [] }
        }
        let routeMethod = record.remoteHost == nil
            ? "complete HTTPS request body; declared and captured lengths match"
            : "complete HTTPS request body + same-flow domain/IP/socket endpoint"
        var events = [GuardEvent(
            id: uuid("\(identity):request"), kind: isModelRoute ? "model" : "network",
            ruleId: isModelRoute ? "workbuddy_network_request_body" : (isMemoryRoute ? "workbuddy_memory_recall_request" : "workbuddy_tool_service_request"),
            path: ("~/.workbuddy" as NSString).expandingTildeInPath, command: metadata,
            agent: "workbuddy", op: isModelRoute ? "network_prompt" : (isMemoryRoute ? "memory_recall" : "tool_service_request"),
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

        if record.captureStage == "response" || record.captureStage == "error" {
            events = [GuardEvent(
                id: uuid("\(identity):transport:\(record.captureStage!)"), kind: "network",
                ruleId: "workbuddy_network_transport", path: record.path, command: metadata,
                agent: "workbuddy", op: record.captureStage == "error" ? "error" : "response",
                severity: record.captureStage == "error" ? "warning" : "info", ts: record.observedAt,
                action: record.captureStage == "error" ? "failed" : "received", sessionId: session,
                traceId: "workbuddy-http:\(identity)", turnId: identity, userIntent: intent,
                source: "agentsight:workbuddy-network-body", attributionConfidence: .confirmed,
                attributionMethod: "same HTTPS flow identifier", localAddress: record.clientAddress,
                remoteHost: record.remoteHost, remotePort: record.remotePort ?? 443, remoteDomain: record.host)]
        }
        if record.captureStage != "request", let encoded = record.responseBodyBase64, let responseData = Data(base64Encoded: encoded) {
            let parsed = parseResponse(responseData)
            events.append(GuardEvent(
                id: uuid("\(identity):response"), kind: isModelRoute ? "model" : "network",
                ruleId: isModelRoute ? "workbuddy_network_response_body" : (isMemoryRoute ? "workbuddy_memory_recall_response" : "workbuddy_tool_service_response"),
                path: ("~/.workbuddy" as NSString).expandingTildeInPath, command: metadata,
                agent: "workbuddy", op: isModelRoute ? "network_response" : (isMemoryRoute ? "memory_recall_response" : "tool_service_response"),
                severity: "info", ts: record.observedAt,
                action: record.responseComplete ? "received_complete" : "received_partial",
                sessionId: session, traceId: "workbuddy-http:\(identity)",
                turnId: identity, userIntent: intent,
                modelDecision: isModelRoute ? parsed.toolInstructions : nil,
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

    static func userIntent(in object: [String: Any]?) -> String? {
        guard let messages = object?["messages"] as? [[String: Any]] else { return nil }
        // Background tool notifications are protocol messages, not a new human task.
        for user in messages.reversed() where user["role"] as? String == "user" {
            let text: String
            if let value = user["content"] as? String { text = value }
            else if let parts = user["content"] as? [[String: Any]] {
                if parts.contains(where: { $0["type"] as? String == "tool_result" }) { continue }
                text = parts.compactMap { $0["text"] as? String }.joined(separator: "\n")
            } else { continue }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("<task-notification>") || trimmed.hasPrefix("<system-reminder>") { continue }
            if let intent = WorkBuddySight.cleanUserIntent(text), !intent.isEmpty { return intent }
        }
        return nil
    }

    private struct ParsedResponse {
        var text: String?
        var reasoning: String?
        var toolInstructions: String?
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
        var calls: [String: [String: String]] = [:]
        for payload in payloads {
            result.model = payload["model"] as? String ?? result.model
            if let choices = payload["choices"] as? [[String: Any]] {
                for (choiceIndex, choice) in choices.enumerated() {
                    let value = choice["delta"] as? [String: Any] ?? choice["message"] as? [String: Any] ?? [:]
                    for (position, call) in (value["tool_calls"] as? [[String: Any]] ?? []).enumerated() {
                        let key = "\(int(choice["index"]) ?? choiceIndex):\(int(call["index"]) ?? position)"
                        var combined = calls[key] ?? [:]
                        if let id = call["id"] as? String { combined["id"] = id }
                        let function = call["function"] as? [String: Any] ?? [:]
                        if let name = function["name"] as? String { combined["name", default: ""] += name }
                        if let arguments = function["arguments"] as? String { combined["arguments", default: ""] += arguments }
                        calls[key] = combined
                    }
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
        if !calls.isEmpty { result.toolInstructions = json(["tool_calls": calls.keys.sorted().compactMap { calls[$0] }]) }
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
