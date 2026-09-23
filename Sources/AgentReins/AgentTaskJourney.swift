import Foundation

/// A request-centered projection. Ordering is observed, not a claim that
/// temporal proximity alone establishes causality.
struct AgentTaskJourney: Codable, Sendable {
    struct RequestSection: Codable, Sendable {
        let id: String
        let category: String
        let content: String
        let byteCount: Int
    }

    struct ToolStep: Codable, Sendable {
        let call: ToolCallLifecycleEvidence
        let result: ToolOutputEvidence?
        let fileActivities: [FileActivityEvidence]
        let durationMS: Double?
    }

    struct Round: Codable, Sendable {
        let ordinal: Int
        let requestEventID: String
        let requestedAt: Date
        let model: String?
        let evidenceSource: String
        let captureMode: AgentOutboundRequestEvidence.CaptureMode
        let completeness: AgentOutboundRequestEvidence.Completeness
        let bodyBytes: Int
        let requestSections: [RequestSection]
        let response: AgentModelResponseEvidence?
        let responseCorrelation: String
        let toolSteps: [ToolStep]
        let requestToResponseMS: Double?
    }

    let rounds: [Round]
    let unassignedResponses: [AgentModelResponseEvidence]
    let unassignedToolSteps: [ToolStep]

    static func build(requests: [AgentOutboundRequestEvidence],
                      responses: [AgentModelResponseEvidence],
                      tools: [ToolCallLifecycleEvidence],
                      toolResults: [ToolOutputEvidence],
                      files: [FileActivityEvidence]) -> Self {
        let selected = preferredRequests(requests)
        let orderedResponses = responses.sorted { $0.receivedAt < $1.receivedAt }
        let results = Dictionary(toolResults.map { ($0.callID, $0) },
                                 uniquingKeysWith: { _, latest in latest })
        func toolStep(_ call: ToolCallLifecycleEvidence) -> ToolStep {
            let duration = call.startedAt.flatMap { start in
                call.completedAt.map { max(0, $0.timeIntervalSince(start) * 1_000) }
            }
            return ToolStep(call: call, result: results[call.callID],
                fileActivities: files.filter { $0.toolCallID == call.callID },
                durationMS: duration)
        }
        let orderedTools = tools.sorted { ($0.startedAt ?? .distantPast) < ($1.startedAt ?? .distantPast) }
        var usedResponses = Set<String>()
        var usedTools = Set<String>()
        let rounds = selected.enumerated().map { index, request -> Round in
            let nextAt = index + 1 < selected.count ? selected[index + 1].capturedAt : Date.distantFuture
            let exact = orderedResponses.first { response in
                !usedResponses.contains(response.eventID) &&
                    request.traceID != nil && response.traceID == request.traceID &&
                    response.receivedAt >= request.capturedAt.addingTimeInterval(-1) &&
                    response.receivedAt < nextAt
            }
            let temporal = orderedResponses.first { response in
                !usedResponses.contains(response.eventID) &&
                    response.receivedAt >= request.capturedAt.addingTimeInterval(-1) &&
                    response.receivedAt < nextAt
            }
            let response = exact ?? temporal
            if let response { usedResponses.insert(response.eventID) }
            let associatedTools = orderedTools.filter { call in
                guard let started = call.startedAt else { return false }
                return started >= request.capturedAt.addingTimeInterval(-1) && started < nextAt
            }
            associatedTools.forEach { usedTools.insert($0.callID) }
            return Round(ordinal: index + 1, requestEventID: request.eventID,
                requestedAt: request.capturedAt, model: request.model,
                evidenceSource: request.evidenceSource, captureMode: request.captureMode,
                completeness: request.completeness, bodyBytes: request.bodyBytes,
                requestSections: sections(in: request), response: response,
                responseCorrelation: exact != nil ? "exactTraceID" : response != nil ? "temporalSequence" : "notObserved",
                toolSteps: associatedTools.map(toolStep),
                requestToResponseMS: response.map {
                    max(0, $0.receivedAt.timeIntervalSince(request.capturedAt) * 1_000)
                })
        }
        return Self(rounds: rounds,
            unassignedResponses: orderedResponses.filter { !usedResponses.contains($0.eventID) },
            unassignedToolSteps: orderedTools.filter { !usedTools.contains($0.callID) }.map(toolStep))
    }

    private static func preferredRequests(_ requests: [AgentOutboundRequestEvidence])
        -> [AgentOutboundRequestEvidence] {
        func priority(_ request: AgentOutboundRequestEvidence) -> Int {
            switch request.captureMode {
            case .completeHTTPSRequestBody: return 0
            case .preEncryptionRequestBody: return 1
            case .agentRecordedContext where request.evidenceSource == "workbuddy-local-trace": return 2
            case .preEncryptionRequestProjection: return 3
            case .agentRecordedContext: return 4
            case .contextFragment: return 5
            }
        }
        var chosen: [AgentOutboundRequestEvidence] = []
        for request in requests.sorted(by: { priority($0) == priority($1)
            ? $0.capturedAt < $1.capturedAt : priority($0) < priority($1) }) {
            let duplicate = chosen.contains { earlier in
                priority(earlier) < priority(request) &&
                    abs(earlier.capturedAt.timeIntervalSince(request.capturedAt)) <= 12
            }
            if !duplicate { chosen.append(request) }
        }
        return chosen.sorted { $0.capturedAt < $1.capturedAt }
    }

    private static func sections(in request: AgentOutboundRequestEvidence) -> [RequestSection] {
        var sections: [RequestSection] = []
        func append(_ category: String, _ value: String) {
            guard !value.isEmpty else { return }
            sections.append(RequestSection(id: "\(request.eventID):\(sections.count)",
                category: category, content: value, byteCount: value.utf8.count))
        }
        if let data = request.body.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let messages = object["messages"] as? [[String: Any]] {
                for message in messages {
                    let role = message["role"] as? String ?? "unknown"
                    if let value = message["content"] as? String { append("message.\(role)", value) }
                    else if let value = message["content"],
                            let encoded = try? JSONSerialization.data(withJSONObject: value,
                                options: [.fragmentsAllowed, .sortedKeys]) {
                        append("message.\(role)", String(decoding: encoded, as: UTF8.self))
                    }
                }
            }
            if let tools = object["tools"],
               let encoded = try? JSONSerialization.data(withJSONObject: tools,
                   options: [.fragmentsAllowed, .sortedKeys]) {
                append("toolDefinitions", String(decoding: encoded, as: UTF8.self))
            }
        }
        for tag in ["user_query", "memory_system", "identity_context", "memory_context",
                    "memory_and_skills_reminder", "project_context", "product_identity",
                    "tone_and_style", "system-reminder"] {
            let escaped = NSRegularExpression.escapedPattern(for: tag)
            guard let regex = try? NSRegularExpression(
                pattern: "<\(escaped)(?:\\s[^>]*)?>[\\s\\S]*?</\(escaped)>",
                options: [.caseInsensitive]) else { continue }
            for match in regex.matches(in: request.body,
                range: NSRange(request.body.startIndex..., in: request.body)) {
                if let range = Range(match.range, in: request.body) {
                    append(tag, String(request.body[range]))
                }
            }
        }
        return sections
    }
}
