import Foundation

enum EgressRiskLevel: String, Codable, CaseIterable, Sendable {
    case critical, high, medium, low, unknown

    var rank: Int {
        switch self {
        case .critical: return 5
        case .high: return 4
        case .medium: return 3
        case .low: return 2
        case .unknown: return 1
        }
    }
}

enum EgressCoverage: String, Codable, Sendable {
    case complete = "Complete"
    case partial = "Partial"
    case metadataOnly = "Metadata only"
    case missingRoute = "Route not captured"
}

enum EgressDataCategory: String, Codable, CaseIterable, Sendable {
    case userInput
    case systemInstructions
    case developerInstructions
    case identityAndPreferences
    case memory
    case agentRules
    case projectContent
    case sourceCode
    case toolCalls
    case toolResults
    case deviceEnvironment
    case connectors
    case permissions
    case conversationHistory
    case attachments
    case otherCaptured
    case notCaptured
}

struct EgressDataEvidence: Identifiable, Codable, Equatable, Sendable {
    let id: String
    let sequence: Int
    let category: EgressDataCategory
    let source: String
    let content: String
    let capturedBytes: Int
}

struct EgressDataClassification: Identifiable, Codable, Equatable, Sendable {
    var id: String { category.rawValue }
    let category: EgressDataCategory
    let capturedBytes: Int
    let estimatedTokens: Int
    let evidenceCount: Int
    let sources: [String]
    let isEstimated: Bool
    let evidence: [EgressDataEvidence]
}

struct CapturedModelReasoning: Identifiable, Codable, Equatable, Sendable {
    let id: String
    let source: String
    let content: String
    let occurredAt: Date
    let captureDetail: String?
}

/// A user-facing, turn-scoped answer to: what did this Agent send, where did it
/// go, and can AgentReins prove that the route and payload were safe?
struct AgentEgressAudit: Identifiable, Codable, Equatable, Sendable {
    let id: String
    let sessionId: String
    let turnId: String
    let agent: String
    let workspace: String?
    let userIntent: String?
    let occurredAt: Date
    let destinations: [AgentTrafficDestination]
    let claimedModels: [String]
    let inputTokens: Int?
    let cachedTokens: Int?
    let outputTokens: Int?
    let reasoningTokens: Int?
    let capturedPromptBytes: Int
    let exposedCategories: [ContextExposureCategory]
    let dataClassifications: [EgressDataClassification]
    let capturedModelReasoning: [CapturedModelReasoning]
    let sensitiveFindings: [SensitiveExposureFinding]
    let coverage: EgressCoverage
    let risk: EgressRiskLevel
    let findings: [String]
    let recommendedActions: [String]
    let evidenceEventIds: [String]

    var primaryDestination: String {
        destinations.first(where: { $0.classification == .modelRelay || $0.classification == .modelProvider })?.destination
            ?? destinations.first?.destination
            ?? "Not captured"
    }

    var routeIdentity: String {
        destinations.first(where: { $0.classification == .modelRelay || $0.classification == .modelProvider })?.identityStatus
            ?? "unverified"
    }

    static func build(sessions: [AgentSessionSnapshot]) -> [AgentEgressAudit] {
        sessions.flatMap(build(session:)).sorted { lhs, rhs in
            if lhs.risk.rank != rhs.risk.rank { return lhs.risk.rank > rhs.risk.rank }
            return lhs.occurredAt > rhs.occurredAt
        }
    }

    static func build(session: AgentSessionSnapshot) -> [AgentEgressAudit] {
        let sessionContext = session.events.filter { $0.turnId == nil }
        let turnRows = Dictionary(grouping: session.events.filter { $0.turnId != nil }) { $0.turnId! }
        return turnRows.compactMap { turnId, rows in
            build(session: session, turnId: turnId, events: sessionContext + rows)
        }
    }

    private static func build(session: AgentSessionSnapshot, turnId: String,
                              events: [GuardEvent]) -> AgentEgressAudit? {
        let hasModelRequest = events.contains { $0.inputTokens != nil || $0.modelPrompt?.isEmpty == false }
        let destinations = AgentTrafficAnalyzer.build(events: events)
        guard hasModelRequest || !destinations.isEmpty else { return nil }

        let exposure = ContextExposureReport.build(events: events)
        let sensitive = SensitiveContextExposure.scan(events: events)
        let relay = RelaySecurityAssessment.build(events: events)
        let inputTokens = events.compactMap(\.inputTokens).max()
        let cachedTokens = events.compactMap(\.cachedTokens).max()
        let outputTokens = events.compactMap(\.outputTokens).max()
        let reasoningTokens = events.compactMap(\.reasoningTokens).max()
        let capturedBytes = exposure?.capturedPromptBytes ?? 0
        let classifications = classify(events: events, inputTokens: inputTokens)
        let capturedReasoning = reasoningEvidence(events: events)
        let modelRoutes = destinations.filter {
            $0.classification == .modelRelay || $0.classification == .modelProvider
        }
        let verifiedNetworkBody = events.contains {
            $0.source == "agentsight:workbuddy-network-body" &&
                $0.op == "network_prompt" && $0.action == "captured_complete"
        }

        let coverage: EgressCoverage
        if destinations.isEmpty {
            coverage = .missingRoute
        } else if capturedBytes == 0 {
            coverage = .metadataOnly
        } else if verifiedNetworkBody {
            coverage = .complete
        } else if let inputTokens, inputTokens > 0,
                  capturedBytes < inputTokens * 2 {
            // This is intentionally conservative. Tokens do not have a fixed byte
            // width, so captured bytes cannot prove full payload coverage.
            coverage = .partial
        } else {
            coverage = .complete
        }

        var findings = relay?.findings ?? []
        if destinations.isEmpty {
            findings.append("A model request was recorded, but no request-level network route was captured")
        }
        if coverage == .metadataOnly {
            findings.append("Transport metadata was captured without the outbound request body")
        } else if coverage == .partial {
            findings.append("Only part of the reported model input is represented by captured prompt evidence")
        }
        if modelRoutes.isEmpty, hasModelRequest, !destinations.isEmpty {
            findings.append("Network activity exists, but no destination is proven to be the model route")
        }
        findings = Array(Set(findings)).sorted()

        let hasRelay = modelRoutes.contains { $0.classification == .modelRelay }
        let identityProblem = modelRoutes.contains { $0.identityStatus == "mismatch" || $0.identityStatus == "unverified" }
        let risk: EgressRiskLevel
        if !sensitive.isEmpty && (hasRelay || identityProblem) {
            risk = .critical
        } else if !sensitive.isEmpty || hasRelay {
            risk = .high
        } else if coverage != .complete || identityProblem {
            risk = .medium
        } else if destinations.isEmpty {
            risk = .unknown
        } else {
            risk = .low
        }

        var actions: [String] = []
        if !sensitive.isEmpty { actions.append("Review and rotate exposed credentials; remove unnecessary secrets from model context") }
        if hasRelay || identityProblem { actions.append("Verify the relay operator, retention policy, region, and upstream model identity") }
        if coverage != .complete { actions.append("Treat the verdict as incomplete until payload and request-to-socket correlation are captured") }
        if actions.isEmpty { actions.append("Retain the evidence and continue real-time monitoring") }

        let rows = events.filter { $0.turnId == turnId || $0.turnId == nil }
        return AgentEgressAudit(
            id: "\(session.id):\(turnId)", sessionId: session.id, turnId: turnId,
            agent: session.agentDisplayName, workspace: session.workspace,
            userIntent: rows.compactMap(\.userIntent).last,
            occurredAt: rows.map(\.ts).max() ?? session.lastActivityAt,
            destinations: destinations,
            claimedModels: Array(Set(rows.compactMap(\.model).filter { !$0.isEmpty })).sorted(),
            inputTokens: inputTokens, cachedTokens: cachedTokens,
            outputTokens: outputTokens, reasoningTokens: reasoningTokens,
            capturedPromptBytes: capturedBytes,
            exposedCategories: exposure?.items.filter(\.present).map(\.category) ?? [],
            dataClassifications: classifications,
            capturedModelReasoning: capturedReasoning,
            sensitiveFindings: sensitive, coverage: coverage, risk: risk,
            findings: findings, recommendedActions: actions,
            evidenceEventIds: rows.map { $0.id.uuidString }.sorted())
    }

    private static func reasoningEvidence(events: [GuardEvent]) -> [CapturedModelReasoning] {
        var seen: Set<String> = []
        return events.sorted { $0.ts < $1.ts }.compactMap { event in
            guard let content = event.modelReasoning?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !content.isEmpty, seen.insert(content).inserted else { return nil }
            return CapturedModelReasoning(
                id: event.id.uuidString,
                source: event.source ?? event.agent ?? "local Agent record",
                content: content,
                occurredAt: event.ts,
                captureDetail: event.command)
        }
    }

    private struct ClassifiedFragment {
        let category: EgressDataCategory
        let bytes: Int
        let source: String
        let content: String
        let eventID: String
    }

    private static func classify(events: [GuardEvent], inputTokens: Int?) -> [EgressDataClassification] {
        var fragments: [ClassifiedFragment] = []
        let hasNetworkBody = events.contains {
            $0.source == "agentsight:workbuddy-network-body" && $0.op == "network_prompt"
        }
        for event in events {
            if let prompt = event.modelPrompt, !prompt.isEmpty,
               !hasNetworkBody || event.source == "agentsight:workbuddy-network-body" {
                fragments.append(contentsOf: classifyPrompt(prompt, event: event))
            }
            if event.op == "turn_context", let command = event.command, !command.isEmpty {
                fragments.append(fragment(.permissions, command, event))
            }
            if event.op == "context_compaction", let command = event.command, !command.isEmpty {
                fragments.append(fragment(.conversationHistory, command, event))
            }
            if event.kind == "tool", event.op == "result",
               let result = event.modelResponse, !result.isEmpty,
               events.contains(where: { $0.inputTokens != nil && $0.ts > event.ts }) {
                fragments.append(fragment(isSourceCode(event) ? .sourceCode : .toolResults, result, event))
            }
            if event.kind == "tool", ["call", "exec", "requested"].contains(event.op),
               let command = event.command, !command.isEmpty,
               events.contains(where: { $0.inputTokens != nil && $0.ts > event.ts }) {
                fragments.append(fragment(.toolCalls, command, event))
            }
        }

        let sequenced = fragments.enumerated().map { (sequence: $0.offset, fragment: $0.element) }
        let grouped = Dictionary(grouping: sequenced, by: { $0.fragment.category })
        var rows = grouped.map { category, values in
            let bytes = values.reduce(0) { $0 + $1.fragment.bytes }
            return EgressDataClassification(category: category, capturedBytes: bytes,
                estimatedTokens: estimatedTokens(forBytes: bytes), evidenceCount: values.count,
                sources: Array(Set(values.map { $0.fragment.source })).sorted(), isEstimated: true,
                evidence: values.enumerated().map { index, value in
                    EgressDataEvidence(id: "\(value.fragment.eventID):\(category.rawValue):\(index)",
                        sequence: value.sequence, category: category, source: value.fragment.source,
                        content: value.fragment.content, capturedBytes: value.fragment.bytes)
                })
        }
        if rows.isEmpty, let inputTokens, inputTokens > 0 {
            rows.append(EgressDataClassification(category: .notCaptured, capturedBytes: 0,
                estimatedTokens: inputTokens, evidenceCount: 0,
                sources: ["provider reported input without locally captured content"], isEstimated: true,
                evidence: []))
        }
        return rows.sorted { classificationOrder($0.category) < classificationOrder($1.category) }
    }

    private static func classifyPrompt(_ text: String, event: GuardEvent) -> [ClassifiedFragment] {
        if event.source == "agentsight:workbuddy-network-body",
           let data = text.data(using: .utf8),
           let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return classifyNetworkRequest(request, event: event)
        }
        switch event.op {
        case "base_instructions": return [fragment(.systemInstructions, text, event)]
        case "developer_instructions": return [fragment(.developerInstructions, text, event)]
        case "attachment": return [fragment(.attachments, text, event)]
        case "context_compaction": return [fragment(.conversationHistory, text, event)]
        case "project_context": return [fragment(.projectContent, text, event)]
        default: break
        }

        return classifyTaggedText(text, defaultCategory: event.op == "prompt" || event.userIntent != nil
                                  ? .userInput : .otherCaptured, event: event)
    }

    private static func classifyNetworkRequest(_ request: [String: Any], event: GuardEvent) -> [ClassifiedFragment] {
        let messages = request["messages"] as? [[String: Any]] ?? []
        let lastUser = messages.lastIndex { $0["role"] as? String == "user" }
        var output: [ClassifiedFragment] = []
        for (index, message) in messages.enumerated() {
            let role = (message["role"] as? String)?.lowercased() ?? "unknown"
            guard let content = readableJSONContent(message["content"]), !content.isEmpty else { continue }
            let category: EgressDataCategory
            switch role {
            case "system": category = .systemInstructions
            case "developer": category = .developerInstructions
            case "tool", "function": category = .toolResults
            case "user" where index == lastUser: category = .userInput
            default: category = .conversationHistory
            }
            output.append(contentsOf: classifyTaggedText(content, defaultCategory: category, event: event))
        }
        if let tools = request["tools"], let content = prettyJSON(tools) {
            output.append(fragment(.toolCalls, content, event))
        }
        let metadata = request.filter { !["messages", "tools"].contains($0.key) }
        if !metadata.isEmpty, let content = prettyJSON(metadata) {
            output.append(fragment(.otherCaptured, content, event))
        }
        return output
    }

    private static func readableJSONContent(_ value: Any?) -> String? {
        if let text = value as? String { return text }
        guard let parts = value as? [[String: Any]] else { return value.flatMap(prettyJSON) }
        return parts.compactMap { part in
            if let text = part["text"] as? String { return text }
            return prettyJSON(part)
        }.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func prettyJSON(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private static func classifyTaggedText(_ text: String, defaultCategory: EgressDataCategory,
                                           event: GuardEvent) -> [ClassifiedFragment] {

        let tagged: [(EgressDataCategory, [String])] = [
            (.identityAndPreferences, ["identity_context", "user_profile", "user_preferences"]),
            (.memory, ["memory", "memory_context"]),
            (.agentRules, ["skills_instructions", "skill", "agent_policy"]),
            (.projectContent, ["project_context", "project_layout", "workspace_context", "code_context"]),
            (.deviceEnvironment, ["environment_context", "user_info", "device_context"]),
            (.connectors, ["connector-status", "connectors", "mcp_servers"]),
            (.permissions, ["permissions", "sandbox_context"]),
            (.conversationHistory, ["conversation_history", "summary", "compacted_context"]),
            (.attachments, ["attachments", "images"]),
            (.developerInstructions, ["developer_instructions", "developer"]),
            (.systemInstructions, ["system_instructions", "system"])
        ]
        var claimed = IndexSet()
        var output: [ClassifiedFragment] = []
        let nsText = text as NSString
        let lowercased = text.lowercased()
        for (category, tags) in tagged {
            for tag in tags {
                guard lowercased.contains("<\(tag.lowercased())") else { continue }
                let pattern = "<\\Q\(tag)\\E(?:\\s[^>]*)?>[\\s\\S]*?</\\Q\(tag)\\E>"
                guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { continue }
                let full = NSRange(text.startIndex..., in: text)
                for match in regex.matches(in: text, range: full) where match.range.length > 0 {
                    let indexes = IndexSet(integersIn: match.range.location..<(match.range.location + match.range.length))
                    guard indexes.intersection(claimed).isEmpty else { continue }
                    claimed.formUnion(indexes)
                    let content = nsText.substring(with: match.range)
                    output.append(ClassifiedFragment(category: category, bytes: content.utf8.count,
                        source: sourceLabel(event), content: content, eventID: event.id.uuidString))
                }
            }
        }
        var remainingParts: [String] = []
        var start = 0
        for range in claimed.rangeView {
            if start < range.lowerBound {
                remainingParts.append(nsText.substring(with: NSRange(location: start, length: range.lowerBound - start)))
            }
            start = range.upperBound
        }
        if start < nsText.length {
            remainingParts.append(nsText.substring(from: start))
        }
        let remainingContent = remainingParts.joined(separator: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if !remainingContent.isEmpty {
            output.append(ClassifiedFragment(category: defaultCategory, bytes: remainingContent.utf8.count,
                source: sourceLabel(event), content: remainingContent, eventID: event.id.uuidString))
        }
        return output
    }

    private static func fragment(_ category: EgressDataCategory, _ text: String,
                                 _ event: GuardEvent) -> ClassifiedFragment {
        ClassifiedFragment(category: category, bytes: text.utf8.count, source: sourceLabel(event),
            content: text, eventID: event.id.uuidString)
    }

    private static func isSourceCode(_ event: GuardEvent) -> Bool {
        let candidate = event.relatedPath ?? event.path
        let codeExtensions = ["swift", "py", "js", "ts", "tsx", "jsx", "java", "kt", "go", "rs",
                              "c", "h", "cpp", "hpp", "cs", "rb", "php", "sh", "sql", "html", "css"]
        return codeExtensions.contains(URL(fileURLWithPath: candidate).pathExtension.lowercased())
            || event.codeFindings?.isEmpty == false
    }

    private static func sourceLabel(_ event: GuardEvent) -> String {
        event.toolName ?? event.source ?? event.op
    }

    private static func estimatedTokens(forBytes bytes: Int) -> Int {
        guard bytes > 0 else { return 0 }
        return Int(ceil(Double(bytes) / 4.0))
    }

    private static func classificationOrder(_ category: EgressDataCategory) -> Int {
        EgressDataCategory.allCases.firstIndex(of: category) ?? .max
    }
}
