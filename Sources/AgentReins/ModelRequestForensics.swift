import Foundation

struct ModelEconomicsReport: Codable, Equatable, Sendable {
    let requestCount: Int
    let cumulativeInputTokens: Int
    let cumulativeOutputTokens: Int
    let cumulativeReasoningTokens: Int
    let cumulativeCachedTokens: Int
    let firstRequestInputTokens: Int
    let lastRequestInputTokens: Int
    /// Input processed after the first request. This measures repeated request load,
    /// but does not claim that every token was byte-for-byte duplicated.
    let subsequentRequestInputLoad: Int
    let totalCostUSD: Double

    static func build(events: [GuardEvent]) -> ModelEconomicsReport? {
        let samples = events.filter { $0.inputTokens != nil }.sorted { $0.ts < $1.ts }
        guard let first = samples.first, let last = samples.last else { return nil }
        let inputs = samples.compactMap(\.inputTokens)
        return ModelEconomicsReport(
            requestCount: samples.count,
            cumulativeInputTokens: inputs.reduce(0, +),
            cumulativeOutputTokens: samples.compactMap(\.outputTokens).reduce(0, +),
            cumulativeReasoningTokens: samples.compactMap(\.reasoningTokens).reduce(0, +),
            cumulativeCachedTokens: samples.compactMap(\.cachedTokens).reduce(0, +),
            firstRequestInputTokens: first.inputTokens ?? 0,
            lastRequestInputTokens: last.inputTokens ?? 0,
            subsequentRequestInputLoad: inputs.dropFirst().reduce(0, +),
            totalCostUSD: samples.compactMap(\.costUSD).reduce(0, +))
    }
}

enum ContextExposureCategory: String, Codable, CaseIterable, Sendable {
    case userInstruction = "User instruction"
    case baseInstructions = "Base instructions"
    case developerInstructions = "Developer instructions"
    case environment = "Device and environment"
    case identity = "Identity and preferences"
    case memory = "Memory context"
    case skills = "Skills and agent policy"
    case project = "Project context"
    case connectors = "Connector status"
    case permissions = "Permissions and sandbox"
    case compaction = "Compacted conversation history"
    case attachments = "Images and attachments"
    case toolResults = "Tool results"
}

struct ContextExposureItem: Codable, Equatable, Sendable {
    let category: ContextExposureCategory
    let present: Bool
    let evidence: [String]
}

struct ContextExposureReport: Codable, Equatable, Sendable {
    let capturedPromptBytes: Int
    let capturedPromptCharacters: Int
    let items: [ContextExposureItem]

    static func build(events: [GuardEvent]) -> ContextExposureReport? {
        let prompts = events.compactMap(\.modelPrompt)
        guard !prompts.isEmpty else { return nil }
        let joined = prompts.joined(separator: "\n")
        let lower = joined.lowercased()
        let toolResultPresent = events.contains { $0.op == "result" && $0.modelResponse?.isEmpty == false }
        let paths = identityPaths(in: joined)
        let evidence: [(ContextExposureCategory, Bool, [String])] = [
            (.userInstruction, events.contains { $0.userIntent?.isEmpty == false }, []),
            (.baseInstructions, events.contains { $0.op == "base_instructions" }, []),
            (.developerInstructions, events.contains { $0.op == "developer_instructions" }, []),
            (.environment, lower.contains("<user_info") || lower.contains("os version:"),
             matches(["OS version", "Shell", "IDE theme", "Workspace folder"], in: lower)),
            (.identity, !paths.isEmpty || lower.contains("<identity_context"), paths),
            (.memory, lower.contains("memory") || lower.contains("user.md"),
             matches(["memory reminder", "USER.md"], in: lower)),
            (.skills, lower.contains("skill") || events.contains { $0.toolName?.lowercased().contains("skill") == true },
             matches(["skills", "SKILL.md", "agent policy"], in: lower)),
            (.project, lower.contains("<project_context") || lower.contains("<project_layout")
                || events.contains { $0.op == "project_context" },
             matches(["project context", "project layout"], in: lower)),
            (.connectors, lower.contains("connector-status") || lower.contains("servernames")
                || lower.contains("mcp"), matches(["connector-status", "serverNames", "MCP"], in: lower)),
            (.permissions, events.contains { $0.op == "turn_context" },
             events.filter { $0.op == "turn_context" }.compactMap(\.command)),
            (.compaction, events.contains { $0.op == "context_compaction" }, []),
            (.attachments, events.contains { $0.op == "attachment" }, []),
            (.toolResults, toolResultPresent, [])
        ]
        return ContextExposureReport(capturedPromptBytes: joined.utf8.count,
            capturedPromptCharacters: joined.count,
            items: evidence.map { ContextExposureItem(category: $0.0, present: $0.1, evidence: $0.2) })
    }

    private static func identityPaths(in text: String) -> [String] {
        let regex = try! NSRegularExpression(pattern: #"Path:\s+([^\r\n]+(?:SOUL|IDENTITY|USER)\.md)"#,
                                             options: .caseInsensitive)
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap {
            Range($0.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    private static func matches(_ labels: [String], in lower: String) -> [String] {
        labels.filter { lower.contains($0.lowercased()) }
    }
}

enum AgentTrafficClass: String, Codable, CaseIterable, Sendable {
    case modelProvider = "Model provider"
    case modelRelay = "Model relay"
    case agentControlPlane = "Agent control plane"
    case telemetry = "Telemetry"
    case toolExternal = "Tool external access"
    case unknown = "Unknown"
}

struct AgentTrafficDestination: Codable, Equatable, Sendable {
    let destination: String
    let classification: AgentTrafficClass
    let confidence: EvidenceConfidence
    let processIds: [Int32]
    let claimedModels: [String]?
    let identityStatus: String?
    let identityReason: String?
}

enum ForensicAssessmentKind: String, Codable, Sendable {
    case modelEconomics = "model_economics"
    case contextExposure = "context_exposure"
    case trafficSeparation = "traffic_separation"
}

struct ForensicAssessmentRecord: Equatable, Sendable {
    let assessmentId: String
    let sessionId: String
    let turnId: String
    let agent: String
    let kind: ForensicAssessmentKind
    let ruleVersion: Int
    let confidence: EvidenceConfidence
    let generatedAt: Date
    let evidenceEventIds: [String]
    let payload: Data

    static func build(events: [GuardEvent], generatedAt: Date = Date()) -> [ForensicAssessmentRecord] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let sessionContext = Dictionary(grouping: events.filter { $0.sessionId != nil && $0.turnId == nil },
                                        by: { $0.sessionId! })
        let grouped = Dictionary(grouping: events.filter { $0.sessionId != nil && $0.turnId != nil }) {
            "\($0.sessionId!):\($0.turnId!)"
        }
        return grouped.flatMap { _, turnRows -> [ForensicAssessmentRecord] in
            guard let first = turnRows.first, let session = first.sessionId, let turn = first.turnId else { return [] }
            let rows = (sessionContext[session] ?? []) + turnRows
            let evidenceIds = rows.map { $0.id.uuidString }.sorted()
            func record<T: Encodable>(_ kind: ForensicAssessmentKind, version: Int,
                                      confidence: EvidenceConfidence, value: T) -> ForensicAssessmentRecord? {
                guard let payload = try? encoder.encode(value) else { return nil }
                return ForensicAssessmentRecord(assessmentId: "\(session):\(turn):\(kind.rawValue):v\(version)",
                    sessionId: session, turnId: turn, agent: first.agent ?? "unknown", kind: kind,
                    ruleVersion: version, confidence: confidence, generatedAt: generatedAt,
                    evidenceEventIds: evidenceIds, payload: payload)
            }
            var result: [ForensicAssessmentRecord] = []
            if let report = ModelEconomicsReport.build(events: rows),
               let item = record(.modelEconomics, version: 1, confidence: .confirmed, value: report) { result.append(item) }
            if let report = ContextExposureReport.build(events: rows),
               let item = record(.contextExposure, version: 1, confidence: .confirmed, value: report) { result.append(item) }
            let traffic = AgentTrafficAnalyzer.build(events: rows)
            if !traffic.isEmpty {
                let confidence: EvidenceConfidence = traffic.allSatisfy { $0.confidence == .confirmed } ? .confirmed : .inferred
                if let item = record(.trafficSeparation, version: 1, confidence: confidence, value: traffic) { result.append(item) }
            }
            return result
        }
    }
}

enum AgentTrafficAnalyzer {
    static func build(events: [GuardEvent]) -> [AgentTrafficDestination] {
        let networkLike = events.filter { $0.remoteDomain != nil || $0.remoteHost != nil }
        let grouped = Dictionary(grouping: networkLike) { ($0.remoteDomain ?? $0.remoteHost!).lowercased() }
        return grouped.map { destination, rows in
            let classification = classify(destination: destination, events: rows, allEvents: events)
            let confidence: EvidenceConfidence = rows.allSatisfy { $0.attributionConfidence == .confirmed }
                ? .confirmed : (rows.contains { $0.attributionConfidence == .inferred } ? .inferred : .unknown)
            let claimedModels = Array(Set(events.compactMap(\.model).filter { !$0.isEmpty })).sorted()
            let identity = modelIdentity(destination: destination, classification: classification,
                                         claimedModels: claimedModels)
            return AgentTrafficDestination(destination: destination, classification: classification,
                confidence: confidence, processIds: Array(Set(rows.compactMap(\.processId))).sorted(),
                claimedModels: claimedModels.isEmpty ? nil : claimedModels,
                identityStatus: identity.status, identityReason: identity.reason)
        }.sorted { $0.destination < $1.destination }
    }

    private static func modelIdentity(destination: String, classification: AgentTrafficClass,
                                      claimedModels: [String]) -> (status: String, reason: String) {
        guard classification == .modelProvider || classification == .modelRelay else {
            return ("not_applicable", "This destination is not classified as a model route.")
        }
        let families = Set(claimedModels.compactMap(modelFamily))
        if classification == .modelRelay {
            return ("unverified", claimedModels.isEmpty
                ? "A relay was observed, but it did not expose a verifiable upstream model identity."
                : "The relay claims \(claimedModels.joined(separator: ", ")), but the encrypted upstream model cannot be independently verified and may be substituted.")
        }
        guard let provider = providerFamily(destination) else {
            return ("unverified", "The endpoint is recognized as model infrastructure, but its provider family was not resolved.")
        }
        guard !families.isEmpty else {
            return ("unverified", "The official \(provider) route was observed, but no model identity was reported for comparison.")
        }
        if families == Set([provider]) {
            return ("consistent", "The claimed model family is consistent with the observed official \(provider) endpoint.")
        }
        return ("mismatch", "Claimed model family \(families.sorted().joined(separator: ", ")) conflicts with the observed official \(provider) endpoint.")
    }

    private static func modelFamily(_ model: String) -> String? {
        let value = model.lowercased()
        if value == "auto" || value.contains("automatic") { return nil }
        if value.contains("deepseek") { return "deepseek" }
        if value.contains("claude") { return "anthropic" }
        if value.contains("gemini") || value.contains("gemma") { return "google" }
        if value.contains("gpt") || value.contains("openai") || value.range(of: #"\bo[134](?:-|\b)"#, options: .regularExpression) != nil { return "openai" }
        if value.contains("grok") { return "xai" }
        if value.contains("mistral") || value.contains("mixtral") { return "mistral" }
        if value.contains("qwen") { return "alibaba" }
        if value.contains("command-r") || value.contains("cohere") { return "cohere" }
        return nil
    }

    private static func providerFamily(_ destination: String) -> String? {
        if matches(destination, ["openai.com", "chatgpt.com", "openai.azure.com"]) { return "openai" }
        if matches(destination, ["anthropic.com", "claude.ai"]) { return "anthropic" }
        if matches(destination, ["deepseek.com"]) { return "deepseek" }
        if matches(destination, ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"]) { return "google" }
        if matches(destination, ["x.ai"]) { return "xai" }
        if matches(destination, ["mistral.ai"]) { return "mistral" }
        if matches(destination, ["dashscope.aliyuncs.com"]) { return "alibaba" }
        if matches(destination, ["cohere.com"]) { return "cohere" }
        return nil
    }

    private static func classify(destination: String, events: [GuardEvent], allEvents: [GuardEvent]) -> AgentTrafficClass {
        if matches(destination, ["copilot.tencent.com", "codebuddy.ai"]) { return .agentControlPlane }
        if matches(destination, ["tdid.m.qq.com", "sentry.io", "segment.io", "datadoghq.com"]) { return .telemetry }
        let assessment = NetworkDestinationAssessment.assess(domain: destination, host: destination)
        if assessment.kind == .modelRelay { return .modelRelay }
        if assessment.kind == .modelProvider { return .modelProvider }
        if events.contains(where: { $0.toolCallId != nil }) { return .toolExternal }
        let modelTurns = Set(allEvents.filter { $0.kind == "model" }.compactMap { event -> String? in
            guard let session = event.sessionId, let turn = event.turnId else { return nil }
            return "\(session):\(turn)"
        })
        let linkedToModelTurn = events.contains { event in
            guard let session = event.sessionId, let turn = event.turnId else { return event.kind == "model" }
            return modelTurns.contains("\(session):\(turn)")
        }
        // A destination carrying model-turn traffic that is neither a known
        // provider nor an explicit tool website is an unverified model route.
        // This catches private gateways and regional relays without pretending
        // that their advertised upstream model was independently observed.
        if linkedToModelTurn { return .modelRelay }
        return .unknown
    }

    private static func matches(_ value: String, _ suffixes: [String]) -> Bool {
        suffixes.contains { value == $0 || value.hasSuffix("." + $0) }
    }
}
