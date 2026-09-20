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
    let outputTokens: Int?
    let reasoningTokens: Int?
    let capturedPromptBytes: Int
    let exposedCategories: [ContextExposureCategory]
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
        let outputTokens = events.compactMap(\.outputTokens).max()
        let reasoningTokens = events.compactMap(\.reasoningTokens).max()
        let capturedBytes = exposure?.capturedPromptBytes ?? 0
        let modelRoutes = destinations.filter {
            $0.classification == .modelRelay || $0.classification == .modelProvider
        }

        let coverage: EgressCoverage
        if destinations.isEmpty {
            coverage = .missingRoute
        } else if capturedBytes == 0 {
            coverage = .metadataOnly
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
            inputTokens: inputTokens, outputTokens: outputTokens, reasoningTokens: reasoningTokens,
            capturedPromptBytes: capturedBytes,
            exposedCategories: exposure?.items.filter(\.present).map(\.category) ?? [],
            sensitiveFindings: sensitive, coverage: coverage, risk: risk,
            findings: findings, recommendedActions: actions,
            evidenceEventIds: rows.map { $0.id.uuidString }.sorted())
    }
}
