import Foundation
import CryptoKit

struct AgentOutboundRequestEvidence: Codable, Sendable {
    enum CaptureMode: String, Codable, Sendable {
        case completeHTTPSRequestBody
        case preEncryptionRequestBody
        case agentRecordedContext
        case contextFragment
    }

    enum Completeness: String, Codable, Sendable {
        case complete
        case partial
        case unknown
    }

    let id: String
    let eventID: String
    let capturedAt: Date
    let model: String?
    let destination: String?
    let traceID: String?
    let requestID: String?
    let userIntent: String?
    let body: String
    let bodyBytes: Int
    let bodySHA256: String
    let evidenceSource: String
    let captureMode: CaptureMode
    let completeness: Completeness
    let confidence: EvidenceConfidence

    static func build(events: [GuardEvent]) -> [AgentOutboundRequestEvidence] {
        events.compactMap { event -> AgentOutboundRequestEvidence? in
            guard let body = event.modelPrompt?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !body.isEmpty else { return nil }
            let source = event.source ?? "unknown"
            let mode: CaptureMode
            let completeness: Completeness
            if source.contains("workbuddy-network-body") {
                mode = .completeHTTPSRequestBody
                completeness = event.action.contains("complete") ? .complete : .partial
            } else if source.lowercased().contains("model-io") ||
                        event.attributionMethod?.lowercased().contains("pre-encryption") == true {
                mode = .preEncryptionRequestBody
                completeness = .complete
            } else if event.op == "prompt" || event.op == "network_prompt" {
                mode = .agentRecordedContext
                completeness = .unknown
            } else {
                mode = .contextFragment
                completeness = .partial
            }
            let bytes = Data(body.utf8)
            let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            return AgentOutboundRequestEvidence(
                id: "outbound:\(event.id.uuidString)", eventID: event.id.uuidString,
                capturedAt: event.ts, model: event.model,
                destination: event.remoteDomain ?? event.remoteHost,
                traceID: event.traceId, requestID: event.traceId,
                userIntent: event.userIntent, body: body, bodyBytes: bytes.count,
                bodySHA256: digest, evidenceSource: source, captureMode: mode,
                completeness: completeness,
                confidence: event.attributionConfidence ?? .unknown)
        }
    }
}

/// A portable, complete task document for inspection and future RAG indexing.
/// It contains both the normalized event stream and the source projection so
/// no evidence is lost while the canonical schema evolves.
struct AgentTaskSnapshot: Codable, Sendable {
    struct Identity: Codable, Sendable {
        let taskID: String
        let projectID: String
        let agentID: String
        let sessionID: String
        let turnID: String?
        let startedAt: Date?
        let endedAt: Date?
    }

    struct Capture: Codable, Sendable {
        let state: CaptureHealthState
        let sources: [AgentEventSource]
        let eventCount: Int
        let gaps: [CaptureGap]
        let missingCapabilities: [String]
    }

    struct Conversation: Codable, Sendable {
        let userInputs: [String]
        let modelResponses: [String]
        let reasoning: [String]
        let models: [String]
        let traceIDs: [String]
    }

    struct Activities: Codable, Sendable {
        let tools: [ToolCallLifecycleEvidence]
        let toolResults: [ToolOutputEvidence]
        let commands: [ToolCallLifecycleEvidence]
        let files: [FileActivityEvidence]
        let network: [NetworkActivityReference]
        let memory: [MemoryActivityEvidence]
    }

    struct Analysis: Codable, Sendable {
        let modelEconomics: ModelEconomicsReport?
        let contextExposure: ContextExposureReport?
        let relaySecurity: RelaySecurityAssessment?
        let egressAudit: AgentEgressAudit?
        let memoryCommits: [MemoryCommitEvidence]
        let codeFindings: [CodeFinding]
        let verification: [VerificationEvidence]
    }

    let schemaVersion: Int
    let revision: String
    let generatedAt: Date
    let task: Identity
    let capture: Capture
    let conversation: Conversation
    let metrics: AgentEventMetrics
    let outboundRequests: [AgentOutboundRequestEvidence]
    let activities: Activities
    let analysis: Analysis
    let events: [AgentEventEnvelope]
    let sourceEvents: [GuardEvent]
    let evidenceReferences: [String]

    static func build(session: AgentSessionSnapshot, turnID: String?) -> AgentTaskSnapshot {
        let scoped = session.events.filter { event in
            guard let turnID else { return true }
            if turnID == "unattributed" { return event.turnId == nil }
            return event.turnId == turnID || (event.turnId == nil && event.kind == "context")
        }.sorted { lhs, rhs in
            lhs.ts == rhs.ts ? lhs.id.uuidString < rhs.id.uuidString : lhs.ts < rhs.ts
        }
        let projectID = session.workspace ?? "unassigned"
        let canonical = LegacyGuardEventAdapter.project(scoped, projectID: projectID)
        let resolvedTurn = turnID == "unattributed" ? nil : turnID
        let taskID = canonical.first?.effectiveTaskID ?? "\(session.id):\(resolvedTurn ?? "session")"
        let health = AgentCaptureHealth.evaluate(canonical)
        let tools = canonical.compactMap { event -> ToolCallLifecycleEvidence? in
            if case let .toolCall(value) = event.payload { return value }
            return nil
        }
        let toolResults = canonical.compactMap { event -> ToolOutputEvidence? in
            if case let .toolOutput(value) = event.payload { return value }
            return nil
        }
        let files = canonical.compactMap { event -> FileActivityEvidence? in
            if case let .fileActivity(value) = event.payload { return value }
            return nil
        }
        let network = canonical.compactMap { event -> NetworkActivityReference? in
            if case let .networkActivity(value) = event.payload { return value }
            return nil
        }
        let memory = canonical.compactMap { event -> MemoryActivityEvidence? in
            if case let .memoryActivity(value) = event.payload { return value }
            return nil
        }
        let verification = canonical.compactMap { event -> VerificationEvidence? in
            if case let .verification(value) = event.payload { return value }
            return nil
        }
        let egress = AgentEgressAudit.build(session: session).first { audit in
            resolvedTurn.map { audit.turnId == $0 } ?? true
        }
        let evidenceReferences = Array(Set(
            canonical.map(\.id) + scoped.map { $0.id.uuidString }
        )).sorted()
        let revisionSeed = evidenceReferences.joined(separator: "|")
        let revision = SHA256.hash(data: Data(revisionSeed.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return AgentTaskSnapshot(
            schemaVersion: 1, revision: revision, generatedAt: Date(),
            task: Identity(taskID: taskID, projectID: projectID,
                           agentID: session.agent, sessionID: session.id,
                           turnID: resolvedTurn, startedAt: scoped.first?.ts,
                           endedAt: scoped.last?.ts),
            capture: Capture(state: health.state,
                sources: Array(Set(canonical.map(\.source))).sorted { $0.rawValue < $1.rawValue },
                eventCount: health.eventCount, gaps: health.gaps,
                missingCapabilities: health.missingCapabilities),
            conversation: Conversation(
                userInputs: unique(scoped.compactMap(\.userIntent)),
                modelResponses: unique(scoped.compactMap(\.modelResponse)),
                reasoning: unique(scoped.compactMap(\.modelReasoning)),
                models: unique(scoped.compactMap(\.model)),
                traceIDs: unique(scoped.compactMap(\.traceId))),
            metrics: AgentEventMetrics.build(events: canonical),
            outboundRequests: AgentOutboundRequestEvidence.build(events: scoped),
            activities: Activities(
                tools: tools, toolResults: toolResults,
                commands: tools.filter { isCommandTool($0.toolName) },
                files: files, network: network, memory: memory),
            analysis: Analysis(
                modelEconomics: ModelEconomicsReport.build(events: scoped),
                contextExposure: ContextExposureReport.build(events: scoped),
                relaySecurity: RelaySecurityAssessment.build(events: scoped),
                egressAudit: egress,
                memoryCommits: MemoryCommitEvidence.build(events: scoped),
                codeFindings: scoped.compactMap(\.codeFindings).flatMap { $0 },
                verification: verification),
            events: canonical, sourceEvents: scoped,
            evidenceReferences: evidenceReferences)
    }

    func prettyJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }

    private static func isCommandTool(_ name: String) -> Bool {
        let value = name.lowercased()
        return value.contains("shell") || value.contains("terminal") ||
            value.contains("command") || value.contains("exec") ||
            value == "bash" || value == "powershell"
    }
}

/// Compatibility name for callers while the UI migrates to the platform
/// snapshot terminology.
typealias AgentTaskJSONExport = AgentTaskSnapshot
