import Foundation
import CryptoKit

struct AgentOutboundRequestEvidence: Codable, Sendable {
    enum CaptureMode: String, Codable, Sendable {
        case completeHTTPSRequestBody
        case preEncryptionRequestBody
        case preEncryptionRequestProjection
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
    let sourceLocator: String?
    let captureMode: CaptureMode
    let completeness: Completeness
    let confidence: EvidenceConfidence

    static func build(events: [GuardEvent]) -> [AgentOutboundRequestEvidence] {
        events.compactMap { event -> AgentOutboundRequestEvidence? in
            guard event.kind == "model",
                  let body = event.modelPrompt?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !body.isEmpty else { return nil }
            let source = event.source ?? "unknown"
            let mode: CaptureMode
            let completeness: Completeness
            if source.contains("workbuddy-network-body") {
                mode = .completeHTTPSRequestBody
                completeness = event.action.contains("complete") ? .complete : .partial
            } else if source.lowercased().contains("zcode-model-io") {
                mode = .preEncryptionRequestProjection
                completeness = .partial
            } else if event.attributionMethod?.lowercased().contains("pre-encryption") == true {
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
                bodySHA256: digest, evidenceSource: source,
                sourceLocator: nil, captureMode: mode,
                completeness: completeness,
                confidence: event.attributionConfidence ?? .unknown)
        }
    }
}

struct AgentModelResponseEvidence: Codable, Sendable {
    let eventID: String
    let receivedAt: Date
    let traceID: String?
    let model: String?
    let content: String
    let recordedReasoning: String?
    let evidenceSource: String
}

struct AgentExternalRequestEvidence: Codable, Sendable {
    let eventID: String
    let capturedAt: Date
    let requestID: String?
    let destination: String?
    let requestPath: String?
    let purpose: String
    let requestBody: String
    let responseBody: String?
    let completeness: AgentOutboundRequestEvidence.Completeness
    let evidenceSource: String

    static func build(events: [GuardEvent]) -> [Self] {
        let responses = Dictionary(grouping: events.filter { $0.op == "memory_recall_response" }) {
            $0.traceId ?? $0.sessionId ?? $0.id.uuidString
        }
        return events.compactMap { event in
            guard event.kind == "network", event.op == "memory_recall",
                  let body = event.modelPrompt else { return nil }
            let metadata = event.command.flatMap { $0.data(using: .utf8) }
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let response = responses[event.traceId ?? event.sessionId ?? ""]?.first
            return Self(eventID: event.id.uuidString, capturedAt: event.ts,
                requestID: event.traceId, destination: event.remoteDomain ?? event.remoteHost,
                requestPath: metadata?["requestPath"] as? String,
                purpose: "agentMemoryRecall", requestBody: body,
                responseBody: response?.modelResponse,
                completeness: event.action == "captured_complete" ? .complete : .partial,
                evidenceSource: event.source ?? "unknown")
        }
    }
}

enum MCPObservationState: String, Codable, Sendable {
    case explicitCallsObserved
    case notEstablishedByCapturedSources
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
        let mcpCalls: [ToolCallLifecycleEvidence]
        let mcpObservation: MCPObservationState
        let toolResults: [ToolOutputEvidence]
        let commands: [ToolCallLifecycleEvidence]
        let files: [FileActivityEvidence]
        let network: [NetworkActivityReference]
        let networkFlows: [NetworkFlowEvidence]
        let memory: [MemoryActivityEvidence]
    }

    struct Analysis: Codable, Sendable {
        let modelEconomics: ModelEconomicsReport?
        let contextExposure: ContextExposureReport?
        let memoryEvidence: AgentMemoryEvidenceReport
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
    let externalRequests: [AgentExternalRequestEvidence]
    let modelResponses: [AgentModelResponseEvidence]
    let journey: AgentTaskJourney
    let activities: Activities
    let analysis: Analysis
    let events: [AgentEventEnvelope]
    let sourceEvents: [GuardEvent]
    let evidenceReferences: [String]

    /// Merge normalized persistent-memory commits even when this older task
    /// has no materialized task-snapshot projection.
    func includingMemoryCommits(_ commits: [MemoryCommitEvidence]) -> AgentTaskSnapshot {
        guard !commits.isEmpty else { return self }
        var merged: [String: MemoryCommitEvidence] = [:]
        for commit in analysis.memoryCommits { merged[commit.commitId] = commit }
        for commit in commits { merged[commit.commitId] = commit }
        let nextAnalysis = Analysis(modelEconomics: analysis.modelEconomics,
            contextExposure: analysis.contextExposure, memoryEvidence: analysis.memoryEvidence,
            relaySecurity: analysis.relaySecurity, egressAudit: analysis.egressAudit,
            memoryCommits: merged.values.sorted { $0.observedAt < $1.observedAt },
            codeFindings: analysis.codeFindings, verification: analysis.verification)
        return AgentTaskSnapshot(schemaVersion: schemaVersion, revision: revision,
            generatedAt: generatedAt, task: task, capture: capture, conversation: conversation,
            metrics: metrics, outboundRequests: outboundRequests, externalRequests: externalRequests,
            modelResponses: modelResponses, journey: journey, activities: activities,
            analysis: nextAnalysis, events: events, sourceEvents: sourceEvents,
            evidenceReferences: evidenceReferences)
    }

    static func build(session: AgentSessionSnapshot, turnID: String?, nextPromptAt: Date? = nil) -> AgentTaskSnapshot {
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
        let tools = toolLifecycles(canonical, sourceEvents: scoped)
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
        let scopedSession = AgentSessionSnapshot.build(from: scoped).first
        let egress = scopedSession.flatMap { AgentEgressAudit.build(session: $0).first { audit in
            resolvedTurn.map { audit.turnId == $0 } ?? true
        } }
        let outboundRequests = AgentOutboundRequestEvidence.build(events: scoped) +
            (session.agent == "workbuddy"
                ? WorkBuddyTraceRequests.load(events: scoped, sessionEvents: session.events, nextPromptAt: nextPromptAt) : [])
        let transcriptResponses = scoped.compactMap { event -> AgentModelResponseEvidence? in
            guard event.kind == "model", ["response", "network_response"].contains(event.op),
                  let content = event.modelResponse, !content.isEmpty else { return nil }
            let recordedReasoning = event.modelReasoning ?? scoped.last(where: { candidate in
                candidate.op == "reasoning_summary" && candidate.modelReasoning != nil &&
                    candidate.ts <= event.ts && event.ts.timeIntervalSince(candidate.ts) <= 30 &&
                    (event.traceId == nil || candidate.traceId == nil || candidate.traceId == event.traceId)
            })?.modelReasoning
            return AgentModelResponseEvidence(eventID: event.id.uuidString,
                receivedAt: event.ts, traceID: event.traceId, model: event.model,
                content: content, recordedReasoning: recordedReasoning,
                evidenceSource: event.source ?? "unknown")
        }
        let traceResponses = WorkBuddyTraceRequests.responses(for: outboundRequests.filter { $0.evidenceSource == "workbuddy-local-trace" })
        let modelResponses = traceResponses + transcriptResponses.filter { response in
            !traceResponses.contains {
                $0.content == response.content && abs($0.receivedAt.timeIntervalSince(response.receivedAt)) < 10
            }
        }
        let journey = AgentTaskJourney.build(requests: outboundRequests,
            responses: modelResponses, tools: tools, toolResults: toolResults,
            files: files)
        let modelObserved = scoped.contains { $0.kind == "model" && ["prompt", "response", "network_prompt"].contains($0.op) }
        let missingBody = modelObserved && !outboundRequests.contains {
            $0.completeness == .complete &&
                [.completeHTTPSRequestBody, .preEncryptionRequestBody].contains($0.captureMode)
        }
        let missingCapabilities = (health.missingCapabilities +
            (missingBody ? ["completeModelRequestBody"] : [])).sorted()
        let evidenceReferences = Array(Set(
            canonical.map(\.id) + scoped.map { $0.id.uuidString } +
                outboundRequests.map(\.eventID)
        )).sorted()
        let revisionSeed = evidenceReferences.joined(separator: "|")
        let revision = SHA256.hash(data: Data(revisionSeed.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return AgentTaskSnapshot(
            schemaVersion: 4, revision: revision, generatedAt: Date(),
            task: Identity(taskID: taskID, projectID: projectID,
                           agentID: session.agent, sessionID: session.id,
                           turnID: resolvedTurn, startedAt: scoped.first?.ts,
                           endedAt: scoped.last?.ts),
            capture: Capture(state: missingBody && health.state == .healthy ? .degraded : health.state,
                sources: Array(Set(canonical.map(\.source))).sorted { $0.rawValue < $1.rawValue },
                eventCount: health.eventCount, gaps: health.gaps,
                missingCapabilities: missingCapabilities),
            conversation: Conversation(
                userInputs: unique(scoped.compactMap(\.userIntent)),
                modelResponses: unique(scoped.compactMap(\.modelResponse)),
                reasoning: unique(scoped.compactMap(\.modelReasoning)),
                models: unique(scoped.compactMap(\.model)),
                traceIDs: unique(scoped.compactMap(\.traceId))),
            metrics: AgentEventMetrics.build(events: canonical),
            outboundRequests: outboundRequests,
            externalRequests: AgentExternalRequestEvidence.build(events: scoped),
            modelResponses: modelResponses,
            journey: journey,
            activities: Activities(
                tools: tools,
                mcpCalls: tools.filter { $0.serverName != nil || $0.toolName.lowercased().hasPrefix("mcp__") },
                mcpObservation: tools.contains { $0.serverName != nil || $0.toolName.lowercased().hasPrefix("mcp__") }
                    ? .explicitCallsObserved : .notEstablishedByCapturedSources,
                toolResults: toolResults,
                commands: tools.filter { isCommandTool($0.toolName) },
                files: files, network: network,
                networkFlows: NetworkFlowEvidence.build(events: scoped), memory: memory),
            analysis: Analysis(
                modelEconomics: ModelEconomicsReport.build(events: scoped),
                contextExposure: ContextExposureReport.build(events: scoped),
                memoryEvidence: AgentMemoryEvidenceReport.build(events: scoped, requests: outboundRequests),
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

    private static func toolLifecycles(_ events: [AgentEventEnvelope],
                                       sourceEvents: [GuardEvent]) -> [ToolCallLifecycleEvidence] {
        var calls: [String: ToolCallLifecycleEvidence] = [:]
        var outcomes: [String: (state: ToolCallState, at: Date, evidenceID: String)] = [:]
        let sourceByID = Dictionary(sourceEvents.map { ($0.id.uuidString, $0) },
                                    uniquingKeysWith: { _, latest in latest })
        for event in events {
            switch event.payload {
            case let .toolCall(call):
                calls[call.callID] = call
            case let .toolOutput(output):
                let sourceID = event.correlation?.sourceEventID ?? event.id
                let failed = sourceByID[sourceID]?.action.lowercased().contains("fail") == true
                outcomes[output.callID] = (failed ? .failed : .completed, event.occurredAt, sourceID)
            default:
                break
            }
        }
        return calls.values.map { call in
            guard let outcome = outcomes[call.callID] else { return call }
            return ToolCallLifecycleEvidence(
                callID: call.callID, toolName: call.toolName,
                serverName: call.serverName, arguments: call.arguments,
                argumentsDigest: call.argumentsDigest, state: outcome.state,
                startedAt: call.startedAt, completedAt: outcome.at,
                exitCode: call.exitCode,
                evidenceIDs: Array(Set(call.evidenceIDs + [outcome.evidenceID])).sorted())
        }.sorted { ($0.startedAt ?? .distantPast) < ($1.startedAt ?? .distantPast) }
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
