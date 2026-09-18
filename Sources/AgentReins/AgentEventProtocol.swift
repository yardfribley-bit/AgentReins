import CryptoKit
import Foundation

/// Canonical, agent-neutral event protocol.
///
/// Adapters may observe Codex JSONL, WorkBuddy logs, process activity, network
/// flows, or browser events. They must all project their observations into this
/// protocol before project understanding, supervision, or UI code consumes it.
struct AgentEventEnvelope: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let agentID: String
    let sessionID: String
    let turnID: String?
    let sequence: UInt64
    let occurredAt: Date
    let observedAt: Date
    let source: AgentEventSource
    let confidence: AlignmentConfidence
    let payload: AgentEventPayload
}

enum AgentEventSource: String, Codable, Sendable {
    case agentProtocol
    case agentTranscript
    case operatingSystem
    case browserExtension
    case git
    case derived
}

enum AgentTurnState: String, Codable, Sendable {
    case queued, preparingContext, requestingModel, executingTool, modifyingFiles
    case building, testing, reportedComplete, verifying, verified, failed, cancelled
}

enum AgentEventPayload: Codable, Sendable {
    case turnState(AgentTurnState)
    case userPrompt(UserPromptEvidence)
    case contextPrepared(ContextAssemblySnapshot)
    case modelMessage(ModelMessageEvidence)
    case plan(AgentPlanEvidence)
    case toolCall(ToolCallLifecycleEvidence)
    case toolOutput(ToolOutputEvidence)
    case fileActivity(FileActivityEvidence)
    case memoryActivity(MemoryActivityEvidence)
    case networkActivity(NetworkActivityReference)
    case contextUsage(ContextUsageEvidence)
    case verification(VerificationEvidence)
    case checkpoint(AgentCheckpointEvidence)
    case prediction(SupervisorPrediction)
}

struct UserPromptEvidence: Codable, Sendable {
    let rawText: String
    let digest: String?
    let requirementIDs: [String]
}

/// One layer of the final input sent to a model. Keeping layers separate lets
/// AgentReins show what the user wrote, what the agent added, and what memory or
/// external material influenced the request without pretending they are equal.
enum ContextLayerKind: String, Codable, Sendable, CaseIterable {
    case userInput
    case systemInstruction
    case projectInstruction
    case agentIdentity
    case conversationHistory
    case sessionHandoff
    case sharedMemory
    case retrievedMemory
    case skill
    case mcpDescription
    case sourceFile
    case externalContent
    case runtimeEnvironment
    case unknown
}

struct ContextLayerEvidence: Codable, Identifiable, Sendable {
    let id: String
    let kind: ContextLayerKind
    let sourceLocator: String?
    let summary: String
    let contentDigest: String?
    let byteCount: Int
    let estimatedTokens: Int?
    let sensitiveDataKinds: [String]
    let evidenceIDs: [String]
    let confidence: AlignmentConfidence
}

struct ContextAssemblySnapshot: Codable, Sendable {
    let capturedAt: Date
    let userPromptDigest: String?
    let finalPromptDigest: String?
    let layers: [ContextLayerEvidence]
    let totalBytes: Int
    let estimatedTokens: Int?
    let model: String?
    let provider: String?
    let route: String?

    var injectedLayers: [ContextLayerEvidence] {
        layers.filter { $0.kind != .userInput }
    }
}

enum ModelMessageRole: String, Codable, Sendable { case assistant, reasoningSummary, toolRequest }

struct ModelMessageEvidence: Codable, Sendable {
    let role: ModelMessageRole
    let text: String
    let digest: String?
    let model: String?
    let provider: String?
    let finishReason: String?
}

struct AgentPlanEvidence: Codable, Sendable {
    let title: String?
    let steps: [String]
    let activeStep: Int?
}

enum ToolCallState: String, Codable, Sendable { case requested, running, completed, failed, denied }

struct ToolCallLifecycleEvidence: Codable, Sendable {
    let callID: String
    let toolName: String
    let serverName: String?
    let arguments: String?
    let argumentsDigest: String?
    let state: ToolCallState
    let startedAt: Date?
    let completedAt: Date?
    let exitCode: Int?
    let evidenceIDs: [String]
}

struct ToolOutputEvidence: Codable, Sendable {
    let callID: String
    let output: String?
    let outputDigest: String?
    let byteCount: Int
    let truncated: Bool
}

enum FileActivityOperation: String, Codable, Sendable { case read, create, modify, delete, rename }

struct FileActivityEvidence: Codable, Sendable {
    let operation: FileActivityOperation
    let path: String
    let beforeDigest: String?
    let afterDigest: String?
    let patch: String?
    let toolCallID: String?
    let attribution: AlignmentConfidence
}

enum MemoryActivityOperation: String, Codable, Sendable { case retrieve, create, update, delete }

struct MemoryActivityEvidence: Codable, Sendable {
    let operation: MemoryActivityOperation
    let scope: ProjectMemoryScope
    let key: String?
    let storageLocator: String?
    let beforeDigest: String?
    let afterDigest: String?
    let summary: String
    let toolCallID: String?
}

struct NetworkActivityReference: Codable, Sendable {
    let destination: String
    let category: String?
    let bytesSent: Int?
    let bytesReceived: Int?
    let toolCallID: String?
    let rawEvidenceIDs: [String]
}

struct ContextUsageEvidence: Codable, Sendable {
    let usedTokens: Int?
    let windowTokens: Int?
    let inputTokens: Int?
    let outputTokens: Int?
    let cost: Double?
    let compacting: Bool
}

struct VerificationEvidence: Codable, Sendable {
    let kind: VerificationKind
    let outcome: VerificationOutcome
    let independentOfAgentClaim: Bool
    let summary: String
    let evidenceIDs: [String]
}

struct AgentCheckpointEvidence: Codable, Sendable {
    let commitHash: String
    let branch: String?
    let touchedPaths: [String]
    let survivingPaths: [String]
    let attribution: AlignmentConfidence
    let evidenceIDs: [String]
}

enum PredictionKind: String, Codable, Sendable {
    case likelyNextAction
    case requirementDrift
    case sensitiveDataExposure
    case dangerousToolUse
    case memoryPoisoning
    case unsafeCodeChange
    case repeatedFailure
}

struct SupervisorPrediction: Codable, Sendable {
    let kind: PredictionKind
    let summary: String
    let probability: Double?
    let severity: AlignmentSeverity
    let recommendedControl: String?
    let evidenceIDs: [String]
}

// MARK: - Capture health and supervision projection

enum CaptureHealthState: String, Codable, Sendable { case healthy, degraded, stopped }

struct CaptureGap: Codable, Identifiable, Sendable, Equatable {
    let id: String
    let sessionID: String
    let expectedSequence: UInt64
    let observedSequence: UInt64
}

struct AgentCaptureHealth: Codable, Sendable {
    let state: CaptureHealthState
    let lastObservedAt: Date?
    let eventCount: Int
    let gaps: [CaptureGap]
    let missingCapabilities: [String]

    static func evaluate(_ events: [AgentEventEnvelope], required: Set<AgentEventSource> = []) -> AgentCaptureHealth {
        let ordered = events.sorted {
            $0.sessionID == $1.sessionID ? $0.sequence < $1.sequence : $0.sessionID < $1.sessionID
        }
        var previousBySession: [String: UInt64] = [:]
        var gaps: [CaptureGap] = []
        for event in ordered {
            if let previous = previousBySession[event.sessionID], event.sequence > previous + 1 {
                gaps.append(CaptureGap(id: "\(event.sessionID):\(previous + 1)-\(event.sequence - 1)",
                                       sessionID: event.sessionID,
                                       expectedSequence: previous + 1,
                                       observedSequence: event.sequence))
            }
            previousBySession[event.sessionID] = max(previousBySession[event.sessionID] ?? 0, event.sequence)
        }
        let observed = Set(events.map(\.source))
        let missing = required.subtracting(observed).map(\.rawValue).sorted()
        let state: CaptureHealthState
        if events.isEmpty { state = .stopped }
        else if !gaps.isEmpty || !missing.isEmpty { state = .degraded }
        else { state = .healthy }
        return AgentCaptureHealth(state: state, lastObservedAt: events.map(\.observedAt).max(),
                                  eventCount: events.count, gaps: gaps,
                                  missingCapabilities: missing)
    }
}

struct ProjectSupervisorSnapshot: Codable, Sendable {
    let projectID: String
    let activeAgentIDs: [String]
    let activeSessionIDs: [String]
    let currentState: AgentTurnState?
    let currentRequirementIDs: [String]
    let captureHealth: AgentCaptureHealth
    let context: ContextAssemblySnapshot?
    let activeTool: ToolCallLifecycleEvidence?
    let predictions: [SupervisorPrediction]
    let lastEventAt: Date?

    static func build(projectID: String, events: [AgentEventEnvelope], now: Date = Date()) -> ProjectSupervisorSnapshot {
        let scoped = events.filter { $0.projectID == projectID }.sorted {
            if $0.occurredAt == $1.occurredAt { return $0.sequence < $1.sequence }
            return $0.occurredAt < $1.occurredAt
        }
        let recentCutoff = now.addingTimeInterval(-15 * 60)
        let recent = scoped.filter { $0.occurredAt >= recentCutoff }
        let state = scoped.reversed().compactMap { event -> AgentTurnState? in
            if case let .turnState(value) = event.payload { return value }
            return nil
        }.first
        let prompt = scoped.reversed().compactMap { event -> UserPromptEvidence? in
            if case let .userPrompt(value) = event.payload { return value }
            return nil
        }.first
        let context = scoped.reversed().compactMap { event -> ContextAssemblySnapshot? in
            if case let .contextPrepared(value) = event.payload { return value }
            return nil
        }.first
        let activeTool = scoped.reversed().compactMap { event -> ToolCallLifecycleEvidence? in
            if case let .toolCall(value) = event.payload, [.requested, .running].contains(value.state) { return value }
            return nil
        }.first
        let predictions = scoped.compactMap { event -> SupervisorPrediction? in
            if case let .prediction(value) = event.payload { return value }
            return nil
        }
        return ProjectSupervisorSnapshot(
            projectID: projectID,
            activeAgentIDs: Array(Set(recent.map(\.agentID)).sorted()),
            activeSessionIDs: Array(Set(recent.map(\.sessionID)).sorted()),
            currentState: state,
            currentRequirementIDs: prompt?.requirementIDs ?? [],
            captureHealth: AgentCaptureHealth.evaluate(scoped),
            context: context,
            activeTool: activeTool,
            predictions: Array(predictions.suffix(20)),
            lastEventAt: scoped.map(\.occurredAt).max())
    }
}

// MARK: - Existing evidence bridge

/// Transitional adapter for the evidence AgentReins already collects. It is
/// deliberately conservative: ambiguous legacy fields become `.unknown`
/// context instead of being mislabeled as system instructions or memory.
enum LegacyGuardEventAdapter {
    static func project(_ events: [GuardEvent], projectID: String,
                        startingSequence: UInt64 = 0) -> [AgentEventEnvelope] {
        let ordered = events.sorted { lhs, rhs in
            if lhs.ts == rhs.ts { return lhs.id.uuidString < rhs.id.uuidString }
            return lhs.ts < rhs.ts
        }
        var sequenceBySession: [String: UInt64] = [:]
        var result: [AgentEventEnvelope] = []

        func append(_ payload: AgentEventPayload, from event: GuardEvent) {
            let session = event.sessionId ?? "unattributed:\(event.agent ?? "unknown")"
            let sequence = (sequenceBySession[session] ?? startingSequence) + 1
            sequenceBySession[session] = sequence
            result.append(AgentEventEnvelope(
                id: "\(event.id.uuidString):\(sequence)", projectID: projectID,
                agentID: event.agent ?? "unknown", sessionID: session, turnID: event.turnId,
                sequence: sequence, occurredAt: event.ts, observedAt: event.ts,
                source: source(for: event), confidence: confidence(for: event), payload: payload))
        }

        for event in ordered {
            if let intent = event.userIntent?.trimmingCharacters(in: .whitespacesAndNewlines), !intent.isEmpty {
                append(.userPrompt(UserPromptEvidence(rawText: intent, digest: nil, requirementIDs: [])), from: event)
            }
            if let prompt = event.modelPrompt?.trimmingCharacters(in: .whitespacesAndNewlines), !prompt.isEmpty {
                let userBytes = event.userIntent?.utf8.count ?? 0
                let layer = ContextLayerEvidence(
                    id: "\(event.id.uuidString):legacy-context", kind: .unknown,
                    sourceLocator: event.source, summary: "Complete model input captured by the legacy adapter",
                    contentDigest: nil, byteCount: prompt.utf8.count, estimatedTokens: nil,
                    sensitiveDataKinds: [], evidenceIDs: [event.id.uuidString],
                    confidence: confidence(for: event))
                append(.contextPrepared(ContextAssemblySnapshot(
                    capturedAt: event.ts, userPromptDigest: nil, finalPromptDigest: nil,
                    layers: [layer], totalBytes: max(userBytes, prompt.utf8.count),
                    estimatedTokens: event.inputTokens, model: event.model,
                    provider: nil, route: event.remoteDomain ?? event.remoteHost)), from: event)
            }
            if let response = event.modelResponse?.trimmingCharacters(in: .whitespacesAndNewlines), !response.isEmpty {
                append(.modelMessage(ModelMessageEvidence(role: .assistant, text: response, digest: nil,
                                                           model: event.model, provider: nil,
                                                           finishReason: event.action)), from: event)
            }
            if let callID = event.toolCallId, event.toolName != nil || event.command != nil {
                let state: ToolCallState = event.action.lowercased().contains("fail") ? .failed :
                    (event.endedAt == nil ? .running : .completed)
                append(.toolCall(ToolCallLifecycleEvidence(
                    callID: callID, toolName: event.toolName ?? "unknown",
                    serverName: nil, arguments: event.command, argumentsDigest: nil,
                    state: state, startedAt: event.startedAt ?? event.ts,
                    completedAt: event.endedAt, exitCode: nil,
                    evidenceIDs: [event.id.uuidString])), from: event)
                if let command = event.command {
                    for file in patchFileActivities(command: command, toolCallID: callID) {
                        append(.fileActivity(file), from: event)
                    }
                }
            }
            if event.kind == "file" || event.relatedPath != nil || event.fileDiff != nil {
                let operation = fileOperation(event.op)
                let target = event.relatedPath ?? (event.path == "-" ? nil : event.path)
                if let target, !target.isEmpty {
                    append(.fileActivity(FileActivityEvidence(
                        operation: operation, path: target,
                        beforeDigest: event.beforeContent.map { SessionCommitAttributor.digest(Data($0.utf8)) },
                        afterDigest: event.afterContent.map { SessionCommitAttributor.digest(Data($0.utf8)) },
                        patch: event.fileDiff, toolCallID: event.toolCallId,
                        attribution: confidence(for: event))), from: event)
                }
            }
            if event.kind == "network", let destination = event.remoteDomain ?? event.remoteHost {
                append(.networkActivity(NetworkActivityReference(
                    destination: destination, category: event.op,
                    bytesSent: nil, bytesReceived: nil, toolCallID: event.toolCallId,
                    rawEvidenceIDs: [event.id.uuidString])), from: event)
            }
            if event.inputTokens != nil || event.outputTokens != nil || event.costUSD != nil {
                append(.contextUsage(ContextUsageEvidence(
                    usedTokens: nil, windowTokens: nil, inputTokens: event.inputTokens,
                    outputTokens: event.outputTokens, cost: event.costUSD, compacting: false)), from: event)
            }
        }
        return result
    }

    private static func source(for event: GuardEvent) -> AgentEventSource {
        let value = (event.source ?? "").lowercased()
        if value.contains("browser") || value.contains("chrome") { return .browserExtension }
        if value.contains("git") { return .git }
        if ["process", "network", "file"].contains(event.kind) { return .operatingSystem }
        return .agentTranscript
    }

    private static func confidence(for event: GuardEvent) -> AlignmentConfidence {
        switch event.attributionConfidence {
        case .confirmed: return .confirmed
        case .inferred: return .inferred
        case .unknown, nil: return .unknown
        }
    }

    private static func fileOperation(_ raw: String) -> FileActivityOperation {
        let value = raw.lowercased()
        if value.contains("read") { return .read }
        if value.contains("delete") || value.contains("remove") { return .delete }
        if value.contains("create") || value.contains("write") { return .create }
        if value.contains("rename") || value.contains("move") { return .rename }
        return .modify
    }

    static func patchFileActivities(command: String, toolCallID: String) -> [FileActivityEvidence] {
        guard command.contains("*** Begin Patch") else { return [] }
        // Codex compatibility evidence may preserve JavaScript string escapes
        // ("\\n") rather than decoded line breaks. Normalize both forms before
        // reading patch headers; the patch body itself is not interpreted here.
        let normalizedCommand = command.replacingOccurrences(of: "\\n", with: "\n")
        let markers: [(String, FileActivityOperation)] = [
            ("*** Add File: ", .create), ("*** Update File: ", .modify),
            ("*** Delete File: ", .delete), ("*** Move to: ", .rename)
        ]
        var seen = Set<String>()
        return normalizedCommand.components(separatedBy: .newlines).compactMap { line in
            guard let marker = markers.first(where: { line.hasPrefix($0.0) }) else { return nil }
            let path = String(line.dropFirst(marker.0.count)).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !path.isEmpty else { return nil }
            let key = "\(marker.1.rawValue):\(path)"
            guard seen.insert(key).inserted else { return nil }
            return FileActivityEvidence(operation: marker.1, path: path,
                beforeDigest: nil, afterDigest: nil, patch: nil,
                toolCallID: toolCallID, attribution: .observed)
        }
    }
}
