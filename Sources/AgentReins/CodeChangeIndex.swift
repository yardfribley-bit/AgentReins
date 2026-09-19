import Foundation

/// The primary unit of project history. A commit may contain many changes and
/// a change may never be committed, so Git is deliberately optional metadata.
struct IndexedCodeChange: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let agentID: String
    let sessionID: String
    let turnID: String?
    let path: String
    let operation: FileActivityOperation
    let beforeDigest: String?
    let afterDigest: String?
    let patch: String?
    let toolCallID: String?
    let toolName: String?
    let userPrompt: String?
    let requirementIDs: [String]
    let model: String?
    let startedAt: Date
    let lastObservedAt: Date
    let attribution: AlignmentConfidence
    let commitHashes: [String]
    let verification: [VerificationEvidence]
    let evidenceIDs: [String]

    var committed: Bool { !commitHashes.isEmpty }
}

enum CodeChangeIndexer {
    static func build(events: [AgentEventEnvelope]) -> [IndexedCodeChange] {
        let ordered = events.sorted {
            if $0.occurredAt == $1.occurredAt { return $0.sequence < $1.sequence }
            return $0.occurredAt < $1.occurredAt
        }
        // A tool call legitimately has multiple lifecycle envelopes (requested,
        // running, completed/failed).  Keep the last observed state instead of
        // using `uniqueKeysWithValues`, which traps when historical evidence
        // contains more than one envelope for the same call ID.
        let tools = ordered.reduce(into: [String: ToolCallLifecycleEvidence]()) { result, event in
            guard case let .toolCall(value) = event.payload else { return }
            result[value.callID] = value
        }
        let checkpoints = ordered.compactMap { event -> AgentCheckpointEvidence? in
            guard case let .checkpoint(value) = event.payload else { return nil }
            return value
        }
        let verifications = ordered.compactMap { event -> VerificationEvidence? in
            guard case let .verification(value) = event.payload else { return nil }
            return value
        }

        return ordered.compactMap { event in
            guard case let .fileActivity(file) = event.payload else { return nil }
            let sameTurn = ordered.filter { $0.sessionID == event.sessionID && $0.turnID == event.turnID }
            let prompt = sameTurn.compactMap { row -> UserPromptEvidence? in
                guard case let .userPrompt(value) = row.payload else { return nil }
                return value
            }.first
            let context = sameTurn.compactMap { row -> ContextAssemblySnapshot? in
                guard case let .contextPrepared(value) = row.payload else { return nil }
                return value
            }.last
            let commits = checkpoints.filter { checkpoint in
                checkpoint.touchedPaths.contains { pathsMatch($0, file.path) }
            }.map(\.commitHash)
            let relevantVerification = verifications.filter { value in
                value.evidenceIDs.isEmpty || value.evidenceIDs.contains(event.id)
            }
            return IndexedCodeChange(
                id: event.id, projectID: event.projectID, agentID: event.agentID,
                sessionID: event.sessionID, turnID: event.turnID, path: file.path,
                operation: file.operation, beforeDigest: file.beforeDigest,
                afterDigest: file.afterDigest, patch: file.patch,
                toolCallID: file.toolCallID, toolName: file.toolCallID.flatMap { tools[$0]?.toolName },
                userPrompt: prompt?.rawText, requirementIDs: prompt?.requirementIDs ?? [],
                model: context?.model,
                startedAt: event.occurredAt, lastObservedAt: event.observedAt,
                attribution: file.attribution, commitHashes: Array(Set(commits)).sorted(),
                verification: relevantVerification, evidenceIDs: [event.id])
        }
    }

    private static func pathsMatch(_ lhs: String, _ rhs: String) -> Bool {
        let a = lhs.replacingOccurrences(of: "\\", with: "/").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let b = rhs.replacingOccurrences(of: "\\", with: "/").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return a == b || a.hasSuffix("/\(b)") || b.hasSuffix("/\(a)")
    }
}
