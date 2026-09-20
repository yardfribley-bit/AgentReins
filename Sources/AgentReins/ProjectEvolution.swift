import Foundation

enum ProjectOrigin: String {
    case observedCreation = "Observed creation"
    case firstObserved = "First observed"
}

enum ProjectVerificationState: String {
    case verified = "Verified"
    case failed = "Verification failed"
    case agentReported = "Agent reported complete"
    case pending = "Verification pending"
}

struct ProjectChangeSet: Identifiable {
    let id: String
    let projectPath: String
    let sessionId: String
    let turnId: String
    let agent: String
    let requirement: String
    let startedAt: Date
    let lastActivityAt: Date
    let createdFiles: [String]
    let modifiedFiles: [String]
    let deletedFiles: [String]
    let readFiles: [String]
    let tools: [String]
    let externalDestinations: [String]
    let memoryReads: Int
    let memoryWrites: Int
    let securityFindings: [String]
    let verification: ProjectVerificationState

    /// Dialogue is evidence attached to the batch, not the identity of the
    /// batch. One batch can legitimately span several turns.
    var contexts: [ProjectChangeContext] = []

    var changedFileCount: Int { Set(createdFiles + modifiedFiles + deletedFiles).count }
    var contextCount: Int { contexts.count }
    var sessionIDs: [String] { Array(Set(contexts.map(\.sessionId) + [sessionId])).sorted() }
    var turnCount: Int { Set(contexts.map(\.turnId)).count }
    var modelNames: [String] { Array(Set(contexts.compactMap(\.model))).sorted() }
    var summary: String {
        var parts: [String] = []
        if !createdFiles.isEmpty { parts.append("created \(createdFiles.count) file(s)") }
        if !modifiedFiles.isEmpty { parts.append("modified \(modifiedFiles.count) file(s)") }
        if !deletedFiles.isEmpty { parts.append("deleted \(deletedFiles.count) file(s)") }
        if parts.isEmpty && !readFiles.isEmpty { parts.append("read \(readFiles.count) file(s)") }
        if parts.isEmpty { parts.append("no file mutation observed") }
        return formattedAgentName(agent) + " " + parts.joined(separator: ", ")
    }
}

struct ProjectChangeContext: Identifiable {
    let id: String
    let sessionId: String
    let turnId: String
    let occurredAt: Date
    let userInput: String?
    let modelResponse: String?
    let model: String?
}

struct ProjectEvolutionSnapshot: Identifiable {
    let id: String
    let name: String
    let path: String
    let origin: ProjectOrigin
    let firstObservedAt: Date
    let lastActivityAt: Date
    let agents: [String]
    let changeSets: [ProjectChangeSet]

    var changedFileCount: Int { Set(changeSets.flatMap { $0.createdFiles + $0.modifiedFiles + $0.deletedFiles }).count }
    var openFindingCount: Int { changeSets.reduce(0) { $0 + $1.securityFindings.count } }
}

enum ProjectEvolution {
    static func build(sessions: [AgentSessionSnapshot], incidents: [SecurityIncident]) -> [ProjectEvolutionSnapshot] {
        let attributable = sessions.compactMap { session -> (String, AgentSessionSnapshot)? in
            let workspace = SupervisedWorkspaceResolver.resolve(session.workspace)
            guard let path = workspace.path else { return nil }
            return (path, session)
        }
        return Dictionary(grouping: attributable, by: \.0).map { path, rows in
            let projectSessions = rows.map(\.1)
            let changes = projectSessions.flatMap { changeSets(session: $0, projectPath: path, incidents: incidents) }
                .sorted { $0.lastActivityAt > $1.lastActivityAt }
            let first = projectSessions.map(\.startedAt).min() ?? .distantPast
            let last = projectSessions.map(\.lastActivityAt).max() ?? first
            return ProjectEvolutionSnapshot(id: path,
                name: URL(fileURLWithPath: path).lastPathComponent,
                path: path, origin: .firstObserved, firstObservedAt: first,
                lastActivityAt: last,
                agents: Array(Set(projectSessions.map { formattedAgentName($0.agent) })).sorted(),
                changeSets: changes)
        }.sorted { $0.lastActivityAt > $1.lastActivityAt }
    }

    static func projectRoot(_ workspace: String?) -> String? {
        SupervisedWorkspaceResolver.resolve(workspace).path
    }

    private static func changeSets(session: AgentSessionSnapshot, projectPath: String,
                                   incidents: [SecurityIncident]) -> [ProjectChangeSet] {
        struct BatchDraft {
            var mutations: [GuardEvent]
        }

        let orderedTurns = session.turns.sorted { $0.startedAt < $1.startedAt }
        let mutations = session.events.filter { event in
            event.kind == "file" && ["create", "modify", "update", "write", "delete", "move", "rename"]
                .contains(event.op.lowercased())
        }.sorted { $0.ts < $1.ts }
        var groups: [BatchDraft] = []
        for mutation in mutations {
            guard let index = groups.indices.last, let last = groups[index].mutations.last else {
                groups.append(BatchDraft(mutations: [mutation])); continue
            }
            let sameTurn = mutation.turnId != nil && mutation.turnId == last.turnId
            let sameTool = mutation.toolCallId != nil && mutation.toolCallId == last.toolCallId
            let gap = mutation.ts.timeIntervalSince(last.ts)
            let verifiedBetween = session.events.contains { event in
                event.kind == "verification" && event.ts >= last.ts && event.ts <= mutation.ts
                    && ["passed", "verified", "success", "failed", "failure", "error"]
                        .contains(event.action.lowercased())
            }
            let related = groups[index].mutations.contains { pathsRelated($0.path, mutation.path) }
            // A turn can remain open for hours or days. Identity alone cannot
            // bridge two stable work periods; all causal continuations are
            // bounded by observed time and verification state.
            if !verifiedBetween && gap >= 0
                && ((sameTurn && gap <= 10 * 60) || (sameTool && gap <= 10 * 60)
                    || (gap <= 120 && related)) {
                groups[index].mutations.append(mutation)
            } else {
                groups.append(BatchDraft(mutations: [mutation]))
            }
        }

        return groups.map { group in
            let mutationTurnIDs = Set(group.mutations.compactMap(\.turnId))
            let exactTurns = orderedTurns.filter { mutationTurnIDs.contains($0.id) }
            let firstMutation = group.mutations[0]
            let lastMutation = group.mutations.last ?? firstMutation
            let firstTurnTime = exactTurns.map(\.startedAt).min() ?? firstMutation.ts
            let turns = orderedTurns.filter { turn in
                mutationTurnIDs.contains(turn.id)
                    || (turn.startedAt >= firstTurnTime && turn.startedAt <= lastMutation.ts)
            }
            let turnIDs = Set(turns.map(\.id))
            let firstTurn = turns.first
            let rows = session.events.filter { event in
                event.turnId.map(turnIDs.contains) ?? false
            }
            let calls = turns.flatMap(\.toolCalls)
            let relatedIncidents = incidents.filter { incident in
                incident.events.contains { event in
                    event.sessionId == session.id && (event.turnId.map(turnIDs.contains) ?? false)
                }
            }
            return ProjectChangeSet(id: "\(session.id):\(firstMutation.id.uuidString)", projectPath: projectPath,
                sessionId: session.id, turnId: firstTurn?.id ?? firstMutation.turnId ?? "unattributed", agent: session.agent,
                requirement: firstTurn?.userInput ?? firstMutation.userIntent ?? "Requirement not captured",
                startedAt: firstMutation.ts, lastActivityAt: rows.map(\.ts).max() ?? lastMutation.ts,
                createdFiles: uniqueFiles(rows, operations: ["create"]),
                modifiedFiles: uniqueFiles(rows, operations: ["modify", "update", "write"]),
                deletedFiles: uniqueFiles(rows, operations: ["delete"]),
                readFiles: uniqueFiles(rows, operations: ["read"]),
                tools: Array(Set(calls.map(\.friendlyName))).sorted(),
                externalDestinations: Array(Set(rows.compactMap { $0.remoteDomain ?? $0.remoteHost })).sorted(),
                memoryReads: calls.filter(\.isMemoryRead).count,
                memoryWrites: calls.filter(\.isMemoryWrite).count,
                securityFindings: Array(Set(relatedIncidents.filter { $0.severity != "info" }.map(\.title))).sorted(),
                verification: verificationState(turns: turns, events: rows),
                contexts: turns.map {
                    ProjectChangeContext(id: "\(session.id):\($0.id)", sessionId: session.id,
                        turnId: $0.id, occurredAt: $0.startedAt, userInput: $0.userInput,
                        modelResponse: $0.finalResponse, model: $0.modelNames == "Not captured" ? nil : $0.modelNames)
                })
        }
    }

    private static func pathsRelated(_ lhs: String, _ rhs: String) -> Bool {
        guard lhs != "-", rhs != "-" else { return false }
        if lhs == rhs { return true }
        let a = URL(fileURLWithPath: lhs).deletingLastPathComponent().standardized.path
        let b = URL(fileURLWithPath: rhs).deletingLastPathComponent().standardized.path
        return a == b || a.hasPrefix(b + "/") || b.hasPrefix(a + "/")
    }

    private static func uniqueFiles(_ events: [GuardEvent], operations: Set<String>) -> [String] {
        Array(Set(events.filter { $0.kind == "file" && operations.contains($0.op.lowercased()) }
            .map(\.path).filter { $0 != "-" })).sorted()
    }

    private static func verificationState(turns: [AgentTurn], events: [GuardEvent]) -> ProjectVerificationState {
        let verification = events.filter { $0.kind == "verification" }
        if verification.contains(where: { ["failed", "failure", "error"].contains($0.action.lowercased()) }) { return .failed }
        if verification.contains(where: { ["passed", "verified", "success"].contains($0.action.lowercased()) }) { return .verified }
        if turns.contains(where: { $0.finalResponse != nil }) { return .agentReported }
        return .pending
    }
}
