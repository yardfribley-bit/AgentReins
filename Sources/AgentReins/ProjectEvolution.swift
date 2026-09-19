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

    var changedFileCount: Int { Set(createdFiles + modifiedFiles + deletedFiles).count }
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
        struct RequirementGroup {
            var turns: [AgentTurn]
        }

        let orderedTurns = session.turns.sorted { $0.startedAt < $1.startedAt }
        var groups: [RequirementGroup] = []
        var hasActiveRequirement = false
        for turn in orderedTurns {
            let text = turn.userInput ?? ""
            let role = ChangeSetIndexer.classify(text, hasActive: hasActiveRequirement)
            if !hasActiveRequirement || role == .newRequirement || role == .start {
                groups.append(RequirementGroup(turns: [turn]))
                hasActiveRequirement = true
            } else {
                groups[groups.count - 1].turns.append(turn)
            }
            if role == .cancel { hasActiveRequirement = false }
        }

        if groups.isEmpty {
            let rows = session.events
            let relatedIncidents = incidents.filter { incident in
                incident.events.contains { $0.sessionId == session.id }
            }
            return [ProjectChangeSet(id: "\(session.id):session", projectPath: projectPath,
                sessionId: session.id, turnId: "session", agent: session.agent,
                requirement: session.latestIntent ?? "Requirement not captured",
                startedAt: session.startedAt, lastActivityAt: rows.map(\.ts).max() ?? session.lastActivityAt,
                createdFiles: uniqueFiles(rows, operations: ["create"]),
                modifiedFiles: uniqueFiles(rows, operations: ["modify", "update", "write"]),
                deletedFiles: uniqueFiles(rows, operations: ["delete"]), readFiles: uniqueFiles(rows, operations: ["read"]),
                tools: [], externalDestinations: Array(Set(rows.compactMap { $0.remoteDomain ?? $0.remoteHost })).sorted(),
                memoryReads: 0, memoryWrites: 0,
                securityFindings: Array(Set(relatedIncidents.filter { $0.severity != "info" }.map(\.title))).sorted(),
                verification: verificationState(turns: [], events: rows))]
        }

        return groups.map { group in
            let turnIDs = Set(group.turns.map(\.id))
            let firstTurn = group.turns[0]
            let rows = session.events.filter { event in
                event.turnId.map(turnIDs.contains) ?? false
            }
            let calls = group.turns.flatMap(\.toolCalls)
            let relatedIncidents = incidents.filter { incident in
                incident.events.contains { event in
                    event.sessionId == session.id && (event.turnId.map(turnIDs.contains) ?? false)
                }
            }
            return ProjectChangeSet(id: "\(session.id):\(firstTurn.id)", projectPath: projectPath,
                sessionId: session.id, turnId: firstTurn.id, agent: session.agent,
                requirement: firstTurn.userInput ?? session.latestIntent ?? "Requirement not captured",
                startedAt: firstTurn.startedAt, lastActivityAt: rows.map(\.ts).max() ?? group.turns.map(\.startedAt).max() ?? session.lastActivityAt,
                createdFiles: uniqueFiles(rows, operations: ["create"]),
                modifiedFiles: uniqueFiles(rows, operations: ["modify", "update", "write"]),
                deletedFiles: uniqueFiles(rows, operations: ["delete"]),
                readFiles: uniqueFiles(rows, operations: ["read"]),
                tools: Array(Set(calls.map(\.friendlyName))).sorted(),
                externalDestinations: Array(Set(rows.compactMap { $0.remoteDomain ?? $0.remoteHost })).sorted(),
                memoryReads: calls.filter(\.isMemoryRead).count,
                memoryWrites: calls.filter(\.isMemoryWrite).count,
                securityFindings: Array(Set(relatedIncidents.filter { $0.severity != "info" }.map(\.title))).sorted(),
                verification: verificationState(turns: group.turns, events: rows))
        }
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
