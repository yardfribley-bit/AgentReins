import Foundation

struct AgentDashboardProjectionKey: Hashable, Sendable {
    let selectedAgent: String
    let dataRevision: UInt64
    let query: String
}

struct AgentDashboardProjectionInput: Sendable {
    let key: AgentDashboardProjectionKey
    let sessions: [AgentSessionSnapshot]
    let events: [GuardEvent]
    let incidents: [SecurityIncident]
}

struct AgentDashboardProjection: Sendable {
    let key: AgentDashboardProjectionKey
    let sessions: [AgentSessionSnapshot]
    let activeSession: AgentSessionSnapshot?
    let events: [GuardEvent]
    let incidents: [SecurityIncident]
    let networkFlows: [NetworkFlowEvidence]
    let networkIPs: [String]
    let sshSessions: [SSHSessionEvidence]
    let memoryCommits: [MemoryCommitEvidence]
    let findingCount: Int
    let hostCount: Int
    let evidenceCoverage: String

    static func build(input: AgentDashboardProjectionInput) throws -> AgentDashboardProjection {
        let selectedAgent = input.key.selectedAgent
        let scopedSessions = input.sessions.filter {
            matches(agent: $0.agent, selectedAgent: selectedAgent)
        }
        let activeSession = scopedSessions.max { $0.lastActivityAt < $1.lastActivityAt }
        let query = input.key.query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let selectedEvents = input.events.filter { event in
            guard let agent = event.agent else { return selectedAgent == "All agents" }
            return matches(agent: agent, selectedAgent: selectedAgent)
        }
        let scopedEvents = query.isEmpty ? selectedEvents : selectedEvents.filter { event in
            [event.agent, event.toolName, event.remoteDomain, event.remoteHost, event.command,
             event.path, event.userIntent, event.modelResponse]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(query) }
        }
        try Task.checkCancellation()
        let scopedIncidents = input.incidents.filter { incident in
            guard let agent = incident.agent else { return selectedAgent == "All agents" }
            return matches(agent: agent, selectedAgent: selectedAgent)
        }
        try Task.checkCancellation()
        let networkFlows = NetworkFlowEvidence.build(events: scopedEvents)
        let networkIPs = Array(Set(networkFlows.compactMap(\.ip))).sorted()
        let sshSessions = SSHSessionEvidence.build(events: scopedEvents)
        let turnID = activeSession?.turns.last?.id
        let memoryRows = activeSession.map { session in
            scopedEvents.filter { event in
                event.sessionId == session.id && (turnID == nil || event.turnId == turnID)
            }
        } ?? []
        let memoryCommits = MemoryCommitEvidence.build(events: memoryRows)
        let confirmed = scopedEvents.filter { $0.attributionConfidence == .confirmed }.count
        let evidenceCoverage = scopedEvents.isEmpty
            ? "—"
            : "\(Int(Double(confirmed) / Double(scopedEvents.count) * 100))%"
        let hosts = Set(scopedEvents.compactMap { $0.remoteDomain ?? $0.remoteHost })
        return AgentDashboardProjection(key: input.key, sessions: scopedSessions,
            activeSession: activeSession, events: scopedEvents, incidents: scopedIncidents,
            networkFlows: networkFlows, networkIPs: networkIPs,
            sshSessions: sshSessions, memoryCommits: memoryCommits,
            findingCount: scopedEvents.compactMap(\.codeFindings).flatMap { $0 }.count,
            hostCount: hosts.count, evidenceCoverage: evidenceCoverage)
    }

    private static func matches(agent: String, selectedAgent: String) -> Bool {
        if selectedAgent == "All agents" { return true }
        if selectedAgent.caseInsensitiveCompare("Web AI") == .orderedSame {
            return ["gemini", "chatgpt", "grok", "claude-web", "web-ai"]
                .contains(agent.lowercased())
        }
        return normalizedAgentIdentity(agent) == normalizedAgentIdentity(selectedAgent)
    }
}
