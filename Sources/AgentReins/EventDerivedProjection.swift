import Foundation

struct EventDerivedProjectionRequest: Sendable {
    let generation: UInt64
    let events: [GuardEvent]
}

struct EventDerivedProjection: Sendable {
    let incidents: [SecurityIncident]
    let sessions: [AgentSessionSnapshot]
    let influenceChains: [InfluenceChain]
    let webResourceChains: [WebResourceChain]

    static func build(events: [GuardEvent]) -> EventDerivedProjection {
        let recent = Array(events.prefix(400))
        let contentFindings = ExternalContentSecurity.findingEvents(events: recent)
        let policyAlerts = AgentPolicyAlertEngine.findings(events: recent)
        // Security is a policy decision, not a second copy of the activity log.
        // Raw network/model/tool/activity evidence remains available in its own
        // views and may support a finding, but it must never become an incident
        // merely because its destination or meaning is still unknown.
        let directFindings = recent.filter(isDirectSecurityFinding)
        let incidents = SecurityIncident.correlate(directFindings + contentFindings + policyAlerts)
        let sessionEvents = liveSessionEvents(events)
        return EventDerivedProjection(incidents: incidents,
            sessions: AgentSessionSnapshot.build(from: sessionEvents),
            influenceChains: ExternalContentSecurity.influenceChains(events: recent),
            webResourceChains: WebResourceSecurity.build(events: recent))
    }

    private static func isDirectSecurityFinding(_ event: GuardEvent) -> Bool {
        if event.kind == "alert" || event.kind == "external-content" { return true }
        if ["blocked", "restored"].contains(event.action.lowercased()) { return true }
        guard ["cmd", "file", "memory"].contains(event.kind) else { return false }
        return ["critical", "high", "medium"].contains(event.severity.lowercased())
    }

    private static func liveSessionEvents(_ events: [GuardEvent]) -> [GuardEvent] {
        let sessionEvents = events.prefix(400).filter { $0.sessionId != nil }
        guard let newest = sessionEvents.first else { return [] }
        let cutoff = newest.ts.addingTimeInterval(-10 * 60)
        let activeIDs = Set(sessionEvents.filter { $0.ts >= cutoff }.compactMap(\.sessionId))
        return sessionEvents.filter { event in
            guard let id = event.sessionId else { return false }
            return activeIDs.contains(id)
        }
    }
}

actor EventDerivedProjectionWorker {
    private var pending: EventDerivedProjectionRequest?
    private var running = false
    private var latestGeneration: UInt64 = 0

    func submit(_ request: EventDerivedProjectionRequest,
                deliver: @escaping @MainActor @Sendable (UInt64, EventDerivedProjection) -> Void) async {
        guard request.generation > latestGeneration else { return }
        latestGeneration = request.generation
        pending = request
        guard !running else { return }
        running = true
        while let next = pending {
            pending = nil
            let projection = EventDerivedProjection.build(events: next.events)
            await deliver(next.generation, projection)
        }
        running = false
    }
}
