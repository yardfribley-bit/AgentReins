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
        let incidents = SecurityIncident.correlate(recent + contentFindings)
        let sessionEvents = liveSessionEvents(events)
        return EventDerivedProjection(incidents: incidents,
            sessions: AgentSessionSnapshot.build(from: sessionEvents),
            influenceChains: ExternalContentSecurity.influenceChains(events: recent),
            webResourceChains: WebResourceSecurity.build(events: recent))
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
