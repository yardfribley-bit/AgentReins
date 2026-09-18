import Combine
import Foundation

/// A bounded, coalesced projection for the live dashboard. Collectors may
/// update independently, but SwiftUI receives at most one coherent snapshot
/// per display interval instead of rebuilding once per publisher.
@MainActor
final class LiveDashboardViewModel: ObservableObject {
    struct Snapshot {
        var evidenceRevision: UInt64 = 0
        var sessions: [AgentSessionSnapshot] = []
        var events: [GuardEvent] = []
        var incidents: [SecurityIncident] = []
        var health: [CollectorHealthRecord] = []
        var processInventory: [ProcessSnapshotRecord] = []
        var discoveredAgents: [DiscoveredAgent] = []
    }

    @Published private(set) var snapshot = Snapshot()
    private var pending = Snapshot()
    private var publishWork: DispatchWorkItem?
    private var notifiedIncidentIDs = Set<UUID>()
    private var evidenceRevision: UInt64 = 0
    private let maximumEvents = 500
    private let publishDelay: TimeInterval = 0.20

    func updateEvidence(sessions: [AgentSessionSnapshot], events: [GuardEvent],
                        incidents: [SecurityIncident], health: [CollectorHealthRecord]) {
        evidenceRevision &+= 1
        pending.evidenceRevision = evidenceRevision
        pending.sessions = sessions
        pending.events = Array(events.prefix(maximumEvents))
        notifySecurityIncidents(incidents)
        pending.incidents = incidents.filter { $0.severity != "info" }
        pending.health = health
        schedulePublish()
    }

    /// Notify only policy-produced findings. Unknown telemetry is evidence,
    /// not a security conclusion, and remains visible in the Network view.
    private func notifySecurityIncidents(_ incidents: [SecurityIncident]) {
        for incident in incidents
        where (incident.primary.kind == "external-content"
               || (incident.primary.kind == "alert" && incident.primary.action == "needs_review"))
            && !notifiedIncidentIDs.contains(incident.id) {
            notifiedIncidentIDs.insert(incident.id)
            if notifiedIncidentIDs.count > 200 { notifiedIncidentIDs.removeAll() }
            AppNotifier.send(title: incident.title, body: incident.summary)
        }
    }

    func updateProcesses(_ processes: [ProcessSnapshotRecord]) {
        guard processes != pending.processInventory else { return }
        pending.processInventory = processes
        schedulePublish()
    }

    func updateAgents(_ agents: [DiscoveredAgent]) {
        guard agents != pending.discoveredAgents else { return }
        pending.discoveredAgents = agents
        schedulePublish()
    }

    func publishImmediately() {
        publishWork?.cancel()
        publishWork = nil
        snapshot = pending
    }

    private func schedulePublish() {
        guard publishWork == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.publishWork = nil
            self.snapshot = self.pending
        }
        publishWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + publishDelay, execute: work)
    }
}
