import Combine
import Foundation

/// A bounded, coalesced projection for the live dashboard. Collectors may
/// update independently, but SwiftUI receives at most one coherent snapshot
/// per display interval instead of rebuilding once per publisher.
@MainActor
final class LiveDashboardViewModel: ObservableObject {
    struct Snapshot {
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
    private let maximumEvents = 500
    private let publishDelay: TimeInterval = 0.20

    func updateEvidence(sessions: [AgentSessionSnapshot], events: [GuardEvent],
                        incidents: [SecurityIncident], health: [CollectorHealthRecord]) {
        pending.sessions = sessions
        pending.events = Array(events.prefix(maximumEvents))
        pending.incidents = incidents.filter { $0.severity != "info" }
        pending.health = health
        schedulePublish()
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
