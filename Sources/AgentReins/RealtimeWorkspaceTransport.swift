import Foundation

/// List/status updates carry one selected task's execution bodies. Other tasks
/// retain identity, demand, lifecycle and search metadata; details load on click.
enum RealtimeWorkspaceTransport {
    struct TaskDetail: Encodable {
        let task: RealtimeTask
        let contexts: [RealtimeContextExchange]
    }
    /// Compare visible revisions/metadata before JSON encoding. Publication time
    /// and database health heartbeats do not represent new workspace content.
    struct PublicationKey: Equatable {
        let tasks: [String], collected: [String]
        let processes: [RealtimeProcess], health: [RealtimeHealth]
        let artifacts: [RealtimeArtifact], locations: [RealtimeIPLocation]
        let readTaskIDs: [String]
        let observing: Bool, truncated: Bool
        let error: String?, continuity: String?
        let count: Int, unattributed: Int
    }
    static func publicationKey(_ payload: RealtimeWorkspacePayload) -> PublicationKey {
        PublicationKey(tasks: payload.tasks.map { $0.id + "\u{0}" + $0.projectionRevision },
            collected: payload.collected.map { $0.id + "\u{0}" + $0.revision },
            processes: payload.processes, health: payload.health, artifacts: payload.artifacts,
            locations: payload.ipGeolocations, readTaskIDs: payload.readTaskIDs,
            observing: payload.observing, truncated: payload.truncated, error: payload.persistenceError,
            continuity: payload.continuityNotice, count: payload.collectedCount, unattributed: payload.unattributedCount)
    }
    struct DetailDelta: Encodable {
        let taskID: String
        let baseRevision: String
        let cardOrder: [String]
        let contextOrder: [String]
    }
    static func selectedID(_ payload: RealtimeWorkspacePayload, requested: String?) -> String? {
        if let requested, payload.tasks.contains(where: { $0.id == requested }) { return requested }
        return payload.tasks.filter(\.isPrimaryTask).max { $0.startedAt < $1.startedAt }?.id ?? payload.tasks.first?.id
    }
    static func project(_ payload: RealtimeWorkspacePayload, selectedTaskID: String?, omitSelectedDetails: Bool = false, knownCollected: [String: String] = [:], knownDetail: TaskDetail? = nil) -> RealtimeWorkspacePayload {
        let id = selectedID(payload, requested: selectedTaskID)
        var value = payload
        value.tasks = payload.tasks.map { task in
            guard task.id != id || omitSelectedDetails else { return task }
            var summary = task; summary.cards = []; summary.detailsLoaded = false
            return summary
        }
        if !omitSelectedDetails, let task = payload.tasks.first(where: { $0.id == id }) {
            value.contexts = contexts(payload, task: task)
        } else { value.contexts = [] }
        if !knownCollected.isEmpty {
            value.collectedOrder = payload.collected.map(\.id)
            value.collected = payload.collected.filter { knownCollected[$0.id] != $0.revision }
        }
        if !omitSelectedDetails, let knownDetail,
           let index = value.tasks.firstIndex(where: { $0.id == knownDetail.task.id && $0.detailsLoaded }) {
            let cards = Dictionary(knownDetail.task.cards.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
            let previousContexts = Dictionary(knownDetail.contexts.map { ($0.id, $0) }, uniquingKeysWith: { _, new in new })
            value.detailDelta = DetailDelta(taskID: knownDetail.task.id, baseRevision: knownDetail.task.projectionRevision,
                cardOrder: value.tasks[index].cards.map(\.id), contextOrder: value.contexts.map(\.id))
            value.tasks[index].cards.removeAll { cards[$0.id] == $0 }
            value.contexts.removeAll { previousContexts[$0.id] == $0 }
        }
        value.lazyTasks = true
        return value
    }
    static func contexts(_ payload: RealtimeWorkspacePayload, task: RealtimeTask) -> [RealtimeContextExchange] {
        payload.contexts.filter { $0.agent == task.agent && $0.session == task.session && $0.turn == task.turn }
    }
}
