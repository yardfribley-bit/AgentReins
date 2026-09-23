import Foundation

/// A lightweight database index row. Full evidence is fetched only after the
/// user opens the task, keeping history navigation independent of JSON size.
struct StoredTaskSummary: Identifiable, Sendable {
    let sessionID: String
    let turnID: String
    let agentID: String
    let title: String?
    let startedAt: Date
    let lastObservedAt: Date
    let eventCount: Int

    var id: String { "\(sessionID)\u{0}\(turnID)" }
}
