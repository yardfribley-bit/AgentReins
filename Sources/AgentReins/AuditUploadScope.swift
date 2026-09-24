import Foundation

/// Upload enrollment time is persisted once, not reset on application launch.
/// A recent observation of an old task never makes that task eligible.
struct AuditUploadScope: Codable, Equatable {
    let enabledAt: Date

    func permits(taskStartedAt: Date?, observedUserRequest: Bool) -> Bool {
        guard observedUserRequest, let taskStartedAt else { return false }
        return taskStartedAt >= enabledAt
    }
}
