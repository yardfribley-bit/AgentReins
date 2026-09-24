import XCTest
@testable import AgentReins

final class AuditUploadScopeTests: XCTestCase {
    func testOnlyTasksStartedAfterEnrollmentWithObservedRequestAreEligible() throws {
        let boundary = Date(timeIntervalSince1970: 1000)
        let scope = AuditUploadScope(enabledAt: boundary)
        XCTAssertFalse(scope.permits(taskStartedAt: boundary.addingTimeInterval(-1), observedUserRequest: true))
        XCTAssertFalse(scope.permits(taskStartedAt: nil, observedUserRequest: true))
        XCTAssertFalse(scope.permits(taskStartedAt: boundary, observedUserRequest: false))
        XCTAssertTrue(scope.permits(taskStartedAt: boundary, observedUserRequest: true))
        let restored = try JSONDecoder().decode(AuditUploadScope.self, from: JSONEncoder().encode(scope))
        XCTAssertEqual(restored, scope)
        XCTAssertFalse(restored.permits(taskStartedAt: boundary.addingTimeInterval(-1), observedUserRequest: true))
    }
}
