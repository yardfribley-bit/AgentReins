import XCTest
@testable import AgentReins

final class DurableEvidencePipelineTests: XCTestCase {
    private func evidence(session: String = "session") -> GuardEvent {
        GuardEvent(kind: "model", ruleId: "test", path: "/tmp/project", command: nil,
                   agent: "workbuddy", op: "prompt", severity: "info", ts: Date(),
                   action: "sent", sessionId: session, turnId: "turn",
                   userIntent: "hello", modelPrompt: "hello")
    }

    func testRestartRecoversWorkAndDuplicateReceiptDoesNotRequeue() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("pipeline.sqlite3")
        let event = evidence()
        do {
            let database = try EvidenceDatabase(url: url)
            try database.append([event, event])
        }
        let reopened = try EvidenceDatabase(url: url)
        let job = try XCTUnwrap(reopened.claimParseJob())
        let canonical = LegacyGuardEventAdapter.project([job.event], projectID: "p", startingSequence: 0)
        try reopened.appendAgentEvents(canonical, completing: job)
        XCTAssertNil(try reopened.claimParseJob())
        try reopened.append([event])
        XCTAssertNil(try reopened.claimParseJob())
        XCTAssertEqual(try reopened.agentEvents(sessionID: "session").count, canonical.count)
    }

    func testExpiredConsumerCannotPublishOrConfirm() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try EvidenceDatabase(url: directory.appendingPathComponent("pipeline.sqlite3"))
        try database.append([evidence()])
        let expired = try XCTUnwrap(database.claimParseJob(now: Date().addingTimeInterval(-120), leaseSeconds: 1))
        let replacement = try XCTUnwrap(database.claimParseJob())
        let canonical = LegacyGuardEventAdapter.project([expired.event], projectID: "p", startingSequence: 0)
        XCTAssertThrowsError(try database.appendAgentEvents(canonical, completing: expired))
        XCTAssertTrue(try database.agentEvents(sessionID: "session").isEmpty)
        try database.appendAgentEvents(canonical, completing: replacement)
        XCTAssertNil(try database.claimParseJob())
    }

    func testRetryDoesNotBlockAnotherSession() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try EvidenceDatabase(url: directory.appendingPathComponent("pipeline.sqlite3"))
        try database.append([evidence(session: "first"), evidence(session: "second")])
        let first = try XCTUnwrap(database.claimParseJob())
        try database.retryParseJob(first, message: "temporary failure")
        let second = try XCTUnwrap(database.claimParseJob())
        XCTAssertNotEqual(first.key, second.key)
    }
}
