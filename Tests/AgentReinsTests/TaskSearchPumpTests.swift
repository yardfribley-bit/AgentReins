import XCTest
@testable import AgentReins

final class TaskSearchPumpTests: XCTestCase {
    func testActiveAgentDoesNotBlockProjectionIndexingOrIndependentReader() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("evidence.sqlite3")
        let database = try EvidenceDatabase(url: url)
        let writer = try TaskSearchIndex(evidenceURL: url)
        let reader = try TaskSearchIndex(evidenceURL: url)
        let event = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date(), action: "sent",
            sessionId: "busy-task", turnId: "turn", userIntent: "持续执行任务", modelPrompt: "hello", inputTokens: 123)
        try database.append([event])
        _ = try await DurableEvidenceProcessor(database: database).processSlice()
        let processed = try await DurableAnalysisProcessor(database: database).processOne()
        XCTAssertTrue(processed)
        XCTAssertTrue(try TaskSearchPump.step(database: database, index: writer, active: true, initialize: true))
        let plan = HistoryQueryUnderstanding(agent: nil, startDate: nil, endDate: nil, searchTerms: [], evidenceKind: nil,
            requiresAddressInModelInput: false, explanation: "全部任务")
        XCTAssertEqual(try reader.aggregate(plan).taskCount, 1)
        XCTAssertEqual(try reader.search(plan).first?.task.sessionID, "busy-task")
        XCTAssertNil(try database.nextTaskSearchJob())
        XCTAssertEqual(TaskSearchPump.delayMilliseconds(active: true, worked: true), 500)
    }
}
