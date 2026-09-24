import XCTest
@testable import AgentReins

final class TaskStoryRegressionTests: XCTestCase {
    func testTraceOutputProvidesModelAndResponseWithExactSpanLink() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let prompt = GuardEvent(kind: "model", ruleId: "test", path: "-", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date(timeIntervalSince1970: 100),
            action: "sent", sessionId: "s", turnId: "t", userIntent: "hello")
        let output = #"[{"model":"hy3","choices":[{"message":{"content":"你好，代码已经写好。"}}]}]"#
        let trace: [String: Any] = [
            "trace": ["traceId": "trace_test", "workerPid": 42, "startedAt": "1970-01-01T00:01:41.000Z"],
            "spans": [["type": "generation", "spanId": "span_1", "startedAt": "1970-01-01T00:01:42.000Z",
                       "endedAt": "1970-01-01T00:01:45.000Z", "toolInput": "hello", "toolOutput": output]]]
        let url = root.appendingPathComponent("trace_test.json")
        try JSONSerialization.data(withJSONObject: trace).write(to: url)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 105)], ofItemAtPath: url.path)
        let requests = WorkBuddyTraceRequests.load(events: [prompt], root: root)
        let responses = WorkBuddyTraceRequests.responses(for: requests)
        XCTAssertEqual(requests.first?.model, "hy3")
        XCTAssertEqual(responses.first?.content, "你好，代码已经写好。")
        let journey = AgentTaskJourney.build(requests: requests, responses: responses, tools: [], toolResults: [], files: [])
        XCTAssertEqual(journey.rounds.first?.responseCorrelation, "exactGenerationSpan")
        XCTAssertEqual(journey.rounds.first?.response?.model, "hy3")
        XCTAssertEqual(journey.rounds.first?.requestToResponseMS, 3_000)
        XCTAssertTrue(journey.unassignedResponses.isEmpty)
    }

    func testResponseWithoutRequestRemainsAvailable() {
        let response = AgentModelResponseEvidence(eventID: "r", receivedAt: Date(), traceID: nil,
            model: "hy3", content: "已完成", recordedReasoning: nil, evidenceSource: "transcript")
        let journey = AgentTaskJourney.build(requests: [], responses: [response], tools: [], toolResults: [], files: [])
        XCTAssertEqual(journey.unassignedResponses.first?.content, "已完成")
    }

    func testHistoryPaginationDoesNotReturnOlderPartOfAlreadyListedTask() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try EvidenceDatabase(url: directory.appendingPathComponent("test.sqlite3"))
        func event(_ sequence: UInt64, _ turn: String, _ time: Double) -> AgentEventEnvelope {
            AgentEventEnvelope(id: "e\(sequence)", projectID: "p", agentID: "workbuddy",
                sessionID: "s", turnID: turn, sequence: sequence, occurredAt: Date(timeIntervalSince1970: time),
                observedAt: Date(timeIntervalSince1970: time), source: .agentProtocol,
                confidence: .confirmed, payload: .turnState(.queued))
        }
        try database.appendAgentEvents([event(1, "a", 1), event(2, "b", 2), event(3, "a", 3)])
        XCTAssertEqual(try database.recentTasks(limit: 1).first?.turnID, "a")
        XCTAssertEqual(try database.recentTasks(limit: 1, offset: 1).first?.turnID, "b")
        XCTAssertEqual(try database.recentTasks(limit: 10, before: Date(timeIntervalSince1970: 3)).map(\.turnID), ["b"])
    }
}
