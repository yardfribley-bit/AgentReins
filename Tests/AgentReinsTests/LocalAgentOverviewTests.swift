import XCTest
@testable import AgentReins

final class LocalAgentOverviewTests: XCTestCase {
    static func agent(_ id: String, _ product: String, running: Bool = true) -> DiscoveredAgent {
        DiscoveredAgent(id: id, product: product, presence: running ? .running : .installed,
            instances: ["Desktop"], processIds: [10, 11, 12], confidence: .confirmed,
            identificationEvidence: [], connection: .native, coverage: [.process, .prompt],
            adapter: nil, missing: [], lastSeen: Date())
    }

    func testRunningAppsAreDeduplicatedAndUnknownIsNotIdle() {
        let a = Self.agent("workbuddy", "WorkBuddy")
        let items = LocalAgentOverviewItem.build(agents: [a, a, Self.agent("cursor", "Cursor", running: false)],
            sessions: [], progress: [:], since: .distantPast)
        XCTAssertEqual(items.count, 1)
        XCTAssertFalse(items[0].active)
        XCTAssertFalse(items[0].idle)
        XCTAssertTrue(items[0].models.isEmpty)
    }

    func testCurrentAndRecentModelsRemainDistinct() throws {
        let now = Date()
        let event = GuardEvent(kind: "model", ruleId: "test", path: "/tmp/demo", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: now, action: "sent",
            sessionId: "s", turnId: "t", userIntent: "编写 hello.cpp", modelPrompt: "hello", model: "hy3")
        let sessions = AgentSessionSnapshot.build(from: [event])
        var state = TaskLiveProgress(sessionID: "s", turnID: "t", startedAt: now, lastActivityAt: now, phase: .preparing)
        state.ingest(event)
        func project(_ value: TaskLiveProgress) -> LocalAgentOverviewItem {
            LocalAgentOverviewItem.build(agents: [Self.agent("workbuddy", "WorkBuddy")], sessions: sessions,
                progress: ["s\u{0}t": value], since: now.addingTimeInterval(-1))[0]
        }
        XCTAssertTrue(project(state).active)
        XCTAssertEqual(project(state).models, ["hy3"])
        state.phase = .completed
        XCTAssertFalse(project(state).active)
        XCTAssertTrue(project(state).idle)
        XCTAssertEqual(project(state).models, ["hy3"])
        XCTAssertEqual(project(state).modelObservedAt, now)
    }
}
