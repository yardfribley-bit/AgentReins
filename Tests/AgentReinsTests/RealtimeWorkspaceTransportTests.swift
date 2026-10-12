import Foundation
import XCTest
@testable import AgentReins

final class RealtimeWorkspaceTransportTests: XCTestCase {
    private func task(_ id: String, at time: TimeInterval) -> RealtimeTask {
        let cards = (0..<10).map { index in
            RealtimeCard(id: "\(id)-\(index)", kind: "command", title: "exec", status: "returned", tag: "工具结果已返回",
                summary: "执行过程", input: String(repeating: "参数", count: 8_000), output: String(repeating: "输出", count: 8_000),
                source: "fixture", basis: "call ID", confidence: "confirmed", call: "call-\(index)", pid: nil,
                timestamp: Date(timeIntervalSince1970: time), eventIDs: ["event-\(index)"])
        }
        return RealtimeTask(id: id, agent: "Codex", session: id, turn: "turn", title: "需求 \(id)",
            startedAt: Date(timeIntervalSince1970: time), lastActivity: Date(timeIntervalSince1970: time),
            cards: cards, model: nil, reportedComplete: false, originalRequest: "真实需求 \(id)",
            lifecycleStatus: "running", currentStep: "正在执行 exec", searchText: "exec /tmp/真实文件.txt example.com")
    }
    private func payload() -> RealtimeWorkspacePayload {
        RealtimeWorkspacePayload(tasks: (0..<10).map { task("task-\($0)", at: Double($0)) }, collected: [], unattributedCount: 0,
            processes: [], health: [], observing: true, persistenceError: nil, publishedAt: Date(), truncated: false)
    }
    func testIdlePublicationKeyIgnoresClockButDetectsActualChanges() {
        var original = payload()
        let key = RealtimeWorkspaceTransport.publicationKey(original)
        original = RealtimeWorkspacePayload(tasks: original.tasks, collected: [], unattributedCount: 0,
            processes: [], health: [], observing: true, persistenceError: nil,
            publishedAt: Date().addingTimeInterval(120), truncated: false)
        XCTAssertEqual(RealtimeWorkspaceTransport.publicationKey(original), key)
        original.tasks[0].projectionRevision = "new evidence"
        XCTAssertNotEqual(RealtimeWorkspaceTransport.publicationKey(original), key)
        original.tasks.removeAll()
        XCTAssertNotEqual(RealtimeWorkspaceTransport.publicationKey(original), key)
    }
    func testActiveDetailDeltaPreservesExactChangedBodiesAndRemoval() throws {
        var original = payload()
        let old = original.tasks[9]
        let known = RealtimeWorkspaceTransport.TaskDetail(task: old, contexts: [])
        original.tasks[9].projectionRevision = "changed"
        original.tasks[9].cards.removeFirst()
        original.tasks[9].cards[0].phase = "repaired"
        let delta = RealtimeWorkspaceTransport.project(original, selectedTaskID: old.id, knownDetail: known)
        XCTAssertEqual(delta.detailDelta?.baseRevision, old.projectionRevision)
        XCTAssertEqual(delta.detailDelta?.cardOrder, original.tasks[9].cards.map(\.id))
        XCTAssertEqual(delta.tasks[9].cards, [original.tasks[9].cards[0]])
        XCTAssertEqual(original.tasks[9].cards.count, 9)
        let full = RealtimeWorkspaceTransport.project(original, selectedTaskID: old.id)
        XCTAssertLessThan(try JSONEncoder().encode(delta).count * 3, try JSONEncoder().encode(full).count)
        let switched = RealtimeWorkspaceTransport.project(original, selectedTaskID: "task-0", knownDetail: known)
        XCTAssertNil(switched.detailDelta)
        XCTAssertEqual(switched.tasks[0].cards, original.tasks[0].cards)
    }
    func testCollectedDeltaPreservesOrderAndTransmitsSameIDRepair() throws {
        var original = payload()
        var record = RealtimeCollectedRecord(id: "record", agent: "Codex", source: "fixture", kind: "model", op: "prompt", summary: "summary", preview: "exact", hasTaskIdentity: true)
        record.details = String(repeating: "original evidence", count: 10000)
        original.collected = [record]
        let known = [record.id: record.revision]
        let delta = RealtimeWorkspaceTransport.project(original, selectedTaskID: nil, knownCollected: known)
        XCTAssertEqual(delta.collectedOrder, [record.id]); XCTAssertTrue(delta.collected.isEmpty)
        XCTAssertEqual(original.collected.first?.details, record.details)
        record.revision = UUID().uuidString; record.details = "repaired exact body"
        original.collected = [record]
        let repaired = RealtimeWorkspaceTransport.project(original, selectedTaskID: nil, knownCollected: known)
        XCTAssertEqual(repaired.collected.first?.details, "repaired exact body")
        original.collected = []
        let removed = RealtimeWorkspaceTransport.project(original, selectedTaskID: nil, knownCollected: known)
        XCTAssertEqual(removed.collectedOrder, [])
    }
    func testUnchangedSelectedDetailsAreReusedWithoutMutatingSource() throws {
        let original = payload()
        let full = RealtimeWorkspaceTransport.project(original, selectedTaskID: "task-9")
        let delta = RealtimeWorkspaceTransport.project(original, selectedTaskID: "task-9", omitSelectedDetails: true)
        XCTAssertTrue(delta.tasks.allSatisfy { !$0.detailsLoaded && $0.cards.isEmpty })
        XCTAssertTrue(delta.contexts.isEmpty)
        XCTAssertEqual(delta.tasks.map(\.projectionRevision), original.tasks.map(\.projectionRevision))
        XCTAssertEqual(delta.tasks.map(\.originalRequest), original.tasks.map(\.originalRequest))
        XCTAssertEqual(original.tasks.last?.cards.count, 10)
        XCTAssertLessThan(try JSONEncoder().encode(delta).count * 3, try JSONEncoder().encode(full).count)
    }
    func testStatusFeedOnlyCarriesSelectedTaskBodiesAndPreservesDemand() throws {
        let original = payload()
        let summary = RealtimeWorkspaceTransport.project(original, selectedTaskID: nil)
        XCTAssertTrue(summary.lazyTasks)
        XCTAssertEqual(summary.tasks.filter(\.detailsLoaded).map(\.id), ["task-9"])
        XCTAssertTrue(summary.tasks.filter { !$0.detailsLoaded }.allSatisfy { $0.cards.isEmpty && $0.originalRequest != nil && !$0.searchText.isEmpty })
        XCTAssertTrue(original.tasks.allSatisfy { $0.cards.count == 10 }, "Transport must not mutate the evidence projection")
        let encoder = JSONEncoder()
        XCTAssertLessThan(try encoder.encode(summary).count * 5, try encoder.encode(original).count)
    }
    func testSelectingOldTaskReturnsExactExecutionBodiesAndState() throws {
        let original = payload()
        let selected = RealtimeWorkspaceTransport.project(original, selectedTaskID: "task-0")
        let old = try XCTUnwrap(selected.tasks.first { $0.id == "task-0" })
        XCTAssertTrue(old.detailsLoaded)
        XCTAssertEqual(old.cards.map(\.input), original.tasks[0].cards.map(\.input))
        XCTAssertEqual(old.cards.map(\.output), original.tasks[0].cards.map(\.output))
        XCTAssertEqual(old.lifecycleStatus, "running")
        XCTAssertFalse(selected.tasks.first { $0.id == "task-9" }!.detailsLoaded)
        XCTAssertEqual(RealtimeWorkspaceTransport.selectedID(original, requested: "unknown"), "task-9")
    }
}
