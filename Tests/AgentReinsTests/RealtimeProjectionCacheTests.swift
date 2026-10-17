import Foundation
import XCTest
@testable import AgentReins

final class RealtimeProjectionCacheTests: XCTestCase {
    private func event(_ session: String, text: String = "原始需求", id: UUID = UUID(), turn: String = "turn", kind: String = "model", agent: String = "codex") -> GuardEvent {
        GuardEvent(id: id, kind: kind, ruleId: "fixture", path: "-", command: nil,
                   agent: agent, op: "prompt", severity: "info", ts: Date(),
                   action: "completed", sessionId: session, turnId: turn,
                   userIntent: text, modelResponse: "hello", toolName: "exec")
    }
    func testUnchangedSessionIsNotReadAgainEvenWhenColdFileIsUnavailable() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        buffer.insert(event("old"))
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let cache = RealtimeProjectionCache()
        let first = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(cache.rebuiltGroups, 1)
        for record in buffer.snapshot().records {
            if case .cold(let lease, _, _) = record.body { try FileManager.default.removeItem(at: lease.url) }
        }
        buffer.insert(event("new", text: "新的需求"))
        let second = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(cache.rebuiltGroups, 2)
        XCTAssertEqual(second.tasks.count, first.tasks.count + 1)
        _ = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(cache.rebuiltGroups, 2, "Idle projection must not rebuild any session")
        buffer.insert(event("old", text: "同会话的新任务", turn: "second"))
        let third = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(third.tasks.count, second.tasks.count + 1, "New turn must not reread the old turn body")
    }
    func testNewContextDoesNotInvalidateUnchangedOldTurn() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let old = event("session", turn: "old", kind: "cmd")
        buffer.insert(old)
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let cache = RealtimeProjectionCache()
        _ = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        for record in buffer.snapshot().records {
            if case .cold(let lease, _, _) = record.body { try FileManager.default.removeItem(at: lease.url) }
        }
        let new = event("session", turn: "new")
        buffer.insert(new)
        let context = RealtimeContextExchange(id: new.id.uuidString, agent: "Codex", session: "session", turn: "new",
            source: "fixture", coverage: "fixture", timestamp: Date(), trace: nil, structured: false,
            characters: 0, counts: [:], blocks: [], fingerprints: [], truncated: false)
        let result = try cache.project(buffer.snapshot(), contexts: [context], since: .distantPast)
        XCTAssertEqual(result.tasks.count, 2)
        XCTAssertTrue(result.tasks.contains { $0.originalRequest == old.userIntent })
    }
    func testUpdatedOriginalRequestRebuildsOnlyItsSession() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        var updated = event("a")
        buffer.insert(updated); buffer.insert(event("b"))
        let cache = RealtimeProjectionCache()
        _ = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(cache.rebuiltGroups, 2)
        updated = event("a", text: "修正后的原始需求", id: updated.id)
        buffer.insert(updated)
        let result = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(cache.rebuiltGroups, 3)
        XCTAssertTrue(result.tasks.contains { $0.originalRequest == "修正后的原始需求" })
    }
    func testWorkBuddyNewTurnKeepsAllUnchangedTaskExportRevisions() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        for turn in 0..<40 { buffer.insert(event("workbuddy", text: "原始需求 \(turn)", turn: "turn-\(turn)", agent: "WorkBuddy")) }
        let cache = RealtimeProjectionCache()
        let first = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        let old = Dictionary(uniqueKeysWithValues: first.tasks.map { ($0.id, $0.projectionRevision) })
        buffer.insert(event("workbuddy", text: "新的实时任务", turn: "new", agent: "WorkBuddy"))
        let second = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        XCTAssertEqual(second.tasks.count, 41)
        XCTAssertEqual(second.tasks.filter { old[$0.id] == $0.projectionRevision }.count, 40,
                       "New WorkBuddy evidence must not trigger re-export of all old task bodies")
        let changed = event("workbuddy", text: "原始需求被修正", id: buffer.snapshot().records.first { $0.turn == "turn-0" }!.id, turn: "turn-0", agent: "WorkBuddy")
        buffer.insert(changed)
        let third = try cache.project(buffer.snapshot(), contexts: [], since: .distantPast)
        let corrected = third.tasks.first { $0.turn == "turn-0" }!
        XCTAssertNotEqual(corrected.projectionRevision, old[corrected.id])
        XCTAssertEqual(corrected.originalRequest, "原始需求被修正")
        XCTAssertEqual(third.tasks.filter { old[$0.id] == $0.projectionRevision }.count, 39)
    }
    func testWorkBuddyAssembledContextChangeInvalidatesOnlyItsTask() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let request = event("workbuddy", agent: "WorkBuddy")
        buffer.insert(request);buffer.insert(event("workbuddy", turn: "other", agent: "WorkBuddy"))
        let cache = RealtimeProjectionCache()
        var context = RealtimeContextExchange(id: request.id.uuidString, agent: "WorkBuddy", session: "workbuddy", turn: "turn",
            source: "fixture", coverage: "fixture", timestamp: request.ts, trace: nil, structured: true,
            characters: 3, counts: ["user":1], blocks: [], fingerprints: [], truncated: false)
        let first = try cache.project(buffer.snapshot(), contexts: [context], contextVersions: [request.id:1], since: .distantPast)
        context.blocks = [RealtimeContextBlock(id: "block", role: "user", label: "用户消息", content: "修正的上下文", fingerprint: "changed", characters: 6, callID: nil)]
        let second = try cache.project(buffer.snapshot(), contexts: [context], contextVersions: [request.id:2], since: .distantPast)
        let firstTask = first.tasks.first { $0.turn == "turn" }!, secondTask = second.tasks.first { $0.turn == "turn" }!
        XCTAssertEqual(firstTask.cards, secondTask.cards)
        XCTAssertNotEqual(firstTask.projectionRevision, secondTask.projectionRevision,
                         "A context change must invalidate detail export even when cards do not change")
        XCTAssertEqual(first.tasks.first { $0.turn == "other" }!.projectionRevision,
                       second.tasks.first { $0.turn == "other" }!.projectionRevision)
    }
}
