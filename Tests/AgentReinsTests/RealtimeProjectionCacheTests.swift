import Foundation
import XCTest
@testable import AgentReins

final class RealtimeProjectionCacheTests: XCTestCase {
    private func event(_ session: String, text: String = "原始需求", id: UUID = UUID(), turn: String = "turn", kind: String = "model") -> GuardEvent {
        GuardEvent(id: id, kind: kind, ruleId: "fixture", path: "-", command: nil,
                   agent: "codex", op: "prompt", severity: "info", ts: Date(),
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
}
