import Foundation
import XCTest
@testable import AgentReins

final class RealtimeEvidenceBufferTests: XCTestCase {
    private func event(_ text: String, id: UUID = UUID(), op: String = "result") -> GuardEvent {
        GuardEvent(id: id, kind: "tool", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: op,
                   severity: "info", ts: Date(), action: "completed", sessionId: "s", turnId: "t",
                   userIntent: "保留原始需求", modelResponse: text, toolName: "exec")
    }
    @MainActor func testCollectedRefreshOnlyReadsNewOrRepairedBody() throws {
        let state = RealtimeWorkspaceState(byteBudget: 1024)
        let originals = (0..<30).map { event("exact original \($0)") }
        state.ingest(originals)
        let initial = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertEqual(state.collectedBodyReads, 30)
        let added = event("exact newly collected body")
        state.ingest([added])
        let next = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertEqual(state.collectedBodyReads, 31, "Unchanged evidence must not be decompressed/decoded again")
        for row in initial.collected {
            XCTAssertEqual(next.collected.first { $0.id == row.id }?.details, row.details)
            XCTAssertEqual(next.collected.first { $0.id == row.id }?.revision, row.revision)
        }
        let repaired = event("exact repaired original body", id: originals[0].id)
        state.ingest([repaired])
        let changed = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertEqual(state.collectedBodyReads, 32)
        let row = try XCTUnwrap(changed.collected.first { $0.id == repaired.id.uuidString })
        XCTAssertTrue(row.preview.contains("exact repaired original body"))
        XCTAssertNotEqual(row.revision, initial.collected.first { $0.id == row.id }?.revision)
        XCTAssertEqual(changed.collected.count, 31)
    }
    func testBoundedCollectedIndexMatchesFullSelectionAfterRepairAndCooling() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        func make(_ i: Int, id: UUID = UUID(), kind: String? = nil, at: Double? = nil) -> GuardEvent {
            GuardEvent(id: id, kind: kind ?? (i < 180 ? "network" : "tool"), ruleId: "fixture", path: "-",
                command: nil, agent: "codex", op: "result", severity: "info", ts: Date(timeIntervalSince1970: at ?? Double(i)),
                action: "completed", modelResponse: "exact body \(i)")
        }
        var values = (0..<600).map { make($0) }
        values.forEach { buffer.insert($0) }
        func expected() -> [UUID] {
            let ordered = values.sorted { $0.ts > $1.ts }
            return Array(Set(Array(ordered.prefix(200)) + ordered.filter { $0.kind == "network" }.prefix(100)))
                .sorted { $0.ts > $1.ts }.map(\.id)
        }
        XCTAssertEqual(buffer.latestCollected().records.map(\.id), expected())
        values[599] = make(599, id: values[599].id, kind: "network", at: -1)
        buffer.insert(values[599])
        XCTAssertEqual(buffer.latestCollected().records.map(\.id), expected(), "Timestamp/kind repair must refill both windows correctly")
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let snapshot = buffer.latestCollected()
        XCTAssertEqual(snapshot.records.map(\.id), expected())
        XCTAssertTrue(snapshot.records.allSatisfy { if case .cold = $0.body { return true }; return false }, "Index must not retain obsolete hot bodies")
        let bodies = Dictionary(uniqueKeysWithValues: try snapshot.read().map { ($0.id, $0.modelResponse) })
        for value in values where bodies[value.id] != nil { XCTAssertEqual(bodies[value.id]!, value.modelResponse) }
    }
    func testCoolingBeyondBothLimitsPreservesEveryRecordAndExactBody() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let original = (0..<30).map { event("record-\($0):" + String(repeating: "原文🙂\n", count: 140_000)) }
        original.forEach { buffer.insert($0) }
        XCTAssertGreaterThan(buffer.hotBytes, 32 * 1024 * 1024)
        let plan = buffer.coolingPlan(byteBudget: 1024, countBudget: 2)
        let cooled = try plan.records.map { try $0.cooled(in: plan.directory) }
        buffer.install(cooled)
        XCTAssertLessThanOrEqual(buffer.hotBytes, 1024)
        XCTAssertLessThanOrEqual(buffer.hotCount, 2)
        XCTAssertEqual(buffer.count, original.count)
        let restored = Dictionary(uniqueKeysWithValues: try buffer.snapshot().read().map { ($0.id, $0) })
        for value in original {
            XCTAssertEqual(restored[value.id]?.modelResponse, value.modelResponse)
            XCTAssertEqual(restored[value.id]?.userIntent, value.userIntent)
        }
    }
    func testConcurrentUpdateCannotBeOverwrittenByOldCoolingResult() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let old = event("old")
        buffer.insert(old)
        let plan = buffer.coolingPlan(byteBudget: 0)
        let oldSnapshot = buffer.snapshot()
        let latest = event("latest complete result", id: old.id)
        buffer.insert(latest)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        XCTAssertEqual(try buffer.read(old.id)?.modelResponse, latest.modelResponse)
        XCTAssertEqual(try oldSnapshot.read().first?.modelResponse, old.modelResponse)
    }
    func testColdSnapshotOutlivesWorkingSetAndDetectsCorruptBody() throws {
        var buffer: RealtimeLiveEvidenceBuffer? = RealtimeLiveEvidenceBuffer()
        let original = event("exact evidence")
        buffer?.insert(original)
        let plan = buffer!.coolingPlan(byteBudget: 0)
        buffer?.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let snapshot = buffer!.snapshot()
        buffer = nil
        XCTAssertEqual(try snapshot.read().first?.modelResponse, original.modelResponse)
        guard case .cold(let lease, _, _) = snapshot.records[0].body else { return XCTFail("Expected cold reference") }
        try Data("corrupt".utf8).write(to: lease.url)
        XCTAssertThrowsError(try snapshot.read(), "A corrupt body must never silently disappear from the lifecycle.")
    }
    func testOldColdRevisionIsReleasedAfterItsLastSnapshot() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let original = event("old version")
        buffer.insert(original)
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        var snapshot: RealtimeLiveEvidenceBuffer.Snapshot? = buffer.snapshot()
        let path: String = {
            guard case .cold(let lease, _, _) = snapshot!.records[0].body else { return "" }
            return lease.url.path
        }()
        buffer.insert(event("new version", id: original.id))
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(try snapshot?.read().first?.modelResponse, "old version")
        snapshot = nil
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }
    func testColdDedupDoesNotReadDiskAndDetectsChangesOutsideOldComparisonFields() throws {
        var buffer = RealtimeLiveEvidenceBuffer()
        let original = event("body")
        buffer.insert(original)
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let snapshot = buffer.snapshot()
        if case .cold(let lease, _, _) = snapshot.records[0].body { try FileManager.default.removeItem(at: lease.url) }
        XCTAssertTrue(buffer.unchanged(original), "Dedup checks the in-memory version, not the cold body")
        XCTAssertFalse(buffer.unchanged(event("updated", id: original.id)))
        XCTAssertThrowsError(try snapshot.read(), "Actual consumers still validate body availability")
    }
    @MainActor func testNewestContextWinsWhenSameEventUpdatesDuringParsing() async throws {
        let state = RealtimeWorkspaceState(byteBudget: 1024)
        let id = UUID(), now = Date()
        func prompt(_ body: String) -> GuardEvent {
            GuardEvent(id: id, kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "prompt", severity: "info", ts: now, action: "sent", sessionId: "s", turnId: "t", modelPrompt: body)
        }
        state.ingest([prompt(String(repeating: "old context ", count: 80_000))])
        state.ingest([prompt("latest-context-must-survive")])
        var seen = false
        for _ in 0..<100 {
            let payload = state.payload(processes: [], health: [], observing: true, error: nil)
            seen = payload.contexts.flatMap(\.blocks).contains { $0.content.contains("latest-context-must-survive") }
            if seen { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertTrue(seen)
    }
    @MainActor func testLowMemoryTaskRemainsReadableAndRestoresOriginalToolAndStoppedState() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        let state = RealtimeWorkspaceState(byteBudget: 1024, checkpointURL: url)
        let now = Date()
        let prompt = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "prompt", severity: "info", ts: now, action: "sent", sessionId: "s", turnId: "t", userIntent: "安装指定软件，并核实版本")
        let tool = event(String(repeating: "actual output\n", count: 1000))
        let stop = GuardEvent(kind: "task", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "task_complete", severity: "info", ts: Date(), action: "completed", sessionId: "s", turnId: "t")
        state.ingest([prompt, tool, stop])
        try await Task.sleep(for: .milliseconds(300))
        state.flushCheckpoint()
        let saved = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(Set(saved.events.map(\.id)), Set([prompt.id, tool.id, stop.id]))
        XCTAssertEqual(saved.events.first { $0.id == tool.id }?.modelResponse, tool.modelResponse)
        XCTAssertFalse(saved.coverageTruncated)
        let restored = RealtimeWorkspaceState(byteBudget: 1024, checkpointURL: url)
        let payload = restored.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertEqual(payload.tasks.first?.originalRequest, prompt.userIntent)
        XCTAssertEqual(payload.tasks.first?.lifecycleStatus, "stopped")
        XCTAssertFalse(payload.truncated)
    }
    @MainActor func testOldCoverageGapIsNotErasedByRestartOrNewSuccessfulSave() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [event("partial prior evidence")], readTaskIDs: [], coverageTruncated: true).save(url)
        let state = RealtimeWorkspaceState(checkpointURL: url)
        state.flushCheckpoint()
        XCTAssertTrue(state.payload(processes: [], health: [], observing: true, error: nil).truncated)
        XCTAssertTrue(try XCTUnwrap(RealtimeActiveCheckpoint.load(url)).coverageTruncated)
    }
    @MainActor func testUnreadableCheckpointManifestIsPreservedBeforeNewWrites() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [event("old record")], readTaskIDs: []).save(url)
        let originalManifest = try Data(contentsOf: url)
        let bodies = RealtimeActiveCheckpoint.bodyDirectory(for: url)
        let missingBody = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: bodies, includingPropertiesForKeys: nil).first)
        try FileManager.default.removeItem(at: missingBody)
        let state = RealtimeWorkspaceState(checkpointURL: url)
        state.ingest([event("new observation")]); state.flushCheckpoint()
        let backup = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil).first { $0.lastPathComponent.contains("unreadable-") })
        XCTAssertEqual(try Data(contentsOf: backup), originalManifest)
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events.first?.modelResponse, "new observation")
        XCTAssertTrue(state.payload(processes: [], health: [], observing: true, error: nil).continuityNotice?.contains("无法恢复") == true)
    }
    @MainActor func testSuccessfulRetryClearsOnlyCheckpointError() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let url = root.appendingPathComponent("active.json")
        let state = RealtimeWorkspaceState(checkpointURL: url)
        state.ingest([event("must survive failed save")])
        // Deterministic failure: destination is a directory, so atomic rename fails.
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        state.flushCheckpoint()
        XCTAssertTrue(state.payload(processes: [], health: [], observing: true, error: nil).continuityNotice?.contains("保存失败") == true)
        try FileManager.default.removeItem(at: url)
        state.flushCheckpoint()
        XCTAssertNil(state.payload(processes: [], health: [], observing: true, error: nil).continuityNotice)
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events.count, 1)
    }
}
