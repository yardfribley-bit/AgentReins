import Foundation
import XCTest
@testable import AgentReins

final class RealtimeDeliveryTests: XCTestCase {
    private func event(_ kind: String = "file", op: String = "create", path: String = "/tmp/report.md", action: String = "observed", source: String = "file-test", ts: Date = Date(), intent: String? = nil, response: String? = nil) -> GuardEvent {
        GuardEvent(kind: kind, ruleId: "fixture", path: path, command: nil, agent: "codex", op: op, severity: "info", ts: ts, action: action, sessionId: "s", turnId: "t", userIntent: intent, modelResponse: response, source: source)
    }
    func testArtifactsRequireExplicitSuccessfulWritesNotReadsOrClaims() {
        let events = [event(op: "read"), event(op: "create", action: "requested", source: "tool-intent"), event("model", op: "response", response: "Created /tmp/fake.md"), event(path: "/tmp/actual.md")]
        let tasks = RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast)
        let candidates = RealtimeArtifactProjector.candidates(events: events, tasks: tasks)
        XCTAssertEqual(candidates.map(\.path), ["/tmp/actual.md"])
    }
    func testArtifactProbePreviewAndDisappearance() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("报告.md")
        try "真实报告\n".write(to: file, atomically: true, encoding: .utf8)
        let write = event(path: file.path)
        let candidates = RealtimeArtifactProjector.candidates(events: [write], tasks: RealtimeWorkspaceProjector.tasks(events: [write], since: .distantPast))
        let value = try XCTUnwrap(RealtimeArtifactProjector.probe(candidates).first)
        XCTAssertEqual(value.preview, "真实报告\n"); XCTAssertTrue(value.exists); XCTAssertTrue(value.openable)
        try FileManager.default.removeItem(at: file)
        let missing = try XCTUnwrap(RealtimeArtifactProjector.probe(candidates).first)
        XCTAssertFalse(missing.exists); XCTAssertFalse(missing.openable); XCTAssertNil(missing.preview)
    }
    func testArtifactPreviewHasExplicitLimitAndNeverOpensScripts() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("large.html")
        try String(repeating: "x", count: 70_000).write(to: file, atomically: true, encoding: .utf8)
        let write = event(path: file.path)
        let candidates = RealtimeArtifactProjector.candidates(events: [write], tasks: RealtimeWorkspaceProjector.tasks(events: [write], since: .distantPast))
        let value = try XCTUnwrap(RealtimeArtifactProjector.probe(candidates).first)
        XCTAssertTrue(value.previewTruncated); XCTAssertEqual(value.preview?.count, 65_536); XCTAssertFalse(value.openable)
    }
    func testCheckpointIsVersionedAndDoesNotReadHistoryDatabase() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        XCTAssertNil(try RealtimeActiveCheckpoint.load(url))
        let original = event("model", op: "prompt", intent: String(repeating: "原话", count: 800))
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [original], readTaskIDs: []).save(url)
        let loaded = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(loaded.events.first?.userIntent, original.userIntent)
        XCTAssertEqual(loaded.events.first?.id, original.id)
    }
    @MainActor func testRestoreActiveOriginWithoutImportingOldUnrelatedEvents() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        let old = Date().addingTimeInterval(-300)
        let original = event("model", op: "prompt", ts: old, intent: "恢复这条原话")
        try RealtimeActiveCheckpoint(version: 1, savedAt: old, events: [original], readTaskIDs: []).save(url)
        let state = RealtimeWorkspaceState(checkpointURL: url)
        state.ingest([event("model", op: "prompt", ts: old.addingTimeInterval(1), intent: "不导入的旧需求")])
        let payload = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertEqual(payload.tasks.count, 1)
        XCTAssertEqual(payload.tasks.first?.originalRequest, "恢复这条原话")
        XCTAssertNotNil(payload.continuityNotice)
    }
    @MainActor func testActiveCheckpointEventuallyFlushesDuringContinuousUpdates() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        let state = RealtimeWorkspaceState(checkpointURL: url)
        let original = event("model", op: "prompt", intent: "持续运行任务")
        state.ingest([original])
        for _ in 0..<12 {
            state.ingest([event("activity", op: "process_sample")])
            try await Task.sleep(for: .milliseconds(100))
        }
        let loaded = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertTrue(loaded.events.contains { $0.id == original.id })
    }
    @MainActor func testImmediateShutdownFlushPreservesOriginalRequest() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("active.json")
        let state = RealtimeWorkspaceState(checkpointURL: url)
        let request = event("model", op: "prompt", intent: "立即退出也保留原话")
        state.ingest([request]); state.flushCheckpoint()
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events.first?.userIntent, request.userIntent)
    }
    func testWorkBuddyOriginalRequestIsNotLimitedToOneThousandCharacters() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("session.jsonl")
        let text = String(repeating: "完整用户原话\n", count: 300) + "ORIGINAL-END"
        let row: [String: Any] = ["id":"task", "sessionId":"s", "type":"message", "role":"user", "content":[["type":"text", "text":text]], "timestamp":Date().timeIntervalSince1970 * 1000]
        try JSONSerialization.data(withJSONObject: row).write(to: file)
        let prompt = try XCTUnwrap(WorkBuddySight.parseSession(file, fullHistory: true).first { $0.op == "prompt" })
        XCTAssertTrue(prompt.userIntent?.hasSuffix("ORIGINAL-END") == true)
        XCTAssertEqual(prompt.userIntent, text)
    }
}
