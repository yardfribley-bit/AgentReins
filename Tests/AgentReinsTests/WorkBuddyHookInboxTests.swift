import Foundation
import XCTest
@testable import AgentReins

final class WorkBuddyHookInboxTests: XCTestCase {
    func testLargeToolResultIsNotSilentlyDroppedAtOldOneMegabyteLimit() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("large.json")
        let result = String(repeating: "x", count: 1_500_000)
        let record: [String: Any] = ["event_id": UUID().uuidString, "hook_event_name": "PostToolUse",
            "observed_at_ms": Date().timeIntervalSince1970 * 1000,
            "payload": ["session_id": "session", "tool_response": result, "call_id": "large"]]
        try JSONSerialization.data(withJSONObject: record).write(to: file)
        let envelope = try XCTUnwrap(WorkBuddyHookInbox.decode(file: file, projects: root))
        let decoded = try JSONSerialization.jsonObject(with: envelope.raw.payload) as! [String: Any]
        XCTAssertEqual((decoded["payload"] as? [String: Any])?["tool_response"] as? String, result)
        XCTAssertEqual(envelope.event.toolCallId, "large")
    }
    func testCaptureGapIsPreservedWithoutConfirmedAttribution() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("gap.json")
        let record: [String: Any] = ["event_id": UUID().uuidString, "hook_event_name": "CaptureGap",
            "observed_at_ms": Date().timeIntervalSince1970 * 1000,
            "payload": ["session_id": "unattributed"],
            "capture_gap": ["reason": "payload_limit_exceeded", "payload_preserved": false]]
        try JSONSerialization.data(withJSONObject: record).write(to: file)
        let envelope = try XCTUnwrap(WorkBuddyHookInbox.decode(file: file, projects: root))
        XCTAssertEqual(envelope.event.op, "hook_capture_gap")
        XCTAssertEqual(envelope.event.attributionConfidence, .unknown)
        XCTAssertTrue(envelope.event.afterContent!.contains("payload_limit_exceeded"))
    }
    func testPreservesToolPayloadAndRejectsOutsideTranscriptHint() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("hook.json")
        let id = UUID()
        let record: [String: Any] = ["event_id": id.uuidString, "hook_event_name": "PreToolUse",
            "observed_at_ms": Date().timeIntervalSince1970 * 1000, "writer_pid": 42,
            "payload": ["session_id": "session", "transcript_path": "/outside/session.jsonl",
                        "tool_name": "Bash", "tool_use_id": "tool-id", "tool_input": ["command": "echo fixture"]]]
        try JSONSerialization.data(withJSONObject: record).write(to: file)
        let envelope = try XCTUnwrap(WorkBuddyHookInbox.decode(file: file, projects: root))
        XCTAssertNil(envelope.transcript)
        XCTAssertEqual(envelope.event.id, id)
        XCTAssertEqual(envelope.event.toolCallId, "tool-id")
        XCTAssertNil(envelope.event.processId, "Hook writer PID must never be attributed as tool PID")
        XCTAssertTrue(envelope.event.afterContent!.contains("echo fixture"))
        XCTAssertEqual(envelope.raw.payload, try Data(contentsOf: file))
    }

    @MainActor
    func testHookWakesNewSessionBeforeStopAndPersistsRawEvidence() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let projects = root.appendingPathComponent("projects")
        let inbox = root.appendingPathComponent("inbox")
        try FileManager.default.createDirectory(at: projects, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase.shared(url: root.appendingPathComponent("evidence.sqlite3"))
        let collector = WorkBuddySight(rootURL: projects, database: database, hookRoot: inbox)
        var events: [GuardEvent] = []
        var deliveryOrder: [String] = []
        collector.onHookSignals = { _ in deliveryOrder.append("signal") }
        collector.onEvents = { events += $0; deliveryOrder.append("committed") }
        collector.start()
        defer { collector.stop() }
        try await Task.sleep(for: .milliseconds(200))
        let file = projects.appendingPathComponent("hook-session.jsonl")
        let row: [String: Any] = ["id": "intent", "sessionId": "hook-session", "type": "message", "role": "user",
            "timestamp": Date().timeIntervalSince1970 * 1000, "content": [["type": "text", "text": "hook fixture task"]]]
        var bytes = try JSONSerialization.data(withJSONObject: row); bytes.append(10)
        try bytes.write(to: file)
        let record: [String: Any] = ["event_id": UUID().uuidString, "hook_event_name": "UserPromptSubmit",
            "observed_at_ms": Date().timeIntervalSince1970 * 1000,
            "payload": ["session_id": "hook-session", "transcript_path": file.path, "prompt": "hook fixture task"]]
        let hookFile = inbox.appendingPathComponent("fixture.json")
        try JSONSerialization.data(withJSONObject: record).write(to: hookFile, options: .atomic)
        let deadline = Date().addingTimeInterval(4)
        while !events.contains(where: { $0.ruleId != "workbuddy_hook_native" && $0.userIntent == "hook fixture task" }) && Date() < deadline {
            try await Task.sleep(for: .milliseconds(25))
        }
        XCTAssertEqual(deliveryOrder.first, "signal", "Control signal must be delivered before committed callback")
        XCTAssertTrue(events.contains { $0.op == "hook_user_prompt" })
        XCTAssertTrue(events.contains { $0.ruleId != "workbuddy_hook_native" && $0.userIntent == "hook fixture task" })
        XCTAssertFalse(FileManager.default.fileExists(atPath: hookFile.path), "Own spool is acknowledged only after transaction")
        XCTAssertTrue(try database.events(sessionId: "hook-session").contains { $0.op == "hook_user_prompt" })
    }
}
