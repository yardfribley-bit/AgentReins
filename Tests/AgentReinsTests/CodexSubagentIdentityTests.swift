import Foundation
import XCTest
@testable import AgentReins

final class CodexSubagentIdentityTests: XCTestCase {
    private let child = "11111111-2222-3333-4444-555555555555"
    private let parent = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    private let agentPath = "/root/checkpoint_audit"

    private func stream() throws -> (URL, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("codex-fork-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("rollout-2026-10-10T02-36-00-\(child).jsonl")
        return (root, url)
    }

    private func row(_ type: String, _ payload: [String: Any], second: Int = 0) throws -> String {
        let value: [String: Any] = ["timestamp": String(format: "2026-10-09T18:38:%02dZ", second),
                                   "type": type, "payload": payload]
        return String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self) + "\n"
    }

    private func header() throws -> String {
        try row("session_meta", ["id": child, "cwd": "/tmp/project", "source": ["subagent": ["thread_spawn": [
            "parent_thread_id": parent, "depth": 1, "agent_path": agentPath]]]])
    }

    private func copiedHistory() throws -> String {
        try row("session_meta", ["id": parent, "source": "vscode"])
        + row("event_msg", ["type": "task_started", "turn_id": "parent-turn"])
        + row("response_item", ["type": "message", "role": "user", "content": [["type": "input_text", "text": "用户真正的原始需求"]],
             "internal_chat_message_metadata_passthrough": ["turn_id": "parent-turn", "content_item_kinds": ["user.text"]]])
        + row("response_item", ["type": "function_call", "call_id": "parent-call", "name": "exec_command", "arguments": "{\"cmd\":\"old command\"}"])
        + row("event_msg", ["type": "task_complete", "turn_id": "parent-turn"])
    }

    private func delegation(turn: String = "child-turn", second: Int = 10) throws -> String {
        try row("response_item", ["type": "agent_message", "id": "amsg-child", "author": "/root", "recipient": agentPath,
            "content": [["type": "input_text", "text": "Message Type: NEW_TASK\nPayload:\n"],
                        ["type": "encrypted_content", "encrypted_content": "opaque-ciphertext"]],
            "internal_chat_message_metadata_passthrough": ["turn_id": turn]], second: second)
    }

    func testFullHistoryForkKeepsChildIdentityAndDoesNotCreateHumanTask() throws {
        let (root, url) = try stream()
        let input = try header() + copiedHistory()
            + row("event_msg", ["type": "thread_settings_applied"], second: 8)
            + row("event_msg", ["type": "task_started", "turn_id": "child-turn"], second: 9)
            + delegation()
            + row("response_item", ["type": "custom_tool_call", "name": "exec", "call_id": "screenshot-call", "input": "echo hello"], second: 11)
            + row("response_item", ["type": "custom_tool_call_output", "call_id": "screenshot-call", "output": "hello"], second: 12)
        try Data(input.utf8).write(to: url)
        let batch = CodexSight.readLiveEvents(root: root.path, previousSizes: [:], baselineOtherStreams: false)
        XCTAssertTrue(batch.events.allSatisfy { $0.sessionId == child })
        XCTAssertFalse(batch.events.contains { $0.turnId == "parent-turn" || $0.op == "prompt" || $0.userIntent != nil })
        XCTAssertFalse(batch.events.contains { $0.toolCallId == "parent-call" })
        let call = try XCTUnwrap(batch.events.first { $0.toolCallId == "screenshot-call" && $0.op == "call" })
        XCTAssertEqual(call.turnId, "child-turn")
        XCTAssertEqual(call.command, "echo hello")
        XCTAssertEqual(batch.events.first { $0.toolCallId == "screenshot-call" && $0.op == "result" }?.modelResponse, "hello")
        XCTAssertFalse(batch.events.contains { $0.modelPrompt?.contains("opaque-ciphertext") == true })
        let tasks = RealtimeWorkspaceProjector.tasks(events: batch.events, since: .distantPast)
        let task = try XCTUnwrap(tasks.first { $0.turn == "child-turn" })
        XCTAssertFalse(task.isPrimaryTask)
        XCTAssertEqual(task.title, "子任务 · checkpoint_audit")
        XCTAssertEqual(task.parentSession, parent)
        XCTAssertEqual(task.subagentPath, agentPath)
        XCTAssertNil(task.originalRequest)
        XCTAssertTrue(task.userInputs.isEmpty)
        XCTAssertTrue(task.cards.contains { $0.title == "exec" })
        XCTAssertTrue(String(decoding: try XCTUnwrap(batch.raw.first).payload, as: UTF8.self).contains("opaque-ciphertext"), "Original bytes remain in raw evidence")
    }

    func testInheritedBoundaryAndRoleSurviveIncrementalPolls() throws {
        let (root, url) = try stream()
        try Data((try header() + copiedHistory()).utf8).write(to: url)
        let first = CodexSight.readLiveEvents(root: root.path, previousSizes: [:], baselineOtherStreams: false)
        XCTAssertEqual(first.states.count, 1)
        let nativeKey = try XCTUnwrap(first.states.keys.first { URL(fileURLWithPath: $0).lastPathComponent == url.lastPathComponent })
        XCTAssertEqual(first.states[nativeKey]?.readingInheritedHistory, true)
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        // The exact recipient supplies the boundary when a runtime does not
        // emit thread_settings_applied. There is no user input in this turn.
        try handle.write(contentsOf: Data((try delegation()
            + row("response_item", ["type": "function_call", "name": "exec_command", "call_id": "own", "arguments": "{}"], second: 11)).utf8))
        try handle.close()
        let second = CodexSight.readLiveEvents(root: root.path, previousSizes: first.sizes, baselineOtherStreams: false, states: first.states)
        XCTAssertEqual(second.events.first { $0.op == "call" }?.sessionId, child)
        XCTAssertEqual(second.events.first { $0.op == "call" }?.turnId, "child-turn")
        XCTAssertEqual(second.states[nativeKey]?.internalRole, "thread_spawn")
        XCTAssertEqual(second.states[nativeKey]?.readingInheritedHistory, false)
        XCTAssertFalse(second.events.contains { $0.op == "prompt" })
    }

    func testRestoreRepairsOldParentSessionCursorWithoutReplayingPrompts() throws {
        let (root, url) = try stream()
        try Data((try header()
            + row("event_msg", ["type": "task_started", "turn_id": "child-turn"], second: 1)).utf8).write(to: url)
        let batch = CodexSight.readLiveEvents(root: root.path, previousSizes: [:], baselineOtherStreams: false)
        var legacyStates = batch.states
        XCTAssertEqual(legacyStates.count, 1)
        let nativeKey = try XCTUnwrap(legacyStates.keys.first { URL(fileURLWithPath: $0).lastPathComponent == url.lastPathComponent })
        _ = try XCTUnwrap(legacyStates[nativeKey], "The legacy cursor must be mutated for this test to prove migration")
        legacyStates[nativeKey]?.session = parent
        legacyStates[nativeKey]?.metadataSessionID = nil
        legacyStates[nativeKey]?.subagentIdentity = nil
        legacyStates[nativeKey]?.internalRole = nil
        legacyStates[nativeKey]?.lastIntent = "误继承的父需求"
        legacyStates[nativeKey]?.intentsByTurn = ["child-turn": "误继承的父需求"]
        let checkpoint = root.appendingPathComponent("cursor.json")
        try CodexSight.saveLiveCursorCheckpoint(sizes: batch.sizes, states: legacyStates, to: checkpoint)
        let nativeRoot = URL(fileURLWithPath: nativeKey).deletingLastPathComponent()
        let restored = CodexSight.restoreLiveCursorCheckpoint(root: nativeRoot, baselineOffsets: batch.sizes, from: checkpoint)
        XCTAssertTrue(restored.gaps.isEmpty)
        XCTAssertEqual(restored.states[nativeKey]?.session, child)
        XCTAssertEqual(restored.states[nativeKey]?.subagentIdentity?.parentSession, parent)
        XCTAssertNil(restored.states[nativeKey]?.lastIntent)
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(try row("response_item", ["type": "function_call", "name": "exec_command", "call_id": "resume", "arguments": "{}"], second: 2).utf8))
        try handle.close()
        let resumed = CodexSight.readLiveEvents(root: root.path, previousSizes: restored.sizes, baselineOtherStreams: false, states: restored.states)
        XCTAssertFalse(resumed.events.contains { $0.op == "prompt" || $0.userIntent != nil })
        XCTAssertEqual(resumed.events.first { $0.op == "call" }?.sessionId, child)
        XCTAssertTrue(resumed.events.contains { $0.ruleId == "codex_subagent_identity" && $0.turnId == "child-turn" })
    }

    func testRepairPlanReturnsOnlyExplicitOwnTurnsAndDoesNotMutateSource() throws {
        let (_, url) = try stream()
        let input = try header() + copiedHistory()
            + row("event_msg", ["type": "thread_settings_applied"], second: 8)
            + row("event_msg", ["type": "task_started", "turn_id": "child-turn"], second: 9)
            + delegation()
            + row("event_msg", ["type": "task_started", "turn_id": "child-next"], second: 13)
        let before = Data(input.utf8)
        try before.write(to: url)
        let plan = try XCTUnwrap(CodexSight.subagentRepairPlan(at: url))
        XCTAssertEqual(plan.identity.session, child)
        XCTAssertEqual(plan.identity.parentSession, parent)
        XCTAssertEqual(plan.turnIDs, ["child-turn", "child-next"])
        XCTAssertEqual(try Data(contentsOf: url), before)
        XCTAssertNil(CodexSight.subagentRepairPlan(at: url, maximumBytes: 0))
    }
}
