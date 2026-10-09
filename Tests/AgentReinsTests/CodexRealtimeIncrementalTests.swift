import Foundation
import XCTest
@testable import AgentReins

/// Source-format checks use a temporary live stream and exact byte checkpoints.
/// They do not treat the projected UI as proof that a record was captured.
final class CodexRealtimeIncrementalTests: XCTestCase {
    private struct Stream {
        let root: URL
        let url: URL
        var sizes: [String: UInt64] = [:]
        var states: [String: CodexSight.StreamState] = [:]
        var raw: [RawEvidenceRecord] = []
        var failures = 0

        func append(_ value: String) throws {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(value.utf8))
        }
        mutating func poll() -> [GuardEvent] {
            let batch = CodexSight.readLiveEvents(root: root.path, previousSizes: sizes,
                                                  baselineOtherStreams: false, states: states)
            sizes.merge(batch.sizes) { _, new in new }
            states = batch.states
            raw = batch.raw
            failures = batch.rawFailures
            return batch.events
        }
    }

    private func stream() throws -> Stream {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("codex-incremental-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("rollout-2026-10-09T00-00-00-11111111-2222-3333-4444-555555555555.jsonl")
        try Data().write(to: url)
        return Stream(root: root, url: url)
    }

    private func row(_ type: String, _ payload: [String: Any], second: Int = 0) throws -> String {
        let object: [String: Any] = ["timestamp": String(format: "2026-10-09T00:00:%02dZ", second),
                                    "type": type, "payload": payload]
        return String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self) + "\n"
    }

    private func begin(_ stream: inout Stream) throws {
        try stream.append(row("session_meta", ["id": "session-real", "cwd": "/tmp/project"]))
        try stream.append(row("event_msg", ["type": "task_started", "turn_id": "one"], second: 1))
        try stream.append(row("event_msg", ["type": "user_message", "message": "原始需求 A", "turn_id": "one"], second: 2))
    }

    func testLiveCursorRestoresIdentityWithoutReadingOldMessagesAgain() throws {
        var source = try stream(); try begin(&source); _ = source.poll()
        let checkpoint = source.root.appendingPathComponent("cursor.json")
        try CodexSight.saveLiveCursorCheckpoint(sizes: source.sizes, states: source.states, to: checkpoint)
        try source.append(row("response_item", ["type":"function_call", "call_id":"resume", "name":"exec_command", "arguments":"{\"cmd\":\"echo next\"}"], second: 3))
        let baseline = RealtimeLogBaseline.offsets(root: source.root)
        let restored = CodexSight.restoreLiveCursorCheckpoint(root: source.root, baselineOffsets: baseline, from: checkpoint)
        XCTAssertNotNil(restored.savedAt); XCTAssertTrue(restored.gaps.isEmpty)
        let batch = CodexSight.readLiveEvents(root: source.root.path, previousSizes: restored.sizes, baselineOtherStreams: false, states: restored.states)
        XCTAssertFalse(batch.events.contains { $0.op == "prompt" })
        let call = try XCTUnwrap(batch.events.first { $0.op == "call" })
        XCTAssertEqual(call.turnId, "one"); XCTAssertEqual(call.sessionId, "session-real")
    }
    func testIdentityAndToolBindingSurviveMoreThan64KiBBetweenPolls() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("response_item", ["type": "function_call", "call_id": "call-a", "name": "exec_command", "arguments": "{\"cmd\":\"printf hello\"}"], second: 3))
        let first = source.poll()
        XCTAssertEqual(first.first { $0.op == "prompt" }?.userIntent, "原始需求 A")
        let firstCheckpoint = try XCTUnwrap(source.sizes.values.first)
        let padding = try row("event_msg", ["type": "status", "padding": String(repeating: "x", count: 150_000)], second: 4)
        try source.append(padding)
        XCTAssertTrue(source.poll().isEmpty)
        try source.append(row("response_item", ["type": "function_call_output", "call_id": "call-a", "output": "hello"], second: 5))
        let output = try XCTUnwrap(source.poll().first { $0.op == "result" })
        XCTAssertEqual(output.sessionId, "session-real")
        XCTAssertEqual(output.turnId, "one")
        XCTAssertEqual(output.toolName, "exec_command")
        XCTAssertEqual(output.modelResponse, "hello")
        XCTAssertEqual(source.raw.first?.offsetStart, Int64(firstCheckpoint) + Int64(padding.utf8.count), "Raw checkpoint remains byte based")
        XCTAssertTrue(source.poll().isEmpty, "Already committed rows are not reprojected")
    }

    func testPartialUTF8RowIsBufferedAndEmittedOnlyOnceAfterNewline() throws {
        var source = try stream()
        let data = Data(try row("event_msg", ["type": "user_message", "message": "中文原话", "turn_id": "one"]).utf8)
        let chinese = try XCTUnwrap(data.range(of: Data("中".utf8)))
        let split = chinese.lowerBound + 1
        try Data(data.prefix(split)).write(to: source.url)
        XCTAssertTrue(source.poll().isEmpty)
        XCTAssertEqual(source.sizes.values.first, 0)
        let handle = try FileHandle(forWritingTo: source.url)
        try handle.seekToEnd()
        try handle.write(contentsOf: data.suffix(from: split))
        try handle.close()
        let output = source.poll()
        XCTAssertEqual(output.filter { $0.op == "prompt" }.count, 1)
        XCTAssertEqual(output.first?.userIntent, "中文原话")
        XCTAssertEqual(source.sizes.values.first, UInt64(data.count))
        XCTAssertTrue(source.poll().isEmpty)
    }

    func testRealtimeEOFBaselineDoesNotReadOrInheritOldRequest() throws {
        var source = try stream()
        try source.append(row("event_msg", ["type": "user_message", "turn_id": "old", "message": "不可回填的旧需求"]))
        source.sizes = RealtimeLogBaseline.offsets(root: source.root)
        try source.append(row("response_item", ["id": "message-is-not-session", "type": "function_call", "call_id": "new-call", "name": "Read", "arguments": "{}"], second: 1))
        let event = try XCTUnwrap(source.poll().first)
        XCTAssertEqual(event.sessionId, "11111111-2222-3333-4444-555555555555")
        XCTAssertNil(event.turnId)
        XCTAssertNil(event.userIntent)
        XCTAssertFalse(String(decoding: try XCTUnwrap(source.raw.first).payload, as: UTF8.self).contains("不可回填"))
    }

    func testBaselineInsideAnOldPartialRowSkipsItsSuffixButCapturesNextRequest() throws {
        var source = try stream()
        try source.append("{\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"旧")
        source.sizes = RealtimeLogBaseline.offsets(root: source.root)
        try source.append("需求\"}}\n")
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "fresh"], second: 1))
        try source.append(row("event_msg", ["type": "user_message", "turn_id": "fresh", "message": "新的原话"], second: 2))
        let events = source.poll()
        XCTAssertEqual(events.filter { $0.op == "prompt" }.map(\.userIntent), ["新的原话"])
        XCTAssertEqual(events.first { $0.op == "prompt" }?.turnId, "fresh")
    }

    func testNewTurnClearsIntentWhileLateUniqueCallOutputKeepsItsOwnTurn() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("response_item", ["type": "function_call", "call_id": "old-call", "name": "Read", "arguments": "{}"], second: 3))
        _ = source.poll()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "two"], second: 4))
        try source.append(row("response_item", ["type": "function_call", "call_id": "new-call", "name": "Bash", "arguments": "{}"], second: 5))
        try source.append(row("response_item", ["type": "function_call_output", "call_id": "old-call", "output": "late A"], second: 6))
        let events = source.poll()
        XCTAssertNil(events.first { $0.toolCallId == "new-call" }?.userIntent)
        XCTAssertEqual(events.first { $0.toolCallId == "new-call" }?.turnId, "two")
        XCTAssertEqual(events.first { $0.toolCallId == "old-call" }?.turnId, "one")
        XCTAssertEqual(events.first { $0.toolCallId == "old-call" }?.toolName, "Read")
        XCTAssertFalse(events.contains { $0.userIntent == "原始需求 A" })
    }

    func testReusedCallIDWithoutTurnRemainsAmbiguousInsteadOfJoiningLatest() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("response_item", ["type": "function_call", "call_id": "same", "name": "Read", "arguments": "{}"], second: 3))
        _ = source.poll()
        try source.append(row("turn_context", ["turn_id": "two"], second: 4))
        try source.append(row("response_item", ["type": "function_call", "call_id": "same", "name": "Bash", "arguments": "{}"], second: 5))
        try source.append(row("response_item", ["type": "function_call_output", "call_id": "same", "output": "ambiguous"], second: 6))
        try source.append(row("response_item", ["type": "function_call_output", "call_id": "same", "output": "explicit A", "turn_id": "one"], second: 7))
        let events = source.poll()
        let ambiguous = try XCTUnwrap(events.first { $0.modelResponse == "ambiguous" })
        XCTAssertNil(ambiguous.turnId)
        XCTAssertEqual(ambiguous.toolName, "unknown_tool")
        XCTAssertEqual(events.first { $0.modelResponse == "explicit A" }?.turnId, "one")
        XCTAssertEqual(events.first { $0.modelResponse == "explicit A" }?.toolName, "Read")
    }

    func testAtomicRotationResetsSessionTurnAndCallStateEvenIfNewFileIsLarger() throws {
        var source = try stream()
        try begin(&source)
        _ = source.poll()
        let replacement = try row("session_meta", ["id": "replacement-session", "cwd": "/new"])
            + row("response_item", ["type": "function_call", "call_id": "replacement-call", "name": "Bash", "arguments": String(repeating: "x", count: 3_000)], second: 5)
        try replacement.write(to: source.url, atomically: true, encoding: .utf8)
        let event = try XCTUnwrap(source.poll().first { $0.op == "call" })
        XCTAssertEqual(event.sessionId, "replacement-session")
        XCTAssertNil(event.turnId)
        XCTAssertNil(event.userIntent)
        XCTAssertEqual(source.raw.first?.offsetStart, 0)
    }

    func testTruncationRestartsAtZeroWithoutOldTurnOrIntent() throws {
        var source = try stream()
        try begin(&source)
        _ = source.poll()
        let handle = try FileHandle(forWritingTo: source.url)
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: Data(try row("response_item", ["type": "function_call", "call_id": "only", "name": "Read", "arguments": "{}"], second: 5).utf8))
        try handle.close()
        let event = try XCTUnwrap(source.poll().first)
        XCTAssertNil(event.turnId)
        XCTAssertNil(event.userIntent)
        XCTAssertEqual(source.raw.first?.offsetStart, 0)
    }

    func testNativeCommandItemsPreserveActualCommandOutputTimingAndExit() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("event_msg", ["type": "item_started", "turn_id": "one", "started_at_ms": 1_000,
            "item": ["type": "CommandExecution", "id": "native-exec", "command": ["/bin/zsh", "-lc", "printf hello"], "cwd": "/work", "status": "in_progress", "process_id": "runner-session", "pid": 123]], second: 3))
        let start = try XCTUnwrap(source.poll().first { $0.op == "exec_start" })
        XCTAssertEqual(start.toolCallId, "execution:native-exec")
        XCTAssertEqual(start.path, "/work")
        XCTAssertEqual(start.processId, 123)
        XCTAssertTrue(start.command?.contains("printf hello") == true)
        XCTAssertEqual(start.startedAt, Date(timeIntervalSince1970: 1))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "one", "started_at_ms": 1_000, "completed_at_ms": 2_500,
            "item": ["type": "CommandExecution", "id": "native-exec", "command": ["/bin/zsh", "-lc", "printf hello"], "cwd": "/work", "status": "failed", "stdout": "hello", "stderr": "problem", "exit_code": 7, "process_id": "runner-session", "pid": 123, "duration": ["secs": 1, "nanos": 500_000_000]]], second: 4))
        let result = try XCTUnwrap(source.poll().first { $0.op == "result" })
        XCTAssertEqual(result.toolCallId, start.toolCallId)
        XCTAssertEqual(result.action, "failed")
        let body = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(try XCTUnwrap(result.modelResponse).utf8)) as? [String: Any])
        XCTAssertEqual(body["stdout"] as? String, "hello")
        XCTAssertEqual(body["stderr"] as? String, "problem")
        XCTAssertEqual(body["exit_code"] as? Int, 7)
        XCTAssertEqual(body["process_id"] as? String, "runner-session")
        XCTAssertEqual(result.durationMS, 1_500)
        XCTAssertEqual(result.endedAt, Date(timeIntervalSince1970: 2.5))
    }

    func testExplicitOutputDeltaDoesNotInventFinalCompletion() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("event_msg", ["type": "exec_command_begin", "turn_id": "one", "call_id": "exec-a", "command": ["sh", "-c", "echo chunk"], "cwd": "/work"], second: 3))
        _ = source.poll()
        try source.append(row("event_msg", ["type": "exec_command_output_delta", "call_id": "exec-a", "channel": "stderr", "delta": "live line\n"], second: 4))
        let delta = try XCTUnwrap(source.poll().first)
        XCTAssertEqual(delta.op, "output")
        XCTAssertEqual(delta.action, "streaming")
        XCTAssertEqual(delta.modelResponse, "live line\n")
        XCTAssertEqual(delta.turnId, "one")
        XCTAssertTrue(delta.command?.contains("stderr") == true)
        try source.append(row("event_msg", ["type": "exec_command_end", "call_id": "exec-a", "stdout": "done", "stderr": "live line\n", "exit_code": 0], second: 5))
        let end = try XCTUnwrap(source.poll().first)
        XCTAssertEqual(end.op, "result")
        XCTAssertEqual(end.action, "completed")
        XCTAssertEqual(end.toolCallId, delta.toolCallId)
    }

    func testExplicitLifecycleDistinguishesCompleteFailureAndConfirmedAbort() throws {
        var source = try stream()
        try begin(&source)
        _ = source.poll()
        try source.append(row("event_msg", ["type": "task_complete", "turn_id": "one", "last_agent_message": "产物在 /tmp/result.txt"], second: 3))
        try source.append(row("event_msg", ["type": "task_failed", "turn_id": "two", "message": "fatal-X"], second: 4))
        try source.append(row("event_msg", ["type": "turn_aborted", "turn_id": "three", "reason": "user cancelled"], second: 5))
        let events = source.poll()
        XCTAssertEqual(events.first { $0.ruleId == "codex_task_complete" }?.action, "completed")
        XCTAssertEqual(events.first { $0.op == "task_failed" }?.modelResponse, "fatal-X")
        XCTAssertEqual(events.first { $0.op == "task_cancelled" }?.action, "cancelled")
        XCTAssertEqual(events.first { $0.op == "task_cancelled" }?.turnId, "three")
    }

    func testNativeUserMessageUsesTurnMetadataAndNeverUsesMessageIDAsTurn() throws {
        var source = try stream()
        try source.append(row("event_msg", ["type": "item_completed", "internal_chat_message_metadata_passthrough": ["turn_id": "native-turn"],
            "item": ["type": "UserMessage", "id": "message-id", "content": [["type": "text", "text": "## My request:\n准确原话"]]]]))
        let event = try XCTUnwrap(source.poll().first)
        XCTAssertEqual(event.turnId, "native-turn")
        XCTAssertEqual(event.userIntent, "准确原话")
        XCTAssertNotEqual(event.sessionId, "message-id")
    }

    func testStructuredFunctionOutputRetainsFieldsInsteadOfDroppingBody() throws {
        var source = try stream()
        try begin(&source)
        try source.append(row("response_item", ["type": "function_call", "call_id": "a", "name": "Read", "arguments": [:]], second: 3))
        _ = source.poll()
        try source.append(row("response_item", ["type": "function_call_output", "call_id": "a", "output": ["stdout": "visible", "exit_code": 0]], second: 4))
        let result = try XCTUnwrap(source.poll().first)
        XCTAssertTrue(result.modelResponse?.contains("visible") == true)
        XCTAssertTrue(result.modelResponse?.contains("exit_code") == true)
        XCTAssertEqual(result.turnId, "one")
    }
}
