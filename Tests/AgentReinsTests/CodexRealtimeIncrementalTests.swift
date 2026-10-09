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

    func testRuntimeUserContextNeverBecomesDemandOrOverwritesHumanInput() throws {
        var source = try stream()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "one"]))
        try source.append(row("response_item", ["type": "message", "role": "user", "content": [["type": "input_text", "text": "<environment_context>runtime</environment_context>"]]], second: 1))
        try source.append(row("response_item", ["type": "message", "role": "user", "content": [["type": "input_text", "text": "真正的用户需求"]]], second: 2))
        try source.append(row("response_item", ["type": "message", "role": "user", "content": [["type": "input_text", "text": "<in-app-browser-context source=\"ambient\">state</in-app-browser-context>"]]], second: 3))
        try source.append(row("response_item", ["type": "function_call", "call_id": "tool", "name": "Read", "arguments": "{}"], second: 4))
        let events = source.poll()
        XCTAssertEqual(events.filter { $0.op == "prompt" }.map(\.userIntent), ["真正的用户需求"])
        XCTAssertEqual(events.filter { $0.op == "runtime_user_context" }.count, 2)
        XCTAssertEqual(events.first { $0.toolCallId == "tool" }?.userIntent, "真正的用户需求")
        let tasks = RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast)
        XCTAssertEqual(tasks.first?.originalRequest, "真正的用户需求")
    }

    func testSourceMetadataSeparatesRuntimeInjectionFromLiteralHumanWrapper() throws {
        var source = try stream()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "one"]))
        let injected = "<environment_context>\n## My request:\n运行时字段不是人的需求\n</environment_context>"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "one", "content_item_kinds": ["environments.environment_context"]],
            "content": [["type": "input_text", "text": injected]]], second: 1))
        let human = "<environment_context>这是用户明确输入的引用文本</environment_context>"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "one", "content_item_kinds": ["user.text"]],
            "content": [["type": "input_text", "text": human]]], second: 2))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "one",
            "item": ["type": "UserMessage", "id": "human-native", "content": [["type": "text", "text": human]]]], second: 3))
        try source.append(row("response_item", ["type": "function_call", "call_id": "tool", "name": "Read", "arguments": "{}"], second: 4))
        let events = source.poll()
        XCTAssertEqual(events.filter { $0.op == "runtime_user_context" }.count, 1)
        XCTAssertEqual(events.filter { $0.op == "prompt" }.map(\.userIntent), [human, human])
        XCTAssertEqual(events.first { $0.toolCallId == "tool" }?.userIntent, human)
        XCTAssertEqual(RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast).first?.originalRequest, human)
    }

    func testHumanTranscriptExampleRemainsDemandWhileRecoveredTranscriptDoesNotRewindTurn() throws {
        var source = try stream(); try begin(&source); _ = source.poll()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "two"], second: 3))
        let human = "请分析这段聊天样例：\n[0] user: 样例问题\n[1] assistant: 样例回答"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "two", "content_item_kinds": ["user.text"]],
            "content": [["type": "input_text", "text": human]]], second: 4))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "two",
            "item": ["type": "UserMessage", "id": "human-example", "content": [["type": "text", "text": human]]]], second: 5))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "one",
            "item": ["type": "UserMessage", "id": "recovered", "content": [["type": "text", "text": "[0] user: 旧需求\n[1] assistant: 旧回答"]]]], second: 6))
        try source.append(row("response_item", ["type": "function_call", "call_id": "current", "name": "Read", "arguments": "{}"], second: 7))
        let events = source.poll()
        XCTAssertEqual(events.filter { $0.op == "prompt" }.map(\.userIntent), [human, human])
        XCTAssertEqual(events.filter { $0.op == "recovered_transcript" }.count, 1)
        XCTAssertEqual(events.first { $0.op == "recovered_transcript" }?.turnId, "one")
        XCTAssertEqual(events.first { $0.toolCallId == "current" }?.turnId, "two")
        XCTAssertEqual(events.first { $0.toolCallId == "current" }?.userIntent, human)
        XCTAssertEqual(source.states.values.first?.currentTurn, "two")
    }

    func testImageOnlyTransportAndNativeMessageCaptureAttachmentsWithoutInventingDemand() throws {
        var source = try stream(); try begin(&source); _ = source.poll()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "image-turn"], second: 3))
        let wrapper = "# Files mentioned by the user:\n\n## screenshot.png: /tmp/screenshot.png\nImage attachment: true\n\n## My request:\n\n"
        let transport = wrapper + "<image name=[Image #1] path=\"/tmp/screenshot.png\">\n</image>"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "image-turn", "content_item_kinds": ["user.text", "user.image"]],
            "content": [["type": "input_text", "text": transport], ["type": "input_image", "image_url": "data:image/png;base64,fixture"]]], second: 4))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "image-turn",
            "item": ["type": "UserMessage", "id": "image-message", "content": [["type": "text", "text": wrapper], ["type": "local_image", "path": "/tmp/screenshot.png"]]]], second: 5))
        try source.append(row("response_item", ["type": "function_call", "call_id": "image-tool", "name": "Read", "arguments": "{}"], second: 6))
        let events = source.poll()
        XCTAssertEqual(events.filter { $0.op == "prompt" }.count, 2)
        XCTAssertTrue(events.filter { $0.op == "prompt" }.allSatisfy { $0.userIntent == nil })
        XCTAssertEqual(events.filter { $0.op == "attachment" }.count, 2)
        let capturedPaths = events.filter { $0.op == "attachment" }.flatMap { event -> [String] in
            let body = RealtimeDetailProjector.object(event.command)
            return (body?["resources"] as? [[String: String]] ?? []).compactMap { $0["path"] }
        }
        XCTAssertEqual(capturedPaths, ["/tmp/screenshot.png", "/tmp/screenshot.png"])
        let imageTask = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast).first)
        XCTAssertEqual(imageTask.inputAttachments.first?.path, "/tmp/screenshot.png")
        XCTAssertFalse(events.filter { $0.op == "attachment" }.contains { $0.command?.contains("base64") == true })
        XCTAssertNil(events.first { $0.toolCallId == "image-tool" }?.userIntent, "The previous text demand must not leak into this input")
        XCTAssertNil(RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast).first?.originalRequest)
        XCTAssertTrue(events.first { $0.op == "prompt" }?.modelPrompt?.contains("<image") == true, "Captured transport body remains unchanged")
    }

    func testAppEnvelopeExtractsHumanTextAndPreservesCompleteCapturedBody() throws {
        var source = try stream()
        let body = "<in-app-browser-context source=\"ambient\">URL</in-app-browser-context>\n\n## My request:\n请照这张图做原型\n<image path=\"/tmp/example.png\"></image>"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "one", "content_item_kinds": ["user.text", "user.image"]],
            "content": [["type": "input_text", "text": body]]]))
        let request = try XCTUnwrap(source.poll().first { $0.op == "prompt" })
        XCTAssertEqual(request.userIntent, "请照这张图做原型")
        XCTAssertEqual(request.modelPrompt, body)
    }

    func testPlainHumanTextContainingRequestHeadingIsNotRewritten() throws {
        var source = try stream()
        let human = "请解释这个 Markdown 示例：\n## My request:\n示例正文"
        try source.append(row("event_msg", ["type": "user_message", "turn_id": "one", "message": human]))
        XCTAssertEqual(source.poll().first?.userIntent, human)
    }

    func testCapturedImageEnvelopeExposesPathWithoutBase64OrInventedText() throws {
        var source = try stream()
        let body = "# Files mentioned by the user:\n\n## chart.png: /tmp/chart.png\nImage attachment: true\n\n## My request:\n<image path=\"/tmp/chart.png\"></image>"
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "image", "content_item_kinds": ["user.image"]],
            "content": [["type": "input_text", "text": body]]]))
        let events = source.poll()
        let attachment = try XCTUnwrap(events.first { $0.op == "attachment" })
        let resources = RealtimeDetailProjector.object(attachment.command)?["resources"] as? [[String: String]]
        XCTAssertEqual(resources?.first?["path"], "/tmp/chart.png")
        XCTAssertNil(events.first { $0.op == "prompt" }?.userIntent)
        XCTAssertEqual(events.first { $0.op == "prompt" }?.modelPrompt, body)
        XCTAssertTrue(CodexSight.appInputAttachments("请读取 /tmp/chart.png，示例 <image path=\"/tmp/chart.png\"></image>", sourceKinds: ["user.text"]).isEmpty)
        XCTAssertTrue(CodexSight.appInputAttachments("## My request:\n解释 <image path=\"/tmp/chart.png\"></image>", sourceKinds: ["user.text"]).isEmpty)
    }

    func testDelayedOldNativeUserEchoDoesNotRewindActiveTurnOrCurrentDemand() throws {
        var source = try stream(); try begin(&source); _ = source.poll()
        try source.append(row("event_msg", ["type": "task_started", "turn_id": "two"], second: 3))
        try source.append(row("response_item", ["type": "message", "role": "user",
            "internal_chat_message_metadata_passthrough": ["turn_id": "two", "content_item_kinds": ["user.text"]],
            "content": [["type": "input_text", "text": "原始需求 B"]]], second: 4))
        try source.append(row("event_msg", ["type": "item_completed", "turn_id": "one",
            "item": ["type": "UserMessage", "id": "late-old-message", "content": [["type": "text", "text": "原始需求 A"]]]], second: 5))
        try source.append(row("response_item", ["type": "function_call", "call_id": "current-call", "name": "Read", "arguments": "{}"], second: 6))
        let events = source.poll()
        XCTAssertEqual(events.first { $0.toolCallId == "current-call" }?.turnId, "two")
        XCTAssertEqual(events.first { $0.toolCallId == "current-call" }?.userIntent, "原始需求 B")
        XCTAssertEqual(events.first { $0.userIntent == "原始需求 A" }?.turnId, "one")
        XCTAssertEqual(source.states.values.first?.currentTurn, "two")
    }

    func testActiveCheckpointRuntimePromptIsShownAsContextAndDoesNotStealRequest() throws {
        let timestamp = Date(timeIntervalSince1970: 1_000)
        let environment = "<environment_context>runtime fields</environment_context>"
        let incorrect = GuardEvent(kind: "model", ruleId: "codex_model_prompt", path: "/tmp",
            command: nil, agent: "codex", op: "prompt", severity: "info", ts: timestamp, action: "sent",
            sessionId: "s", turnId: "t", userIntent: environment, modelPrompt: environment,
            source: "agentsight:codex-local-compat")
        let human = GuardEvent(kind: "model", ruleId: "codex_model_prompt", path: "/tmp",
            command: nil, agent: "codex", op: "prompt", severity: "info", ts: timestamp.addingTimeInterval(1), action: "sent",
            sessionId: "s", turnId: "t", userIntent: "真正需求", modelPrompt: "真正需求",
            source: "agentsight:codex-local-compat")
        let task = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: [incorrect, human], since: .distantPast).first)
        XCTAssertEqual(task.originalRequest, "真正需求")
        XCTAssertEqual(task.requestEventID, human.id.uuidString)
        XCTAssertEqual(task.cards.filter { $0.kind == "user" }.count, 1)
        let context = try XCTUnwrap(task.cards.first { $0.kind == "context" })
        XCTAssertEqual(context.input, environment)
        XCTAssertEqual(context.eventIDs, [incorrect.id.uuidString])
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

    func testTypedPageContextIsNotDemandAndSteeringInputsStayVisible() throws {
        var source = try stream()
        try source.append(row("event_msg", ["type":"task_started", "turn_id":"one"]))
        try source.append(row("response_item", ["type":"message", "role":"user", "id":"page",
            "internal_chat_message_metadata_passthrough":["turn_id":"one", "content_item_kinds":["additional_content.codex_apps_open_page"]],
            "content":[["type":"input_text", "text":"<external_codex_apps_open_page>{\"page_id\":null}</external_codex_apps_open_page>"]]], second:1))
        for (second, content) in [(2, "继续完成"), (10, "<in-app-browser-context>ambient</in-app-browser-context>\n\n## My request:\ncodex 的用户输入 一直采集失败"), (20, "codex 的用户输入 一直采集失败")] {
            try source.append(row("response_item", ["type":"message", "role":"user", "id":"transport-\(second)",
                "internal_chat_message_metadata_passthrough":["turn_id":"one", "content_item_kinds":["user.text"]],
                "content":[["type":"input_text", "text":content]]], second:second))
            try source.append(row("event_msg", ["type":"item_completed", "turn_id":"one", "item":["type":"UserMessage", "id":"native-\(second)", "content":[["type":"text", "text":content]]]], second:second))
        }
        let events = source.poll()
        let task = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events:events, since:.distantPast).first)
        XCTAssertEqual(task.originalRequest, "继续完成")
        XCTAssertEqual(task.latestUserInput?.content, "codex 的用户输入 一直采集失败")
        XCTAssertEqual(task.userInputs.compactMap(\.content), ["继续完成", "codex 的用户输入 一直采集失败", "codex 的用户输入 一直采集失败"])
        XCTAssertTrue(task.userInputs.allSatisfy { $0.eventIDs.count == 2 })
        XCTAssertEqual(task.cards.filter { $0.kind == "user" }.count, 3)
        XCTAssertEqual(events.filter { $0.op == "runtime_user_context" }.count, 1)
        XCTAssertFalse(task.userInputs.contains { $0.content?.contains("external_codex") == true })
    }

    func testAmbiguousEchoAndDifferentTurnNeverCollapseDistinctInputs() throws {
        var source = try stream()
        for (format, id, turn) in [("transport", "a", "one"), ("native", "b", "one"), ("native", "c", "one"), ("native", "d", "two")] {
            if format == "transport" {
                try source.append(row("response_item", ["type":"message", "role":"user", "id":id, "internal_chat_message_metadata_passthrough":["turn_id":turn, "content_item_kinds":["user.text"]], "content":[["type":"input_text", "text":"重复输入"]]]))
            } else {
                try source.append(row("event_msg", ["type":"item_completed", "turn_id":turn, "item":["type":"UserMessage", "id":id, "content":[["type":"text", "text":"重复输入"]]]]))
            }
        }
        let inputs = RealtimeWorkspaceProjector.userInputs(source.poll())
        XCTAssertEqual(inputs.count, 4)
        XCTAssertTrue(inputs.allSatisfy { $0.eventIDs.count == 1 })
    }

    func testInternalReviewSessionIsObservationNotHumanTask() throws {
        var source = try stream()
        try source.append(row("session_meta", ["id":"review-session", "source":["subagent":["other":"guardian"]]]))
        try source.append(row("event_msg", ["type":"task_started", "turn_id":"review"]))
        try source.append(row("response_item", ["type":"message", "role":"user", "internal_chat_message_metadata_passthrough":["turn_id":"review", "content_item_kinds":["user.text"]], "content":[["type":"input_text", "text":"自动审批器的评审指令"]]]))
        try source.append(row("response_item", ["type":"function_call", "call_id":"review-call", "name":"Read", "arguments":"{}"], second:1))
        let events = source.poll()
        XCTAssertTrue(events.contains { $0.toolName == "codex.internal_review_context" })
        XCTAssertFalse(events.contains { $0.op == "prompt" })
        let task = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events:events, since:.distantPast).first)
        XCTAssertFalse(task.isPrimaryTask)
        XCTAssertNil(task.originalRequest)
        XCTAssertTrue(task.cards.contains { $0.call == "review-call" }, "Keep the underlying technical evidence")
        let legacy = GuardEvent(kind:"model", ruleId:"codex_model_prompt", path:"-", command:nil, agent:"codex", op:"prompt", severity:"info", ts:Date(), action:"sent", sessionId:"old-review", turnId:"old", userIntent:"自动评审", modelPrompt:"自动评审", model:"codex-auto-review", source:"agentsight:codex-local-compat")
        let repaired = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events:[legacy], since:.distantPast).first)
        XCTAssertNil(repaired.originalRequest); XCTAssertFalse(repaired.isPrimaryTask)
    }

    func testActualActiveCodexInputSourceAndCheckpointAgree() throws {
        guard let directory = ProcessInfo.processInfo.environment["AGENTREINS_CODEX_INPUT_FIELD_DIR"] else { throw XCTSkip("需指定本轮真实 Codex 原始切片") }
        let root = URL(fileURLWithPath:directory)
        let events = CodexSight.parseSession(root.appendingPathComponent("current-turn.jsonl"), fullHistory:true)
        let tasks = RealtimeWorkspaceProjector.tasks(events:events, since:.distantPast)
        let earlier = try XCTUnwrap(tasks.first { $0.turn == "01a120d3-559e-7143-bfb8-5548bb348706" })
        XCTAssertEqual(earlier.originalRequest, "继续完成")
        XCTAssertEqual(earlier.userInputs.compactMap(\.content), ["继续完成", "codex 的用户输入 一直采集失败"])
        XCTAssertTrue(earlier.userInputs.allSatisfy { $0.eventIDs.count == 2 })
        let latest = try XCTUnwrap(tasks.first { $0.turn == "01a12119-af3b-79a3-ab43-c251bd1a5423" })
        XCTAssertEqual(latest.originalRequest, "修复 这个问题")
        XCTAssertEqual(latest.userInputs.count, 1)
        XCTAssertEqual(latest.latestUserInput?.content, "修复 这个问题")
        XCTAssertEqual(latest.userInputs.first?.eventIDs.count, 2)
        XCTAssertFalse(tasks.contains { $0.originalRequest?.contains("external_codex_apps") == true })
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let payload = RealtimeWorkspacePayload(tasks:[latest,earlier], collected:[], unattributedCount:0, processes:[], health:[], observing:false, persistenceError:nil, publishedAt:Date(), truncated:false, contexts:RealtimeContextProjector.assemble(events.compactMap(RealtimeContextProjector.parse), events:events))
        try encoder.encode(payload).write(to:root.appendingPathComponent("actual-codex-input-payload.json"))
        if let path = ProcessInfo.processInfo.environment["AGENTREINS_CODEX_REPAIR_CHECKPOINT"] {
            let old = try XCTUnwrap(RealtimeActiveCheckpoint.load(URL(fileURLWithPath:path)))
            let promptIDs = Set(old.events.filter { $0.source == "agentsight:codex-local-compat" && $0.op == "prompt" }.map(\.id))
            var repaired = Dictionary(old.events.map { ($0.id,$0) }, uniquingKeysWith:{ _,new in new })
            // Repair only already-observed user/context records; don't import tool history.
            for event in events where promptIDs.contains(event.id) { repaired[event.id] = event }
            try RealtimeActiveCheckpoint(version:old.version, savedAt:Date(), events:Array(repaired.values), readTaskIDs:old.readTaskIDs).save(root.appendingPathComponent("repaired-active-checkpoint.json"))
        }
    }
}
