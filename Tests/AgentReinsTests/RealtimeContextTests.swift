import Foundation
import XCTest
@testable import AgentReins

final class RealtimeContextTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private func request(_ messages: [[String: Any]], turn: String = "one", agent: String = "workbuddy", seconds: Double = 0, trace: String? = "workbuddy-http:one") throws -> GuardEvent {
        let body = try JSONSerialization.data(withJSONObject: ["messages": messages, "tools": [["type":"function", "function":["name":"read_file"]]]], options: .sortedKeys)
        return GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: agent, op: "network_prompt", severity: "info", ts: start.addingTimeInterval(seconds), action: "captured_complete", sessionId: "session", traceId: trace, turnId: turn, userIntent: messages.last(where: { $0["role"] as? String == "user" })?["content"] as? String, modelPrompt: String(decoding: body, as: UTF8.self), source: "agentsight:workbuddy-network-body")
    }
    func testContextCompositionPreservesRolesAndToolDefinitions() throws {
        let event = try request([["role":"system", "content":"rules"], ["role":"user", "content":"hello"], ["role":"assistant", "tool_calls":[["id":"call", "function":["name":"read_file", "arguments":"{}"]]]], ["role":"tool", "tool_call_id":"call", "content":"file text"]])
        let context = try XCTUnwrap(RealtimeContextProjector.parse(event))
        XCTAssertEqual(context.counts, ["system":1, "user":1, "assistant":1, "tool":1, "tools":1])
        XCTAssertTrue(context.structured); XCTAssertEqual(context.blocks.first { $0.role == "tool" }?.callID, "call")
        XCTAssertTrue(context.blocks.first { $0.role == "assistant" }?.content.contains("read_file") ?? false)
    }
    func testDeltaCountsDuplicatesAndTracksToolResultReturningNextRound() throws {
        let first = try request([["role":"user", "content":"same"], ["role":"user", "content":"same"]])
        let next = try request([["role":"user", "content":"same"], ["role":"tool", "tool_call_id":"call", "content":"hello"]], turn: "two", seconds: 2, trace: "workbuddy-http:two")
        let result = GuardEvent(kind: "tool", ruleId: "fixture", path: "-", command: nil, agent: "workbuddy", op: "result", severity: "info", ts: start.addingTimeInterval(1), action: "completed", sessionId: "session", turnId: "one", toolCallId: "call", modelResponse: "hello")
        let contexts = RealtimeContextProjector.assemble([first,next].compactMap(RealtimeContextProjector.parse), events: [first,next,result])
        let context = try XCTUnwrap(contexts.last)
        XCTAssertEqual(context.previousID, first.id.uuidString)
        XCTAssertEqual(context.added, 1); XCTAssertEqual(context.removed, 1); XCTAssertEqual(context.retained, 2) // includes retained tool definition
        XCTAssertEqual(context.blocks.first { $0.role == "tool" }?.toolEvidenceIDs, [result.id.uuidString])
    }
    func testResponsePairsByFlowNotNearestTimestampOrOtherAgent() throws {
        let first = try request([["role":"user", "content":"hello"]])
        func response(_ agent: String, trace: String) -> GuardEvent { GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: agent, op: "network_response", severity: "info", ts: start.addingTimeInterval(1), action: "received_complete", sessionId: "session", traceId: trace, turnId: "one", modelResponse: agent) }
        let wrong = response("workbuddy", trace: "other"), otherAgent = response("codex", trace: "workbuddy-http:one"), correct = response("workbuddy", trace: "workbuddy-http:one")
        let parsed = try XCTUnwrap(RealtimeContextProjector.parse(first))
        let unmatched = RealtimeContextProjector.assemble([parsed], events: [first,wrong,otherAgent])
        XCTAssertNil(unmatched.first?.responseID)
        XCTAssertEqual(RealtimeContextProjector.assemble([parsed], events: [first,wrong,otherAgent,correct]).first?.responseID, correct.id.uuidString)
    }
    func testLocalFragmentDoesNotBecomeFullContextOrMixAgents() throws {
        let local = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "prompt", severity: "info", ts: start, action: "sent", sessionId: "session", turnId: "one", modelPrompt: "hello")
        let parsed = try XCTUnwrap(RealtimeContextProjector.parse(local))
        XCTAssertFalse(parsed.structured); XCTAssertTrue(parsed.coverage.contains("不代表完整"))
        let workbuddy = try request([["role":"user", "content":"hello"]], seconds: 1)
        let all = RealtimeContextProjector.assemble([parsed,try XCTUnwrap(RealtimeContextProjector.parse(workbuddy))], events: [local,workbuddy])
        XCTAssertEqual(all.count, 2); XCTAssertTrue(all.allSatisfy { $0.previousID == nil })
    }
    func testPreviewLimitDoesNotChangeDeltaFingerprintsOrCompositionCount() throws {
        let first = try request([["role":"system", "content":String(repeating: "a", count: 20_000)]])
        let second = try request([["role":"system", "content":String(repeating: "a", count: 20_000) + "changed-after-preview"]], seconds: 1, trace: "workbuddy-http:two")
        let parsed = [first,second].compactMap(RealtimeContextProjector.parse)
        XCTAssertEqual(parsed[0].blocks[0].content.count, 16_000); XCTAssertTrue(parsed[0].truncated)
        let contexts = RealtimeContextProjector.assemble(parsed, events: [first,second])
        XCTAssertEqual(contexts.last?.added, 1); XCTAssertEqual(contexts.last?.removed, 1)
    }
    func testResponsesAPIInputAndInstructionsAreVisible() throws {
        let body = "{\"instructions\":\"rules\",\"input\":[{\"type\":\"function_call_output\",\"call_id\":\"call\",\"output\":\"hello\"}]}"
        let event = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "network_prompt", severity: "info", ts: start, action: "captured_partial", sessionId: "session", turnId: "one", modelPrompt: body)
        let context = try XCTUnwrap(RealtimeContextProjector.parse(event))
        XCTAssertEqual(context.counts["instructions"], 1); XCTAssertEqual(context.counts["tool"], 1)
        XCTAssertTrue(context.coverage.contains("完整性待核对"))
    }
    @MainActor func testBackgroundParserPublishesToProductionPayload() async throws {
        let event = try request([["role":"user", "content":"hello"]])
        // Runtime start filtering uses current time, not this suite's fixed fixture time.
        let state = RealtimeWorkspaceState()
        state.ingest([event])
        for _ in 0..<50 {
            if !state.payload(processes: [], health: [], observing: true, error: nil).contexts.isEmpty { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        XCTAssertEqual(state.payload(processes: [], health: [], observing: true, error: nil).contexts.first?.counts["user"], 1)
    }
    func testRecordedFieldRequestIfProvided() throws {
        guard let file = ProcessInfo.processInfo.environment["AGENTREINS_CONTEXT_FIELD_CAPTURE"] else { return }
        let records = WorkBuddyNetworkCapture.read(url: URL(fileURLWithPath: file), offset: 0)
        let parsed = records.events.compactMap(RealtimeContextProjector.parse)
        let context = try XCTUnwrap(RealtimeContextProjector.assemble(parsed, events: records.events).first)
        XCTAssertTrue(context.structured)
        XCTAssertNotNil(context.responseID)
        XCTAssertGreaterThan(context.counts["user"] ?? 0, 0)
        XCTAssertEqual(records.malformed, 0)
        if let output = ProcessInfo.processInfo.environment["AGENTREINS_CONTEXT_REVIEW_DIR"] {
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            let payload = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: records.events, since: .distantPast), collected: [], unattributedCount: 0, processes: [], health: [], observing: false, persistenceError: nil, publishedAt: Date(), truncated: false, contexts: [context])
            try encoder.encode(payload).write(to: URL(fileURLWithPath: output).appendingPathComponent("recorded-field-context.json"))
        }
    }
    func testGenerateContextReviewFixture() throws {
        guard let path = ProcessInfo.processInfo.environment["AGENTREINS_CONTEXT_REVIEW_DIR"] else { return }
        let first = try request([["role":"system", "content":"用中文回复。保留真实文件路径，先执行再报告结果。"], ["role":"user", "content":"创建文本文件，写入 hello，然后读取它。"]])
        let next = try request([["role":"system", "content":"用中文回复。保留真实文件路径，先执行再报告结果。"], ["role":"user", "content":"创建文本文件，写入 hello，然后读取它。"], ["role":"assistant", "tool_calls":[["id":"read-call", "function":["name":"read_file", "arguments":"{\"path\":\"/tmp/example.txt\"}"]]]], ["role":"tool", "tool_call_id":"read-call", "content":"hello\n<img src=x onerror='window.hacked=1'>"]], seconds: 2, trace: "workbuddy-http:two")
        let result = GuardEvent(kind: "tool", ruleId: "fixture", path: "/tmp/example.txt", command: "read_file", agent: "workbuddy", op: "result", severity: "info", ts: start.addingTimeInterval(1), action: "completed", sessionId: "session", turnId: "one", toolCallId: "read-call", modelResponse: "hello", toolName: "read_file")
        let response = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "workbuddy", op: "network_response", severity: "info", ts: start.addingTimeInterval(3), action: "received_complete", sessionId: "session", traceId: "workbuddy-http:two", turnId: "one", modelResponse: "文件已创建并读取，内容为 hello。")
        let events = [first,next,result,response]
        let contexts = RealtimeContextProjector.assemble([first,next].compactMap(RealtimeContextProjector.parse), events: events)
        let payload = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: events, since: start), collected: [], unattributedCount: 0, processes: [], health: [], observing: true, persistenceError: nil, publishedAt: start, truncated: false, contexts: contexts)
        let directory = URL(fileURLWithPath: path); try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(payload).write(to: directory.appendingPathComponent("context-fixture.json"))
    }
}
