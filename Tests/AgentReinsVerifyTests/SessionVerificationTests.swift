import XCTest
@testable import AgentReinsVerify

final class SessionVerificationTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func testClaudeEditKeepsReasoningExcerptAndClaimedPath() throws {
        let raw = """
        {"type":"user","timestamp":"2026-11-08T02:00:00Z","sessionId":"sess-claude","message":{"role":"user","content":"把标题改成你好"}}
        {"type":"assistant","timestamp":"2026-11-08T02:00:02Z","sessionId":"sess-claude","message":{"content":[{"type":"thinking","thinking":"标题在 src/app.swift。"},{"type":"text","text":"我改 src/app.swift 的标题。"},{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"/tmp/proj/src/app.swift","old_string":"Hello","new_string":"你好"}}]}}
        {"type":"assistant","timestamp":"2026-11-08T02:00:30Z","sessionId":"sess-claude","message":{"content":[{"type":"text","text":"已完成，改了 1 个文件。"}]}}
        {"not json"}
        """
        let batch = SessionVerification.parseClaude(Data(raw.utf8), sourcePath: "/tmp/claude.jsonl")
        XCTAssertEqual(batch.malformed, 1)
        XCTAssertEqual(batch.calls.count, 1)
        let call = try XCTUnwrap(batch.calls.first)
        XCTAssertEqual(call.callId, "toolu_1")
        XCTAssertEqual(call.toolName, "Edit")
        XCTAssertTrue(call.reasoning.contains("src/app.swift"))
        XCTAssertEqual(call.claimedPaths, ["/tmp/proj/src/app.swift"])
        XCTAssertTrue(call.claimsEdit)
        XCTAssertEqual(batch.completions["sess-claude"], "已完成，改了 1 个文件。")
        XCTAssertFalse(call.reasoning.contains("已完成"))
    }

    func testLongReasoningIsExcerptNotFullLog() {
        let thinking = String(repeating: "想", count: 2000)
        let raw = """
        {"type":"assistant","timestamp":"2026-11-08T02:00:02Z","sessionId":"s","message":{"content":[{"type":"thinking","thinking":"\(thinking)"},{"type":"tool_use","id":"toolu_long","name":"Read","input":{"file_path":"/tmp/a.txt"}}]}}
        """
        let call = SessionVerification.parseClaude(Data(raw.utf8)).calls[0]
        XCTAssertEqual(call.reasoning.count, SessionVerification.excerptLimit)
        XCTAssertTrue(call.reasoningTruncated)
        XCTAssertFalse(call.claimsEdit)
    }

    func testCodexShellAndCompletion() throws {
        let raw = """
        {"timestamp":"2026-11-08T03:00:01Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"先看本地配置，不访问网络。"}]}}
        {"timestamp":"2026-11-08T03:00:02Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\\"command\\":\\"curl https://uploads.example/secret\\"}"}}
        {"timestamp":"2026-11-08T03:00:20Z","type":"event_msg","payload":{"type":"task_complete","last_agent_message":"已完成"}}
        """
        let path = "/tmp/rollout-2026-11-08T03-00-00-11111111-1111-1111-1111-111111111111.jsonl"
        let batch = SessionVerification.parseCodex(Data(raw.utf8), sourcePath: path)
        let call = try XCTUnwrap(batch.calls.first)
        XCTAssertEqual(call.sessionId, "11111111-1111-1111-1111-111111111111")
        XCTAssertEqual(call.toolName, "shell")
        XCTAssertEqual(call.reasoning, "先看本地配置，不访问网络。")
        XCTAssertEqual(batch.completions[call.sessionId], "已完成")
        XCTAssertFalse(call.claimsEdit)
    }

    func testWorkBuddyEditJoinsALaterFileChangeByPath() throws {
        let line = #"{"type":"function_call","sessionId":"wb-1","timestamp":"2026-11-09T01:00:00Z","name":"Edit","callId":"call-1","arguments":"{\"file_path\":\"/tmp/proj/add.js\"}"}"#
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wb-\(UUID().uuidString)", isDirectory: true)
        let projects = root.appendingPathComponent("projects", isDirectory: true)
        try FileManager.default.createDirectory(at: projects, withIntermediateDirectories: true)
        try Data(line.utf8).write(to: projects.appendingPathComponent("session.jsonl"))
        defer { try? FileManager.default.removeItem(at: root) }
        let loaded = SessionVerification.load(
            claudeRoot: root.appendingPathComponent("missing-claude").path,
            codexRoot: root.appendingPathComponent("missing-codex").path,
            workbuddyRoots: [projects.path])
        XCTAssertEqual(loaded.calls.count, 1)
        let call = try XCTUnwrap(loaded.calls.first)
        XCTAssertEqual(call.agent, "WorkBuddy")
        XCTAssertEqual(call.claimedPaths, ["/tmp/proj/add.js"])
        XCTAssertTrue(call.claimsEdit)
        XCTAssertTrue(loaded.sources.contains { $0.agent == "WorkBuddy" && $0.state == "present" })
        let file = HostEffect(id: "f1", kind: "file", timestamp: call.timestamp.addingTimeInterval(40), path: "/tmp/proj/add.js", source: "file-observe")
        let document = SessionVerification.verify(calls: loaded.calls, effects: [file])
        XCTAssertEqual(document.fileObservation, "present")
        XCTAssertEqual(document.cards.first?.status, "matched")
        XCTAssertEqual(document.cards.first?.happened.first?.join, "path")
        XCTAssertTrue(document.unclaimed.isEmpty)
    }

    func testMissingLogDirectoryStaysEmpty() {
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let loaded = SessionVerification.load(claudeRoot: missing, codexRoot: missing)
        XCTAssertTrue(loaded.calls.isEmpty)
        XCTAssertEqual(loaded.sources.map(\.state), ["absent", "absent"])
        XCTAssertTrue(loaded.sources.allSatisfy { $0.note.contains("目录不在") })
    }

    func testJoinByTimeAndPidAttachesDiff() throws {
        let call = editCall(id: "toolu_1", at: t0, pid: 40, path: "/tmp/proj/src/app.swift", reasoning: "我改 src/app.swift。")
        let file = HostEffect(id: "f1", kind: "file", timestamp: t0.addingTimeInterval(1), pid: 41, path: "/tmp/proj/src/app.swift", diff: "+你好\n-Hello\n", source: "task-card")
        let document = SessionVerification.verify(calls: [call], effects: [file], processes: [ProcessLink(pid: 41, parentPid: 40)], fileChannel: true)
        let card = try XCTUnwrap(document.cards.first)
        XCTAssertEqual(card.status, "matched")
        XCTAssertEqual(card.happened.first?.join, "time-pid")
        XCTAssertEqual(card.happened.first?.diff, "+你好\n-Hello\n")
        XCTAssertTrue(document.unclaimed.isEmpty)
    }

    func testClaimedEditWithoutDiffIsMismatchOnlyWhenFileChannelExists() throws {
        let call = editCall(id: "toolu_1", at: t0, pid: nil, path: "/tmp/proj/src/app.swift", reasoning: "我改 src/app.swift。")
        let flagged = SessionVerification.verify(calls: [call], effects: [], fileChannel: true)
        XCTAssertEqual(flagged.cards.first?.status, "mismatched")
        XCTAssertEqual(flagged.cards.first?.mismatches.map(\.label), ["说了没做"])
        let quiet = SessionVerification.verify(calls: [call], effects: [], fileChannel: false)
        XCTAssertEqual(quiet.cards.first?.status, "matched")
        XCTAssertTrue(quiet.cards.first?.note.contains("文件观测没接上") == true)
        XCTAssertTrue(quiet.cards.first?.mismatches.isEmpty == true)
    }

    func testUnmentionedEgressAndCredential() throws {
        let call = ParsedToolCall(id: "call_1", callId: "call_1", sessionId: "s", agent: "Codex", sourcePath: "x", sourceOffset: 0, timestamp: t0, pid: 7, reasoning: "先看本地配置，不访问网络。", reasoningTruncated: false, toolName: "shell", arguments: "curl", argumentsTruncated: false, claimedPaths: [], claimsEdit: false)
        let net = HostEffect(id: "n1", kind: "network", timestamp: t0.addingTimeInterval(1), pid: 7, remote: "uploads.example", source: "transport")
        let secret = HostEffect(id: "c1", kind: "file", timestamp: t0.addingTimeInterval(1), pid: 7, path: "/tmp/proj/.env", diff: "+TOKEN=1\n", source: "task-card")
        let document = SessionVerification.verify(calls: [call], effects: [net, secret], fileChannel: true)
        let labels = try XCTUnwrap(document.cards.first?.mismatches.map(\.label))
        XCTAssertTrue(labels.contains("做了没说"))
        XCTAssertEqual(document.unclaimed.count, 0)
        let named = ParsedToolCall(id: "call_2", callId: "call_2", sessionId: "s", agent: "Codex", sourcePath: "x", sourceOffset: 0, timestamp: t0, pid: 7, reasoning: "我会请求 uploads.example，并改 .env。", reasoningTruncated: false, toolName: "shell", arguments: "curl", argumentsTruncated: false, claimedPaths: ["/tmp/proj/.env"], claimsEdit: true)
        let quiet = SessionVerification.verify(calls: [named], effects: [net, secret], fileChannel: true)
        XCTAssertFalse(quiet.cards.first?.mismatches.contains { $0.label == "做了没说" } == true)
    }

    func testExtraPathsAndUnclaimedFile() throws {
        let call = editCall(id: "toolu_1", at: t0, pid: 10, path: "/tmp/proj/a.swift", reasoning: "只改 a.swift。")
        let a = HostEffect(id: "a", kind: "file", timestamp: t0.addingTimeInterval(1), pid: 10, path: "/tmp/proj/a.swift", diff: "+a\n", source: "task-card")
        let b = HostEffect(id: "b", kind: "file", timestamp: t0.addingTimeInterval(1), pid: 10, path: "/tmp/proj/b.swift", diff: "+b\n", source: "task-card")
        let stray = HostEffect(id: "c", kind: "file", timestamp: t0.addingTimeInterval(120), pid: 99, path: "/tmp/other.swift", diff: "+c\n", source: "task-card")
        let document = SessionVerification.verify(calls: [call], effects: [a, b, stray], fileChannel: true)
        XCTAssertEqual(document.cards.first?.mismatches.map(\.label), ["做的比说的多"])
        XCTAssertEqual(document.unclaimed.map(\.path), ["/tmp/other.swift"])
    }

    func testExplicitCallIdJoinsAcrossPid() throws {
        let call = editCall(id: "toolu_9", at: t0, pid: 1, path: "/tmp/a.swift", reasoning: "改 a.swift。")
        let file = HostEffect(id: "f", kind: "file", timestamp: t0.addingTimeInterval(80), pid: 2, path: "/tmp/a.swift", diff: "+x\n", toolCallId: "toolu_9", source: "endpoint-security")
        let card = try XCTUnwrap(SessionVerification.verify(calls: [call], effects: [file], fileChannel: true).cards.first)
        XCTAssertEqual(card.happened.first?.join, "call-id")
        XCTAssertEqual(card.status, "matched")
    }

    func testChecklistCountsClaimedActualEgressAndCredentials() throws {
        let call = editCall(id: "toolu_1", at: t0, pid: 3, path: "/tmp/proj/a.swift", reasoning: "改 a.swift。")
        let file = HostEffect(id: "f", kind: "file", timestamp: t0.addingTimeInterval(1), pid: 3, path: "/tmp/proj/a.swift", diff: "+a\n", source: "task-card")
        let other = HostEffect(id: "g", kind: "file", timestamp: t0.addingTimeInterval(2), pid: 3, path: "/tmp/proj/b.swift", diff: "+b\n", source: "task-card")
        let net = HostEffect(id: "n", kind: "network", timestamp: t0.addingTimeInterval(2), pid: 3, remote: "example.com", source: "transport")
        let secret = HostEffect(id: "s", kind: "process", timestamp: t0.addingTimeInterval(2), pid: 3, command: "cat ~/.ssh/id_rsa", credential: true, source: "task-card")
        let document = SessionVerification.verify(
            calls: [call], effects: [file, other, net, secret], completions: [call.sessionId: "已完成，改了 1 个文件。"],
            taskIDs: [call.sessionId: "task-1"], fileChannel: true)
        let list = try XCTUnwrap(document.checklists.first)
        XCTAssertEqual(list.claimedFiles, 1)
        XCTAssertEqual(list.claimedFrom, "done-text")
        XCTAssertEqual(list.actualFiles, 2)
        XCTAssertEqual(list.egressCount, 1)
        XCTAssertTrue(list.credentialsTouched)
        XCTAssertEqual(list.taskId, "task-1")
    }

    func testFiveHundredUnclaimedChangesStayBounded() throws {
        var calls: [ParsedToolCall] = []
        var effects: [HostEffect] = []
        for index in 0..<500 {
            let at = t0.addingTimeInterval(Double(index) * 400)
            calls.append(editCall(id: "call-\(index)", at: at, pid: 10, path: "/tmp/proj/claimed-\(index).swift", reasoning: "改 claimed-\(index).swift。"))
            effects.append(HostEffect(
                id: "stray-\(index)", kind: "file", timestamp: at.addingTimeInterval(200), pid: 99,
                path: "/tmp/other/unclaimed-\(index).swift", diff: "+x\n", sessionId: "sess", source: "file-observe"))
        }
        let distant = editCall(id: "far-call", at: t0.addingTimeInterval(500 * 400), pid: 3, path: "/tmp/proj/far.swift", reasoning: "改 far.swift。")
        calls.append(distant)
        effects.append(HostEffect(
            id: "far-file", kind: "file", timestamp: t0.addingTimeInterval(500 * 400 + 5_000), pid: 4,
            path: "/tmp/proj/far.swift", diff: "+y\n", toolCallId: "far-call", sessionId: "sess", source: "endpoint-security"))
        let document = SessionVerification.verify(calls: calls, effects: effects, fileChannel: true)
        XCTAssertEqual(document.unclaimed.count, 500)
        let joined = try XCTUnwrap(document.cards.first { $0.callId == "far-call" }?.happened.first)
        XCTAssertEqual(joined.join, "call-id")
        XCTAssertLessThan(SessionVerification.lastJoinComparisons, 500 * 6, "join scanned \(SessionVerification.lastJoinComparisons) pairs; a full effects×calls scan is 500×501")
    }

    private func editCall(id: String, at: Date, pid: Int32?, path: String, reasoning: String) -> ParsedToolCall {
        ParsedToolCall(id: id, callId: id, sessionId: "sess", agent: "Claude Code", sourcePath: "x", sourceOffset: 0, timestamp: at, pid: pid, reasoning: reasoning, reasoningTruncated: false, toolName: "Edit", arguments: "{\"file_path\":\"\(path)\"}", argumentsTruncated: false, claimedPaths: [path], claimsEdit: true)
    }
}
