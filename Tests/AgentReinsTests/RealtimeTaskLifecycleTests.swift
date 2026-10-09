import XCTest
@testable import AgentReins

final class RealtimeTaskLifecycleTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private func record(_ op: String, kind: String = "tool", action: String = "observed", seconds: Double = 0,
                        call: String? = "call", command: String? = nil, output: String? = nil, intent: String? = nil,
                        turn: String? = "turn", source: String? = "fixture", name: String? = "Bash") -> GuardEvent {
        GuardEvent(kind: kind, ruleId: "fixture", path: "/project", command: command, agent: "codex", op: op,
            severity: "info", ts: start.addingTimeInterval(seconds), action: action, sessionId: "session", turnId: turn,
            toolCallId: call, userIntent: intent, modelResponse: output, toolName: name, source: source)
    }
    private func task(_ events: [GuardEvent]) throws -> RealtimeTask {
        try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: events, since: start).first)
    }
    func testStopAfterInstallFailureRetainsFailureEvidenceWithoutClaimingGoalComplete() throws {
        let prompt = record("prompt", kind: "model", call: nil, intent: "安装软件")
        let call = record("call", seconds: 1, command: #"{"cmd":"sudo -n installer -pkg app.pkg -target /"}"#)
        let error = record("result", seconds: 2, output: #"{"exit_code":1,"stderr":"sudo: a password is required"}"#)
        let stop = record("hook_turn_stop", kind: "task", seconds: 3, call: nil, output: "软件尚未安装，需要密码。", source: "workbuddy-hook")
        let value = try task([prompt, call, error, stop])
        XCTAssertEqual(value.lifecycleStatus, "stopped")
        XCTAssertEqual(value.executionState, "stopped")
        XCTAssertEqual(value.completionEvidence, "unknown")
        XCTAssertFalse(value.reportedComplete)
        XCTAssertTrue(value.currentStep.contains("退出码 1"))
        XCTAssertEqual(value.lastFailureCardID, "call:call")
        XCTAssertEqual(value.nativeEndMessage, "软件尚未安装，需要密码。")
        XCTAssertNil(value.stopReason, "Final prose is not a structured reason")
    }
    func testStopResolvesMissingReturnsWithoutInventingBackgroundExecution() throws {
        let submitted = record("hook_tool_start", action: "started", command: "install")
        let stop = record("hook_turn_stop", kind: "task", seconds: 3, call: nil, source: "workbuddy-hook")
        let value = try task([submitted, stop])
        XCTAssertEqual(value.lifecycleStatus, "stopped")
        XCTAssertEqual(value.unresolvedCallIDs, ["call"])
        XCTAssertTrue(value.statusBasis.contains("缺最终返回"))
    }
    func testNativeRunningExecutorMayContinueAfterAgentStop() throws {
        let submitted = record("call", command: #"{"cmd":"download"}"#)
        let running = record("result", seconds: 1, output: #"{"session_id":"runner","status":"running","stdout":"download started"}"#)
        let stop = record("hook_turn_stop", kind: "task", seconds: 2, call: nil, source: "workbuddy-hook")
        let value = try task([submitted, running, stop])
        XCTAssertEqual(value.lifecycleStatus, "running")
        XCTAssertEqual(value.executionState, "background_running")
        XCTAssertFalse(value.reportedComplete)
        let returned = record("result", seconds: 3, output: #"{"exit_code":0,"stdout":"download finished"}"#)
        XCTAssertEqual(try task([submitted, running, stop, returned]).lifecycleStatus, "stopped")
    }
    func testDeliveryMustBeExplicitAndExistenceChecked() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("report.md")
        try "delivered".write(to: file, atomically: true, encoding: .utf8)
        let output = String(decoding: try JSONSerialization.data(withJSONObject: ["type":"present_files_result", "files":[file.path]]), as: UTF8.self)
        let delivery = record("result", seconds: 1, call: "delivery", output: output, name: "present_files")
        let stop = record("hook_turn_stop", kind: "task", seconds: 2, call: nil, source: "workbuddy-hook")
        let events = [delivery, stop], initial = try task(events)
        XCTAssertEqual(initial.lifecycleStatus, "stopped")
        let artifacts = RealtimeArtifactProjector.probe(RealtimeArtifactProjector.candidates(events: events, tasks: [initial]))
        let verified = try XCTUnwrap(RealtimeWorkspaceProjector.assessingDelivery([initial], artifacts: artifacts).first)
        XCTAssertEqual(verified.lifecycleStatus, "completed")
        XCTAssertEqual(verified.completionEvidence, "verified_delivery")
        try FileManager.default.removeItem(at: file)
        let absent = RealtimeArtifactProjector.probe(RealtimeArtifactProjector.candidates(events: events, tasks: [initial]))
        XCTAssertEqual(RealtimeWorkspaceProjector.assessingDelivery([initial], artifacts: absent).first?.lifecycleStatus, "stopped")
        XCTAssertEqual(RealtimeWorkspaceProjector.assessingDelivery([initial], artifacts: []).first?.lifecycleStatus, "stopped")
    }
    func testSingleToolFailureIsNotTaskFailureAndRetryRetainsBothAttempts() throws {
        let first = record("call", action: "requested", command: #"{"cmd":"false"}"#)
        let failure = record("result", action: "completed", seconds: 1, output: #"{"exit_code":1,"stderr":"bad"}"#)
        let second = record("call", action: "requested", seconds: 2, call: "retry", command: #"{"cmd":"true"}"#)
        let projected = try task([first, failure, second])
        XCTAssertEqual(projected.lifecycleStatus, "running")
        XCTAssertEqual(projected.cards.filter { $0.phase == "failed" }.count, 1)
        XCTAssertEqual(projected.currentCardID, "call:retry")
        XCTAssertFalse(projected.reportedComplete)
    }
    func testExplicitTaskTerminalsDoNotRegressWhenLateStartAppears() throws {
        for (op, action, expected) in [("task_complete", "completed", "stopped"), ("task_failed", "failed", "failed"), ("task_cancelled", "cancelled", "cancelled")] {
            let end = record(op, kind: "task", action: action, seconds: 1, call: nil)
            let late = record("start", action: "running", seconds: 3)
            let projected = try task([late, end])
            XCTAssertEqual(projected.lifecycleStatus, expected)
            XCTAssertEqual(projected.reportedComplete, expected == "completed")
            XCTAssertTrue(projected.statusBasis.contains(end.id.uuidString))
        }
    }
    func testApprovalMustBeExplicitAndCompletionResolvesIt() throws {
        let ordinary = record("call", action: "requested", command: "echo 'approval_required'")
        XCTAssertEqual(try task([ordinary]).lifecycleStatus, "running")
        let wait = record("call", action: "awaiting_approval", command: "npm install")
        XCTAssertEqual(try task([wait]).lifecycleStatus, "awaiting_confirmation")
        let done = record("result", action: "completed", seconds: 1, output: #"{"exit_code":0}"#)
        XCTAssertEqual(try task([wait, done]).lifecycleStatus, "running")
    }
    func testCompletedMessageDoesNotDeclareTaskEnded() throws {
        let response = record("response", kind: "model", action: "completed", call: nil, output: "先执行检查")
        XCTAssertEqual(try task([response]).lifecycleStatus, "running")
        XCTAssertFalse(try task([response]).reportedComplete)
        let final = record("response", kind: "model", action: "final_answer", seconds: 1, call: nil, output: "已交付")
        XCTAssertEqual(try task([response, final]).lifecycleStatus, "stopped")
        XCTAssertFalse(try task([response, final]).reportedComplete)
    }
    func testExecutorIdentifierIsNotOperatingSystemPID() throws {
        let call = record("start", command: #"{"command":["python3","stream.py"]}"#)
        let result = record("result", seconds: 1, output: #"{"process_id":1234,"status":"running","stdout":"line"}"#)
        let execution = try XCTUnwrap(try task([call, result]).cards.first?.execution)
        XCTAssertEqual(execution.executionID, "1234")
        XCTAssertNil(execution.processID)
        XCTAssertEqual(execution.command, #"["python3","stream.py"]"#)
    }
    func testStopExactFinalMessageBindsUniqueNativeTurnAndRejectsAmbiguity() throws {
        let reply = record("response", kind: "model", action: "completed", call: nil, output: "最终报告已交付", source: "agentsight:workbuddy-local")
        let body = #"{"payload":{"last_assistant_message":"最终报告已交付"}}"#
        let stop = GuardEvent(kind: "activity", ruleId: "hook", path: "-", command: nil, agent: "codex", op: "hook_turn_stop", severity: "info", ts: start.addingTimeInterval(2), action: "observed", sessionId: "session", afterContent: body, source: "workbuddy-hook")
        let unique = RealtimeWorkspaceProjector.tasks(events: [reply, stop], since: start)
        XCTAssertEqual(unique.count, 1); XCTAssertEqual(unique.first?.lifecycleStatus, "stopped")
        XCTAssertEqual(unique.first?.nativeEndMessage, "最终报告已交付")
        let repeated = record("response", kind: "model", action: "completed", call: nil, output: "最终报告已交付", turn: "other", source: "agentsight:workbuddy-local")
        let ambiguous = RealtimeWorkspaceProjector.tasks(events: [reply, repeated, stop], since: start)
        XCTAssertEqual(ambiguous.count, 3); XCTAssertTrue(ambiguous.allSatisfy { !$0.reportedComplete })
    }
    func testSessionOnlyStopAndUserHookDoNotInventAnOngoingTurn() throws {
        let user = record("hook_user_prompt", kind: "activity", call: nil, intent: "之前的研究任务", turn: nil, source: "workbuddy-hook")
        let submitted = record("hook_tool_start", seconds: 1, command: "run", turn: nil)
        let stop = record("hook_turn_stop", kind: "activity", seconds: 2, call: nil, turn: nil, source: "workbuddy-hook")
        let value = try task([user, submitted, stop])
        XCTAssertEqual(value.lifecycleStatus, "observed")
        XCTAssertFalse(value.reportedComplete)
        XCTAssertTrue(value.currentStep.contains("归属待确认"))
    }

    func testSessionOnlyHookStopDoesNotCompleteOtherTurnOrLane() throws {
        let stop = record("hook_turn_stop", kind: "activity", seconds: 2, call: nil, turn: nil, source: "workbuddy-hook")
        let tasks = RealtimeWorkspaceProjector.tasks(events: [record("call"), stop], since: start)
        XCTAssertEqual(tasks.count, 2)
        XCTAssertTrue(tasks.allSatisfy { !$0.reportedComplete })
        XCTAssertEqual(tasks.first { $0.turn == "turn" }?.lifecycleStatus, "running")
    }
    func testInheritedIntentCannotMasqueradeAsOriginalRequest() throws {
        let response = record("response", kind: "model", call: nil, output: "response", intent: "old arbitrary inherited input")
        let projected = try task([response])
        XCTAssertNil(projected.originalRequest)
        XCTAssertFalse(projected.title.contains("old arbitrary"))
        XCTAssertEqual(projected.coverage.first { $0.category == "user" }?.status, "missing")
    }
    func testLocalUserInputDoesNotPretendFullModelRequestWasCaptured() throws {
        let user = record("prompt", kind: "model", action: "sent", call: nil, intent: "创建报告")
        let projected = try task([user])
        XCTAssertEqual(projected.originalRequest, "创建报告")
        XCTAssertEqual(projected.cards.first?.kind, "user")
        XCTAssertFalse(projected.cards.contains { $0.id.hasPrefix("waiting:") })
        XCTAssertEqual(projected.coverage.first { $0.category == "context" }?.status, "missing")
    }
    func testModelDecisionDoesNotCreateExecutedTool() throws {
        let response = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "response", severity: "info", ts: start, action: "received", sessionId: "session", turnId: "turn", modelDecision: #"{"tool_calls":[{"name":"Bash","arguments":"echo hi"}]}"#, modelResponse: "", source: "fixture")
        let projected = try task([response])
        let decision = try XCTUnwrap(projected.cards.first { $0.kind == "plan" })
        XCTAssertEqual(decision.phase, "recorded")
        XCTAssertNil(decision.execution)
        XCTAssertEqual(projected.coverage.first { $0.category == "tool" }?.count, 0)
    }
    func testCommandFieldsAndRunningSessionAreDifferentFromToolReturn() throws {
        let call = record("call", action: "requested", command: #"{"cmd":"python3 long.py","workdir":"/project/run"}"#)
        let returned = record("result", action: "completed", seconds: 1, output: #"{"session_id":"runner-1","stdout":"first line\n","status":"running"}"#)
        let card = try XCTUnwrap(try task([call, returned]).cards.first)
        let execution = try XCTUnwrap(card.execution)
        XCTAssertEqual(execution.command, "python3 long.py")
        XCTAssertEqual(execution.cwd, "/project/run")
        XCTAssertEqual(execution.executionID, "runner-1")
        XCTAssertEqual(execution.status, "running")
        XCTAssertFalse(execution.outputComplete)
        XCTAssertNil(execution.endAt)
        XCTAssertEqual(card.phase, "running")
    }
    func testIncrementalOutputIsVisibleBeforeFinalResult() throws {
        let call = record("call", action: "requested", command: #"{"cmd":"stream"}"#)
        let delta = record("output", action: "streaming", seconds: 1, command: #"{"channel":"stdout","execution_id":"exec-1"}"#, output: "line 1\n")
        let err = record("output", action: "streaming", seconds: 2, command: #"{"channel":"stderr","execution_id":"exec-1"}"#, output: "warning\n")
        let card = try XCTUnwrap(try task([call, delta, err]).cards.first)
        let execution = try XCTUnwrap(card.execution)
        XCTAssertEqual(execution.stdout, "line 1\n")
        XCTAssertEqual(execution.stderr, "warning\n")
        XCTAssertEqual(execution.chunks.map(\.eventID), [delta.id.uuidString, err.id.uuidString])
        XCTAssertEqual(execution.status, "running")
        XCTAssertFalse(execution.outputComplete)
        XCTAssertEqual(try task([call, delta, err]).coverage.first { $0.category == "execution" }?.count, 2)
    }
    func testWorkBuddyBashEnvelopeSeparatesOutputAndExitCode() throws {
        let call = record("call", command: #"Bash({"command":"echo hello"})"#)
        let end = record("result", action: "completed", seconds: 1, output: "Command: echo hello\nStdout: hello\n\nStderr: failure\nExit Code: 7\nSignal: (none)")
        let card = try XCTUnwrap(try task([call, end]).cards.first)
        XCTAssertEqual(card.execution?.command, "echo hello")
        XCTAssertEqual(card.execution?.stdout, "hello\n")
        XCTAssertEqual(card.execution?.stderr, "failure")
        XCTAssertEqual(card.execution?.exitCode, 7)
        XCTAssertEqual(card.phase, "failed")
        XCTAssertEqual(try task([call, end]).lifecycleStatus, "running")
    }
    func testCodexNativeTextProtocolKeepsOutputAndExitCode() throws {
        let call = record("call", command: #"{"cmd":"echo hi"}"#)
        let running = record("result", seconds: 1, output: "Chunk ID: 1\nProcess running with session ID 123\nOutput:\nhi\n")
        let runningCard = try XCTUnwrap(try task([call, running]).cards.first)
        XCTAssertEqual(runningCard.execution?.executionID, "123")
        XCTAssertEqual(runningCard.execution?.stdout, "hi\n")
        XCTAssertEqual(runningCard.phase, "running")
        let final = record("result", seconds: 2, output: "Chunk ID: 2\nProcess exited with code 7\nFinal output:\nreal error\n")
        let finalCard = try XCTUnwrap(try task([call, final]).cards.first)
        XCTAssertEqual(finalCard.execution?.exitCode, 7)
        XCTAssertEqual(finalCard.execution?.stdout, "real error\n")
        XCTAssertEqual(finalCard.phase, "failed")
        XCTAssertEqual(try task([call, final]).lifecycleStatus, "running")
    }
    func testLargeOutputSignalsTruncationAndNoIntermediateOutputInvented() throws {
        let output = String(repeating: "x", count: 20_000)
        let call = record("call", command: #"{"cmd":"large"}"#)
        let end = record("result", seconds: 1, output: "{\"stdout\":\"\(output)\",\"exit_code\":0}")
        let projected = try task([call, end])
        let card = try XCTUnwrap(projected.cards.first)
        XCTAssertTrue(card.outputTruncated)
        XCTAssertEqual(card.execution?.stdout?.count, 16_000)
        XCTAssertEqual(card.execution?.stdoutTruncated, true)
        XCTAssertTrue(card.execution?.chunks.isEmpty == true)
        XCTAssertEqual(projected.coverage.first { $0.category == "execution" }?.status, "missing")
    }
    func testCommandRequestDoesNotInventExecutorOrStartTime() throws {
        let projected = try task([record("call", action: "requested", command: "Bash({\"command\":\"pwd\"})")])
        let execution = try XCTUnwrap(projected.cards.first?.execution)
        XCTAssertEqual(execution.command, "pwd")
        XCTAssertEqual(execution.status, "requested")
        XCTAssertNil(execution.processID)
        XCTAssertNil(execution.startAt)
        XCTAssertNil(execution.exitCode)
        XCTAssertTrue(projected.currentStep.contains("等待执行记录"))
    }
    func testNetworkResourceDetailsDoNotInferURLOrLocationFromIP() throws {
        let network = GuardEvent(kind: "network", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "connect", severity: "info", ts: start, action: "observed", sessionId: "session", turnId: "turn", remoteHost: "203.0.113.10", remotePort: 443)
        let resource = try XCTUnwrap(try task([network]).cards.first?.resource)
        XCTAssertEqual(resource.remoteIP, "203.0.113.10")
        XCTAssertEqual(resource.ipScope, "reserved")
        XCTAssertNil(resource.url)
        XCTAssertNil(resource.location)
        XCTAssertNil(resource.method)
    }
    func testNetworkHTTPSFlowExposesResourceURLAndSocketSeparately() throws {
        let network = GuardEvent(kind: "network", ruleId: "fixture", path: "-", command: #"{"requestPath":"/v2/resource?q=test","method":"POST","responseStatus":429}"#, agent: "workbuddy", op: "response", severity: "info", ts: start, action: "received", sessionId: "session", turnId: "turn", source: "agentsight:workbuddy-network-body", remoteHost: "10.2.0.5", remotePort: 443, remoteDomain: "example.test")
        let resource = try XCTUnwrap(try task([network]).cards.first?.resource)
        XCTAssertEqual(resource.url, "https://example.test/v2/resource?q=test")
        XCTAssertEqual(resource.remoteIP, "10.2.0.5")
        XCTAssertEqual(resource.ipScope, "private")
        XCTAssertEqual(resource.method, "POST")
        XCTAssertEqual(resource.statusCode, 429)
    }
    func testFileVersionAndDiffKeepActualData() throws {
        let file = GuardEvent(kind: "file", ruleId: "fixture", path: "/project/report.md", command: nil, agent: "codex", op: "modify", severity: "info", ts: start, action: "observed", sessionId: "session", turnId: "turn", beforeContent: "old\n", afterContent: "new\n", fileDiff: "-old\n+new\n")
        let resource = try XCTUnwrap(try task([file]).cards.first?.resource)
        XCTAssertEqual(resource.path, "/project/report.md")
        XCTAssertEqual(resource.before, "old\n")
        XCTAssertEqual(resource.after, "new\n")
        XCTAssertEqual(resource.diff, "-old\n+new\n")
    }
    func testStageContractContainsTwelveStableIDsAndNoFutureCompletion() throws {
        let projected = try task([record("call", action: "requested", command: "echo hi")])
        XCTAssertEqual(projected.lifecycle?.stages.map(\.id), ["user", "environment", "context", "model", "plan", "command", "mcp", "files", "network", "failure", "verify", "artifact"])
        XCTAssertEqual(projected.lifecycle?.currentStageID, "command")
        XCTAssertEqual(projected.lifecycle?.stages.first { $0.id == "verify" }?.status, "absent")
        XCTAssertEqual(projected.lifecycle?.stages.first { $0.id == "artifact" }?.status, "absent")
    }
}
