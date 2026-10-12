import AppKit
import SwiftUI
import WebKit
import XCTest
@testable import AgentReins

final class RealtimeWorkspaceTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private func event(_ op: String, agent: String = "workbuddy", turn: String = "one", call: String? = "same", result: String? = nil, action: String = "observed", seconds: Double = 1) -> GuardEvent {
        GuardEvent(kind: "tool", ruleId: "fixture", path: "/project", command: "run-tests", agent: agent,
            op: op, severity: "info", ts: start.addingTimeInterval(seconds), action: action,
            sessionId: "session", turnId: turn, toolCallId: call, modelResponse: result, toolName: "Bash")
    }
    func testCodexIncrementalChunkKeepsSessionIdentityAndCompletion() throws {
        let sid = UUID().uuidString.lowercased()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("rollout-2026-10-09T00-00-00-" + sid + ".jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = [
            #"{"type":"response_item","payload":{"id":"message-not-session","type":"message","role":"user","turn_id":"turn","content":[{"type":"input_text","text":"原始任务"}]}}"#,
            #"{"type":"event_msg","payload":{"type":"task_complete","turn_id":"turn","last_agent_message":"已交付"}}"#
        ]
        try rows.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        let events = CodexSight.parseSession(url)
        XCTAssertEqual(Set(events.compactMap(\.sessionId)), [sid])
        let tasks = RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast)
        XCTAssertEqual(tasks.count, 1)
        XCTAssertEqual(tasks.first?.originalRequest, "原始任务")
        XCTAssertEqual(tasks.first?.reportedComplete, false)
        XCTAssertEqual(tasks.first?.lifecycleStatus, "stopped")
    }
    func testCodexUserMessageFormatsCaptureOriginalRequest() throws {
        for record in [
            #"{"type":"event_msg","payload":{"type":"user_message","message":"用户原话","turn_id":"turn"}}"#,
            #"{"type":"response_item","payload":{"type":"message","role":"user","turn_id":"turn","content":[{"type":"input_text","text":"用户原话"}]}}"#
        ] {
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".jsonl")
            defer { try? FileManager.default.removeItem(at: url) }
            try (record + "\n").write(to: url, atomically: true, encoding: .utf8)
            let prompt = try XCTUnwrap(CodexSight.parseSession(url).first { $0.op == "prompt" })
            XCTAssertEqual(prompt.userIntent, "用户原话")
        }
    }
    func testOriginalRequestIsSeparateFromFallbackTitleAndNotTruncated() throws {
        let missing = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: [event("call")], since: start).first)
        XCTAssertNil(missing.originalRequest)
        let original = String(repeating: "我的原始需求", count: 100)
        let prompt = GuardEvent(kind: "model", ruleId: "fixture", path: "/project", command: nil, agent: "codex", op: "prompt", severity: "info", ts: start.addingTimeInterval(1), action: "sent", sessionId: "session", turnId: "one", userIntent: original)
        let captured = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: [prompt], since: start).first)
        XCTAssertEqual(captured.originalRequest, original)
        XCTAssertEqual(captured.requestEventID, prompt.id.uuidString)
    }
    func testParallelAgentsAndTurnsNeverShareToolResults() throws {
        let events = [event("call"), event("result", turn: "two", result: "{\"exit_code\":0}"), event("result", agent: "codex", result: "codex-result")]
        let tasks = RealtimeWorkspaceProjector.tasks(events: events, since: start)
        XCTAssertEqual(tasks.count, 3)
        let one = try XCTUnwrap(tasks.first { $0.agent == "WorkBuddy" && $0.turn == "one" })
        XCTAssertEqual(one.cards.first?.status, "running")
        XCTAssertEqual(one.cards.first?.output, "结果尚未采集")
    }
    func testStructuredFailureOverridesOuterSuccessfulReturn() throws {
        let events = [event("call"), event("result", result: "{\"exit_code\":1,\"stdout\":\"failed test\"}", action: "completed", seconds: 2)]
        let card = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: events, since: start).first?.cards.first)
        XCTAssertEqual(card.status, "attention"); XCTAssertEqual(card.tag, "执行失败")
        let healthy = event("result", result: "{\"exit_code\":0,\"stdout\":\"error handling tests passed\"}")
        XCTAssertFalse(RealtimeWorkspaceProjector.isFailure(healthy, result: healthy.modelResponse))
    }
    func testUnknownToolsAreNotCalledMCPAndPlansRemainPlans() throws {
        XCTAssertEqual(RealtimeWorkspaceProjector.toolKind(name: "unknown_tool", input: "{}"), "tool")
        XCTAssertEqual(RealtimeWorkspaceProjector.toolKind(name: "mcp__docs__query", input: "{}"), "mcp")
        let task = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: [event("call", action: "queued")], since: start).first)
        XCTAssertEqual(task.cards.first?.status, "pending")
    }
    func testNoHistoricalOrUnattributedTaskAndNoInventedPlans() {
        let tasks = RealtimeWorkspaceProjector.tasks(events: [event("call", seconds: -1), event("call", call: nil)], since: start)
        XCTAssertEqual(tasks.count, 1)
        XCTAssertFalse(tasks.flatMap(\.cards).contains { $0.status == "pending" })
        XCTAssertTrue(RealtimeWorkspaceProjector.tasks(events: [GuardEvent(kind: "network", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "connect", severity: "info", ts: start, action: "observed")], since: start).isEmpty)
    }
    func testBaselineDoesNotReadHistoryAndKeepsExistingEOF() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let log = directory.appendingPathComponent("old.jsonl")
        try Data("old task body\n".utf8).write(to: log)
        XCTAssertEqual(Array(RealtimeLogBaseline.offsets(root: directory).values), [14])
    }
    @MainActor func testRealtimeStoreDoesNotCreateHistorySearchIndex() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("events.json")
        let store = EventStore(fileURL: file, realtimeOnly: true)
        XCTAssertFalse(store.taskSearchIndexReady)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.appendingPathExtension("search.sqlite3").path))
    }
    func testNativeHookLifecycleWithoutTurnRemainsVisibleAndPairsFinish() throws {
        func hook(_ op: String, body: String, seconds: Double) -> GuardEvent {
            GuardEvent(kind: "activity", ruleId: "workbuddy_hook_native", path: "-", command: nil, agent: "workbuddy", op: op, severity: "info", ts: start.addingTimeInterval(seconds), action: "observed", sessionId: "session", toolCallId: "hook-call", toolName: "Bash", afterContent: body, source: "workbuddy-hook")
        }
        let records = [hook("hook_tool_start", body: "{\"payload\":{\"tool_input\":{\"command\":\"echo hello\"}}}", seconds: 1), hook("hook_tool_finish", body: "{\"payload\":{\"tool_response\":{\"exit_code\":0,\"stdout\":\"hello\"}}}", seconds: 2)]
        let task = try XCTUnwrap(RealtimeWorkspaceProjector.tasks(events: records, since: start).first)
        XCTAssertEqual(task.turn, "")
        let card = try XCTUnwrap(task.cards.first)
        XCTAssertEqual(card.status, "returned")
        XCTAssertTrue(card.input.contains("echo hello")); XCTAssertTrue(card.output.contains("hello"))
        XCTAssertEqual(card.eventIDs.count, 2)
    }
    func testMissingHookTurnJoinsOnlyUniqueNativeCallIdentity() throws {
        let hook = GuardEvent(kind: "activity", ruleId: "workbuddy_hook_native", path: "-", command: nil, agent: "workbuddy", op: "hook_tool_finish", severity: "info", ts: start.addingTimeInterval(2), action: "observed", sessionId: "session", toolCallId: "same", toolName: "Bash", source: "workbuddy-hook")
        let single = RealtimeWorkspaceProjector.tasks(events: [event("call"), hook], since: start)
        XCTAssertEqual(single.count, 1); XCTAssertEqual(single.first?.cards.first?.status, "returned")
        let ambiguous = RealtimeWorkspaceProjector.tasks(events: [event("call"), event("call", turn: "two"), hook], since: start)
        XCTAssertEqual(ambiguous.count, 3)
        XCTAssertEqual(ambiguous.filter { !$0.turn.isEmpty }.flatMap(\.cards).filter { $0.status == "running" }.count, 2)
    }
    @MainActor func testSystemEvidenceAndVanishedProcessesRemainVisibleWithoutTask() {
        let state = RealtimeWorkspaceState()
        state.updateProcesses([ProcessSnapshotRecord(pid: "100", ppid: "1", command: "Electron", agent: "workbuddy", birthIdentity: 1)])
        state.updateProcesses([])
        state.ingest([GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil, agent: "workbuddy", op: "process_ipc_observation", severity: "info", ts: Date(), action: "observed", afterContent: "{\"connections\":[]}", source: "process-observation-lsof-unix", processId: 100)])
        let payload = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertTrue(payload.tasks.isEmpty)
        XCTAssertEqual(payload.collected.first?.pid, 100)
        XCTAssertFalse(payload.collected.first?.hasTaskIdentity ?? true)
        XCTAssertEqual(payload.processes.first?.active, false)
        XCTAssertEqual(payload.collectedCount, 1)
    }
    @MainActor func testFileObservationWithoutAgentAttributionIsNotDiscarded() {
        let state = RealtimeWorkspaceState()
        state.ingest([GuardEvent(kind: "file", ruleId: "file-observation", path: "/project/output.txt", command: nil, agent: nil, op: "modify", severity: "info", ts: Date(), action: "observed", afterContent: "output", source: "file-observation")])
        let payload = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertTrue(payload.tasks.isEmpty)
        XCTAssertEqual(payload.collected.first?.agent, "归属未确认")
        XCTAssertTrue(payload.collected.first?.details.contains("/project/output.txt") ?? false)
    }
    func testActualNetworkPromptDirectionAndBackgroundFlowClassification() throws {
        let prompt = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "workbuddy", op: "network_prompt", severity: "info", ts: start, action: "captured_complete", sessionId: "session", turnId: "one", modelPrompt: "hello", source: "agentsight:workbuddy-network-body")
        let memory = GuardEvent(kind: "network", ruleId: "fixture", path: "-", command: nil, agent: "workbuddy", op: "memory_recall", severity: "info", ts: start.addingTimeInterval(1), action: "captured_complete", sessionId: "network-flow", turnId: "flow", source: "agentsight:workbuddy-network-body")
        let tasks = RealtimeWorkspaceProjector.tasks(events: [prompt, memory], since: start)
        XCTAssertEqual(tasks.first { $0.session == "network-flow" }?.isPrimaryTask, false)
        let task = try XCTUnwrap(tasks.first { $0.session == "session" })
        XCTAssertTrue(task.isPrimaryTask)
        XCTAssertEqual(task.cards.first?.title, "Agent → 大模型")
    }
    @MainActor func testProcessInventoryIsVisibleWithoutTaskOrTranscript() throws {
        let state = RealtimeWorkspaceState()
        let root = ProcessSnapshotRecord(pid: "100", ppid: "1", command: "Electron", agent: "workbuddy", birthIdentity: 1, executablePath: "/Applications/WorkBuddy.app/Contents/MacOS/Electron")
        let child = ProcessSnapshotRecord(pid: "101", ppid: "100", command: "node --token secret-value", agent: "workbuddy", birthIdentity: 2, executablePath: "/usr/local/bin/node")
        let payload = state.payload(processes: [root, child], health: [], observing: true, error: nil)
        XCTAssertTrue(payload.tasks.isEmpty)
        XCTAssertEqual(payload.processes.count, 2)
        XCTAssertEqual(payload.processes.last?.parent, "100")
        XCTAssertEqual(payload.processes.last?.executable, "/usr/local/bin/node")
        XCTAssertEqual(payload.processes.last?.command, ProcessArgumentRedactor.redact(child.command))
    }
    @MainActor func testHotCachePressureDoesNotDiscardTaskEvidence() {
        let state = RealtimeWorkspaceState(byteBudget: 1024)
        let large = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "prompt", severity: "info", ts: Date(), action: "sent", sessionId: "s", turnId: "t", userIntent: "保留原始需求", modelPrompt: String(repeating: "a", count: 3000))
        state.ingest([large])
        let payload = state.payload(processes: [], health: [], observing: true, error: nil)
        XCTAssertFalse(payload.truncated)
        XCTAssertEqual(payload.collectedCount, 1)
        XCTAssertEqual(payload.tasks.first?.requestEventID, large.id.uuidString)
    }
    @MainActor func testOlderDatabaseReplayDoesNotUndoRestoredLiveAttribution() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("live-repair-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at:url) }
        let id = UUID(), time = Date().addingTimeInterval(-60)
        let repaired = GuardEvent(id:id, kind:"model", ruleId:"codex_model_prompt", path:"-", command:nil, agent:"codex", op:"prompt", severity:"info", ts:time, action:"sent", sessionId:"s", turnId:"correct", userIntent:"真实原话", source:"agentsight:codex-local-compat")
        try RealtimeActiveCheckpoint(version:1, savedAt:Date(), events:[repaired], readTaskIDs:[]).save(url)
        let state = RealtimeWorkspaceState(checkpointURL:url)
        let stale = GuardEvent(id:id, kind:"model", ruleId:"codex_model_prompt", path:"-", command:nil, agent:"codex", op:"prompt", severity:"info", ts:time, action:"sent", sessionId:"s", turnId:"wrong", userIntent:"旧的错误需求", source:"agentsight:codex-local-compat")
        state.ingest([stale])
        let task = try XCTUnwrap(state.payload(processes:[],health:[],observing:true,error:nil).tasks.first)
        XCTAssertEqual(task.turn,"correct");XCTAssertEqual(task.originalRequest,"真实原话")
    }
    @MainActor func testInternalReviewDoesNotOccupyUnreadUserRestartBudget() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("review-restart-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at:url) }
        let now = Date().addingTimeInterval(60)
        let human = GuardEvent(kind:"model",ruleId:"fixture",path:"-",command:nil,agent:"codex",op:"prompt",severity:"info",ts:now,action:"sent",sessionId:"human",turnId:"t",userIntent:"真实需求",source:"agentsight:codex-local-compat")
        let review = GuardEvent(kind:"model",ruleId:"fixture",path:"-",command:nil,agent:"codex",op:"prompt",severity:"info",ts:now,action:"sent",sessionId:"internal",turnId:"r",userIntent:"评审指令",model:"codex-auto-review",source:"agentsight:codex-local-compat")
        let state = RealtimeWorkspaceState(checkpointURL:url);state.ingest([human,review]);state.flushCheckpoint()
        let checkpoint = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertTrue(checkpoint.events.contains { $0.id == human.id });XCTAssertFalse(checkpoint.events.contains { $0.id == review.id })
        XCTAssertTrue(state.payload(processes:[],health:[],observing:true,error:nil).collected.contains { $0.id == review.id.uuidString })
    }
    @MainActor func testMemoryPressureKeepsStopAndItsExactNativeReplyAheadOfInternalReviews() throws {
        let now = Date().addingTimeInterval(60)
        let prompt = GuardEvent(kind:"model",ruleId:"fixture",path:"-",command:nil,agent:"workbuddy",op:"prompt",severity:"info",ts:now,action:"sent",sessionId:"s",turnId:"t",userIntent:"安装软件",source:"agentsight:workbuddy-local")
        let reply = GuardEvent(kind:"model",ruleId:"fixture",path:"-",command:nil,agent:"workbuddy",op:"response",severity:"info",ts:now.addingTimeInterval(1),action:"received",sessionId:"s",turnId:"t",modelResponse:"安装尚未完成",source:"agentsight:workbuddy-local")
        let stop = GuardEvent(kind:"task",ruleId:"fixture",path:"-",command:nil,agent:"workbuddy",op:"hook_turn_stop",severity:"info",ts:now.addingTimeInterval(2),action:"stopped",sessionId:"s",afterContent:"{\"payload\":{\"last_assistant_message\":\"安装尚未完成\",\"background_tasks\":[]}}",source:"workbuddy-hook")
        let review = GuardEvent(kind:"model",ruleId:"fixture",path:"-",command:nil,agent:"codex",op:"prompt",severity:"info",ts:now.addingTimeInterval(3),action:"sent",sessionId:"internal",turnId:"review",userIntent:String(repeating:"x",count:4000),modelPrompt:String(repeating:"x",count:4000),model:"codex-auto-review",source:"agentsight:codex-local-compat")
        let state = RealtimeWorkspaceState(byteBudget:4096);state.ingest([prompt,reply,stop,review])
        let payload = state.payload(processes:[],health:[],observing:true,error:nil)
        let task = try XCTUnwrap(payload.tasks.first { $0.turn == "t" })
        XCTAssertEqual(task.lifecycleStatus,"stopped");XCTAssertEqual(task.nativeEndMessage,"安装尚未完成")
        XCTAssertFalse(payload.truncated)
        XCTAssertEqual(payload.collectedCount, 4)
    }
    @MainActor func testActualWorkBuddyFieldSnapshot() async throws {
        guard let source = ProcessInfo.processInfo.environment["AGENTREINS_FIELD_CHECKPOINT"],
              let session = ProcessInfo.processInfo.environment["AGENTREINS_FIELD_SESSION"],
              let directoryPath = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] else {
            throw XCTSkip("现场测试需指定独立实际采集快照和会话")
        }
        let checkpoint = try XCTUnwrap(RealtimeActiveCheckpoint.load(URL(fileURLWithPath: source)))
        let records = checkpoint.events
        let tasks = RealtimeWorkspaceProjector.tasks(events: records, since: .distantPast)
        let actual = try XCTUnwrap(tasks.first { $0.session == session && !$0.turn.isEmpty })
        XCTAssertNotNil(actual.originalRequest)
        XCTAssertEqual(actual.lifecycleStatus, "stopped")
        XCTAssertTrue(actual.cards.contains { $0.kind == "command" && $0.execution?.exitCode == 0 && $0.execution?.stdout?.isEmpty == false })
        XCTAssertTrue(actual.cards.contains { $0.title == "WebSearch" && $0.phase == "returned" })
        let candidates = RealtimeArtifactProjector.candidates(events: records, tasks: tasks)
        let artifacts = RealtimeArtifactProjector.probe(candidates).filter { $0.taskID == actual.id }
        XCTAssertTrue(artifacts.contains { $0.exists && $0.preview?.isEmpty == false })
        var payload = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.assessingDelivery([actual], artifacts: artifacts), collected: [], unattributedCount: 0, processes: [], health: [], observing: true, persistenceError: nil, publishedAt: Date(), truncated: false,
            contexts: RealtimeContextProjector.assemble(records.compactMap(RealtimeContextProjector.parse), events: records))
        payload.artifacts = artifacts
        let directory = URL(fileURLWithPath: directoryPath)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(payload).write(to: directory.appendingPathComponent("actual-workbuddy-payload.json"))
        _ = NSApplication.shared
        let host = NSHostingView(rootView: RealtimeWorkspaceView(payload: payload))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1536, height: 1100), styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentView = host; host.frame = window.contentLayoutRect; window.orderBack(nil)
        defer { window.close() }
        func find(_ v: NSView) -> WKWebView? { (v as? WKWebView) ?? v.subviews.compactMap { find($0) }.first }
        var web: WKWebView?
        for _ in 0..<50 {
            try await Task.sleep(for: .milliseconds(100)); web = find(host)
            if let web, (try? await web.evaluateJavaScript("document.querySelector('.task-head h1')?.textContent")) as? String == actual.title { break }
        }
        let browser = try XCTUnwrap(web)
        let renderedTitle = try await browser.evaluateJavaScript("document.querySelector('.task-head h1').textContent") as? String
        XCTAssertEqual(renderedTitle, actual.title)
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-view=results]').click()")
        let completedCount = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=completed] .board-card').length") as? Int
        XCTAssertEqual(completedCount, 1)
        let image = try await browser.takeSnapshot(configuration: nil)
        let bitmap = try XCTUnwrap(NSBitmapImageRep(data: try XCTUnwrap(image.tiffRepresentation)))
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: directory.appendingPathComponent("actual-workbuddy-board.png"))
    }
    @MainActor func testProductionWebKitRendersAndEscapesEvidence() async throws {
        let bad = "<img src=x onerror='window.hacked=1'>"
        let evidence = [event("call"), event("result", result: "{\"exit_code\":1}", seconds: 2), GuardEvent(kind: "model", ruleId: "fixture", path: "/project", command: nil, agent: "workbuddy", op: "prompt", severity: "info", ts: start, action: "sent", sessionId: "session", turnId: "one", userIntent: bad, modelPrompt: bad)]
        let payload = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: evidence, since: start), collected: [], unattributedCount: 0, processes: [], health: [], observing: true, persistenceError: nil, publishedAt: start, truncated: false, contexts: RealtimeContextProjector.assemble(evidence.compactMap(RealtimeContextProjector.parse), events: evidence))
        _ = NSApplication.shared
        let host = NSHostingView(rootView: RealtimeWorkspaceView(payload: payload))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1536, height: 1100), styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentView = host; host.frame = window.contentLayoutRect; window.orderBack(nil)
        defer { window.close() }
        func find(_ view: NSView) -> WKWebView? { (view as? WKWebView) ?? view.subviews.compactMap { find($0) }.first }
        var web: WKWebView?
        for _ in 0..<50 {
            try await Task.sleep(for: .milliseconds(100)); web = find(host)
            if let web, (try? await web.evaluateJavaScript("document.querySelector('.task-head h1')?.textContent")) as? String == bad { break }
        }
        let browser = try XCTUnwrap(web)
        let title = try await browser.evaluateJavaScript("document.querySelector('.task-head h1').textContent") as? String
        XCTAssertEqual(title, bad)
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-flow-node=context]').dispatchEvent(new MouseEvent('click'))")
        let contextText = try await browser.evaluateJavaScript("document.getElementById('detail-code').textContent") as? String
        XCTAssertTrue(contextText?.contains(bad) ?? false)
        let graphVisible = try await browser.evaluateJavaScript("!document.getElementById('graph-screen').hidden") as? Bool
        XCTAssertEqual(graphVisible, true)
        let hacked = try await browser.evaluateJavaScript("window.hacked===1") as? Bool
        XCTAssertEqual(hacked, false)
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-view=results]').click()")
        let failureCount = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=failed] .board-card').length") as? Int
        XCTAssertEqual(failureCount, 0, "单次工具失败不是整个任务失败")
        let runningCount = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=running] .board-card').length") as? Int
        XCTAssertEqual(runningCount, 1)
        XCTAssertEqual(payload.tasks.first(where: { $0.originalRequest != nil })?.lifecycleStatus, "running")
        let mock = try await browser.evaluateJavaScript("document.body.textContent.includes('模拟数据') || !!document.getElementById('board-scenario')") as? Bool
        XCTAssertEqual(mock, false)
        if let output = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] {
            let directory = URL(fileURLWithPath: output); try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; try encoder.encode(payload).write(to: directory.appendingPathComponent("fixture-payload.json"))
            for (name, view) in [("production-board", "results"), ("production-process", "process"), ("production-collection", "collection")] {
                _ = try await browser.evaluateJavaScript("document.querySelector('[data-view=\(view)]').click()")
                try await Task.sleep(for: .milliseconds(150))
                let image = try await browser.takeSnapshot(configuration: nil)
                let tiff = try XCTUnwrap(image.tiffRepresentation)
                let bitmap = try XCTUnwrap(NSBitmapImageRep(data: tiff))
                try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: directory.appendingPathComponent(name + ".png"))
            }
        }
    }
}
