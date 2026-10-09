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
    @MainActor func testBoundedLiveStateReportsMissingCoverage() {
        let state = RealtimeWorkspaceState(byteBudget: 1024)
        let large = GuardEvent(kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex", op: "prompt", severity: "info", ts: Date(), action: "sent", sessionId: "s", turnId: "t", modelPrompt: String(repeating: "a", count: 3000))
        state.ingest([large])
        XCTAssertTrue(state.payload(processes: [], health: [], observing: true, error: nil).truncated)
    }
    @MainActor func testProductionWebKitRendersAndEscapesEvidence() async throws {
        let bad = "<img src=x onerror='window.hacked=1'>"
        let evidence = [event("call"), event("result", result: "{\"exit_code\":1}", seconds: 2), GuardEvent(kind: "model", ruleId: "fixture", path: "/project", command: nil, agent: "workbuddy", op: "prompt", severity: "info", ts: start, action: "sent", sessionId: "session", turnId: "one", userIntent: bad, modelPrompt: bad)]
        let payload = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: evidence, since: start), collected: [], unattributedCount: 0, processes: [], health: [], observing: true, persistenceError: nil, publishedAt: start, truncated: false)
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
        let hacked = try await browser.evaluateJavaScript("window.hacked===1") as? Bool
        XCTAssertEqual(hacked, false)
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-view=results]').click()")
        let failureCount = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=attention] .work-card').length") as? Int
        XCTAssertEqual(failureCount, 1)
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
