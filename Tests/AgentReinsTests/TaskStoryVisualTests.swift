import AppKit
import SwiftUI
import XCTest
@testable import AgentReins

/// Opt-in native rendering: no collectors, no production database, no installed
/// app replacement. Images exercise production views with controlled evidence.
final class TaskStoryVisualTests: XCTestCase {
    @MainActor func testRenderToolCompanion() async throws {
        guard let output = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] else { throw XCTSkip("Set UI review output directory") }
        let directory = URL(fileURLWithPath: output)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let step = ToolEvidenceCompanionTests.step(#"{"file":"差旅报销.xlsx","sheet":"报销明细","range":"A2:D4"}"#,
            output: "[[\"李明\",\"交通费\",128,\"待审核\"],[\"王芳\",\"住宿费\",480,\"待审核\"]]")
        try await render(ScrollView { ToolEvidenceCompanion(step: step).padding(24) }.background(TaskStoryStyle.background),
            to: directory.appendingPathComponent("tool-companion.png"))
    }
    @MainActor func testRenderRealWorkBuddyTask() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let output = env["AGENTREINS_UI_REVIEW_DIR"],
              let path = env["AGENTREINS_STORY_SESSION"], let turn = env["AGENTREINS_STORY_TURN"] else {
            throw XCTSkip("Set local session and turn for real-data visual validation")
        }
        let events = WorkBuddySight.parseSession(URL(fileURLWithPath: path), fullHistory: true)
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: events).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: turn)
        XCTAssertFalse(snapshot.outboundRequests.isEmpty)
        XCTAssertTrue(snapshot.modelResponses.contains { $0.model == "hy3" })
        XCTAssertTrue(snapshot.journey.rounds.contains { $0.response != nil })
        try await render(VStack(alignment: .leading, spacing: 20) {
            Text("WorkBuddy · 实际任务").font(.caption)
            Text(snapshot.conversation.userInputs.first ?? "").font(.title2)
            AgentTaskJourneyView(snapshot: snapshot)
        }.padding(24).background(TaskStoryStyle.background),
            to: URL(fileURLWithPath: output).appendingPathComponent("real-task.png"))
        try await render(AgentTaskJourneyView(snapshot: snapshot, initialSelection: .request(1))
            .padding(24).background(TaskStoryStyle.background),
            to: URL(fileURLWithPath: output).appendingPathComponent("real-request.png"))
    }

    @MainActor func testRenderApprovedStoryViews() async throws {
        guard let output = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] else {
            throw XCTSkip("Set AGENTREINS_UI_REVIEW_DIR for native visual review")
        }
        let directory = URL(fileURLWithPath: output)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let store = EventStore(fileURL: directory.appendingPathComponent("events.json"))
        let start = Date().addingTimeInterval(1)
        let evidence = [
            GuardEvent(kind: "model", ruleId: "preview", path: "/Projects/hello-demo", command: nil,
                agent: "workbuddy", op: "prompt", severity: "info", ts: start, action: "sent",
                sessionId: "visual-review", turnId: "task", userIntent: "编写并验证 Hello World C++ 程序",
                modelPrompt: "<user_query>创建 hello.cpp，编译运行并确认输出。</user_query>", model: "hy3"),
            GuardEvent(kind: "tool", ruleId: "preview", path: "/Projects/hello-demo/hello.cpp",
                command: #"{"command":"clang++ -std=c++17 hello.cpp -o hello && ./hello"}"#,
                agent: "workbuddy", op: "call", severity: "info", ts: start.addingTimeInterval(3),
                action: "requested", sessionId: "visual-review", turnId: "task", toolCallId: "compile", toolName: "Bash"),
            GuardEvent(kind: "tool", ruleId: "preview", path: "/Projects/hello-demo/hello.cpp", command: nil,
                agent: "workbuddy", op: "result", severity: "info", ts: start.addingTimeInterval(5), action: "completed",
                sessionId: "visual-review", turnId: "task", toolCallId: "compile", modelResponse: "Hello, World!", toolName: "Bash"),
            GuardEvent(kind: "model", ruleId: "preview", path: "/Projects/hello-demo", command: nil,
                agent: "workbuddy", op: "response", severity: "info", ts: start.addingTimeInterval(8), action: "completed",
                sessionId: "visual-review", turnId: "task", modelResponse: "已创建 hello.cpp，编译运行后输出 Hello, World!。",
                model: "hy3", inputTokens: 3240, outputTokens: 206)
        ]
        store.record(evidence)
        let sessions = AgentSessionSnapshot.build(from: evidence)
        let snapshot = AgentTaskSnapshot.build(session: try XCTUnwrap(sessions.first), turnID: "task")
        let agents = [LocalAgentOverviewTests.agent("workbuddy", "WorkBuddy"),
                      LocalAgentOverviewTests.agent("codex", "Codex"),
                      LocalAgentOverviewTests.agent("zcode", "Zcode"),
                      LocalAgentOverviewTests.agent("cursor", "Cursor")]
        let activeEvidence = Array(evidence.prefix(2))
        let activeSessions = AgentSessionSnapshot.build(from: activeEvidence)
        let activeStore = EventStore(fileURL: directory.appendingPathComponent("active-events.json"))
        activeStore.record(activeEvidence)
        try await render(TaskWorkspaceView(sessions: activeSessions, observing: true, agents: agents).environmentObject(activeStore),
                         to: directory.appendingPathComponent("overview.png"))
        try await render(VStack(alignment: .leading, spacing: 20) {
            Text("WorkBuddy · 当前任务").font(.caption)
            Text("编写并验证 Hello World C++ 程序").font(.system(size: 23, weight: .semibold))
            AgentTaskJourneyView(snapshot: snapshot)
        }.padding(24).background(TaskStoryStyle.background), to: directory.appendingPathComponent("task.png"))
        for (name, selection) in [("tool", AgentTaskJourneyView.Selection.tool(1, "compile")),
                                  ("response", .response(1)), ("reasoning-missing", .reasoning(1)), ("context", .request(1))] {
            try await render(AgentTaskJourneyView(snapshot: snapshot, initialSelection: selection)
                .padding(24).background(TaskStoryStyle.background),
                to: directory.appendingPathComponent("\(name).png"))
        }
        store.record([GuardEvent(kind: "model", ruleId: "preview", path: "/Projects/hello-demo", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date().addingTimeInterval(-3600),
            action: "sent", sessionId: "historical-review", turnId: "historical-task",
            userIntent: "检查 C++ 项目的构建配置", modelPrompt: "检查 C++ 项目的构建配置", model: "hy3")])
        try await Task.sleep(nanoseconds: 500_000_000)
        try await render(TaskWorkspaceView(sessions: sessions, observing: true, initialSurface: .history)
            .environmentObject(store), to: directory.appendingPathComponent("history.png"))
    }

    @MainActor private func render<V: View>(_ view: V, to url: URL) async throws {
        _ = NSApplication.shared
        let host = NSHostingView(rootView: view.environment(\.colorScheme, .light))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1180, height: 900),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = host
        host.frame = NSRect(x: 0, y: 0, width: 1180, height: 900)
        window.orderBack(nil)
        try await Task.sleep(nanoseconds: 300_000_000)
        host.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
        host.cacheDisplay(in: host.bounds, to: bitmap)
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: url)
        window.close()
    }
}
