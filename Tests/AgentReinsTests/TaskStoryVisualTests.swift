import AppKit
import SwiftUI
import XCTest
@testable import AgentReins

/// Opt-in native rendering: no collectors, no production database, no installed
/// app replacement. Images exercise production views with controlled evidence.
final class TaskStoryVisualTests: XCTestCase {
    @MainActor func testRenderSecurityDecision() async throws {
        guard let output = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] else {
            throw XCTSkip("Set UI review output directory")
        }
        let directory = URL(fileURLWithPath: output)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let event = GuardEvent(kind: "network", ruleId: "fixture", path: "-", command: nil,
            agent: "WorkBuddy", op: "connect", severity: "medium", ts: Date(), action: "observed",
            source: "测试证据", remoteHost: "203.0.113.20", remotePort: 443, remoteDomain: "gateway.example")
        try await render(ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("我的 Agent，哪些行为需要留意？").font(.title2)
                Text("界面测试数据 · 非真实任务").foregroundStyle(.secondary)
                SecurityDecisionView(summary: "观察到 WorkBuddy 连接模型中转入口，需核对发送内容。",
                    recommendation: "核对该地址是否由你配置，再查看原始请求。仅凭连接记录不能确定发生了数据泄露。",
                    events: [event])
            }.padding(24)
        }.background(TaskStoryStyle.background), to: directory.appendingPathComponent("security-decisions.png"))
    }
    @MainActor func testRenderHistorySecurityPrototype() async throws {
        guard let output = ProcessInfo.processInfo.environment["AGENTREINS_UI_REVIEW_DIR"] else {
            throw XCTSkip("Set UI review output directory")
        }
        let directory = URL(fileURLWithPath: output)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let store = EventStore(fileURL: directory.appendingPathComponent("review-events.json"))
        let analyzer = SemanticAnalyzer()
        try await render(TaskWorkspaceView(sessions: [], observing: false, initialSurface: .history)
            .environmentObject(store).environmentObject(analyzer),
            to: directory.appendingPathComponent("history-review.png"))
        let fixtureDatabase = try EvidenceDatabase(url: directory.appendingPathComponent("review-events.json.sqlite3"))
        try fixtureDatabase.append([GuardEvent(kind: "alert", ruleId: "credential_in_tool_arguments",
            path: "/example/report.txt", command: "测试证据：非真实凭据", agent: "workbuddy",
            op: "call", severity: "high", ts: Date(), action: "observed", sessionId: "ui-fixture",
            turnId: "review", toolName: "Bash")])
        try await Task.sleep(for: .milliseconds(500))
        try await render(TaskWorkspaceView(sessions: [], observing: false, initialSurface: .security)
            .environmentObject(store).environmentObject(analyzer),
            to: directory.appendingPathComponent("security-review.png"))
        for (name, section) in [("rules-review", SecurityGovernanceView.Section.rules), ("ai-review", .analysis)] {
            try await render(ScrollView {
                SecurityGovernanceView(section: section).padding(24)
            }.environmentObject(store).background(TaskStoryStyle.background),
                to: directory.appendingPathComponent("\(name).png"))
        }
        let summary = TaskAggregates(topTokenTasks: [
            .init(sessionID: "fixture-a", turnID: "a", title: "重构审计上传模块", agent: "Codex", inputTokens: 453840, outputTokens: 28320),
            .init(sessionID: "fixture-b", turnID: "b", title: "整理本月差旅报销表", agent: "WorkBuddy", inputTokens: 21000, outputTokens: 3000)
        ], agents: [.init(value: "codex", tasks: 2, occurrences: 2, inputTokens: 474840, outputTokens: 31320)],
           repeatedTools: [], modelInputAddresses: [])
        try await render(ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("查找任务，理解过去发生了什么").font(.title2.bold())
                Text("界面测试数据 · 非真实任务").foregroundStyle(.secondary)
                HistoryAggregateReview(summary: summary, question: "哪个任务 Token 最多？") { _, _ in }
            }.padding(24)
        }.background(TaskStoryStyle.background), to: directory.appendingPathComponent("ranking-review.png"))
    }
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
        try await render(ExecutionChainView(snapshot: snapshot)
            .padding(24).background(TaskStoryStyle.background),
            to: directory.appendingPathComponent("v2-execution-chain.png"))
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
        let host = NSHostingView(rootView: view.environmentObject(SemanticAnalyzer())
            .environmentObject(AlertPolicyStore()).environment(\.colorScheme, .light))
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
