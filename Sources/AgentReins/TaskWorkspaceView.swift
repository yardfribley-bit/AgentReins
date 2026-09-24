import AppKit
import SwiftUI

/// The product's task-first surface. The previous dashboard and operations
/// console remain in the repository while this experience is built out, but
/// are deliberately not the default navigation.
struct TaskWorkspaceView: View {
    enum Surface { case overview, live, history }
    @EnvironmentObject private var eventStore: EventStore
    let sessions: [AgentSessionSnapshot]
    let observing: Bool
    let agents: [DiscoveredAgent]

    @State private var selectedSessionID: String?
    @State private var selectedTurnID: String?
    @State private var taskSnapshot: AgentTaskSnapshot?
    @State private var loading = false
    @State private var loadGeneration = UUID()
    @State private var loadError: String?
    @State private var lastLoadedActivity: Date?
    @State private var showingRawJSON = false
    @State private var rawJSON = ""
    @State private var followingTask = true
    @State private var surface: Surface = .overview
    @State private var historyTasks: [StoredTaskSummary] = []
    @State private var historyLoading = false
    @State private var historyError: String?
    @State private var hasMoreHistory = true
    @State private var historyCutoff = Date()
    private let refreshTimer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    init(sessions: [AgentSessionSnapshot], observing: Bool, initialSurface: Surface = .overview, agents: [DiscoveredAgent] = []) {
        self.sessions = sessions
        self.observing = observing
        self.agents = agents
        _surface = State(initialValue: initialSurface)
    }

    private let canvas = TaskStoryStyle.background
    private let panel = TaskStoryStyle.panel
    private let raised = TaskStoryStyle.soft
    private let line = TaskStoryStyle.border
    private let cyan = TaskStoryStyle.accent

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(line)
            if let taskSnapshot { taskPage(taskSnapshot) }
            else if loading {
                VStack(spacing: 12) {
                    ProgressView("正在读取这项任务…")
                    Button("返回任务列表") {
                        loadGeneration = UUID(); loading = false
                        if surface == .live { surface = .overview }
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            else if surface == .history { history }
            else if surface == .live { emptyLive }
            else { overview }
        }
        .frame(minWidth: 1050, minHeight: 680)
        .background(canvas)
        .foregroundStyle(TaskStoryStyle.text)
        .onAppear { if surface == .history && historyTasks.isEmpty { reloadHistory() } }
        .onReceive(refreshTimer) { _ in
            guard followingTask, surface == .live, taskSnapshot != nil, !loading, let selectedSessionID,
                  let lastLoadedActivity,
                  let selectedTurnID,
                  let latest = eventStore.taskProgress["\(selectedSessionID)\u{0}\(selectedTurnID)"],
                  latest.lastActivityAt > lastLoadedActivity else { return }
            reloadSelected(automatic: true)
        }
        .sheet(isPresented: $showingRawJSON) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("完整任务 JSON").font(.headline)
                    Spacer()
                    Button("复制 JSON") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(rawJSON, forType: .string)
                    }
                    Button("关闭") { showingRawJSON = false }
                }
                TextEditor(text: .constant(rawJSON))
                    .font(.system(size: 11, design: .monospaced))
            }
            .padding(18).frame(minWidth: 850, minHeight: 600)
        }
    }

    private var header: some View {
        HStack(spacing: 18) {
            (Text("Agent") + Text("Reins").foregroundColor(cyan))
                .font(.system(size: 19, weight: .semibold))
            HStack(spacing: 5) {
                navButton("任务总览", selected: surface == .overview && taskSnapshot == nil) {
                    taskSnapshot = nil
                    loadGeneration = UUID(); loading = false; selectedSessionID = nil; selectedTurnID = nil
                    surface = .overview
                }
                navButton("当前任务", selected: surface == .live) {
                    loadGeneration = UUID(); loading = false; taskSnapshot = nil
                    surface = .live
                    if let latest = latestLiveTask { open(session: latest.session, turn: latest.turn) }
                    else { taskSnapshot = nil }
                }
                navButton("历史任务", selected: surface == .history) {
                    taskSnapshot = nil
                    loadGeneration = UUID(); loading = false; selectedSessionID = nil; selectedTurnID = nil
                    surface = .history
                    if historyTasks.isEmpty { reloadHistory() }
                }
            }
            .padding(.leading, 25)
            Spacer()
            Text(observing ? "● 实时采集中" : "○ 采集已暂停")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(observing ? Color.green : .secondary)
        }
        .padding(.horizontal, 24).frame(height: 64)
        .background(panel)
    }

    private var emptyLive: some View {
        VStack(spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 36)).foregroundStyle(cyan)
            Text("当前没有本次运行中采集到的任务").font(.title3.bold())
            if let loadError {
                Text(loadError).foregroundStyle(.orange)
                Button("重试") { reloadSelected() }
            }
            Text("旧任务请到「历史任务」查询；这里不会把启动前的数据伪装成正在发生。")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func navButton(_ label: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) { Text(label).font(.system(size: 13, weight: .semibold)) }
            .buttonStyle(.plain)
            .padding(.horizontal, 13).padding(.vertical, 8)
            .background(selected ? raised : .clear, in: RoundedRectangle(cornerRadius: 7))
            .foregroundStyle(selected ? cyan : Color.secondary)
    }

    private var history: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("历史任务").font(.system(size: 23, weight: .semibold))
                        Text("按需读取任务摘要，打开某项后加载它的执行过程。")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("刷新历史") { reloadHistory() }.buttonStyle(.bordered)
                }
                if historyLoading { ProgressView("正在检索历史任务…") }
                if let historyError { Text(historyError).foregroundStyle(.orange) }
                if let loadError {
                    Text(loadError).foregroundStyle(.orange)
                    Button("重新读取任务") { reloadSelected() }
                }
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(historyTasks) { task in
                        Button {
                            selectedSessionID = task.sessionID
                            selectedTurnID = task.turnID
                            reloadSelected()
                        } label: {
                            HStack(spacing: 14) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(task.title ?? "任务描述未采集")
                                        .font(.system(size: 15, weight: .semibold)).lineLimit(2)
                                    Text("\(formattedAgentName(task.agentID)) · \(task.startedAt.formatted(date: .abbreviated, time: .shortened)) · \(duration(task.startedAt, task.lastObservedAt))")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Text("查看执行过程与结果").font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(task.lastObservedAt, style: .date)
                                    .font(.caption).foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").foregroundStyle(cyan)
                            }
                            .padding(18).frame(maxWidth: .infinity, alignment: .leading)
                            .background(panel, in: RoundedRectangle(cornerRadius: 10))
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(line))
                        }
                        .buttonStyle(.plain)
                    }
                    if historyTasks.isEmpty && !historyLoading && historyError == nil {
                        Text("暂无可回放的任务证据。")
                            .foregroundStyle(.secondary).padding(16)
                    }
                    if hasMoreHistory && !historyTasks.isEmpty {
                        Button(historyLoading ? "正在读取…" : "加载更早的 20 项任务") {
                            reloadHistory(reset: false)
                        }
                        .disabled(historyLoading)
                        .buttonStyle(.bordered)
                        .frame(maxWidth: .infinity)
                        .padding(.top, 10)
                    }
                }
                .storyPanel()
            }
            .padding(24)
        }
    }

    private var overview: some View {
        ScrollView {
            LocalAgentOverview(items: LocalAgentOverviewItem.build(agents: agents, sessions: sessions,
                progress: eventStore.taskProgress, since: eventStore.liveSince), onOpen: open)
                .padding(24)
            if let loadError { Text(loadError).foregroundStyle(.orange).padding(.horizontal, 24) }
        }
    }

    private func metricStrip(session: AgentSessionSnapshot, turn: AgentTurn) -> some View {
        let state = progress(session: session, turn: turn)
        return HStack(spacing: 10) {
            metric("任务阶段", state?.phase.rawValue ?? "等待证据")
            metric("已观测耗时", state.map { duration($0.startedAt, $0.lastActivityAt) } ?? "—")
            metric("模型 请求 / 响应", state.map { "\($0.modelRequests.count) / \($0.modelResponses.count)" } ?? "—")
            metric("工具 完成 / 调用", state.map { "\($0.toolResults.count) / \($0.toolCalls.count)" } ?? "—")
            metric("已确认 Token", state.map { ($0.inputTokens + $0.outputTokens).formatted() } ?? "—")
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(size: 18, weight: .semibold, design: .rounded))
                .lineLimit(1).minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14).background(panel, in: RoundedRectangle(cornerRadius: 10))
    }

    private func taskRow(session: AgentSessionSnapshot, turn: AgentTurn) -> some View {
        let state = progress(session: session, turn: turn)
        let title = turn.userInput ?? session.latestIntent ?? "任务描述未采集"
        return Button { open(session: session, turn: turn) } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    Text(title).font(.system(size: 15, weight: .semibold)).lineLimit(2)
                    Spacer()
                    Text(state?.phase.rawValue ?? "等待证据").font(.caption)
                        .foregroundStyle(cyan).padding(.horizontal, 7).padding(.vertical, 3)
                        .background(raised, in: RoundedRectangle(cornerRadius: 5))
                }
                Text(state?.phase == .completed ? "Agent 已返回结果，点击查看交付内容与验证记录。" : turn.plainTaskProgress)
                    .foregroundStyle(TaskStoryStyle.muted).lineLimit(2)
                Text(state.map { "\(session.agentDisplayName) · \(duration($0.startedAt, $0.lastActivityAt)) · \($0.modelRequests.count) 次模型请求 · \(($0.inputTokens + $0.outputTokens).formatted()) Token" } ?? session.agentDisplayName)
                    .font(.caption).foregroundStyle(TaskStoryStyle.muted)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(18).background(panel, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(line))
        }
        .buttonStyle(.plain)
    }

    private func taskPage(_ snapshot: AgentTaskSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button {
                    taskSnapshot = nil; selectedSessionID = nil; selectedTurnID = nil
                    if surface == .live { surface = .overview }
                } label: {
                    Label(surface == .history ? "返回历史任务" : "返回任务总览", systemImage: "chevron.left")
                }.buttonStyle(.plain).foregroundStyle(cyan)
                Spacer()
                if loading { ProgressView().controlSize(.small) }
            }
            Text(snapshot.conversation.userInputs.last ?? "任务描述未采集")
                .font(.system(size: 23, weight: .bold)).lineLimit(2)
            Text("\(formattedAgentName(snapshot.task.agentID)) · \(surface == .history ? "历史任务" : "当前任务") · \(snapshot.task.startedAt?.formatted(date: .abbreviated, time: .shortened) ?? "开始时间未采集")")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
            if let loadError { Text(loadError).font(.caption).foregroundStyle(.orange) }
            AgentTaskJourneyView(snapshot: snapshot, following: $followingTask)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .id(snapshot.task.taskID)
            HStack {
                Spacer()
                Button("刷新") { reloadSelected() }.disabled(loading)
                Button("任务原始 JSON") { showRawJSON(snapshot) }
            }
        }
        .padding(22)
    }

    private var orderedSessions: [AgentSessionSnapshot] {
        sessions.filter { !liveTurns(for: $0).isEmpty }
            .sorted { $0.lastActivityAt > $1.lastActivityAt }
    }

    private func liveTurns(for session: AgentSessionSnapshot) -> [AgentTurn] {
        session.turns.filter { turn in
            guard let state = progress(session: session, turn: turn) else { return false }
            return state.isCurrentTask(since: eventStore.liveSince)
        }
    }

    private var latestLiveTask: (session: AgentSessionSnapshot, turn: AgentTurn)? {
        for session in orderedSessions {
            if let turn = liveTurns(for: session).last { return (session, turn) }
        }
        return nil
    }

    private func progress(session: AgentSessionSnapshot, turn: AgentTurn) -> TaskLiveProgress? {
        eventStore.taskProgress["\(session.id)\u{0}\(turn.id)"]
    }

    private func fact(_ label: String, _ value: String) -> some View {
        HStack { Text(label).foregroundStyle(.secondary); Spacer(); Text(value) }
            .font(.caption).padding(.vertical, 7)
            .overlay(Divider().overlay(line), alignment: .bottom)
    }

    private func duration(_ start: Date, _ end: Date) -> String {
        let seconds = max(0, Int(end.timeIntervalSince(start)))
        return seconds < 60 ? "\(seconds) 秒" : "\(seconds / 60) 分 \(seconds % 60) 秒"
    }

    private func open(session: AgentSessionSnapshot, turn: AgentTurn) {
        followingTask = true
        surface = .live
        selectedSessionID = session.id
        selectedTurnID = turn.id
        reloadSelected()
    }

    private func reloadSelected(automatic: Bool = false) {
        guard let selectedSessionID, !loading else { return }
        let generation = UUID()
        loadGeneration = generation
        let turnID = selectedTurnID
        let observedActivity = selectedTurnID.flatMap {
            eventStore.taskProgress["\(selectedSessionID)\u{0}\($0)"]?.lastActivityAt
        }
        loading = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
            guard loading, loadGeneration == generation else { return }
            loadGeneration = UUID(); loading = false
            loadError = "读取时间过长，请重试。"
        }
        eventStore.loadTask(sessionID: selectedSessionID, turnID: selectedTurnID) { result in
            guard loadGeneration == generation, self.selectedSessionID == selectedSessionID, selectedTurnID == turnID else { return }
            loading = false
            if automatic && !followingTask { return }
            switch result {
            case .success(let snapshot):
                taskSnapshot = snapshot
                lastLoadedActivity = observedActivity
                loadError = nil
            case .failure(let error):
                loadError = error.localizedDescription
            }
        }
    }

    private func showRawJSON(_ snapshot: AgentTaskSnapshot) {
        Task {
            let result = await Task.detached(priority: .utility) {
                try? snapshot.prettyJSON()
            }.value
            rawJSON = result ?? "任务 JSON 编码失败"
            showingRawJSON = true
        }
    }

    private func reloadHistory(reset: Bool = true) {
        guard !historyLoading else { return }
        historyLoading = true
        if reset { historyCutoff = Date() }
        eventStore.loadRecentTasks(limit: 20, before: historyCutoff, offset: reset ? 0 : historyTasks.count) { result in
            historyLoading = false
            switch result {
            case .success(let tasks):
                historyTasks = reset ? tasks : historyTasks + tasks
                hasMoreHistory = tasks.count == 20
                historyError = nil
            case .failure(let error):
                historyError = error.localizedDescription
            }
        }
    }
}

private extension AgentTurn {
    var plainTaskProgress: String {
        guard let call = toolCalls.last else { return "已收到任务，正在跟踪模型请求与回复。" }
        if call.completedAt == nil { return "正在执行 \(call.name)，等待返回结果。" }
        return "已收到 \(call.name) 的执行结果，等待后续进展。"
    }
}
