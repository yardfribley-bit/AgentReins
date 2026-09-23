import AppKit
import SwiftUI

/// The product's task-first surface. The previous dashboard and operations
/// console remain in the repository while this experience is built out, but
/// are deliberately not the default navigation.
struct TaskWorkspaceView: View {
    private enum Surface { case overview, history }
    @EnvironmentObject private var eventStore: EventStore
    let sessions: [AgentSessionSnapshot]
    let observing: Bool

    @State private var selectedSessionID: String?
    @State private var selectedTurnID: String?
    @State private var taskSnapshot: AgentTaskSnapshot?
    @State private var loading = false
    @State private var loadError: String?
    @State private var lastLoadedActivity: Date?
    @State private var showingRawJSON = false
    @State private var rawJSON = ""
    @State private var surface: Surface = .overview
    @State private var historyTasks: [StoredTaskSummary] = []
    @State private var historyLoading = false
    @State private var historyError: String?
    private let refreshTimer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    private let canvas = Color(red: 5/255, green: 17/255, blue: 28/255)
    private let panel = Color(red: 12/255, green: 32/255, blue: 47/255)
    private let raised = Color(red: 18/255, green: 42/255, blue: 59/255)
    private let line = Color(red: 42/255, green: 70/255, blue: 86/255)
    private let cyan = Color(red: 55/255, green: 207/255, blue: 220/255)

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(line)
            if let taskSnapshot { taskPage(taskSnapshot) }
            else if surface == .history { history }
            else { overview }
        }
        .frame(minWidth: 1050, minHeight: 680)
        .background(canvas)
        .environment(\.colorScheme, .dark)
        .onReceive(refreshTimer) { _ in
            guard taskSnapshot != nil, !loading, let selectedSessionID,
                  let lastLoadedActivity,
                  let latest = sessions.first(where: { $0.id == selectedSessionID }),
                  latest.lastActivityAt > lastLoadedActivity else { return }
            reloadSelected()
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
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 23)).foregroundStyle(cyan)
            Text("AgentReins").font(.system(size: 20, weight: .bold))
            HStack(spacing: 5) {
                navButton("任务总览", selected: surface == .overview) {
                    taskSnapshot = nil
                    surface = .overview
                }
                navButton("历史任务", selected: surface == .history) {
                    taskSnapshot = nil
                    surface = .history
                    reloadHistory()
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
                        Text("历史任务").font(.system(size: 27, weight: .bold))
                        Text("从本地证据库读取任务；进入后与实时任务使用同一执行链。")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("刷新历史") { reloadHistory() }.buttonStyle(.bordered)
                }
                if historyLoading { ProgressView("正在检索历史任务…") }
                if let historyError { Text(historyError).foregroundStyle(.orange) }
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(historyTasks) { task in
                        Button {
                            selectedSessionID = task.sessionID
                            selectedTurnID = task.turnID
                            reloadSelected()
                        } label: {
                            HStack(spacing: 14) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("\(task.agentID) · \(task.title ?? "任务描述未采集")")
                                        .font(.system(size: 14, weight: .semibold)).lineLimit(2)
                                    Text("已观测 \(task.eventCount) 条证据 · \(duration(task.startedAt, task.lastObservedAt))")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(task.lastObservedAt, style: .date)
                                    .font(.caption).foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").foregroundStyle(cyan)
                            }
                            .padding(13).frame(maxWidth: .infinity, alignment: .leading)
                            .background(raised, in: RoundedRectangle(cornerRadius: 9))
                        }
                        .buttonStyle(.plain)
                    }
                    if historyTasks.isEmpty && !historyLoading && historyError == nil {
                        Text("暂无可回放的任务证据。")
                            .foregroundStyle(.secondary).padding(16)
                    }
                }
                .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
            }
            .padding(24)
        }
    }

    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 5) {
                    Text("正在发生什么").font(.system(size: 27, weight: .bold))
                    Text("从任务进入每一轮模型交互、工具执行和文件变化；未采集的内容明确标注。")
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                }
                if loading { ProgressView("正在读取完整任务证据…") }
                if let loadError { Text(loadError).foregroundStyle(.orange) }
                if let latest = orderedSessions.first,
                   let turn = latest.turns.last {
                    metricStrip(session: latest, turn: turn)
                }
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 13) {
                        Text("最近任务").font(.system(size: 16, weight: .semibold))
                        ForEach(orderedSessions.prefix(12)) { session in
                            ForEach(session.turns.suffix(2)) { turn in
                                taskRow(session: session, turn: turn)
                            }
                        }
                        if orderedSessions.isEmpty {
                            Text("尚未采集到任务。Agent 开始工作后，任务会出现在这里。")
                                .foregroundStyle(.secondary).padding(16)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
                    VStack(alignment: .leading, spacing: 13) {
                        Text("当前状态").font(.system(size: 16, weight: .semibold))
                        if let latest = orderedSessions.first,
                           let turn = latest.turns.last,
                           let progress = progress(session: latest, turn: turn) {
                            Text(progress.phase.rawValue).foregroundStyle(cyan)
                            fact("最近工具", progress.lastTool ?? "未采集")
                            fact("模型交互", "\(progress.modelRequests.count) 请求 · \(progress.modelResponses.count) 响应")
                            fact("工具完成", "\(progress.toolResults.count) / \(progress.toolCalls.count)")
                            fact("风险事件", "\(progress.riskEvents.count)")
                        } else {
                            Text("等待任务证据").foregroundStyle(.secondary)
                        }
                        Text("这里显示的是已观测事件，不以空白推断某事没有发生。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(width: 295, alignment: .leading)
                    .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
                }
            }
            .padding(24)
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
            HStack(alignment: .top, spacing: 12) {
                Circle().fill(state == nil ? Color.gray : cyan).frame(width: 8, height: 8).padding(.top, 6)
                VStack(alignment: .leading, spacing: 6) {
                    Text("\(session.agentDisplayName) · \(title)")
                        .font(.system(size: 14, weight: .semibold)).lineLimit(2)
                    Text(state.map { "\($0.phase.rawValue) · \($0.modelRequests.count) 次模型请求 · \($0.toolResults.count) 个工具已完成" }
                         ?? "点击读取本地完整证据")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                Text(turn.startedAt, style: .time)
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                Image(systemName: "chevron.right").foregroundStyle(cyan)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(13).background(raised, in: RoundedRectangle(cornerRadius: 9))
        }
        .buttonStyle(.plain)
    }

    private func taskPage(_ snapshot: AgentTaskSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button { taskSnapshot = nil; selectedSessionID = nil; selectedTurnID = nil } label: {
                    Label(surface == .history ? "返回历史任务" : "返回任务总览", systemImage: "chevron.left")
                }.buttonStyle(.plain).foregroundStyle(cyan)
                Spacer()
                if loading { ProgressView().controlSize(.small) }
                Button("刷新证据") { reloadSelected() }.buttonStyle(.bordered)
                Button("完整 JSON") { showRawJSON(snapshot) }.buttonStyle(.bordered)
            }
            Text(snapshot.conversation.userInputs.last ?? "任务描述未采集")
                .font(.system(size: 23, weight: .bold)).lineLimit(2)
            Text("\(snapshot.task.agentID) · \(snapshot.task.sessionID) · 证据 \(snapshot.capture.eventCount) 条")
                .font(.caption.monospaced()).foregroundStyle(.secondary)
            if let loadError { Text(loadError).font(.caption).foregroundStyle(.orange) }
            AgentTaskJourneyView(snapshot: snapshot)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(panel, in: RoundedRectangle(cornerRadius: 12))
        }
        .padding(22)
    }

    private var orderedSessions: [AgentSessionSnapshot] {
        sessions.sorted { $0.lastActivityAt > $1.lastActivityAt }
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
        return "\(seconds / 60) 分 \(seconds % 60) 秒"
    }

    private func open(session: AgentSessionSnapshot, turn: AgentTurn) {
        selectedSessionID = session.id
        selectedTurnID = turn.id
        reloadSelected()
    }

    private func reloadSelected() {
        guard let selectedSessionID else { return }
        loading = true
        eventStore.loadTask(sessionID: selectedSessionID, turnID: selectedTurnID) { result in
            loading = false
            switch result {
            case .success(let snapshot):
                taskSnapshot = snapshot
                lastLoadedActivity = sessions.first(where: { $0.id == selectedSessionID })?.lastActivityAt
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

    private func reloadHistory() {
        guard !historyLoading else { return }
        historyLoading = true
        eventStore.loadRecentTasks { result in
            historyLoading = false
            switch result {
            case .success(let tasks):
                historyTasks = tasks
                historyError = nil
            case .failure(let error):
                historyError = error.localizedDescription
            }
        }
    }
}
