import SwiftUI

/// A bounded projection over the already-published inventory and live evidence.
/// No database reads, process scans or history reconstruction during rendering.
struct LocalAgentOverviewItem: Identifiable {
    let agent: DiscoveredAgent
    let session: AgentSessionSnapshot?
    let turn: AgentTurn?
    let progress: TaskLiveProgress?
    let models: [String]
    let modelObservedAt: Date?
    var id: String { agent.id }
    var active: Bool { progress.map { ![.completed, .failed].contains($0.phase) } ?? false }
    var idle: Bool { progress?.phase == .completed }
    var status: String { active ? "● 执行中" : (idle ? "○ 空闲" : "◌ 任务状态待确认") }
    var activityDescription: String {
        guard active else { return "" }
        guard let tool = turn?.toolCalls.last, progress?.phase == .runningTool || progress?.phase == .processingResult else {
            return progress?.phase.rawValue ?? "等待任务证据"
        }
        let call = ToolCallLifecycleEvidence(callID: tool.id, toolName: tool.name, serverName: nil,
            arguments: tool.arguments, argumentsDigest: nil,
            state: tool.completedAt == nil ? .running : .completed,
            startedAt: tool.startedAt, completedAt: tool.completedAt, exitCode: nil, evidenceIDs: [])
        let narrative = HumanActionNarrative.build(.init(call: call, result: nil, fileActivities: [], durationMS: nil))
        return narrative.headline + (tool.completedAt == nil ? "，等待执行结果" : "，已收到工具结果")
    }

    static func build(agents: [DiscoveredAgent], sessions: [AgentSessionSnapshot],
                      progress: [String: TaskLiveProgress], since: Date) -> [Self] {
        var seen = Set<String>()
        return agents.filter { $0.presence == .running && $0.id != "web-ai" && seen.insert($0.id).inserted }
            .map { agent in
                let related = sessions.filter { $0.agent.lowercased() == agent.id.lowercased() }
                let tasks = related.flatMap { session in
                    session.turns.compactMap { turn -> (AgentSessionSnapshot, AgentTurn, TaskLiveProgress)? in
                        guard let state = progress["\(session.id)\u{0}\(turn.id)"], state.isCurrentTask(since: since) else { return nil }
                        return (session, turn, state)
                    }
                }.sorted { lhs, rhs in
                    let la = ![TaskLiveProgress.Phase.completed, .failed].contains(lhs.2.phase)
                    let ra = ![TaskLiveProgress.Phase.completed, .failed].contains(rhs.2.phase)
                    if la != ra { return la }
                    return lhs.2.lastActivityAt > rhs.2.lastActivityAt
                }
                let task = tasks.first
                let active = task.map { ![TaskLiveProgress.Phase.completed, .failed].contains($0.2.phase) } ?? false
                let observations = related.flatMap(\.events).filter { event in
                    guard event.kind == "model", event.model?.isEmpty == false,
                          ["prompt", "response", "network_prompt", "network_response"].contains(event.op) else { return false }
                    return !active || (event.sessionId == task?.0.id && event.turnId == task?.1.id)
                }.sorted { $0.ts > $1.ts }
                let models = active ? Array(Set(observations.compactMap(\.model))).sorted()
                    : observations.first?.model.map { [$0] } ?? []
                return Self(agent: agent, session: task?.0, turn: task?.1, progress: task?.2,
                    models: models, modelObservedAt: observations.first?.ts)
            }.sorted {
                if $0.active != $1.active { return $0.active }
                return $0.agent.product.localizedCaseInsensitiveCompare($1.agent.product) == .orderedAscending
            }
    }
}

struct LocalAgentOverview: View {
    let items: [LocalAgentOverviewItem]
    let onOpen: (AgentSessionSnapshot, AgentTurn) -> Void
    @State private var expanded: String?
    private var active: [LocalAgentOverviewItem] { items.filter(\.active) }
    private var idleCount: Int { items.filter(\.idle).count }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 5) {
                Text("本机 Agent 总览").font(.system(size: 24, weight: .semibold))
                Text("谁在运行，用什么模型，正在做什么。")
                    .foregroundStyle(TaskStoryStyle.muted)
            }
            HStack(alignment: .top, spacing: 20) {
                statistic("运行中的 Agent", value: items.count, unit: "个应用",
                    detail: "按应用去重，不把子进程重复计数")
                Divider()
                statistic("正在执行任务", value: active.count, unit: "个 Agent",
                    detail: "另有 \(idleCount) 个空闲 · \(items.count - active.count - idleCount) 个任务状态待确认")
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    Text("当前任务使用的模型").foregroundStyle(TaskStoryStyle.muted)
                    if active.isEmpty { Text("暂无已确认的活动模型请求") }
                    ForEach(active) { item in
                        Text("\(item.models.isEmpty ? "模型尚未确认" : item.models.joined(separator: "、")) · \(item.agent.product)")
                            .font(.caption).padding(7).background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 5))
                    }
                    Text("依据已采集请求中的模型标识；不含仅配置未调用的模型")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.fixedSize(horizontal: false, vertical: true).storyPanel()
            HStack {
                Text("运行中的 Agent").font(.headline)
                Spacer()
                if let date = items.map(\.agent.lastSeen).max() {
                    Text("状态观测于 \(date.formatted(date: .omitted, time: .standard))")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }
            }
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .top), GridItem(.flexible(), alignment: .top)], spacing: 14) {
                ForEach(items) { item in agentCard(item) }
            }
            if items.isEmpty {
                Text("尚未发现运行中的本机 Agent。已安装但未运行的应用不计入。")
                    .foregroundStyle(TaskStoryStyle.muted).frame(maxWidth: .infinity, alignment: .leading).storyPanel()
            }
            HStack {
                Text("当前任务仅展示本次采集期间确认起点的任务。")
                Spacer()
                Text("历史任务单独查询，不自动混入这里。")
            }.font(.caption).foregroundStyle(TaskStoryStyle.muted)
        }
    }

    private func statistic(_ title: String, value: Int, unit: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).foregroundStyle(TaskStoryStyle.muted)
            HStack(alignment: .firstTextBaseline) {
                Text(value.formatted()).font(.system(size: 30, weight: .semibold)).monospacedDigit()
                Text(unit).font(.caption).foregroundStyle(TaskStoryStyle.muted)
            }
            Text(detail).font(.caption).foregroundStyle(TaskStoryStyle.muted)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func agentCard(_ item: LocalAgentOverviewItem) -> some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Text(String(item.agent.product.prefix(1))).font(.headline)
                    .frame(width: 34, height: 34).background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 3) {
                    Text(item.agent.product).font(.system(size: 17, weight: .semibold))
                    // Discovery instances are environment labels, not a count of independent processes.
                    Text("运行中" + (item.agent.instances.isEmpty ? "" : " · " + item.agent.instances.map {
                        $0 == "Desktop" ? "桌面应用" : ($0 == "CLI / background service" ? "命令行 / 后台服务" : $0)
                    }.joined(separator: " / ")))
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }
                Spacer()
                Text(item.status).font(.caption).foregroundStyle(item.active ? TaskStoryStyle.accent : TaskStoryStyle.muted)
            }
            HStack(spacing: 8) {
                Text(item.active ? "当前模型" : "最近使用").foregroundStyle(TaskStoryStyle.muted)
                Text(item.models.isEmpty ? "尚未观测到" : item.models.joined(separator: "、")).fontWeight(.semibold)
                if !item.models.isEmpty {
                    Text(item.active ? "交互中已记录" : item.modelObservedAt?.formatted(date: .omitted, time: .shortened) ?? "")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }
            }.font(.callout)
            VStack(alignment: .leading, spacing: 5) {
                Text(item.active ? (item.turn?.userInput ?? "当前任务目标尚未采集")
                    : (item.idle ? "当前没有执行中的任务" : "已发现应用，等待请求证据"))
                    .fontWeight(.medium).lineLimit(2)
                Text(item.active ? item.activityDescription
                    : (item.idle ? "应用仍在运行；最近使用的模型不代表现在正在调用。" : "不会根据产品名称或默认配置猜测它使用的模型。"))
                    .font(.callout).foregroundStyle(item.active ? TaskStoryStyle.accent : TaskStoryStyle.muted)
                if item.active, let workspace = item.session?.workspace {
                    Text("\(URL(fileURLWithPath: workspace).lastPathComponent) · 本次任务")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }
            }.frame(maxWidth: .infinity, minHeight: 70, alignment: .topLeading)
                .padding(13).background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 8))
            HStack {
                if item.active, let state = item.progress {
                    Text("已观测 \(Int(max(0, state.lastActivityAt.timeIntervalSince(state.startedAt)))) 秒 · \(state.modelRequests.count) 轮交互 · \(state.usage.isEmpty ? "Token 未采集" : "\((state.inputTokens + state.outputTokens).formatted()) Token")")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                } else {
                    Text(item.idle ? "等待新的任务" : "已发现进程 · 任务状态待确认")
                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                }
                Spacer()
                Button(item.active ? "查看任务过程 →" : (item.idle ? "查看 Agent 详情" : "查看采集状态")) {
                    if item.active, let session = item.session, let turn = item.turn { onOpen(session, turn) }
                    else { expanded = expanded == item.id ? nil : item.id }
                }.buttonStyle(.bordered)
            }
            if expanded == item.id {
                Divider()
                Text("已观测进程：\(item.agent.processIds.map(String.init).joined(separator: "、"))")
                Text(item.agent.missing.isEmpty ? "采集适配器已连接" : "采集覆盖：\(item.agent.coverage.map(\.rawValue).sorted().joined(separator: "、"))")
                if let session = item.session, let turn = item.turn {
                    Button("查看最近任务的执行过程与结果") { onOpen(session, turn) }
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading).storyPanel()
    }
}
