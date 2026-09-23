import SwiftUI

struct UnifiedDashboardMetrics: Equatable, Sendable {
    struct AgentRow: Identifiable, Equatable, Sendable {
        let id: String
        let name: String
        let sessions: Int
        let events: Int
        let llmRequests: Int
        let tokens: Int
        let tools: Int
        let findings: Int
        let lastActivity: Date?
    }

    let sessionCount: Int
    let taskCount: Int
    let llmRequests: Int
    let inputTokens: Int
    let outputTokens: Int
    let cachedTokens: Int
    let toolCalls: Int
    let fileActivities: Int
    let commands: Int
    let networkDestinations: Int
    let findings: Int
    let verifiedTasks: Int
    let runningAgents: Int
    let degradedCollectors: Int
    let agents: [AgentRow]

    var totalTokens: Int { inputTokens + outputTokens }

    static func build(sessions: [AgentSessionSnapshot], events: [GuardEvent],
                      incidents: [SecurityIncident], health: [CollectorHealthRecord],
                      discoveredAgents: [DiscoveredAgent]) -> Self {
        let tasks = Set(events.map { "\($0.sessionId ?? "unattributed"):\($0.turnId ?? "session")" })
        let requestEvents = events.filter { $0.kind == "model" && $0.op == "prompt" }
        let requestKeys = Set(requestEvents.map {
            $0.traceId ?? "\($0.sessionId ?? "session"):\($0.turnId ?? $0.id.uuidString)"
        })
        let toolEvents = events.filter { $0.kind == "tool" && $0.op == "call" }
        let toolKeys = Set(toolEvents.map { $0.toolCallId ?? $0.id.uuidString })
        let usageGroups = Dictionary(grouping: events.filter {
            $0.inputTokens != nil || $0.outputTokens != nil || $0.cachedTokens != nil
        }) {
            "\($0.sessionId ?? "session"):\($0.turnId ?? "turn"):\($0.traceId ?? "trace")"
        }
        let usage = usageGroups.values.map { samples in
            (samples.compactMap(\.inputTokens).max() ?? 0,
             samples.compactMap(\.outputTokens).max() ?? 0,
             samples.compactMap(\.cachedTokens).max() ?? 0)
        }
        let destinations = Set(events.filter { $0.kind == "network" }.compactMap {
            $0.remoteDomain ?? $0.remoteHost
        })
        let agentNames = Set(sessions.map(\.agent) + events.compactMap(\.agent))
        let rows = agentNames.map { name -> AgentRow in
            let agentSessions = sessions.filter { $0.agent.caseInsensitiveCompare(name) == .orderedSame }
            let agentEvents = events.filter { $0.agent?.caseInsensitiveCompare(name) == .orderedSame }
            let agentUsage = Dictionary(grouping: agentEvents.filter { $0.inputTokens != nil || $0.outputTokens != nil }) {
                "\($0.sessionId ?? "session"):\($0.turnId ?? "turn"):\($0.traceId ?? "trace")"
            }.values.reduce(0) { total, samples in
                total + (samples.compactMap(\.inputTokens).max() ?? 0)
                    + (samples.compactMap(\.outputTokens).max() ?? 0)
            }
            return AgentRow(id: name.lowercased(), name: name,
                sessions: agentSessions.count, events: agentEvents.count,
                llmRequests: agentEvents.filter { $0.kind == "model" && $0.op == "prompt" }.count,
                tokens: agentUsage,
                tools: Set(agentEvents.filter { $0.kind == "tool" && $0.op == "call" }
                    .map { $0.toolCallId ?? $0.id.uuidString }).count,
                findings: agentEvents.filter { $0.severity != "info" }.count,
                lastActivity: agentEvents.map(\.ts).max())
        }.sorted { ($0.lastActivity ?? .distantPast) > ($1.lastActivity ?? .distantPast) }

        return Self(sessionCount: sessions.count, taskCount: tasks.count,
            llmRequests: requestKeys.count,
            inputTokens: usage.reduce(0) { $0 + $1.0 },
            outputTokens: usage.reduce(0) { $0 + $1.1 },
            cachedTokens: usage.reduce(0) { $0 + $1.2 },
            toolCalls: toolKeys.count,
            fileActivities: events.filter { $0.kind == "file" }.count,
            commands: events.filter { $0.kind == "cmd" || ($0.kind == "tool" && $0.toolName == "command") }.count,
            networkDestinations: destinations.count,
            findings: incidents.count,
            verifiedTasks: Set(events.filter { $0.kind == "verification" && $0.action != "failed" }
                .map { "\($0.sessionId ?? "session"):\($0.turnId ?? "turn")" }).count,
            runningAgents: discoveredAgents.filter { $0.presence == .running }.count,
            degradedCollectors: health.filter { $0.state != .healthy }.count,
            agents: rows)
    }
}

struct UnifiedMetricsDashboardView: View {
    private enum Drilldown: String, Identifiable {
        case requests, tools, network
        var id: String { rawValue }
    }

    let dataRevision: UInt64
    let sessions: [AgentSessionSnapshot]
    let events: [GuardEvent]
    let incidents: [SecurityIncident]
    let health: [CollectorHealthRecord]
    let observing: Bool
    let discoveredAgents: [DiscoveredAgent]
    let onSession: (AgentSessionSnapshot) -> Void
    @State private var drilldown: Drilldown?

    private var metrics: UnifiedDashboardMetrics {
        .build(sessions: sessions, events: events, incidents: incidents,
               health: health, discoveredAgents: discoveredAgents)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                header
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 155), spacing: 12)], spacing: 12) {
                    metric("运行中 Agent", metrics.runningAgents, "dot.radiowaves.left.and.right", .green)
                    metric("任务", metrics.taskCount, "checklist", .blue)
                    metric("LLM 请求", metrics.llmRequests, "brain.head.profile", .purple) { drilldown = .requests }
                    metric("总 Token", metrics.totalTokens, "number", .orange)
                    metric("工具调用", metrics.toolCalls, "hammer", .cyan) { drilldown = .tools }
                    metric("文件活动", metrics.fileActivities, "doc.badge.gearshape", .indigo)
                    metric("命令", metrics.commands, "terminal", .mint)
                    metric("网络目标", metrics.networkDestinations, "network", .teal) { drilldown = .network }
                    metric("风险发现", metrics.findings, "exclamationmark.shield", .red)
                    metric("已验证任务", metrics.verifiedTasks, "checkmark.seal", .green)
                }
                tokenPanel
                HStack(alignment: .top, spacing: 14) {
                    agentPanel.frame(maxWidth: .infinity, alignment: .top)
                    recentTasks.frame(maxWidth: .infinity, alignment: .top)
                }
                collectorPanel
            }
            .padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .id(dataRevision)
        .sheet(item: $drilldown) { selection in
            DashboardEvidenceDrilldown(kind: selection.rawValue, events: events)
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 5) {
                Text("AgentReins Dashboard").font(.system(size: 30, weight: .bold))
                Text("统一事件协议上的任务、模型、工具与安全指标")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label(observing ? "实时采集中" : "采集已暂停",
                  systemImage: observing ? "wave.3.right.circle.fill" : "pause.circle")
                .foregroundStyle(observing ? .green : .orange)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(.regularMaterial, in: Capsule())
        }
    }

    @ViewBuilder private func metric(_ title: String, _ value: Int, _ icon: String, _ color: Color,
                                     action: (() -> Void)? = nil) -> some View {
        let card = VStack(alignment: .leading, spacing: 12) {
            HStack {
            Image(systemName: icon).foregroundStyle(color).font(.title3)
                Spacer()
                if action != nil { Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
            }
            Text(value.formatted()).font(.system(size: 27, weight: .semibold, design: .rounded))
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(15)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 13))
        if let action {
            Button(action: action) { card.contentShape(Rectangle()) }.buttonStyle(.plain)
        } else { card }
    }

    private var tokenPanel: some View {
        dashboardPanel("Token 使用", subtitle: "按会话 / 轮次 / Trace 去重") {
            HStack(spacing: 28) {
                tokenValue("输入", metrics.inputTokens, .blue)
                tokenValue("输出", metrics.outputTokens, .purple)
                tokenValue("缓存命中", metrics.cachedTokens, .green)
                Spacer()
            }
        }
    }

    private func tokenValue(_ label: String, _ value: Int, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(value.formatted()).font(.title3.bold()).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }

    private var agentPanel: some View {
        dashboardPanel("Agent 活动", subtitle: "跨 Agent 的统一口径") {
            if metrics.agents.isEmpty { emptyState("尚未识别到 Agent 活动") }
            else {
                VStack(spacing: 0) {
                    ForEach(metrics.agents.prefix(8)) { row in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(row.name.capitalized).fontWeight(.semibold)
                                Text("\(row.sessions) 会话 · \(row.llmRequests) 请求 · \(row.tools) 工具")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("\(row.tokens.formatted()) tokens").font(.caption.monospacedDigit())
                        }.padding(.vertical, 9)
                        if row.id != metrics.agents.prefix(8).last?.id { Divider() }
                    }
                }
            }
        }
    }

    private var recentTasks: some View {
        dashboardPanel("最近任务", subtitle: "点击查看完整证据链") {
            if sessions.isEmpty { emptyState("等待第一个任务") }
            else {
                VStack(spacing: 0) {
                    ForEach(sessions.prefix(6)) { session in
                        Button { onSession(session) } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(session.latestIntent ?? session.plainSummary).lineLimit(1)
                                    Text("\(session.agentDisplayName) · \(session.toolCallCount) 工具 · \(session.riskCount) 风险")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(session.lastActivityAt, style: .relative).font(.caption).foregroundStyle(.secondary)
                            }.padding(.vertical, 9).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                        if session.id != sessions.prefix(6).last?.id { Divider() }
                    }
                }
            }
        }
    }

    private var collectorPanel: some View {
        dashboardPanel("采集健康度", subtitle: "数据源是否完整、滞后或丢弃") {
            if health.isEmpty { emptyState("暂无采集器状态") }
            else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 230), spacing: 12)], spacing: 10) {
                    ForEach(health, id: \.source) { item in
                        HStack {
                            Circle().fill(item.state == .healthy ? Color.green : Color.orange).frame(width: 8, height: 8)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.source).fontWeight(.medium)
                                Text("accepted \(item.accepted) · malformed \(item.malformed) · dropped \(item.dropped)")
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }.padding(10).background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 9))
                    }
                }
            }
        }
    }

    private func dashboardPanel<Content: View>(_ title: String, subtitle: String,
                                                @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            content()
        }.padding(16).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 13))
    }

    private func emptyState(_ text: String) -> some View {
        Text(text).foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 55, alignment: .center)
    }
}

private struct DashboardEvidenceDrilldown: View {
    let kind: String
    let events: [GuardEvent]
    @Environment(\.dismiss) private var dismiss
    @StateObject private var ipGeolocation = IPGeolocationStore()
    @State private var query = ""

    private var title: String {
        switch kind { case "requests": return "LLM 请求上下文"; case "tools": return "工具调用"; default: return "网络活动" }
    }

    private var subtitle: String {
        switch kind {
        case "requests": return "Agent 实际发送给模型的上下文、模型响应与关联标识"
        case "tools": return "调用了哪些工具、参数如何使用、返回了什么结果"
        default: return "目标地址、端口、进程、工具、Agent 与任务之间的关联"
        }
    }

    private var relevantEvents: [GuardEvent] {
        let selected: [GuardEvent]
        switch kind {
        case "requests": selected = events.filter { $0.kind == "model" || $0.kind == "context" }
        case "tools": selected = events.filter { $0.kind == "tool" }
        default: selected = events.filter { $0.kind == "network" }
        }
        guard !query.isEmpty else { return selected.sorted { $0.ts > $1.ts } }
        return selected.filter { searchableText($0).localizedCaseInsensitiveContains(query) }.sorted { $0.ts > $1.ts }
    }

    private var networkFlows: [NetworkFlowEvidence] {
        let flows = NetworkFlowEvidence.build(events: events)
        guard !query.isEmpty else { return flows }
        return flows.filter { flow in
            [flow.destination, flow.ip, flow.agent, flow.purpose, flow.reason,
             flow.sourceEvent.sessionId, flow.sourceEvent.turnId, flow.sourceEvent.toolName]
                .compactMap { $0 }.joined(separator: " ").localizedCaseInsensitiveContains(query)
        }
    }

    private var displayCount: Int { kind == "network" ? networkFlows.count : relevantEvents.count }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.title2.bold())
                    Text(subtitle).foregroundStyle(.secondary)
                }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction)
            }.padding(20)
            Divider()
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("搜索 Agent、模型、工具、域名、会话或内容", text: $query).textFieldStyle(.plain)
                if kind == "network" {
                    Button("查询位置与归属") { ipGeolocation.resolve(networkFlows.compactMap(\.ip)) }
                        .help("将未缓存的公网 IP 发送给 ipwho.is 查询估算位置、ASN 和网络所有者")
                }
                Text("\(displayCount) 条\(kind == "network" ? "网络流" : "事件")").font(.caption).foregroundStyle(.secondary)
            }.padding(11).background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 9)).padding(16)
            if displayCount == 0 {
                VStack(spacing: 9) {
                    Image(systemName: "tray").font(.system(size: 32)).foregroundStyle(.secondary)
                    Text("暂无匹配证据").font(.headline)
                    Text("采集到相关事件后会在这里展示。").font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        if kind == "network" {
                            ForEach(networkFlows) { networkFlowCard($0) }
                        } else {
                            ForEach(relevantEvents) { event in
                                if kind == "requests" { requestCard(event) }
                                else { toolCard(event) }
                            }
                        }
                    }.padding(.horizontal, 16).padding(.bottom, 20)
                }
            }
        }.frame(minWidth: 980, minHeight: 680)
    }

    private func requestCard(_ event: GuardEvent) -> some View {
        evidenceCard(
            title: event.op == "prompt" ? "请求 · \(event.model ?? "未知模型")" : "响应 · \(event.model ?? "未知模型")",
            icon: event.op == "prompt" ? "arrow.up.circle.fill" : "arrow.down.circle.fill",
            color: event.op == "prompt" ? .purple : .blue,
            event: event
        ) {
            metadata(event)
            if let intent = event.userIntent { evidenceBlock("用户任务", intent) }
            if let prompt = event.modelPrompt { evidenceBlock("发送给 LLM 的上下文", prompt) }
            if let reasoning = event.modelReasoning { evidenceBlock("记录的推理摘要", reasoning) }
            if let response = event.modelResponse { evidenceBlock("LLM 响应", response) }
            if event.modelPrompt == nil && event.modelResponse == nil {
                missing("该数据源只记录了请求元数据，没有捕获正文")
            }
            tokenLine(event)
        }
    }

    private func toolCard(_ event: GuardEvent) -> some View {
        evidenceCard(title: "\(event.toolName ?? "未知工具") · \(event.op)", icon: "hammer.fill", color: .cyan, event: event) {
            metadata(event)
            if let arguments = event.command { evidenceBlock("调用参数 / 用法", arguments) }
            if let result = event.modelResponse { evidenceBlock("工具结果", result) }
            if let path = meaningful(event.path) { evidenceBlock("关联路径", path) }
            HStack(spacing: 16) {
                fact("状态", event.action)
                fact("Call ID", event.toolCallId ?? "未采集")
                if let duration = event.durationMS { fact("耗时", String(format: "%.0f ms", duration)) }
                Spacer()
            }
        }
    }

    private func networkFlowCard(_ flow: NetworkFlowEvidence) -> some View {
        let event = flow.sourceEvent
        let geo = flow.ip.flatMap { ipGeolocation.records[$0] }
        return evidenceCard(title: "\(flow.destination):\(flow.port.map(String.init) ?? "—")",
                            icon: "network", color: .teal, event: event) {
            HStack(spacing: 18) {
                fact("流量类型", flow.category.rawValue)
                fact("归属等级", flow.grade.rawValue)
                fact("用途", flow.purpose)
                fact("连接次数", flow.connectionCount.formatted())
                Spacer()
            }
            metadata(event)
            HStack(spacing: 20) {
                fact("域名", flow.domain ?? "未解析")
                fact("远端 IP", flow.ip ?? event.remoteHost ?? "未采集")
                fact("端口", flow.port.map(String.init) ?? "未采集")
                fact("本地地址", event.localAddress ?? "未采集")
                Spacer()
            }
            HStack(spacing: 20) {
                fact("估算位置", geo?.locationLabel ?? (flow.ip == nil ? "需要公网 IP" : "解析中 / 暂不可用"))
                fact("ASN / 网络归属", geo?.ownerLabel ?? (flow.ip == nil ? "需要公网 IP" : "解析中 / 暂不可用"))
                Spacer()
            }
            HStack(spacing: 20) {
                fact("进程 PID", event.processId.map(String.init) ?? "未采集")
                fact("父进程", event.parentProcessId.map(String.init) ?? "未采集")
                fact("关联工具", event.toolName ?? "未关联")
                fact("关联依据", flow.reason)
                Spacer()
            }
            HStack(spacing: 20) {
                fact("首次发现", flow.firstObservedAt.formatted(date: .abbreviated, time: .standard))
                fact("最近发现", flow.lastObservedAt.formatted(date: .abbreviated, time: .standard))
                fact("原始采集源", event.source ?? "unknown")
                Spacer()
            }
            if let command = event.command { evidenceBlock("触发该连接的调用", command) }
            Text("位置与 ASN/网络所有者来自第三方 IP 情报估算；Agent、进程、会话与工具归属来自本机证据关联。")
                .font(.caption2).foregroundStyle(.tertiary)
        }
    }

    private func evidenceCard<Content: View>(title: String, icon: String, color: Color,
                                             event: GuardEvent,
                                             @ViewBuilder content: @escaping () -> Content) -> some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 12) { content() }.padding(.top, 12)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: icon).foregroundStyle(color)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).fontWeight(.semibold).lineLimit(1)
                    Text("\(event.agent?.capitalized ?? "未知 Agent") · \(event.ts.formatted(date: .abbreviated, time: .standard))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(event.source ?? "unknown").font(.caption2).foregroundStyle(.secondary)
            }
        }.padding(14).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
    }

    private func metadata(_ event: GuardEvent) -> some View {
        HStack(spacing: 18) {
            fact("Session", event.sessionId ?? "未关联")
            fact("Turn", event.turnId ?? "未关联")
            fact("Trace", event.traceId ?? "未关联")
            fact("置信度", event.attributionConfidence?.rawValue ?? "unknown")
            Spacer()
        }
    }

    private func tokenLine(_ event: GuardEvent) -> some View {
        HStack(spacing: 18) {
            fact("输入 Token", event.inputTokens?.formatted() ?? "未采集")
            fact("输出 Token", event.outputTokens?.formatted() ?? "未采集")
            fact("缓存 Token", event.cachedTokens?.formatted() ?? "未采集")
            fact("推理 Token", event.reasoningTokens?.formatted() ?? "未采集")
            Spacer()
        }
    }

    private func fact(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label.uppercased()).font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).lineLimit(2).textSelection(.enabled)
        }
    }

    private func evidenceBlock(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption.bold()).foregroundStyle(.secondary)
            Text(value).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
        }
    }

    private func missing(_ text: String) -> some View {
        Label(text, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
    }

    private func meaningful(_ value: String) -> String? { value == "-" || value.isEmpty ? nil : value }

    private func searchableText(_ event: GuardEvent) -> String {
        [event.agent, event.model, event.toolName, event.remoteDomain, event.remoteHost,
         event.sessionId, event.turnId, event.traceId, event.command, event.userIntent,
         event.modelPrompt, event.modelResponse].compactMap { $0 }.joined(separator: " ")
    }
}
