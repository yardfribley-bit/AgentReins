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
    let dataRevision: UInt64
    let sessions: [AgentSessionSnapshot]
    let events: [GuardEvent]
    let incidents: [SecurityIncident]
    let health: [CollectorHealthRecord]
    let observing: Bool
    let discoveredAgents: [DiscoveredAgent]
    let onSession: (AgentSessionSnapshot) -> Void

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
                    metric("LLM 请求", metrics.llmRequests, "brain.head.profile", .purple)
                    metric("总 Token", metrics.totalTokens, "number", .orange)
                    metric("工具调用", metrics.toolCalls, "hammer", .cyan)
                    metric("文件活动", metrics.fileActivities, "doc.badge.gearshape", .indigo)
                    metric("命令", metrics.commands, "terminal", .mint)
                    metric("网络目标", metrics.networkDestinations, "network", .teal)
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

    private func metric(_ title: String, _ value: Int, _ icon: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Image(systemName: icon).foregroundStyle(color).font(.title3)
            Text(value.formatted()).font(.system(size: 27, weight: .semibold, design: .rounded))
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading).padding(15)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 13))
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
