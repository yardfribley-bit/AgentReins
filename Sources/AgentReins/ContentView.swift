import SwiftUI

private enum CenterPage: String, CaseIterable, Identifiable {
    case home, sessions, timeline, protection, recovery
    var id: String { rawValue }
    func title(english: Bool) -> String {
        switch self {
        case .home: return english ? "Overview" : "安全状态"
        case .sessions: return english ? "Agent Sessions" : "Agent 会话"
        case .timeline: return english ? "Activity" : "活动时间线"
        case .protection: return english ? "Protection" : "保护设置"
        case .recovery: return english ? "Recovery" : "恢复"
        }
    }
    var icon: String {
        switch self {
        case .home: return "shield.checkered"
        case .sessions: return "bubble.left.and.bubble.right"
        case .timeline: return "clock.arrow.circlepath"
        case .protection: return "lock.shield"
        case .recovery: return "arrow.uturn.backward.circle"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var store: RuleStore
    @EnvironmentObject private var fileGuard: FileGuard
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore
    @EnvironmentObject private var workBuddySight: WorkBuddySight
    @EnvironmentObject private var semanticAnalyzer: SemanticAnalyzer
    @EnvironmentObject private var memoryScan: MemoryScanManager
    @EnvironmentObject private var memoryRuleStore: MemoryRuleStore

    @AppStorage("agr_protectionMode") private var protectionMode = "recommended"
    @AppStorage("agr_onboardingComplete") private var onboardingComplete = false
    @State private var page: CenterPage? = .home
    @State private var ruleText = ""
    @State private var ruleFeedback = ""
    @State private var dismissedEventIDs = Set<UUID>()
    @State private var selectedIncident: SecurityIncident?
    @State private var selectedSession: AgentSessionSnapshot?
    @State private var openRouterKey = ""
    @State private var analysisModel = "openai/gpt-4o-mini"
    @State private var modelFeedback = ""

    private var events: [GuardEvent] {
        eventStore.events
    }
    private var todayEvents: [GuardEvent] { eventStore.events(on: Date()) }
    private var incidents: [SecurityIncident] { eventStore.incidents }
    private var sessions: [AgentSessionSnapshot] { eventStore.sessions }
    private var riskIncidents: [SecurityIncident] { incidents.filter { $0.severity != "info" } }
    private var activityIncidents: [SecurityIncident] { incidents.filter { $0.severity == "info" } }
    private var todayIncidents: [SecurityIncident] { SecurityIncident.correlate(todayEvents) }
    private var attentionIncident: SecurityIncident? {
        riskIncidents.first { ($0.severity == "critical" || $0.severity == "high") && !dismissedEventIDs.contains($0.id) }
    }
    private var isRunning: Bool { fileGuard.running || processGuard.running }
    private let english = true
    private func l(_ en: String, _ localizedFallback: String) -> String { en }

    var body: some View {
        NavigationSplitView {
            List(CenterPage.allCases, selection: $page) { item in
                Label(item.title(english: english), systemImage: item.icon).tag(item)
            }
            .navigationTitle("AgentReins")
            .safeAreaInset(edge: .bottom) { localOnlyBadge }
        } detail: {
            Group {
                switch page ?? .home {
                case .home: home
                case .sessions: sessionsPage
                case .timeline: timeline
                case .protection: protection
                case .recovery: recovery
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(nsColor: .windowBackgroundColor))
        }
        .frame(minWidth: 960, minHeight: 640)
        .task {
            guard !isRunning else { return }
            fileGuard.start()
            processGuard.start()
        }
        .sheet(isPresented: Binding(
            get: { !onboardingComplete },
            set: { if !$0 { onboardingComplete = true } }
        )) { onboarding }
        .sheet(item: $selectedIncident) { incident in incidentDetail(incident) }
        .sheet(item: $selectedSession) { session in sessionDetail(session) }
    }

    private var localOnlyBadge: some View {
        HStack(spacing: 8) {
            Image(systemName: "network.slash")
            VStack(alignment: .leading, spacing: 1) {
                Text(l("Private by default", "完全本地运行")).font(.caption.bold())
                Text(l("Activity stays on this Mac", "安全数据不会上传")).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(12).background(.ultraThinMaterial)
    }

    private var home: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header(l("See what your AI agent is doing", "看清你的 Agent 正在做什么"), subtitle: l("AgentReins connects intent, model activity, tool calls, and outcomes — in one clear timeline.", "AgentReins 将用户意图、模型活动、工具调用和结果关联在一条清晰时间线上。"))
                safetyHero
                liveAgentsCard
                recentSessions
                if let incident = attentionIncident { decisionCard(incident) }
                HStack(spacing: 14) {
                    metricCard(title: l("Protection", "正在保护"), value: isRunning ? l("Active", "运行中") : l("Paused", "已暂停"), icon: "dot.radiowaves.left.and.right", tint: isRunning ? .green : .secondary)
                    metricCard(title: l("Today's activity", "今日活动"), value: "\(todayIncidents.count)", icon: "waveform.path.ecg", tint: .blue)
                    metricCard(title: l("Auto-recovered", "今日自动恢复"), value: "\(todayEvents.filter { $0.action == "restored" }.count)", icon: "arrow.uturn.backward", tint: .purple)
                }
                recentActivity
            }
            .padding(32).frame(maxWidth: 980, alignment: .leading)
        }
    }

    private var recentSessions: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(l("Recent agent sessions", "最近 Agent 会话")).font(.headline)
                Spacer(); Button(l("View all", "查看全部")) { page = .sessions }.buttonStyle(.link)
            }
            if sessions.isEmpty {
                emptyState(l("No connected sessions yet", "暂无可关联会话"), detail: l("AgentSight automatically discovers supported local agents.", "接入 Agent 原生上下文后，会话会出现在这里。"), icon: "bubble.left")
                    .frame(height: 120)
            } else {
                ForEach(sessions.prefix(4)) { session in
                    Button { selectedSession = session } label: { sessionRow(session) }.buttonStyle(.plain)
                }
            }
        }
    }

    private var sessionsPage: some View {
        VStack(alignment: .leading, spacing: 18) {
            header(l("Agent sessions", "Agent 会话"), subtitle: l("Follow every turn from user intent to model response, tool calls, and system impact.", "以用户意图和模型上下文为起点，查看 Agent 的完整执行过程。"))
            if sessions.isEmpty {
                emptyState(l("No sessions yet", "暂无会话"), detail: l("AgentSight automatically discovers supported local agents.", "AgentSight 会自动发现支持的本地 Agent 会话。"), icon: "bubble.left.and.bubble.right")
            } else {
                List(sessions) { session in
                    Button { selectedSession = session } label: { sessionRow(session).padding(.vertical, 7) }.buttonStyle(.plain)
                }.listStyle(.inset)
            }
        }.padding(32)
    }

    private func sessionRow(_ session: AgentSessionSnapshot) -> some View {
        HStack(spacing: 13) {
            ZStack {
                Circle().fill(Color.blue.opacity(0.12))
                Image(systemName: "sparkles").foregroundStyle(.blue)
            }.frame(width: 38, height: 38)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(session.agent.capitalized).font(.headline)
                    if let model = session.model { Text(model).font(.caption).foregroundStyle(.secondary) }
                }
                Text(session.latestIntent ?? l("User intent wasn't captured", "未采集用户意图")).lineLimit(2).foregroundStyle(.primary)
                Text(session.plainSummary).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                Text(english ? "\(session.toolCallCount) actions · \(session.riskCount == 0 ? "No risk found" : "\(session.riskCount) risks found")" : "完成了 \(session.toolCallCount) 次操作 · \(session.riskCount == 0 ? "未发现风险" : "发现 \(session.riskCount) 项风险")")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer(); Text(session.lastActivityAt, style: .relative).font(.caption).foregroundStyle(.tertiary)
            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
        }.contentShape(Rectangle())
    }

    private func sessionDetail(_ session: AgentSessionSnapshot) -> some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(session.agent.capitalized).font(.largeTitle.bold())
                            Text(session.model ?? l("Model not recorded", "模型未记录")).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Label(english ? "\(session.riskCount) risks" : "\(session.riskCount) 项风险", systemImage: session.riskCount == 0 ? "checkmark.shield" : "exclamationmark.shield")
                            .foregroundStyle(session.riskCount == 0 ? .green : .orange)
                    }
                    GroupBox(l("Session context", "会话上下文")) {
                        VStack(alignment: .leading, spacing: 10) {
                            contextField(l("Latest user intent", "用户意图"), session.latestIntent ?? l("Not captured", "未采集"))
                            contextField("Session ID", session.id)
                            contextField(l("Workspace", "工作区"), session.workspace ?? l("Not recorded", "未记录"))
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6)
                    }
                    ForEach(session.turns) { turn in turnDetail(turn) }
                }.padding(28)
            }.frame(minWidth: 780, minHeight: 650)
            .toolbar { Button(l("Done", "完成")) { selectedSession = nil } }
        }
    }

    private func turnDetail(_ turn: AgentTurn) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 18) {
                    Label(turn.modelNames, systemImage: "cpu")
                    Divider().frame(height: 18)
                    Label(english ? "\(turn.contextCharacters.formatted()) context chars" : "上下文 \(turn.contextCharacters.formatted()) 字符", systemImage: "text.alignleft")
                    Divider().frame(height: 18)
                    Label(english ? "\(turn.responseCharacters.formatted()) response chars" : "返回 \(turn.responseCharacters.formatted()) 字符", systemImage: "arrow.down.message")
                    Spacer()
                }.font(.caption.weight(.medium)).foregroundStyle(.secondary)
                if let input = turn.inputTokens {
                    HStack(spacing: 14) {
                        Label(english ? "\(input.formatted()) input tokens" : "输入 \(input.formatted()) tokens", systemImage: "arrow.up.circle")
                        if let output = turn.outputTokens { Text(english ? "\(output.formatted()) output" : "输出 \(output.formatted())") }
                        if let cached = turn.cachedTokens { Text(english ? "\(cached.formatted()) cached" : "缓存命中 \(cached.formatted())") }
                        if let reasoning = turn.reasoningTokens { Text(english ? "\(reasoning.formatted()) reasoning" : "推理 \(reasoning.formatted())") }
                        Spacer()
                    }.font(.caption).foregroundStyle(.secondary)
                } else {
                    Text(l("Exact token usage was not reported for this turn", "本轮未采集到模型上报的精确 Token 用量"))
                        .font(.caption).foregroundStyle(.tertiary)
                }
                aiAnalysisCard(turn)
                summaryStep(number: "1", title: l("Your instruction", "用户输入的指令"), value: turn.userInput ?? l("Not captured", "未采集"), tint: .blue)
                evidenceStep(number: "2", title: l("Model context captured by WorkBuddy", "WorkBuddy 已落盘的模型上下文"), value: turn.fullPrompt, tint: .indigo, showPreview: true)
                summaryStep(number: "3", title: l("Instructions returned by the model", "模型返回的指令"), value: turn.modelInstructionSummary, tint: .purple)
                summaryStep(number: "4", title: l("Tools & MCP actually called", "Agent 实际调用的 Tool / MCP"), value: turn.executionSummary, tint: .cyan)
                evidenceStep(number: "5", title: l("Tool execution results", "工具执行结果"), value: turn.toolResultSummary, tint: .teal)
                evidenceStep(number: "6", title: l("File & code changes", "发现的文件与代码更改"), value: turn.codeChangeSummary, tint: .orange)
                evidenceStep(number: "7", title: l("Final result", "最终回答与任务结果"), value: turn.finalResponse ?? l("No final response was captured", "未采集到最终回答"), tint: .green, showPreview: true)
                evidenceStep(number: "8", title: l("Memory retrieved", "记忆读取与隐私唤醒"), value: turn.memoryRetrievalSummary, tint: .pink)
                evidenceStep(number: "9", title: l("Memory committed", "新增或修改的持久化记忆"), value: turn.memoryCommitSummary, tint: .red)

                DisclosureGroup(l("View complete model & execution evidence", "查看完整模型与执行证据")) {
                    VStack(alignment: .leading, spacing: 14) {
                        ForEach(turn.exchanges) { exchange in
                            Divider()
                            contextField(l("Full prompt sent to the model", "Agent 向大模型发送的完整内容"), exchange.prompt ?? exchange.userIntent ?? l("Not captured", "未采集"))
                            contextField(l("Full model response", "大模型完整返回"), exchange.response ?? l("No text response recorded", "未记录文本返回"))
                            contextField(l("Recorded reasoning", "模型推理记录"), exchange.reasoning ?? l("Not logged by the agent", "未落盘"))
                            contextField(l("Model decision", "模型执行决定"), exchange.decision ?? l("Not recorded", "未记录"))
                            ForEach(exchange.toolCalls) { call in toolCallView(call) }
                        }
                    }.padding(.top, 10)
                }
            }.padding(.vertical, 7)
        } label: {
            HStack {
                Text(english ? "Turn \(turn.index)" : "第 \(turn.index) 轮")
                Spacer(); Text(english ? "\(turn.toolCalls.count) tool calls" : "\(turn.toolCalls.count) 次工具调用").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func aiAnalysisCard(_ turn: AgentTurn) -> some View {
        if let analysis = semanticAnalyzer.results[turn.id] {
            VStack(alignment: .leading, spacing: 10) {
                Label(l("AI summary", "AI 分析结论"), systemImage: "sparkles")
                    .font(.headline).foregroundStyle(.indigo)
                contextField(l("Goal", "用户目标"), analysis.goal)
                contextField(l("Agent actions", "Agent 实际行为"), analysis.actions)
                contextField(l("Risk", "是否值得关注"), analysis.risk)
                contextField(l("Recommendation", "用户需要做什么"), analysis.nextStep)
                if let usage = semanticAnalyzer.usage[turn.id] {
                    Text(english ? "OpenRouter usage: \(usage.inputTokens.formatted()) input + \(usage.outputTokens.formatted()) output = \(usage.totalTokens.formatted()) tokens" : "OpenRouter 用量：输入 \(usage.inputTokens.formatted()) + 输出 \(usage.outputTokens.formatted()) = 共 \(usage.totalTokens.formatted()) tokens")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 13).fill(Color.indigo.opacity(0.08)))
        } else {
            HStack(spacing: 14) {
                Image(systemName: "sparkles").font(.title2).foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 3) {
                    Text(l("Understand this turn at a glance", "先看懂这一轮发生了什么")).font(.headline)
                    Text(l("Get a plain-language summary before reviewing the raw evidence.", "AI 会先用普通语言说明目标、行为、风险和建议，再由你查看原始证据。"))
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    Task { await semanticAnalyzer.analyze(turn) }
                } label: {
                    Text(semanticAnalyzer.analyzing.contains(turn.id) ? l("Analyzing…", "正在分析…") : l("Analyze", "AI 分析"))
                }.buttonStyle(.borderedProminent).tint(.indigo)
                    .disabled(semanticAnalyzer.analyzing.contains(turn.id))
            }
            .padding(16).background(RoundedRectangle(cornerRadius: 13).fill(Color.indigo.opacity(0.06)))
        }
    }

    private func summaryStep(number: String, title: String, value: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number).font(.caption.bold()).foregroundStyle(.white)
                .frame(width: 23, height: 23).background(Circle().fill(tint))
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(value).foregroundStyle(.secondary).lineLimit(5)
            }
            Spacer()
        }
    }

    private func evidenceStep(number: String, title: String, value: String?, tint: Color, showPreview: Bool = false) -> some View {
        let evidence = value ?? l("Not captured", "未采集")
        return HStack(alignment: .top, spacing: 12) {
            Text(number).font(.caption.bold()).foregroundStyle(.white)
                .frame(width: 23, height: 23).background(Circle().fill(tint))
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(.headline)
                if showPreview {
                    Text(english ? "\(evidence.utf8.count.formatted()) bytes captured" : "已采集 \(evidence.utf8.count.formatted()) 字节")
                        .font(.caption).foregroundStyle(.indigo)
                    Text(String(evidence.prefix(900)) + (evidence.count > 900 ? "…" : ""))
                        .font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                        .textSelection(.enabled).lineLimit(12)
                        .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 9).fill(tint.opacity(0.06)))
                }
                DisclosureGroup(l("View complete evidence", "查看完整证据")) {
                    ScrollView(.horizontal) {
                        Text(evidence).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(maxHeight: 260).padding(.top, 6)
                }
            }
            Spacer()
        }
    }

    private func toolCallView(_ call: AgentToolCall) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack { Label(call.friendlyName, systemImage: "function").font(.headline); Spacer(); Text(call.friendlyStatus).font(.caption).foregroundStyle(.secondary) }
            Text("Function call：\(call.name)").font(.caption).foregroundStyle(.secondary)
            if let args = call.arguments {
                ScrollView(.horizontal) { Text(args).font(.system(.caption, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: true, vertical: false) }
            }
            if let result = call.result {
                DisclosureGroup(l("Tool result", "工具返回")) {
                    Text(result).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 6)
                }
            }
        }.padding(10).background(RoundedRectangle(cornerRadius: 9).fill(Color.secondary.opacity(0.07)))
    }

    private func contextField(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled)
        }
    }

    private var liveAgentsCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(l("Live agents", "实时 Agent"), systemImage: "dot.radiowaves.left.and.right").font(.headline)
                Spacer()
                Text(l("Live", "实时更新")).font(.caption).foregroundStyle(.secondary)
            }
            if processGuard.activeAgents.isEmpty {
                Text(l("No supported agent is running", "当前未识别到运行中的 Agent")).foregroundStyle(.secondary)
            } else {
                HStack(spacing: 10) {
                    ForEach(processGuard.activeAgents, id: \.self) { agent in
                        HStack(spacing: 7) {
                            Circle().fill(Color.green).frame(width: 8, height: 8)
                            Text(agent.capitalized).font(.callout.weight(.medium))
                            Text(l("Active", "运行中")).font(.caption).foregroundStyle(.secondary)
                        }.padding(.horizontal, 11).padding(.vertical, 7)
                            .background(Capsule().fill(Color.green.opacity(0.09)))
                    }
                    Spacer()
                }
            }
            HStack(spacing: 6) {
                Image(systemName: workBuddySight.connected ? "link.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle(workBuddySight.connected ? .green : .orange)
                Text(workBuddySight.connected ? l("AgentSight connected to WorkBuddy", "AgentSight · WorkBuddy 会话源已连接") : l("AgentSight is waiting for WorkBuddy", "AgentSight · WorkBuddy 会话源未连接"))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let latest = activityIncidents.first {
                Divider()
                Button { selectedIncident = latest } label: {
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(l("Latest activity", "最近正常活动")).font(.caption).foregroundStyle(.secondary)
                            Text(latest.command ?? latest.title).lineLimit(2).font(.system(.callout, design: .monospaced))
                        }
                        Spacer(); Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }
                }.buttonStyle(.plain)
            }
        }.cardStyle()
    }

    private var safetyHero: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle().fill((attentionIncident == nil ? Color.green : Color.orange).opacity(0.14))
                Image(systemName: attentionIncident == nil ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 34)).foregroundStyle(attentionIncident == nil ? .green : .orange)
            }.frame(width: 72, height: 72)
            VStack(alignment: .leading, spacing: 5) {
                Text(attentionIncident == nil ? l("You're in control", "一切正常") : l("One action needs your attention", "有一项操作需要注意")).font(.title2.bold())
                Text(attentionIncident == nil ? l("Agent activity is visible and no action needs your attention.", "Agent 活动清晰可见，目前无需你处理。") : l("Review the plain-English explanation before you decide.", "查看下方说明，然后决定是否信任该操作。"))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(isRunning ? l("Pause", "暂停保护") : l("Resume", "继续保护")) {
                if isRunning { fileGuard.stop(); processGuard.stop() }
                else { fileGuard.start(); processGuard.start() }
            }.buttonStyle(.bordered)
        }
        .padding(22).background(RoundedRectangle(cornerRadius: 18).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func decisionCard(_ incident: SecurityIncident) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label(l("Your decision needed", "需要你的决定"), systemImage: "exclamationmark.triangle.fill").font(.headline).foregroundStyle(.orange)
                Spacer()
                Text(incident.agent?.capitalized ?? "本机 Agent").font(.caption).padding(.horizontal, 9).padding(.vertical, 4)
                    .background(Capsule().fill(Color.secondary.opacity(0.12)))
            }
            Text(incident.title).font(.title3.bold())
            Text(incident.summary).foregroundStyle(.secondary)
            if let command = incident.command {
                Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled).lineLimit(4)
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 9).fill(Color.black.opacity(0.06)))
            } else if incident.primary.path != "-" {
                Label(incident.primary.path, systemImage: "doc").font(.callout).textSelection(.enabled)
            }
            HStack {
                Button(l("Don't trust", "标记为不信任")) { dismissedEventIDs.insert(incident.id) }.buttonStyle(.borderedProminent).tint(.red)
                Button(l("Trust once", "仅本次信任")) { dismissedEventIDs.insert(incident.id) }.buttonStyle(.bordered)
                Spacer(); Button(l("View full trace", "查看完整过程")) { selectedIncident = incident }.buttonStyle(.link)
            }
        }
        .padding(22).background(RoundedRectangle(cornerRadius: 18).fill(Color.orange.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.orange.opacity(0.35)))
    }

    private var recentActivity: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack { Text(l("Recent activity", "最近活动")).font(.headline); Spacer(); Button(l("View all", "查看全部")) { page = .timeline }.buttonStyle(.link) }
            if incidents.isEmpty {
                emptyState(l("Nothing needs attention", "还没有重要活动"), detail: l("Important agent actions will appear here in plain language.", "Agent 的重要操作会以容易理解的方式出现在这里。"), icon: "checkmark.circle")
                    .frame(height: 180)
            } else { ForEach(incidents.prefix(5)) { incident in incidentRow(incident) } }
        }
    }

    private var timeline: some View {
        VStack(alignment: .leading, spacing: 18) {
            header(l("Activity timeline", "活动时间线"), subtitle: l("See the agent's intent and its real impact on your computer, in order.", "按时间查看 Agent 的意图和在电脑上造成的实际影响。"))
            if incidents.isEmpty {
                emptyState(l("No activity yet", "暂无活动"), detail: l("Keep protection on and activity will appear automatically.", "保持保护开启，活动会自动出现在这里。"), icon: "clock")
            } else { List(incidents) { incident in Button { selectedIncident = incident } label: { incidentRow(incident).padding(.vertical, 6) }.buttonStyle(.plain) }.listStyle(.inset) }
        }.padding(32)
    }

    private var protection: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header("Protection", subtitle: "Choose a protection level or describe what your agents must never do.")
                VStack(alignment: .leading, spacing: 14) {
                    Text("Protection mode").font(.headline)
                    Picker("Protection mode", selection: $protectionMode) {
                        Text("Quiet").tag("quiet"); Text("Recommended").tag("recommended"); Text("Strict").tag("strict")
                    }.pickerStyle(.segmented)
                    Text(modeDescription).font(.callout).foregroundStyle(.secondary)
                }.cardStyle()
                VStack(alignment: .leading, spacing: 14) {
                    Text("Add a protection rule").font(.headline)
                    TextField("Example: Never let agents modify my Photos folder", text: $ruleText).textFieldStyle(.roundedBorder).onSubmit(addLocalRule)
                    HStack {
                        Text("Rules are parsed and stored locally. No account or API key required.").font(.caption).foregroundStyle(.secondary)
                        Spacer(); Button("Add") { addLocalRule() }.disabled(ruleText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    if !ruleFeedback.isEmpty { Text(ruleFeedback).font(.caption).foregroundStyle(.green) }
                }.cardStyle()
                modelConfigurationCard
                VStack(alignment: .leading, spacing: 8) {
                    Text("Your protection rules").font(.headline)
                    if store.rules.isEmpty { Text("No custom rules yet. Built-in high-risk rules remain active.").foregroundStyle(.secondary) }
                    ForEach(store.rules) { rule in
                        HStack(spacing: 12) {
                            Image(systemName: "checkmark.shield.fill").foregroundStyle(.green)
                            VStack(alignment: .leading) {
                                Text(rule.naturalLanguage ?? rule.message)
                                Text(rule.triggerSummary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer(); Button { store.remove(rule) } label: { Image(systemName: "trash") }.buttonStyle(.plain)
                        }.padding(.vertical, 7)
                    }
                }.cardStyle()
            }.padding(32).frame(maxWidth: 900, alignment: .leading)
        }
    }

    private var modelConfigurationCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(l("AI analysis model", "AI 分析模型"), systemImage: "sparkles")
                    .font(.headline)
                Spacer()
                Text(semanticAnalyzer.configured ? l("Configured", "已配置") : l("Not configured", "未配置"))
                    .font(.caption).foregroundStyle(semanticAnalyzer.configured ? .green : .secondary)
            }
            Text(l("Use your own OpenRouter key and choose any compatible model. The key is stored in your Mac Keychain and is never included in the app package.", "使用你自己的 OpenRouter Key，并选择任意兼容模型。Key 只保存在本机钥匙串，不会写入安装包。"))
                .font(.callout).foregroundStyle(.secondary)
            SecureField(l("OpenRouter API key", "OpenRouter API Key"), text: $openRouterKey)
                .textFieldStyle(.roundedBorder)
            Picker(l("Model", "模型"), selection: $analysisModel) {
                Text("GPT-4o mini").tag("openai/gpt-4o-mini")
                Text("Claude 3.5 Haiku").tag("anthropic/claude-3.5-haiku")
                Text("Gemini 2.5 Flash").tag("google/gemini-2.5-flash")
                Text("DeepSeek Chat").tag("deepseek/deepseek-chat-v3.1")
                Text("Qwen 3").tag("qwen/qwen3-30b-a3b")
            }
            HStack {
                Button(l("Save configuration", "保存配置")) {
                    if semanticAnalyzer.configure(key: openRouterKey, model: analysisModel) {
                        openRouterKey = ""
                        modelFeedback = l("Saved securely", "已安全保存")
                    } else {
                        modelFeedback = semanticAnalyzer.lastError ?? l("Save failed", "保存失败")
                    }
                }.buttonStyle(.borderedProminent).disabled(openRouterKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                if semanticAnalyzer.configured {
                    Button(l("Remove key", "删除 Key"), role: .destructive) {
                        semanticAnalyzer.removeConfiguration()
                        modelFeedback = l("Key removed", "Key 已删除")
                    }
                }
                Spacer()
                if !modelFeedback.isEmpty { Text(modelFeedback).font(.caption).foregroundStyle(.secondary) }
            }
        }
        .cardStyle()
        .onAppear { analysisModel = semanticAnalyzer.model }
    }

    private var recovery: some View {
        VStack(alignment: .leading, spacing: 18) {
            header("Recovery", subtitle: "Review file operations automatically recovered by AgentReins. Irreversible external actions are clearly labeled.")
            let restored = events.filter { $0.action == "restored" }
            if restored.isEmpty {
                emptyState("Nothing to recover", detail: "When protected files change, AgentReins keeps a recovery record.", icon: "arrow.uturn.backward.circle")
            } else { List(restored) { event in eventRow(event).padding(.vertical, 6) }.listStyle(.inset) }
        }.padding(32)
    }

    private var onboarding: some View {
        VStack(spacing: 22) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 62)).foregroundStyle(.blue)
            Text(l("Let AI agents work. Stay in control.", "让 Agent 放心工作")).font(.largeTitle.bold())
            Text(l("AgentReins reveals what your local AI agent sees, decides, and does — without turning every action into an alarm.", "AgentReins 在本机理解 Agent 的上下文和实际操作。\n平时保持安静，遇到风险时讲清楚再让你决定。"))
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 12) {
                Label(l("Local-first activity monitoring", "完整离线，不上传监控数据"), systemImage: "network.slash")
                Label(l("Plain-English agent timelines", "高风险操作及时提醒"), systemImage: "list.bullet.rectangle")
                Label(l("Recovery for protected files", "重要文件改错后可以恢复"), systemImage: "arrow.uturn.backward")
            }
            Button(l("Start protecting", "开始保护")) { onboardingComplete = true }.buttonStyle(.borderedProminent).controlSize(.large)
        }.padding(46).frame(width: 520, height: 470)
    }

    private func header(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 5) { Text(title).font(.largeTitle.bold()); Text(subtitle).foregroundStyle(.secondary) }
    }
    private func emptyState(_ title: String, detail: String, icon: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 34)).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(detail).font(.callout).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func metricCard(title: String, value: String, icon: String, tint: Color) -> some View {
        HStack(spacing: 12) { Image(systemName: icon).font(.title2).foregroundStyle(tint); VStack(alignment: .leading) { Text(value).font(.headline); Text(title).font(.caption).foregroundStyle(.secondary) }; Spacer() }
            .padding(16).frame(maxWidth: .infinity).background(RoundedRectangle(cornerRadius: 14).fill(Color(nsColor: .controlBackgroundColor)))
    }
    private func eventRow(_ event: GuardEvent) -> some View {
        HStack(spacing: 12) {
            Image(systemName: event.kind == "cmd" ? "terminal" : (event.kind == "memory" ? "key.horizontal" : "doc.badge.gearshape")).frame(width: 28).foregroundStyle(Color.agrSeverity(event.severity))
            VStack(alignment: .leading, spacing: 3) {
                Text(eventTitle(event)).font(.body.weight(.medium))
                Text(event.command ?? event.path).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(); Text(event.ts, style: .time).font(.caption).foregroundStyle(.tertiary)
        }
    }
    private func incidentRow(_ incident: SecurityIncident) -> some View {
        HStack(spacing: 12) {
            Image(systemName: (incident.primary.kind == "cmd" || incident.primary.kind == "activity") ? "terminal" : (incident.primary.kind == "memory" ? "key.horizontal" : "doc.badge.gearshape"))
                .frame(width: 28).foregroundStyle(Color.agrSeverity(incident.severity))
            VStack(alignment: .leading, spacing: 3) {
                Text(incident.title).font(.body.weight(.medium))
                Text(incident.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if incident.events.count > 1 { Text("\(incident.events.count) 条关联").font(.caption).foregroundStyle(.blue) }
            Text(incident.ts, style: .time).font(.caption).foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    private func incidentDetail(_ incident: SecurityIncident) -> some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text(incident.title).font(.title2.bold())
                    Text(incident.summary).foregroundStyle(.secondary)
                    GroupBox("完整事件链") {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(incident.causalChain.enumerated()), id: \.element.id) { index, stage in
                                HStack(alignment: .top, spacing: 13) {
                                    VStack(spacing: 0) {
                                        Circle().fill(stage.captured ? Color.green : Color.orange).frame(width: 11, height: 11)
                                        if index < incident.causalChain.count - 1 {
                                            Rectangle().fill(Color.secondary.opacity(0.25)).frame(width: 2, height: 50)
                                        }
                                    }.padding(.top, 5)
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack {
                                            Text(stage.title).font(.headline)
                                            if !stage.captured {
                                                Text(stage.value == "未采集" || stage.value == "未识别" ? "证据缺失" : "推断")
                                                    .font(.caption2).padding(.horizontal, 6).padding(.vertical, 2)
                                                    .background(Capsule().fill(Color.orange.opacity(0.14))).foregroundStyle(.orange)
                                            }
                                        }
                                        Text(stage.value).font(.body)
                                        Text(stage.evidence).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                            }
                        }.padding(.vertical, 8)
                    }
                    GroupBox("事件信息") {
                        Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 9) {
                            GridRow { Text("时间").foregroundStyle(.secondary); Text(incident.ts.formatted(date: .abbreviated, time: .standard)) }
                            GridRow { Text("Agent").foregroundStyle(.secondary); Text(incident.agent?.capitalized ?? "未识别") }
                            GridRow { Text("结果").foregroundStyle(.secondary); Text(incident.wasBlocked ? "已阻止" : (incident.wasRestored ? "已恢复" : "仅记录")) }
                            GridRow { Text("关联规则").foregroundStyle(.secondary); Text(incident.ruleIDs.joined(separator: "、")).textSelection(.enabled) }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6)
                    }
                    if let command = incident.command {
                        GroupBox("完整命令") {
                            ScrollView(.horizontal) {
                                Text(command).font(.system(.callout, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: true, vertical: false)
                            }.padding(.vertical, 6)
                        }
                    }
                    GroupBox("关联证据（\(incident.events.count)）") {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(incident.events) { event in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack { Text(event.ruleId).font(.headline); Spacer(); Text(event.ts, style: .time).foregroundStyle(.secondary) }
                                    Text("严重级别：\(event.severity) · 动作：\(event.action)").font(.caption).foregroundStyle(.secondary)
                                    if event.path != "-" { Text(event.path).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                                }
                                if event.id != incident.events.last?.id { Divider() }
                            }
                        }.padding(.vertical, 6)
                    }
                }.padding(28)
            }
            .frame(minWidth: 720, minHeight: 560)
            .toolbar { Button("完成") { selectedIncident = nil } }
        }
    }
    private func eventTitle(_ event: GuardEvent) -> String {
        if event.kind == "memory" { return "记忆体扫描发现敏感信息" }
        if event.kind == "cmd" { return "\((event.agent ?? "Agent").capitalized) 执行了高风险命令" }
        if event.action == "restored" { return "已恢复 Agent 对文件的\(event.op == "delete" ? "删除" : "修改")" }
        return "Agent 改动了受保护文件"
    }
    private var modeDescription: String {
        switch protectionMode {
        case "quiet": return "只提醒明显危险的操作，其余行为安静记录。"
        case "strict": return "Agent 离开项目范围、访问敏感数据或运行高风险命令时都要求确认。"
        default: return "密钥、破坏性删除、数据外传和重要外部操作需要确认。适合大多数人。"
        }
    }
    private func addLocalRule() {
        let input = ruleText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { return }
        let rule = NLParser.parseLocal(input)
        store.add(rule); ruleText = ""; ruleFeedback = "已添加：\(rule.message)"
    }
}

private extension View {
    func cardStyle() -> some View {
        padding(20).background(RoundedRectangle(cornerRadius: 16).fill(Color(nsColor: .controlBackgroundColor)))
    }
}
