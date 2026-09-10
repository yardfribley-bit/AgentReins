import SwiftUI

private enum CenterPage: String, CaseIterable, Identifiable {
    case home, sessions, timeline, protection, recovery
    var id: String { rawValue }
    func title(english: Bool) -> String {
        switch self {
        case .home: return english ? "Overview" : "安全状态"
        case .sessions: return english ? "History" : "历史"
        case .timeline: return english ? "Activity" : "活动时间线"
        case .protection: return english ? "Protection" : "保护设置"
        case .recovery: return english ? "Recovery" : "恢复"
        }
    }
    var icon: String {
        switch self {
        case .home: return "shield.checkered"
        case .sessions: return "clock.arrow.circlepath"
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
    @EnvironmentObject private var turnJournalStore: TurnJournalStore
    @EnvironmentObject private var workBuddySight: WorkBuddySight
    @EnvironmentObject private var codexSight: CodexSight
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
    @State private var selectedTraceNodeID: String?
    @State private var traceInspectorTab = "Activity"
    @State private var liveTrace: DevelopmentTaskTrace?
    @State private var recoveryCandidate: AgentTurnJournal?
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
    private var todayIncidents: [SecurityIncident] {
        incidents.filter { Calendar.current.isDateInToday($0.lastTs) }
    }
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
        .confirmationDialog("Restore the clean Git baseline?", isPresented: Binding(
            get: { recoveryCandidate != nil },
            set: { if !$0 { recoveryCandidate = nil } }
        ), presenting: recoveryCandidate) { journal in
            Button("Undo this agent turn", role: .destructive) {
                turnJournalStore.recoverCleanBaseline(journalId: journal.id)
                recoveryCandidate = nil
            }
            Button("Cancel", role: .cancel) { recoveryCandidate = nil }
        } message: { journal in
            Text("This restores \(journal.mutations.count) recorded working-tree changes. Recovery will stop if the workspace changed after the snapshot.")
        }
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
                header(l("Your coding agent, under control", "你的编程 Agent，尽在掌控"), subtitle: l("See what it is doing now, verify what it changed, and recover when something goes wrong.", "实时了解它正在做什么、验证代码更改，并在出现问题时恢复。"))
                activeTaskCard
                productValueStrip
                safetyHero
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

    private var liveContextEvents: [GuardEvent] {
        Array(events.filter {
            $0.source?.hasPrefix("agentsight:") == true &&
            ["prompt", "call", "result", "response"].contains($0.op)
        }.prefix(14).reversed())
    }

    private var latestSession: AgentSessionSnapshot? { sessions.first }
    private var latestTurn: AgentTurn? { latestSession?.turns.last }
    private var latestSessionEvent: GuardEvent? {
        latestSession?.events.last { ["prompt", "call", "result", "response"].contains($0.op) }
    }
    private var latestJournal: AgentTurnJournal? {
        guard let session = latestSession, let turn = latestTurn else { return nil }
        return turnJournalStore.journals.first { $0.sessionId == session.id && $0.turnId == turn.id }
    }
    private var latestIsLive: Bool {
        guard let date = latestSession?.lastActivityAt else { return false }
        return Date().timeIntervalSince(date) < 90
    }
    private var activeTaskCard: some View {
        VStack(alignment: .leading, spacing: 18) {
            if let session = latestSession, let turn = latestTurn {
                HStack(alignment: .top, spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 12).fill(Color.blue.opacity(0.12))
                        Image(systemName: "terminal.fill").font(.title2).foregroundStyle(.blue)
                    }.frame(width: 48, height: 48)
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 8) {
                            Text(session.agent.capitalized).font(.caption.bold()).foregroundStyle(.secondary)
                            Text("·").foregroundStyle(.tertiary)
                            Text(latestIsLive ? "LIVE NOW" : "LATEST TASK")
                                .font(.caption2.bold()).foregroundStyle(latestIsLive ? .green : .secondary)
                        }
                        Text(turn.userInput ?? session.latestIntent ?? "Agent activity detected")
                            .font(.title2.weight(.semibold)).lineLimit(2)
                        if let workspace = session.workspace {
                            Text(URL(fileURLWithPath: workspace).lastPathComponent)
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    activeTaskStatusBadge(turn: turn)
                }

                Divider()
                if let trace = liveTrace { developmentTraceExplorer(trace) }

                HStack(spacing: 12) {
                    taskOutcomeMetric(icon: "wrench.and.screwdriver", value: "\(liveTrace?.nodes.reduce(0) { $0 + $1.tools.count } ?? 0)", label: "Tool calls", tint: .blue)
                    taskOutcomeMetric(icon: "doc.badge.ellipsis", value: "\(detectedChangeCount)", label: changeMetricLabel, tint: .orange)
                    taskOutcomeMetric(icon: turn.riskCount == 0 ? "checkmark.shield" : "exclamationmark.shield", value: turn.riskCount == 0 ? "None" : "\(turn.riskCount)", label: "Risks detected", tint: turn.riskCount == 0 ? .green : .red)
                    taskOutcomeMetric(icon: "checkmark.seal", value: verificationLabel, label: "Verification", tint: verificationColor)
                }

                HStack {
                    Button("View complete task") { selectedSession = session }
                        .buttonStyle(.borderedProminent)
                    Button("Open activity stream") { page = .timeline }
                        .buttonStyle(.bordered)
                    Spacer()
                    Text("Full evidence remains available for every step")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                HStack(spacing: 18) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 14).fill(Color.blue.opacity(0.12))
                        Image(systemName: "scope").font(.largeTitle).foregroundStyle(.blue)
                    }.frame(width: 64, height: 64)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Start a coding-agent task").font(.title2.bold())
                        Text("AgentReins will show the request, model activity, tools, code changes, risks, and verified result here in real time.")
                            .foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 12)
            }
        }
        .padding(20)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.blue.opacity(0.22), lineWidth: 1))
        .onAppear { refreshLiveTrace() }
        .onChange(of: latestSessionEvent?.id) { _ in refreshLiveTrace() }
    }

    private func refreshLiveTrace() {
        guard let session = latestSession, let turn = latestTurn else { liveTrace = nil; return }
        let state = latestJournal.flatMap { turnJournalStore.verificationStates[$0.id] }
        liveTrace = DevelopmentTaskTrace.build(session: session, turn: turn, journal: latestJournal, verificationState: state)
    }

    private func developmentTraceExplorer(_ trace: DevelopmentTaskTrace) -> some View {
        let selected = trace.nodes.first { $0.id == selectedTraceNodeID }
            ?? trace.nodes.last { $0.status == .running }
            ?? trace.nodes.first
        return HStack(alignment: .top, spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Development process").font(.headline)
                    Spacer()
                    Text("\(trace.nodes.count) steps").font(.caption).foregroundStyle(.secondary)
                }.padding(.horizontal, 4)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(trace.nodes.enumerated()), id: \.element.id) { index, node in
                            traceNodeRow(node, selected: node.id == selected?.id,
                                         showConnector: index < trace.nodes.count - 1)
                        }
                    }
                }.frame(height: 350)
            }
            .frame(width: 355)
            Divider().padding(.horizontal, 18)
            if let selected {
                traceEvidencePanel(selected)
                    .frame(maxWidth: .infinity, minHeight: 350, maxHeight: 350, alignment: .topLeading)
            }
        }
    }

    private func traceNodeRow(_ node: DevelopmentTraceNode, selected: Bool, showConnector: Bool) -> some View {
        Button { selectedTraceNodeID = node.id } label: {
            HStack(alignment: .top, spacing: 11) {
                VStack(spacing: 0) {
                    ZStack {
                        Circle().fill(traceStatusColor(node.status).opacity(node.status == .pending ? 0.12 : 1))
                        Image(systemName: traceStatusIcon(node.status))
                            .font(.caption.bold()).foregroundStyle(node.status == .pending ? Color.secondary : Color.white)
                    }.frame(width: 27, height: 27)
                    if showConnector {
                        Rectangle().fill(Color.secondary.opacity(0.18)).frame(width: 2, height: 37)
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(node.kind.title.uppercased()).font(.caption2.bold()).foregroundStyle(traceStatusColor(node.status))
                        Spacer()
                        if let timestamp = node.timestamp { Text(timestamp, style: .time).font(.caption2).foregroundStyle(.tertiary) }
                    }
                    Text(node.title).font(.callout.weight(.semibold)).foregroundStyle(.primary).lineLimit(1)
                    Text(node.summary).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }.padding(.bottom, showConnector ? 8 : 0)
            }
            .padding(9)
            .background(RoundedRectangle(cornerRadius: 10).fill(selected ? Color.blue.opacity(0.1) : Color.clear))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func traceEvidencePanel(_ node: DevelopmentTraceNode) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                ZStack {
                    RoundedRectangle(cornerRadius: 9).fill(traceStatusColor(node.status).opacity(0.1))
                    Image(systemName: node.kind.icon).foregroundStyle(traceStatusColor(node.status))
                }.frame(width: 38, height: 38)
                VStack(alignment: .leading, spacing: 3) {
                    Text(node.title).font(.headline)
                    Text(node.summary).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                securityBadge(node.confidence.rawValue + " evidence",
                              color: node.confidence == .confirmed ? .green : (node.confidence == .inferred ? .orange : .secondary))
            }
            Divider()
            Picker("Inspector", selection: $traceInspectorTab) {
                ForEach(["Activity", "Context", "Tools", "Evidence"], id: \.self) { Text($0).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
            traceInspectorContent(node)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.primary.opacity(0.035)))
    }

    @ViewBuilder
    private func traceInspectorContent(_ node: DevelopmentTraceNode) -> some View {
        switch traceInspectorTab {
        case "Activity":
            if node.activities.isEmpty { traceEmptyState("No stage activity has been observed yet.") }
            else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(node.activities) { activity in
                            HStack(alignment: .top, spacing: 9) {
                                Image(systemName: traceStatusIcon(activity.status)).foregroundStyle(traceStatusColor(activity.status)).frame(width: 16)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(activity.title).font(.callout.weight(.semibold))
                                    Text(activity.summary).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if let timestamp = activity.timestamp { Text(timestamp, style: .time).font(.caption2).foregroundStyle(.tertiary) }
                            }
                        }
                    }
                }
            }
        case "Context": traceEvidenceList(node.context, empty: "No model context belongs to this stage.")
        case "Tools":
            if node.tools.isEmpty { traceEmptyState("No Tool, Function Call, or MCP invocation belongs to this stage.") }
            else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(node.tools) { call in
                            DisclosureGroup {
                                VStack(alignment: .leading, spacing: 9) {
                                    if let arguments = call.arguments { liveEvidenceField("Arguments / command", arguments) }
                                    if let result = call.result { liveEvidenceField("Execution result", result) }
                                    liveEvidenceField("Call ID", call.id)
                                }.padding(.top, 7)
                            } label: {
                                HStack {
                                    Image(systemName: "wrench.and.screwdriver").foregroundStyle(.blue)
                                    VStack(alignment: .leading) {
                                        Text(call.friendlyName).font(.callout.weight(.semibold))
                                        Text("\(call.name) · \(call.friendlyStatus)").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        default: traceEvidenceList(node.evidence, empty: "No raw evidence was captured for this stage.")
        }
    }

    private func traceEvidenceList(_ items: [DevelopmentTraceEvidence], empty: String) -> some View {
        Group {
            if items.isEmpty { traceEmptyState(empty) }
            else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        ForEach(items) { item in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(item.title.uppercased()).font(.caption2.bold()).foregroundStyle(.secondary)
                                Text(item.value).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
            }
        }
    }

    private func traceEmptyState(_ text: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: "doc.text.magnifyingglass").font(.title).foregroundStyle(.tertiary)
            Text(text).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func traceStatusColor(_ status: DevelopmentTraceNodeStatus) -> Color {
        switch status {
        case .completed: return .green
        case .running: return .blue
        case .pending: return .secondary
        case .attention: return .orange
        }
    }

    private func traceStatusIcon(_ status: DevelopmentTraceNodeStatus) -> String {
        switch status {
        case .completed: return "checkmark"
        case .running: return "ellipsis"
        case .pending: return "circle"
        case .attention: return "exclamationmark"
        }
    }

    private var productValueStrip: some View {
        HStack(spacing: 0) {
            valuePromise("eye", "Watch", "Understand every live step")
            Divider().frame(height: 42)
            valuePromise("checkmark.seal", "Verify", "Run independent checks")
            Divider().frame(height: 42)
            valuePromise("lock.shield", "Protect", "Catch risky behavior")
            Divider().frame(height: 42)
            valuePromise("arrow.uturn.backward", "Recover", "Undo a bad agent turn")
        }
        .padding(.vertical, 14)
        .background(RoundedRectangle(cornerRadius: 13).fill(Color.primary.opacity(0.035)))
    }

    private func valuePromise(_ icon: String, _ title: String, _ detail: String) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon).foregroundStyle(.blue).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.callout.bold())
                Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
        }.frame(maxWidth: .infinity)
    }

    private var currentActivityTitle: String {
        guard let event = latestSessionEvent else { return "Waiting for activity" }
        switch event.op {
        case "prompt": return "Understanding your request"
        case "call": return "Using \(resolvedToolName(event) ?? "a tool")"
        case "result": return "Reviewing the tool result"
        case "response": return latestIsLive ? "Preparing the next step" : "Task response received"
        case "usage": return "Updating model context"
        default: return "Working on the task"
        }
    }

    private var currentActivityDetail: String {
        guard let event = latestSessionEvent else { return "Connect WorkBuddy or Codex to begin." }
        if event.op == "call", let command = event.command { return String(command.replacingOccurrences(of: "\n", with: " ").prefix(220)) }
        if event.op == "result", let result = event.modelResponse { return String(result.replacingOccurrences(of: "\n", with: " ").prefix(220)) }
        if event.op == "prompt" { return "The model received the captured task context." }
        if event.op == "response" { return "A model response was captured and associated with this turn." }
        return latestSession?.plainSummary ?? "Agent activity is being captured."
    }

    private func taskProgress(turn: AgentTurn) -> some View {
        let steps: [(String, String, Bool)] = [
            ("1", "Request", turn.userInput != nil),
            ("2", "Model", !turn.exchanges.isEmpty),
            ("3", "Tools", !turn.toolCalls.isEmpty),
            ("4", "Verify", verificationLabel == "Passed")
        ]
        return HStack(spacing: 0) {
            ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                VStack(spacing: 6) {
                    ZStack {
                        Circle().fill(step.2 ? Color.green : (index == currentProgressIndex ? Color.blue : Color.secondary.opacity(0.15)))
                        if step.2 {
                            Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(.white)
                        } else {
                            Text(step.0).font(.caption.bold())
                                .foregroundStyle(index == currentProgressIndex ? .white : .secondary)
                        }
                    }.frame(width: 26, height: 26)
                    Text(step.1).font(.caption.weight(.medium)).foregroundStyle(step.2 || index == currentProgressIndex ? .primary : .secondary)
                }
                if index < steps.count - 1 {
                    Rectangle().fill(step.2 ? Color.green.opacity(0.55) : Color.secondary.opacity(0.15))
                        .frame(height: 2).padding(.horizontal, 7).offset(y: -10)
                }
            }
        }
    }

    private var currentProgressIndex: Int {
        guard let event = latestSessionEvent else { return 0 }
        if event.op == "prompt" { return 1 }
        if event.op == "call" || event.op == "result" { return 2 }
        return 3
    }

    private func activeTaskStatusBadge(turn: AgentTurn) -> some View {
        let hasRisk = turn.riskCount > 0
        return Label(hasRisk ? "Needs review" : (latestIsLive ? "Agent working" : "Activity captured"),
                     systemImage: hasRisk ? "exclamationmark.triangle.fill" : (latestIsLive ? "waveform" : "checkmark.circle.fill"))
            .font(.caption.bold()).foregroundStyle(hasRisk ? .orange : (latestIsLive ? .blue : .green))
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(Capsule().fill((hasRisk ? Color.orange : (latestIsLive ? Color.blue : Color.green)).opacity(0.1)))
    }

    private func taskOutcomeMetric(icon: String, value: String, label: String, tint: Color) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 1) {
                Text(value).font(.callout.bold())
                Text(label).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }.padding(10).frame(maxWidth: .infinity)
            .background(RoundedRectangle(cornerRadius: 9).fill(tint.opacity(0.07)))
    }

    private var detectedChangeCount: Int {
        if let mutations = latestJournal?.mutations, !mutations.isEmpty { return mutations.count }
        return liveTrace?.nodes.first { $0.kind == .build }?.tools.count ?? 0
    }

    private var changeMetricLabel: String {
        if let mutations = latestJournal?.mutations, !mutations.isEmpty { return "Files changed" }
        return "Change calls"
    }

    private var verificationLabel: String {
        guard let journal = latestJournal else { return "Not run" }
        if turnJournalStore.verificationStates[journal.id] == .running { return "Running" }
        guard let last = journal.verificationRuns.last else { return "Not run" }
        return last.exitCode == 0 ? "Passed" : "Failed"
    }

    private var verificationColor: Color {
        switch verificationLabel {
        case "Passed": return .green
        case "Failed": return .red
        case "Running": return .blue
        default: return .secondary
        }
    }

    private var latestContextMetrics: ContextGrowthMetrics? {
        sessions.first?.turns.last?.contextGrowth
    }

    private var recentInfluenceChains: [InfluenceChain] {
        Array(eventStore.influenceChains.suffix(3))
    }

    private var liveContextMonitor: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Circle().fill((workBuddySight.connected || codexSight.connected) ? Color.green : Color.secondary)
                            .frame(width: 8, height: 8)
                        Text("Live context monitor").font(.headline)
                    }
                    Text("Watch model requests, context growth, tool activity, and results as they arrive.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if let update = workBuddySight.lastUpdate {
                    Text("Updated \(update, style: .relative)")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text((workBuddySight.connected || codexSight.connected) ? "Waiting for activity" : "Agent not connected")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            if let metrics = latestContextMetrics {
                HStack(spacing: 24) {
                    contextMetric("Current context", metrics.latestInputTokens.formatted())
                    contextMetric("This turn", "\(metrics.growthTokens >= 0 ? "+" : "")\(metrics.growthTokens.formatted())")
                    contextMetric("Model requests", metrics.requestCount.formatted())
                    contextMetric("Cache reported", metrics.cumulativeCachedTokens.formatted())
                    Spacer()
                    if metrics.needsAttention {
                        Label("Context growing quickly", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption.bold()).foregroundStyle(.orange)
                    }
                }
            }

            if let turn = sessions.first?.turns.last {
                contextIntegritySummary(turn.contextIntegrity)
            }

            if !recentInfluenceChains.isEmpty {
                VStack(alignment: .leading, spacing: 9) {
                    Text("Possible influence chains").font(.callout.bold())
                    ForEach(recentInfluenceChains) { chain in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "link").foregroundStyle(.red)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(chain.source.sourceKind.rawValue) content → \(chain.nextActionName ?? "No later tool call")")
                                    .font(.caption.bold())
                                Text(chain.explanation).font(.caption).foregroundStyle(.secondary)
                                if let command = chain.nextActionCommand {
                                    Text(command).font(.caption2.monospaced()).lineLimit(2).textSelection(.enabled)
                                }
                            }
                            Spacer()
                            securityBadge(chain.evidence.rawValue, color: chain.evidence == .inferred ? .orange : .purple)
                        }
                    }
                }
                .padding(12).background(RoundedRectangle(cornerRadius: 10).fill(Color.red.opacity(0.06)))
            }

            Divider()
            if liveContextEvents.isEmpty {
                HStack {
                    Spacer()
                    Text("Start an agent task to see the live stream.")
                        .font(.callout).foregroundStyle(.secondary).padding(.vertical, 18)
                    Spacer()
                }
            } else {
                ScrollViewReader { proxy in
                    ScrollView(.vertical) {
                        LazyVStack(alignment: .leading, spacing: 9) {
                            ForEach(liveContextEvents) { event in
                                liveContextRow(event).id(event.id)
                            }
                        }
                    }
                    .frame(height: 190)
                    .onAppear { if let id = liveContextEvents.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
                    .onChange(of: liveContextEvents.last?.id) { id in
                        if let id { withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(id, anchor: .bottom) } }
                    }
                }
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.primary.opacity(0.08)))
    }

    private func contextIntegritySummary(_ assessment: ContextIntegrityAssessment) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Label("Context health: \(assessment.health.rawValue)", systemImage: assessment.health == .healthy ? "checkmark.circle.fill" : "brain.head.profile")
                    .font(.callout.bold()).foregroundStyle(contextHealthColor(assessment.health))
                Spacer()
                securityBadge("\(assessment.evidence.rawValue) evidence", color: assessment.evidence == .exact ? .green : .orange)
            }
            HStack(spacing: 22) {
                contextMetric("Requirement retention", assessment.requirementRetentionPercent.map { "\($0)%" } ?? "Unknown")
                contextMetric("Repeated payload", "\(assessment.duplicatePayloadPercent)%")
                contextMetric("Tool noise", "\(assessment.toolNoisePercent)%")
                Spacer()
            }
            ForEach(assessment.findings, id: \.self) { finding in
                Label(finding, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(12).background(RoundedRectangle(cornerRadius: 10).fill(contextHealthColor(assessment.health).opacity(0.07)))
    }

    private func contextHealthColor(_ health: ContextHealth) -> Color {
        switch health {
        case .healthy: return .green
        case .growing: return .orange
        case .memoryAtRisk: return .red
        }
    }

    private func liveContextRow(_ event: GuardEvent) -> some View {
        let toolName = resolvedToolName(event)
        let assessment = ToolSecurityAssessment.assess(name: toolName, command: event.command)
        let contentAssessment = ExternalContentSecurity.assess(event)
        return HStack(alignment: .top, spacing: 10) {
            Image(systemName: liveContextIcon(event.op))
                .foregroundStyle(liveContextColor(event.op)).frame(width: 18)
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 8) {
                    if let contentAssessment {
                        HStack(spacing: 8) {
                            securityBadge(contentAssessment.sourceKind.rawValue, color: .purple)
                            securityBadge(contentAssessment.trust.rawValue, color: contentAssessment.trust == .untrusted ? .red : .orange)
                            if !contentAssessment.findings.isEmpty {
                                securityBadge("\(contentAssessment.findings.count) content risks", color: .red)
                            }
                        }
                        ForEach(contentAssessment.findings) { finding in
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(finding.category.rawValue) · \(finding.severity.uppercased()) · \(finding.confidence) confidence")
                                    .font(.caption.bold()).foregroundStyle(.red)
                                Text(finding.evidence).font(.caption.monospaced()).textSelection(.enabled)
                            }
                        }
                    }
                    if event.op == "call" || event.op == "result" {
                        HStack(spacing: 8) {
                            securityBadge(assessment.kind.rawValue, color: .blue)
                            securityBadge("\(assessment.risk.rawValue) risk", color: riskColor(assessment.risk))
                            Text(assessment.capability).font(.caption.weight(.medium))
                        }
                        Text(assessment.reason).font(.caption).foregroundStyle(.secondary)
                    }
                    if let command = event.command {
                        liveEvidenceField("Arguments / command", command)
                    }
                    if let result = event.modelResponse {
                        liveEvidenceField("Execution result", result)
                    }
                    if let decision = event.modelDecision {
                        liveEvidenceField("Model decision", decision)
                    }
                    if let turn = event.turnId { liveEvidenceField("Turn ID", turn) }
                    if let trace = event.traceId { liveEvidenceField("Trace ID", trace) }
                    if event.command == nil && event.modelResponse == nil && event.modelDecision == nil {
                        Text("No additional payload was recorded for this event.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.top, 7)
            } label: {
                VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(liveContextTitle(event, toolName: toolName)).font(.callout.weight(.medium))
                    if let model = event.model { Text(model).font(.caption).foregroundStyle(.secondary) }
                    Spacer()
                    Text(event.ts, style: .time).font(.caption.monospacedDigit()).foregroundStyle(.tertiary)
                }
                if let input = event.inputTokens {
                    Text("\(input.formatted()) input · \((event.outputTokens ?? 0).formatted()) output · \((event.cachedTokens ?? 0).formatted()) cached")
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                } else if event.op == "prompt", let intent = event.userIntent {
                    Text(intent).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                } else if event.op == "call", let command = event.command {
                    Text(command).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2)
                } else if event.op == "result", let result = event.modelResponse {
                    Text(result).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(3)
                }
            }
            }
        }
    }

    private func resolvedToolName(_ event: GuardEvent) -> String? {
        if let name = event.toolName, name != "unknown_tool" { return name }
        guard let callId = event.toolCallId else { return event.toolName }
        return events.first { $0.toolCallId == callId && $0.op == "call" }?.toolName
    }

    private func securityBadge(_ text: String, color: Color) -> some View {
        Text(text.uppercased()).font(.caption2.bold()).foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.12)))
    }

    private func riskColor(_ risk: CapabilityRisk) -> Color {
        switch risk {
        case .low: return .green
        case .medium: return .orange
        case .high: return .red
        case .unknown: return .secondary
        }
    }

    private func liveEvidenceField(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title.uppercased()).font(.caption2.bold()).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8).background(RoundedRectangle(cornerRadius: 7).fill(Color.primary.opacity(0.04)))
        }
    }

    private func liveContextTitle(_ event: GuardEvent, toolName: String?) -> String {
        switch event.op {
        case "prompt": return "User turn captured"
        case "call":
            let tool = toolName ?? "Unknown tool"
            return event.inputTokens == nil ? "Tool requested · \(tool)" : "Model request · \(tool)"
        case "result": return "Tool completed · \(toolName ?? "Unknown tool")"
        case "response": return "Model response received"
        default: return "Agent activity"
        }
    }

    private func liveContextIcon(_ op: String) -> String {
        switch op {
        case "prompt": return "person.crop.circle"
        case "call": return "hammer"
        case "result": return "checkmark.circle"
        case "response": return "sparkles"
        default: return "circle.fill"
        }
    }

    private func liveContextColor(_ op: String) -> Color {
        switch op {
        case "prompt": return .blue
        case "call": return .orange
        case "result": return .teal
        case "response": return .purple
        default: return .secondary
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
            header(l("History", "历史"), subtitle: l("Old sessions stay dormant until you choose to reconstruct them. Live monitoring remains fast.", "旧会话默认不加载，只有需要时才在后台还原。"))
            if !eventStore.historyLoaded {
                historyRestoreCard
            } else if historyRestoring {
                VStack(alignment: .leading, spacing: 10) {
                    HStack { Text("Reconstructing local agent history…").font(.headline); Spacer(); Text(historyProgress, format: .percent) }
                    ProgressView(value: historyProgress)
                    Text("You can leave this page. Live monitoring continues while history is restored in the background.")
                        .font(.caption).foregroundStyle(.secondary)
                }.cardStyle()
            } else if sessions.isEmpty {
                emptyState(l("No sessions yet", "暂无会话"), detail: l("AgentSight automatically discovers supported local agents.", "AgentSight 会自动发现支持的本地 Agent 会话。"), icon: "bubble.left.and.bubble.right")
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Text("\(sessions.count) reconstructed sessions").font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        if historyFileCount > 0 { Text("\(historyFileCount) local logs scanned").font(.caption).foregroundStyle(.tertiary) }
                    }
                    List(sessions) { session in
                        Button { selectedSession = session } label: { sessionRow(session).padding(.vertical, 7) }.buttonStyle(.plain)
                    }.listStyle(.inset)
                }
            }
        }.padding(32)
    }

    private var historyRestoreCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 14) {
                Image(systemName: "archivebox").font(.title).foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 4) {
                    Text("History is not loaded").font(.title3.bold())
                    Text("AgentReins only restored the active task at startup, so opening the app stays responsive.")
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            Text("When requested, AgentReins will slowly reconstruct local sessions, prompts, model responses, tools, and results. Processing stays on this Mac.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("Restore history") {
                    eventStore.loadHistory()
                    codexSight.restoreHistory()
                    workBuddySight.restoreHistory()
                }.buttonStyle(.borderedProminent)
                Text("This may take several minutes for large logs.").font(.caption).foregroundStyle(.tertiary)
            }
        }.cardStyle()
    }

    private var historyRestoring: Bool { codexSight.historyRestoring || workBuddySight.historyRestoring }
    private var historyProgress: Double {
        let sources = [codexSight.connected ? codexSight.historyProgress : nil,
                       workBuddySight.connected ? workBuddySight.historyProgress : nil].compactMap { $0 }
        return sources.isEmpty ? 0 : sources.reduce(0, +) / Double(sources.count)
    }
    private var historyFileCount: Int { codexSight.historyFileCount + workBuddySight.historyFileCount }

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
                    ForEach(session.turns) { turn in turnDetail(turn, sessionId: session.id) }
                }.padding(28)
            }.frame(minWidth: 780, minHeight: 650)
            .toolbar { Button(l("Done", "完成")) { selectedSession = nil } }
        }
    }

    private func turnDetail(_ turn: AgentTurn, sessionId: String) -> some View {
        let journalId = TurnJournalStore.journalId(sessionId: sessionId, turnId: turn.id)
        let journal = turnJournalStore.journals.first { $0.id == journalId }
        return GroupBox {
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
                contextGrowthCard(turn.contextGrowth)
                contextIntegritySummary(turn.contextIntegrity)
                outcomeCard(journal)
                aiAnalysisCard(turn)
                summaryStep(number: "1", title: l("Your instruction", "用户输入的指令"), value: turn.userInput ?? l("Not captured", "未采集"), tint: .blue)
                evidenceStep(number: "2", title: l("Captured model context", "已采集的模型上下文"), value: turn.fullPrompt, tint: .indigo, showPreview: true)
                summaryStep(number: "3", title: l("Instructions returned by the model", "模型返回的指令"), value: turn.modelInstructionSummary, tint: .purple)
                summaryStep(number: "4", title: l("Tools & MCP actually called", "Agent 实际调用的 Tool / MCP"), value: turn.executionSummary, tint: .cyan)
                evidenceStep(number: "5", title: l("Tool execution results", "工具执行结果"), value: turn.toolResultSummary, tint: .teal)
                evidenceStep(number: "6", title: l("File & code changes", "发现的文件与代码更改"), value: turn.codeChangeSummary, tint: .orange)
                evidenceStep(number: "7", title: l("Final result", "最终回答与任务结果"), value: turn.finalResponse ?? l("No final response was captured", "未采集到最终回答"), tint: .green, showPreview: true)
                evidenceStep(number: "8", title: l("Memory retrieved", "记忆读取与隐私唤醒"), value: turn.memoryRetrievalSummary, tint: .pink)
                evidenceStep(number: "9", title: l("Memory committed", "新增或修改的持久化记忆"), value: turn.memoryCommitSummary, tint: .red)

                externalContentSection(turn)

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
    private func externalContentSection(_ turn: AgentTurn) -> some View {
        let assessments = turn.externalContentAssessments
        if !assessments.isEmpty {
            DisclosureGroup("External content security") {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(assessments) { assessment in
                        HStack {
                            securityBadge(assessment.sourceKind.rawValue, color: .purple)
                            securityBadge(assessment.trust.rawValue, color: assessment.trust == .untrusted ? .red : .orange)
                            Text(assessment.sourceIdentity).font(.callout.bold())
                            Spacer(); Text(assessment.timestamp, style: .time).font(.caption).foregroundStyle(.secondary)
                        }
                        if assessment.findings.isEmpty {
                            Text("No configured injection pattern was detected. This is not a trust guarantee.")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            ForEach(assessment.findings) { finding in
                                liveEvidenceField("\(finding.category.rawValue) · \(finding.severity) · \(finding.confidence) confidence", finding.evidence)
                            }
                        }
                        Divider()
                    }
                }.padding(.top, 10)
            }
        }
    }

    @ViewBuilder
    private func contextGrowthCard(_ metrics: ContextGrowthMetrics?) -> some View {
        if let metrics {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label(l("Context growth", "上下文增长"), systemImage: "chart.line.uptrend.xyaxis")
                        .font(.headline)
                    Spacer()
                    Text(metrics.needsAttention ? l("Growing quickly", "增长较快") : l("Stable", "稳定"))
                        .font(.caption.bold())
                        .foregroundStyle(metrics.needsAttention ? .orange : .green)
                }
                HStack(spacing: 24) {
                    contextMetric(l("First request", "首次请求"), metrics.initialInputTokens.formatted())
                    contextMetric(l("Latest request", "最近请求"), metrics.latestInputTokens.formatted())
                    contextMetric(l("Growth", "增长"), "\(metrics.growthTokens >= 0 ? "+" : "")\(metrics.growthTokens.formatted()) (\(metrics.growthPercent.formatted(.number.precision(.fractionLength(1))))%)")
                    contextMetric(l("Cumulative input", "累计输入"), metrics.cumulativeInputTokens.formatted())
                    contextMetric(l("Cache reported", "上报缓存"), metrics.cumulativeCachedTokens.formatted())
                }
                Text(english
                     ? "Provider-reported usage across \(metrics.requestCount) model requests. Cumulative input is total processed input, not unique context. Largest one-step increase: \(metrics.largestInputIncrease.formatted()) tokens."
                     : "模型服务商上报了 \(metrics.requestCount) 次请求用量。累计输入是各次处理量之和，并非唯一上下文。最大单步增长：\(metrics.largestInputIncrease.formatted()) tokens。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 12).fill((metrics.needsAttention ? Color.orange : Color.blue).opacity(0.08)))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke((metrics.needsAttention ? Color.orange : Color.blue).opacity(0.25)))
        }
    }

    private func contextMetric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value).font(.title3.monospacedDigit().bold())
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func outcomeCard(_ journal: AgentTurnJournal?) -> some View {
        if let journal {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("Observed outcome", systemImage: "checklist.checked")
                        .font(.headline)
                    Spacer()
                    Text(journal.status.rawValue.capitalized)
                        .font(.caption.bold())
                        .padding(.horizontal, 9).padding(.vertical, 4)
                        .background(Capsule().fill(journal.status == .completed ? Color.green.opacity(0.15) : Color.orange.opacity(0.15)))
                }
                HStack(spacing: 20) {
                    journalMetric("Workspace", value: journal.workspace.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "Unknown")
                    journalMetric("Git changes", value: "\(journal.mutations.count)")
                    journalMetric("Existing changes", value: journal.baseline == nil ? "Unknown" : (journal.hasPreExistingChanges ? "Present" : "None"))
                    journalMetric("Baseline", value: journal.baselinePrecedesMutation == true ? "Before tools" : (journal.baselinePrecedesMutation == false ? "Too late" : "Unknown"))
                }
                if !journal.mutations.isEmpty {
                    Divider()
                    ForEach(journal.mutations.prefix(8)) { mutation in
                        HStack(spacing: 9) {
                            Image(systemName: mutation.attribution == .confirmed ? "checkmark.seal.fill" : "questionmark.diamond.fill")
                                .foregroundStyle(mutation.attribution == .confirmed ? .green : (mutation.attribution == .inferred ? .orange : .secondary))
                            Text(mutation.path).font(.system(.caption, design: .monospaced)).lineLimit(1)
                            Spacer()
                            Text("\(mutation.baselineStatus ?? "clean") → \(mutation.finalStatus ?? "clean")")
                                .font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                            Text(mutation.attribution.rawValue.capitalized)
                                .font(.caption2.bold()).foregroundStyle(.secondary)
                        }
                    }
                    if journal.mutations.count > 8 {
                        Text("+ \(journal.mutations.count - 8) more changes")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let snapshot = journal.finalSnapshot {
                        DisclosureGroup("View Git diff evidence") {
                            VStack(alignment: .leading, spacing: 10) {
                                if !snapshot.diffStat.isEmpty {
                                    contextField("Diff summary", snapshot.diffStat)
                                }
                                contextField("Working-tree patch",
                                             snapshot.patch.isEmpty ? "No unstaged patch captured" : snapshot.patch)
                                if !snapshot.stagedPatch.isEmpty {
                                    contextField("Staged patch", snapshot.stagedPatch)
                                }
                            }
                            .font(.caption).padding(.top, 8)
                        }
                    }
                } else {
                    Text(journal.finalSnapshot == nil
                         ? "No final Git snapshot was captured for this turn."
                         : "No working-tree state change was detected between snapshots.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Divider()
                HStack {
                    if let run = journal.verificationRuns.last {
                        Label(run.exitCode == 0 ? "Independent verification passed" : "Independent verification failed",
                              systemImage: run.exitCode == 0 ? "checkmark.seal.fill" : "xmark.octagon.fill")
                            .font(.caption.bold()).foregroundStyle(run.exitCode == 0 ? .green : .red)
                        Text("\(run.command) · \(run.duration.formatted(.number.precision(.fractionLength(1))))s")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Build and tests have not been independently verified.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(turnJournalStore.verificationStates[journal.id] == .running ? "Verifying…" : "Run verification") {
                        turnJournalStore.runVerification(journalId: journal.id)
                    }
                    .buttonStyle(.bordered)
                    .disabled(turnJournalStore.verificationStates[journal.id] == .running || journal.workspace == nil)
                    Button("Undo turn") { recoveryCandidate = journal }
                        .buttonStyle(.borderedProminent).tint(.orange)
                        .disabled(!journal.canRecoverSafely)
                }
                if let message = turnJournalStore.recoveryMessages[journal.id] {
                    Text(message).font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 13).fill(Color.blue.opacity(0.07)))
        } else {
            HStack(spacing: 10) {
                Image(systemName: "clock.badge.questionmark").foregroundStyle(.secondary)
                Text("This turn predates the persistent journal or was imported without lifecycle evidence.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 11).fill(Color.secondary.opacity(0.06)))
        }
    }

    private func journalMetric(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.caption.bold()).lineLimit(1)
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
                Image(systemName: (workBuddySight.connected || codexSight.connected) ? "link.circle.fill" : "exclamationmark.circle")
                    .foregroundStyle((workBuddySight.connected || codexSight.connected) ? .green : .orange)
                Text(adapterStatus)
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

    private var adapterStatus: String {
        let connected = [workBuddySight.connected ? "WorkBuddy" : nil, codexSight.connected ? "Codex" : nil]
            .compactMap { $0 }
        if connected.isEmpty { return l("AgentSight is waiting for a supported agent", "AgentSight 正在等待受支持的 Agent") }
        return l("AgentSight connected to \(connected.joined(separator: " + "))",
                 "AgentSight · \(connected.joined(separator: " + ")) 会话源已连接")
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
                            GridRow {
                                Text("Attribution").foregroundStyle(.secondary)
                                Text(incident.primary.attributionConfidence?.rawValue.capitalized ?? "Unknown")
                            }
                            if let method = incident.primary.attributionMethod {
                                GridRow {
                                    Text("Attribution evidence").foregroundStyle(.secondary)
                                    Text(method).textSelection(.enabled)
                                }
                            }
                            if let pid = incident.primary.processId {
                                GridRow { Text("Process").foregroundStyle(.secondary); Text("PID \(pid)").textSelection(.enabled) }
                            }
                            if let tool = incident.primary.toolName {
                                GridRow { Text("Tool / MCP").foregroundStyle(.secondary); Text(tool).textSelection(.enabled) }
                            }
                            if let call = incident.primary.toolCallId {
                                GridRow { Text("Tool call ID").foregroundStyle(.secondary); Text(call).textSelection(.enabled) }
                            }
                            if let host = incident.primary.remoteHost {
                                GridRow {
                                    Text("Remote endpoint").foregroundStyle(.secondary)
                                    Text("\(host):\(incident.primary.remotePort.map(String.init) ?? "?")").textSelection(.enabled)
                                }
                            }
                            if let domain = incident.primary.remoteDomain {
                                GridRow {
                                    Text("Website").foregroundStyle(.secondary)
                                    Text(domain).textSelection(.enabled)
                                }
                            }
                            if incident.primary.kind == "network" {
                                GridRow {
                                    Text("Destination class").foregroundStyle(.secondary)
                                    Text(incident.networkDestination.kind.rawValue)
                                        .foregroundStyle(incident.networkDestination.needsAttention ? .orange : .secondary)
                                }
                                GridRow {
                                    Text("Security focus").foregroundStyle(.secondary)
                                    Text(incident.networkDestination.reason)
                                }
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6)
                    }
                    if let diff = incident.events.compactMap(\.fileDiff).first {
                        GroupBox("Code changes") {
                            VStack(alignment: .leading, spacing: 10) {
                                Label(incident.wasRestored ? "AgentReins restored the original file" : "Change recorded — original file available", systemImage: incident.wasRestored ? "arrow.uturn.backward.circle.fill" : "doc.badge.clock")
                                    .font(.headline).foregroundStyle(incident.wasRestored ? .green : .orange)
                                Text(incident.primary.path).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                ScrollView([.horizontal, .vertical]) {
                                    Text(diff).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                        .fixedSize(horizontal: true, vertical: true)
                                }.frame(maxHeight: 320)
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6)
                        }
                    }
                    let codeFindings = incident.events.flatMap { $0.codeFindings ?? [] }
                    if !codeFindings.isEmpty {
                        GroupBox("Security review") {
                            VStack(alignment: .leading, spacing: 12) {
                                Text("\(codeFindings.count) potential security issue\(codeFindings.count == 1 ? "" : "s") in agent-generated code")
                                    .font(.headline)
                                Text("These findings require review. A pattern match does not prove the code is exploitable.")
                                    .font(.caption).foregroundStyle(.secondary)
                                ForEach(codeFindings) { finding in
                                    HStack(alignment: .top, spacing: 10) {
                                        Image(systemName: "exclamationmark.shield.fill")
                                            .foregroundStyle(Color.agrSeverity(finding.severity))
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(finding.title).font(.body.weight(.semibold))
                                            Text("Line \(finding.line) · \(finding.severity.uppercased())")
                                                .font(.caption).foregroundStyle(.secondary)
                                            Text(finding.evidence).font(.system(.caption, design: .monospaced))
                                                .textSelection(.enabled)
                                        }
                                        Spacer()
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 6)
                        }
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
