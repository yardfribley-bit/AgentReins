import AppKit
import SwiftUI

/// Live agent posture first; complete evidence appears only after node selection.
struct AgentOperationsCenterView: View {
    @EnvironmentObject private var webAgentSight: WebAgentSight
    @EnvironmentObject private var semanticAnalyzer: SemanticAnalyzer
    @EnvironmentObject private var language: AppLanguageStore
    @EnvironmentObject private var alertPolicyStore: AlertPolicyStore
    @EnvironmentObject private var eventStore: EventStore
    let dataRevision: UInt64
    let sessions: [AgentSessionSnapshot]
    let events: [GuardEvent]
    let incidents: [SecurityIncident]
    let health: [CollectorHealthRecord]
    let observing: Bool
    let processInventory: [ProcessSnapshotRecord]
    let discoveredAgents: [DiscoveredAgent]
    let onSession: (AgentSessionSnapshot) -> Void
    let onIncident: (SecurityIncident) -> Void

    @State private var selectedAgent = "All agents"
    @State private var selectedEvent: GuardEvent?
    @State private var selectedProcess: ProcessSnapshotRecord?
    @State private var selectedProcessGroup: [ProcessSnapshotRecord] = []
    @State private var centerTab: CenterTab = .overview
    @State private var query = ""
    @State private var didSelectInitialAgent = false
    @State private var didUserSelectAgent = false
    @State private var selectedStageID: String?
    @State private var selectedMemoryCommitID: String?
    @State private var followingLive = true
    @State private var showingBrowserProtection = false
    @State private var showingAnalysisModel = false
    @State private var showingHistory = false
    @State private var showingAlertPolicies = false
    @StateObject private var ipGeolocation = IPGeolocationStore()
    @StateObject private var projectIndex = ProjectIndexStore()
    @State private var cachedRuntimeGraph = RuntimeGraphPresentation(groups: [], edges: [])
    @State private var agentProjection: AgentDashboardProjection?
    @State private var projectionError: String?
    @State private var globalTab: GlobalTab = .projects
    @State private var selectedProjectPath: String?
    @State private var projectView: ProjectView = .requirements
    @State private var selectedRequirementID: String?
    @State private var projectHistoricalIncidents: [String: [SecurityIncident]] = [:]
    @State private var projectHistoryLoading = Set<String>()
    @State private var projectHistoryErrors: [String: String] = [:]
    @State private var projectQuestion = ""
    @State private var projectQuestionPath: String?
    @State private var projectQuestionLoading = false
    @State private var projectQuestionError: String?
    @State private var projectQuestionResults: [FeatureProvenanceRecord] = []
    @State private var selectedQuestionBatchID: String?
    @State private var selectedEgressAudit: AgentEgressAudit?
    @State private var selectedEgressCategory: EgressDataCategory?
    @State private var egressReaderMode: EgressReaderMode = .organized
    @State private var egressReaderPage = 0
    @State private var selectedTaskJSON: TaskJSONDocument?
    @State private var taskReaderShowsJSON = false

    private struct TaskJSONDocument: Identifiable {
        let id = UUID()
        let title: String
        let json: String
        let snapshot: AgentTaskSnapshot
    }

    private enum EgressReaderMode: String, CaseIterable {
        case organized
        case raw
        case reasoning
    }

    private enum GlobalTab: String, CaseIterable, Identifiable {
        case projects = "Workspaces"
        case agents = "Agents"
        case egress = "Outbound"
        case security = "Security"
        var id: String { rawValue }
    }

    private enum ProjectView: String, CaseIterable, Identifiable {
        case requirements = "Requirements"
        case ask = "Ask Project"
        case security = "Security"
        var id: String { rawValue }
    }

    private enum ProjectQuestionIntent {
        case context, tools, files, network, memory, verification, overview
    }

    private enum CenterTab: String, CaseIterable, Identifiable {
        case overview = "Overview"
        case processes = "Processes"
        case network = "Network"
        case files = "Files"
        case memory = "Memory"
        case code = "Generated Code"
        case tools = "Tool Calls"
        case timeline = "Timeline"
        var id: String { rawValue }
    }

    private let canvas = Color(red: 4/255, green: 14/255, blue: 26/255)
    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let border = Color(red: 27/255, green: 66/255, blue: 96/255)
    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
    private let green = Color(red: 57/255, green: 214/255, blue: 117/255)
    private let amber = Color(red: 255/255, green: 177/255, blue: 45/255)

    private func L(_ english: String) -> String { language.text(english) }

    private var projectionKey: AgentDashboardProjectionKey {
        AgentDashboardProjectionKey(selectedAgent: selectedAgent, dataRevision: dataRevision,
            query: query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
    }
    private var currentProjection: AgentDashboardProjection? {
        guard agentProjection?.key.selectedAgent == projectionKey.selectedAgent,
              agentProjection?.key.query == projectionKey.query else { return nil }
        return agentProjection
    }
    private var scopedSessions: [AgentSessionSnapshot] { currentProjection?.sessions ?? [] }
    private var activeSession: AgentSessionSnapshot? { currentProjection?.activeSession }
    private var activeTurn: AgentTurn? { currentProjection?.liveTask.turn ?? activeSession?.turns.last }
    private var scopedEvents: [GuardEvent] { currentProjection?.events ?? [] }
    private var liveTaskFiles: [GuardEvent] { currentProjection?.liveTask.files ?? [] }
    private var liveTaskTools: [AgentToolCall] { currentProjection?.liveTask.tools ?? [] }
    private var liveTaskCodeFindings: [CodeFinding] { currentProjection?.liveTask.codeFindings ?? [] }
    private var processes: [ProcessSnapshotRecord] {
        let agents = selectedAgent == "All agents"
            ? discoveredAgents.filter { $0.presence == .running }.map(\.product)
            : [selectedAgent]
        let list = processInventory.filter { process in
            guard let owner = process.agent else { return false }
            return agents.contains { normalizedAgentKey(owner) == normalizedAgentKey($0) }
        }
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return list }
        return list.filter { $0.command.lowercased().contains(q) || $0.pid.contains(q) }
    }
    private var processTree: [TreeNode] { Self.buildTree(processes) }
    private var runtimeTopologyFingerprint: String {
        let topology = processes.map { "\($0.pid):\($0.ppid):\($0.command.hashValue)" }.joined(separator: "|")
        return "\(selectedAgent)|\(topology)"
    }
    private var isWebAISelected: Bool { selectedAgent.caseInsensitiveCompare("Web AI") == .orderedSame }
    private var scopedIncidents: [SecurityIncident] { currentProjection?.incidents ?? [] }
    private func matchesSelectedAgent(_ agent: String) -> Bool {
        if selectedAgent == "All agents" { return true }
        if isWebAISelected {
            return ["gemini", "chatgpt", "grok", "claude-web", "web-ai"]
                .contains(agent.lowercased())
        }
        return normalizedAgentKey(agent) == normalizedAgentKey(selectedAgent)
    }
    private func normalizedAgentKey(_ value: String) -> String {
        normalizedAgentIdentity(value)
    }
    private var sshSessions: [SSHSessionEvidence] { currentProjection?.sshSessions ?? [] }
    private var networkFlows: [NetworkFlowEvidence] { currentProjection?.networkFlows ?? [] }
    private var findingCount: Int { currentProjection?.findingCount ?? 0 }
    private var memoryCommits: [MemoryCommitEvidence] { currentProjection?.memoryCommits ?? [] }
    private var selectedMemoryCommit: MemoryCommitEvidence? {
        memoryCommits.first { $0.commitId == selectedMemoryCommitID }
    }
    private var focusedTaskEvent: GuardEvent? {
        guard followingLive else { return selectedEvent }
        guard let session = activeSession else { return nil }
        // Runtime highlighting must stay cheap: rebuilding the complete staged
        // journey here makes every graph node and service card reclassify all
        // tool calls during a SwiftUI update.
        if let running = session.events.last(where: {
            $0.action == "running" || $0.action == "requested"
        }) { return running }
        return session.events.last(where: {
            $0.kind == "verification" || $0.kind == "file" || $0.kind == "tool" ||
                ($0.kind == "model" && $0.op == "response") || $0.kind == "context"
        })
    }
    private var focusedProcessIDs: Set<String> {
        let rawPIDs: [String]
        if followingLive {
            rawPIDs = focusedTaskEvent?.processId.map { [String($0)] } ?? []
        } else if !selectedProcessGroup.isEmpty {
            rawPIDs = selectedProcessGroup.map(\.pid)
        } else {
            rawPIDs = selectedProcess.map { [$0.pid] } ??
                (focusedTaskEvent?.processId.map { [String($0)] } ?? [])
        }
        let byPID = Dictionary(uniqueKeysWithValues: processInventory.map { ($0.pid, $0) })
        var result = Set<String>()
        for rawPID in rawPIDs {
            var current = rawPID
            while let process = byPID[current], result.insert(current).inserted {
                current = process.ppid
            }
        }
        return result
    }
    private var evidenceCoverage: String { currentProjection?.evidenceCoverage ?? "—" }
    private struct ProjectMission: Identifiable {
        let id: String
        let name: String
        let path: String
        let kind: SupervisedWorkspaceKind
        let sessions: [AgentSessionSnapshot]
        var lastActivity: Date { sessions.map(\.lastActivityAt).max() ?? .distantPast }
    }
    private var projectMissions: [ProjectMission] {
        let grouped = Dictionary(grouping: sessions) { session -> String in
            SupervisedWorkspaceResolver.resolve(session.workspace).id
        }
        return grouped.map { path, rows in
            let identity = SupervisedWorkspaceResolver.resolve(path == "Unassigned" ? nil : path)
            let kind = identity.kind
            let directoryName = path == "Unassigned" ? "Unassigned activity" : URL(fileURLWithPath: path).lastPathComponent
            let recentIntent = rows.sorted { $0.lastActivityAt > $1.lastActivityAt }
                .compactMap { $0.turns.reversed().compactMap(\.userInput).first ?? $0.latestIntent }.first
            let name = kind == .task
                ? String((recentIntent ?? (language.language == .english ? "Temporary Agent task" : "临时 Agent 任务")).prefix(72))
                : directoryName
            return ProjectMission(id: path, name: name.isEmpty ? path : name, path: path, kind: kind,
                                  sessions: rows.sorted { $0.lastActivityAt > $1.lastActivityAt })
        }.sorted { $0.lastActivity > $1.lastActivity }
    }

    private var projectEvolution: [ProjectEvolutionSnapshot] {
        ProjectEvolution.build(sessions: sessions, incidents: incidents)
    }
    private var activeTaskCount: Int {
        sessions.filter(sessionIsLive).count
    }

    private func sessionIsLive(_ session: AgentSessionSnapshot) -> Bool {
        guard Date().timeIntervalSince(session.lastActivityAt) <= 90,
              let turn = session.turns.last else { return false }
        if turn.finalResponse != nil { return false }
        if turn.toolCalls.contains(where: { $0.completedAt == nil }) { return true }
        return session.events.suffix(5).contains {
            ["running", "requested", "started"].contains($0.action.lowercased())
        }
    }
    private var rootPID: String? {
        let agent = activeSession?.agent ?? (selectedAgent == "All agents" ? nil : selectedAgent)
        let candidates = agent.map { owner in
            processInventory.filter { process in
                process.agent.map { normalizedAgentKey($0) == normalizedAgentKey(owner) } == true
            }
        } ?? processes
        let ids = Set(candidates.map(\.pid))
        return candidates
            .filter { !ids.contains($0.ppid) }
            .min { (Int($0.pid) ?? .max) < (Int($1.pid) ?? .max) }?.pid
            ?? activeSession?.events.compactMap(\.processId).first.map(String.init)
    }
    private var liveHeadline: String {
        readableActivity(activeTurn)
    }

    private func selectInitialAgentIfNeeded() {
        // The product now opens as a global mission-control surface. Agent
        // detail is an explicit drill-down, never an automatic redirect.
        guard selectedAgent != "All agents" else {
            didSelectInitialAgent = true
            return
        }
        guard !didUserSelectAgent else { return }
        let running = Set(discoveredAgents.filter { $0.presence == .running }
            .map { normalizedAgentIdentity($0.product) })
        guard !running.isEmpty else { return }
        if let latest = sessions.filter({ running.contains(normalizedAgentIdentity($0.agent)) })
            .max(by: { $0.lastActivityAt < $1.lastActivityAt }) {
            let next = latest.agentDisplayName
            if selectedAgent.caseInsensitiveCompare(next) != .orderedSame {
                selectedAgent = next
                selectedEvent = nil
                selectedProcess = nil
                selectedProcessGroup = []
                selectedStageID = nil
                selectedMemoryCommitID = nil
                followingLive = true
            }
        } else if let first = discoveredAgents.first(where: { $0.presence == .running }) {
            selectedAgent = first.product
        } else {
            return
        }
        didSelectInitialAgent = true
    }

    private func readableActivity(_ turn: AgentTurn?) -> String {
        guard let turn else { return "Monitoring runtime" }
        if let call = turn.toolCalls.last(where: { $0.completedAt == nil }) {
            let name = call.name.lowercased()
            if name.contains("exec") || name.contains("terminal") || name == "bash" || name == "shell" {
                return "Running a terminal command"
            }
            if name.contains("read") || name.contains("search") { return "Reading project context" }
            if name.contains("write") || name.contains("edit") || name.contains("patch") { return "Editing project files" }
            if name.contains("mcp") { return "Using MCP · \(call.friendlyName)" }
            return "Using tool · \(call.friendlyName)"
        }
        if turn.finalResponse != nil { return "Reported complete · awaiting verification" }
        if let call = turn.toolCalls.last { return "Last action · \(call.friendlyName)" }
        if let input = turn.userInput, !input.isEmpty { return String(input.prefix(52)) }
        return "Processing the current task"
    }

    var body: some View {
        GeometryReader { geometry in
            let compactLayout = geometry.size.width < 1420
            VStack(spacing: 0) {
                header(compactLayout: compactLayout)
                HStack(spacing: 0) {
                    fleet.frame(width: compactLayout ? 260 : 278)
                    Rectangle().fill(border).frame(width: 1)
                    ScrollView {
                        if selectedAgent == "All agents" {
                            globalMissionControl.padding(16)
                        } else if currentProjection == nil {
                            projectionStatusView.padding(16)
                        } else {
                            VStack(alignment: .leading, spacing: 14) {
                                if let projectionError {
                                    projectionErrorView(projectionError)
                                }
                                taskHeader
                                tabBar
                                centerContent
                                evidencePanel
                                flowLegend
                            }.padding(16)
                        }
                    }
                    if !compactLayout && selectedAgent != "All agents" {
                        inspector.frame(width: 318)
                    }
                }
                .frame(height: max(0, geometry.size.height - 110))
                .clipped()
                statusBar
            }
        }
        .background(canvas).environment(\.colorScheme, .dark)
        .onAppear {
            selectInitialAgentIfNeeded()
            refreshRuntimeGraph()
        }
        .task(id: projectionKey) { await refreshAgentProjection(key: projectionKey) }
        .onChange(of: runtimeTopologyFingerprint) { _ in refreshRuntimeGraph() }
        .onChange(of: sessions.count) { _ in selectInitialAgentIfNeeded() }
        .onChange(of: sessions.map { "\($0.agent):\($0.lastActivityAt.timeIntervalSince1970)" }.joined(separator: "|")) { _ in
            selectInitialAgentIfNeeded()
        }
        .onChange(of: discoveredAgents.count) { _ in selectInitialAgentIfNeeded() }
        .onChange(of: discoveredAgents.map { "\($0.product):\($0.presence.rawValue)" }.joined(separator: "|")) { _ in
            selectInitialAgentIfNeeded()
        }
        .sheet(isPresented: $showingHistory) {
            HistoryView()
        }
        .sheet(isPresented: $showingBrowserProtection) {
            BrowserProtectionView(extensionConnected: webAgentSight.connected)
        }
        .sheet(isPresented: $showingAnalysisModel) {
            AnalysisModelSettingsView().environmentObject(semanticAnalyzer)
        }
        .sheet(isPresented: $showingAlertPolicies) {
            AlertPolicySettingsView().environmentObject(alertPolicyStore)
        }
        .sheet(item: $selectedEgressAudit) { report in
            egressReader(report)
        }
        .sheet(item: $selectedTaskJSON) { document in
            taskJSONReader(document)
        }
    }

    @MainActor
    private func refreshAgentProjection(key: AgentDashboardProjectionKey) async {
        projectionError = nil
        let input = AgentDashboardProjectionInput(key: key, sessions: sessions, events: events,
            incidents: incidents)
        let worker = Task.detached(priority: .userInitiated) {
            try AgentDashboardProjection.build(input: input)
        }
        let result = await withTaskCancellationHandler {
            await worker.result
        } onCancel: {
            worker.cancel()
        }
        guard !Task.isCancelled, key == projectionKey else { return }
        switch result {
        case .success(let projection):
            projectionError = nil
            agentProjection = projection
            ipGeolocation.resolve(projection.networkIPs)
            if let selectedMemoryCommitID,
               !projection.memoryCommits.contains(where: { $0.commitId == selectedMemoryCommitID }) {
                self.selectedMemoryCommitID = nil
            }
        case .failure(let error):
            guard !(error is CancellationError) else { return }
            projectionError = "Agent 投影构建失败：\(error.localizedDescription)"
        }
    }

    @ViewBuilder
    private var projectionStatusView: some View {
        if let projectionError {
            projectionErrorView(projectionError)
        } else {
            HStack(spacing: 10) {
                ProgressView().controlSize(.small).tint(cyan)
                Text(language.language == .english ? "Preparing Agent evidence…" : "正在准备智能体证据…")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(border))
        }
    }

    private func projectionErrorView(_ message: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(amber)
            Text(message).font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(border))
    }

    // MARK: - Chrome

    private func header(compactLayout: Bool) -> some View {
        HStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 26)).foregroundStyle(cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("AgentReins").font(.system(size: 20, weight: .bold))
                if !compactLayout {
                    Text(language.language == .english ? "See what your AI agents are doing — and whether it is safe." : "看清 AI 智能体正在做什么，以及它是否安全。")
                        .font(.system(size: 13)).foregroundStyle(cyan.opacity(0.9)).lineLimit(1)
                }
            }
            Spacer(minLength: compactLayout ? 10 : 18)
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(language.language == .english ? (compactLayout ? "Search…" : "Search agents, processes, or domains") : "搜索智能体、进程或域名", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 14))
            }
            .padding(.horizontal, 12).frame(width: compactLayout ? 230 : 280, height: 40)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
            Button { language.toggle() } label: {
                HStack(spacing: 5) {
                    Image(systemName: "globe")
                    Text(language.language == .english ? "中文" : "EN")
                }
                .font(.system(size: 12, weight: .bold)).foregroundStyle(cyan)
                .padding(.horizontal, 9).padding(.vertical, 7)
                .background(cyan.opacity(0.10), in: Capsule())
            }.buttonStyle(.plain).help(language.language == .english ? "Switch to Chinese" : "切换到英文")
            Label(L(observing ? "MONITORING LIVE" : "PAUSED"), systemImage: "circle.fill")
                .font(.system(size: 13, weight: .bold)).foregroundStyle(observing ? green : amber)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background((observing ? green : amber).opacity(0.12), in: Capsule())
            Button { showingHistory = true } label: {
                Label(L("HISTORY"), systemImage: "clock.arrow.circlepath")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(cyan)
                    .padding(.horizontal, 11).padding(.vertical, 7)
                    .background(cyan.opacity(0.12), in: Capsule())
            }.buttonStyle(.plain)
            Button { showingAlertPolicies = true } label: {
                Label(L("ALERT RULES"), systemImage: "slider.horizontal.3")
                    .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .background(cyan.opacity(0.12), in: Capsule())
            }.buttonStyle(.plain).help("Configure local alert policies")
            Button { showingAnalysisModel = true } label: {
                Label(L(semanticAnalyzer.configured ? "ANALYSIS READY" : "ANALYSIS MODEL"),
                      systemImage: "brain.head.profile")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(semanticAnalyzer.configured ? green : cyan)
                    .padding(.horizontal, 11).padding(.vertical, 7)
                    .background((semanticAnalyzer.configured ? green : cyan).opacity(0.12), in: Capsule())
            }.buttonStyle(PillActionButtonStyle())
                .help("Configure the optional external analysis model")
            Button { showingBrowserProtection = true } label: {
                Label(L(webAgentSight.connected ? "WEB PROTECTED" : "PROTECT WEB AI"),
                      systemImage: webAgentSight.connected ? "checkmark.shield.fill" : "shield.lefthalf.filled")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(webAgentSight.connected ? green : cyan)
                    .padding(.horizontal, 11).padding(.vertical, 7)
                    .background((webAgentSight.connected ? green : cyan).opacity(0.12), in: Capsule())
            }.buttonStyle(PillActionButtonStyle())
                .help("Open browser protection setup")
        }
        .padding(.horizontal, 18).frame(height: 72).background(panel)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)
        .fixedSize(horizontal: false, vertical: true)
        .layoutPriority(10)
    }

    private var fleet: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(L("AI AGENT FLEET")).micro(cyan)
                Spacer()
                Text("\(discoveredAgents.count)").badge(cyan)
            }.padding(16)
            fleetRow(name: "All agents",
                     title: language.language == .english ? "Workspace mission control" : "工作空间监工",
                     detail: "\(activeTaskCount) active tasks · \(scopedIncidents.count) findings",
                     live: observing)
            ForEach(discoveredAgents) { item in
                let session = sessions.filter { session in
                    if item.product.caseInsensitiveCompare("Web AI") == .orderedSame {
                        return ["gemini", "chatgpt", "grok", "claude-web", "web-ai"]
                            .contains(session.agent.lowercased())
                    }
                    return normalizedAgentKey(session.agent) == normalizedAgentKey(item.product)
                }
                    .max { $0.lastActivityAt < $1.lastActivityAt }
                let turn = session?.turns.last
                let running = item.presence == .running
                fleetRow(name: item.product,
                         title: running ? readableActivity(turn) : "Idle",
                         detail: "\(item.processIds.count) processes · \(item.connection.rawValue)",
                         live: running)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 9) {
                Text(L("NODE STATUS")).micro(.secondary)
                legend(green, L("Confirmed")); legend(.blue, L("Inferred")); legend(.gray, L("Unknown"))
            }.padding(16)
        }.background(panel)
    }

    private func fleetRow(name: String, title: String, detail: String, live: Bool) -> some View {
        let selected = selectedAgent.caseInsensitiveCompare(name) == .orderedSame
        return Button {
            didUserSelectAgent = true
            selectedAgent = name
            selectedEvent = nil
            selectedProcess = nil
            selectedProcessGroup = []
            selectedStageID = nil
            selectedMemoryCommitID = nil
            followingLive = true
            centerTab = .overview
        } label: {
            HStack(spacing: 11) {
                Circle().fill(live ? green : Color.gray.opacity(0.55)).frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(name == "All agents" ? L(name) : name).font(.system(size: 15, weight: .semibold))
                        Text(L(live ? "Running" : "Idle"))
                            .font(.system(size: 12, weight: .bold))
                            .foregroundStyle(live ? green : .secondary)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background((live ? green : Color.gray).opacity(0.12), in: Capsule())
                    }
                    Text(title).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    Text(detail).font(.system(size: 13)).foregroundStyle(.tertiary).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 12)).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }.buttonStyle(FleetRowButtonStyle(selected: selected))
    }

    // MARK: - Global mission control

    private var globalMissionControl: some View {
        VStack(alignment: .leading, spacing: 14) {
            GlobalSituationHeaderView(
                eyebrow: L("LIVE MISSION CONTROL"), headline: globalHeadline,
                subtitle: L("Track every repository, temporary task and safety decision across your AI agents."),
                projects: projectMissions.count, activeTasks: activeTaskCount,
                reviews: scopedIncidents.filter { $0.severity != "info" }.count,
                evidenceCoverage: evidenceCoverage,
                projectLabel: language.language == .english ? "WORKSPACES" : "工作空间",
                activeTaskLabel: L("ACTIVE TASKS"),
                reviewLabel: L("REVIEW"), evidenceLabel: L("EVIDENCE")
            )

            globalTaskOverview

            HStack(spacing: 4) {
                ForEach(GlobalTab.allCases) { tab in
                    Button { globalTab = tab } label: {
                        Text(L(tab.rawValue).uppercased())
                            .font(.system(size: 12, weight: .bold))
                            .foregroundStyle(globalTab == tab ? cyan : .secondary)
                            .padding(.horizontal, 15).padding(.vertical, 9)
                    }.buttonStyle(TabButtonStyle(selected: globalTab == tab))
                }
                Spacer()
                Text(L("REAL-TIME · RECENT ACTIVITY ONLY")).micro(.secondary)
            }
            .overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)

            switch globalTab {
            case .projects: globalProjectsView
            case .agents: globalAgentsView
            case .egress: globalEgressView
            case .security: globalSecurityView
            }
        }
    }

    private var globalHeadline: String {
        let critical = scopedIncidents.contains { $0.severity == "critical" || $0.severity == "high" }
        if critical { return language.language == .english ? "Review required across active AI work" : "当前 AI 工作存在需要审查的风险" }
        if activeTaskCount > 0 { return language.language == .english ? "\(activeTaskCount) AI task\(activeTaskCount == 1 ? "" : "s") running now" : "\(activeTaskCount) 个 AI 任务正在运行" }
        return L(observing ? "Monitoring for new Agent activity" : "Monitoring is paused")
    }

    private var globalTaskOverview: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Text(language.language == .english ? "RECENT TASKS" : "最近任务")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundStyle(cyan)
                Spacer()
                Text(language.language == .english ? "Open a task to inspect its full evidence chain" : "点击任务查看完整证据链")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(sessions.sorted { $0.lastActivityAt > $1.lastActivityAt }.prefix(3))) { session in
                let turn = session.turns.last
                let progress = turn.flatMap { eventStore.taskProgress["\(session.id)\u{0}\($0.id)"] }
                Button {
                    showTaskJSON(session: session, turnID: turn?.id)
                } label: {
                    HStack(spacing: 14) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(session.agentDisplayName) · \(turn?.userInput ?? session.latestIntent ?? "未采集任务描述")")
                                .font(.system(size: 13, weight: .semibold)).lineLimit(1)
                            Text(progress.map { "\($0.phase.rawValue) · 模型 \($0.modelRequests.count) 请求 / \($0.modelResponses.count) 响应 · 工具 \($0.toolResults.count) / \($0.toolCalls.count)" }
                                 ?? "点击从 SQLite 读取完整任务证据")
                                .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer(minLength: 8)
                        Text(session.lastActivityAt, style: .time)
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                        Image(systemName: "chevron.right").font(.system(size: 11)).foregroundStyle(cyan)
                    }
                    .padding(11)
                    .background(raised, in: RoundedRectangle(cornerRadius: 8))
                }
                .buttonStyle(.plain)
            }
            if sessions.isEmpty {
                Text("尚未采集到任务。启动 Agent 后，这里会随证据到达更新。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(14).background(panel, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(border))
    }

    private var globalProjectsView: some View {
        LazyVStack(spacing: 12) {
            if projectMissions.isEmpty { empty("Waiting for an Agent task with a project workspace") }
            ForEach(projectMissions) { project in projectMissionCard(project) }
        }
    }

    private func projectMissionCard(_ project: ProjectMission) -> some View {
        let evolution = projectEvolution.first { $0.path == project.path }
        let index = projectIndex.snapshot(for: project.path)
        let liveProjectIncidents = incidents.filter { incident in
            project.sessions.contains { session in
                incident.events.contains { $0.sessionId == session.id }
            }
        }
        let projectIncidents = mergeIncidents(liveProjectIncidents,
            projectHistoricalIncidents[project.path] ?? [])
        let changedFiles = evolution?.changedFileCount ?? 0
        let observedFiles = Set(evolution?.changeSets.flatMap { $0.createdFiles + $0.modifiedFiles + $0.deletedFiles + $0.readFiles } ?? []).count
        let isSelected = selectedProjectPath == project.id
        let latestSession = project.sessions.max { $0.lastActivityAt < $1.lastActivityAt }
        let latestGoal = latestSession?.turns.reversed().compactMap(\.userInput).first
            ?? latestSession?.latestIntent
            ?? evolution?.changeSets.first?.requirement
        return VStack(alignment: .leading, spacing: 13) {
            Button {
                selectedProjectPath = isSelected ? nil : project.id
                if !isSelected {
                    if project.kind == .repository { projectIndex.request(path: project.path) }
                    loadProjectHistory(project)
                }
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: project.kind == .repository ? "shippingbox.fill" : "checklist")
                        .font(.system(size: 21)).foregroundStyle(cyan)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(project.name).font(.system(size: 18, weight: .bold))
                        Text(project.path).font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(1)
                        Text(String((project.kind == .repository
                            ? (index?.purpose ?? (language.language == .english
                                ? "Open this repository to index tracked source"
                                : "展开代码项目以索引已跟踪源码"))
                            : (language.language == .english
                                ? "Temporary task evidence — Git is not required"
                                : "临时任务证据——无需 Git")).prefix(150)))
                            .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer()
                    labelChip(workspaceKindLabel(project.kind), color: project.kind == .repository ? .blue : cyan)
                    labelChip("\(project.sessions.count) AGENT\(project.sessions.count == 1 ? "" : "S")", color: cyan)
                    labelChip(project.kind == .repository ? "\(changedFiles) CHANGED" : "\(observedFiles) FILE EVIDENCE",
                              color: (project.kind == .repository ? changedFiles : observedFiles) > 0 ? .blue : .gray)
                    labelChip(L(projectIncidents.isEmpty ? "MONITORING" : "REVIEW REQUIRED"),
                              color: projectIncidents.isEmpty ? green : amber)
                    Image(systemName: isSelected ? "chevron.up" : "chevron.down")
                        .foregroundStyle(.secondary).padding(.top, 4)
                }
            }.buttonStyle(.plain)
                if isSelected {
                HStack {
                    if project.kind == .repository {
                        projectIndexControl(project.path, snapshot: index)
                        if let error = projectIndex.error(for: project.path) {
                            Text(error).font(.system(size: 10)).foregroundStyle(.red).lineLimit(2)
                        } else {
                            Text(language.language == .english
                                 ? "Git-tracked source is indexed into structural evidence; Atlas indexes are imported when present"
                                 : "Git 已跟踪源码会转为结构证据；如存在 Atlas 索引则直接导入")
                                .font(.system(size: 10)).foregroundStyle(.tertiary)
                        }
                    } else {
                        Label(language.language == .english
                              ? "Temporary task workspace — Git is not required"
                              : "临时任务空间——无需 Git",
                              systemImage: "checkmark.circle")
                            .font(.system(size: 10, weight: .semibold)).foregroundStyle(green)
                    }
                    if projectHistoryLoading.contains(project.path) {
                        ProgressView().controlSize(.mini).tint(cyan)
                        Text(L("Restoring project security history…"))
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    } else if let historyError = projectHistoryErrors[project.path] {
                        Text(historyError).font(.system(size: 10)).foregroundStyle(.red).lineLimit(2)
                    }
                    Spacer()
                }
                Divider().overlay(border)
                let intelligence = project.kind == .repository
                    ? ProjectIntelligence.build(projectPath: project.path,
                        sessions: project.sessions, evolution: evolution, index: index)
                    : nil
                projectCockpit(project, evolution: evolution, intelligence: intelligence,
                               projectIncidents: projectIncidents)
            } else {
                HStack(spacing: 8) {
                    Text(latestGoal ?? (language.language == .english
                         ? "Requirement evidence has not been captured for this project"
                         : "该项目尚未捕获需求证据"))
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    if let index {
                        Text("\(index.featureNames.count) declared features · \(index.areas.count) areas")
                            .font(.system(size: 11)).foregroundStyle(.tertiary)
                    }
                }
            }
        }
        .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(projectIncidents.isEmpty ? border : amber.opacity(0.65)))
    }

    private func projectIndexControl(_ path: String, snapshot: ProjectIndexSnapshot?) -> some View {
        let running = projectIndex.isIndexing(path)
        return Button {
            if running { projectIndex.cancel(path: path) }
            else { projectIndex.refresh(path: path) }
        } label: {
            HStack(spacing: 5) {
                if running {
                    ProgressView().controlSize(.mini).tint(cyan)
                } else {
                    Image(systemName: snapshot == nil ? "play.circle.fill" : "arrow.clockwise.circle.fill")
                }
                Text(projectIndexLabel(running: running, snapshot: snapshot))
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
            }
            .foregroundStyle(snapshot != nil && !running ? green : cyan)
            .padding(.horizontal, 7).padding(.vertical, 4)
            .background((snapshot != nil && !running ? green : cyan).opacity(0.10), in: Capsule())
        }
        .buttonStyle(.plain)
        .help(language.language == .english
              ? "Index up to 2,500 Git-tracked files. Click again to cancel or refresh."
              : "最多索引 2,500 个 Git 已跟踪文件；再次点击可取消或刷新。")
    }

    private func projectIndexLabel(running: Bool, snapshot: ProjectIndexSnapshot?) -> String {
        if running { return language.language == .english ? "INDEXING" : "正在索引" }
        guard let snapshot else { return language.language == .english ? "INDEX PROJECT" : "索引项目" }
        let suffix = snapshot.complete ? "" : "+"
        return language.language == .english
            ? "INDEXED \(snapshot.files.count)\(suffix)"
            : "已索引 \(snapshot.files.count)\(suffix)"
    }

    private func workspaceKindLabel(_ kind: SupervisedWorkspaceKind) -> String {
        switch kind {
        case .repository: return language.language == .english ? "REPOSITORY" : "代码项目"
        case .task: return language.language == .english ? "TASK WORKSPACE" : "任务空间"
        case .unassigned: return language.language == .english ? "UNASSIGNED" : "未归属"
        }
    }

    private func projectCockpit(_ project: ProjectMission, evolution: ProjectEvolutionSnapshot?,
                                intelligence: ProjectIntelligenceSnapshot?,
                                projectIncidents: [SecurityIncident]) -> some View {
        let liveSessions = project.sessions.filter(sessionIsLive)
        return VStack(alignment: .leading, spacing: 12) {
            if project.kind == .repository, let intelligence {
                projectBrief(project, evolution: evolution, intelligence: intelligence,
                             projectIncidents: projectIncidents)
            } else {
                taskWorkspaceBrief(project, evolution: evolution, projectIncidents: projectIncidents)
            }

            HStack(spacing: 4) {
                ForEach(ProjectView.allCases) { tab in
                    Button { projectView = tab } label: {
                        Text(projectTabLabel(tab, kind: project.kind).uppercased()).font(.system(size: 11, weight: .bold))
                            .foregroundStyle(projectView == tab ? cyan : .secondary)
                            .padding(.horizontal, 12).padding(.vertical, 7)
                    }.buttonStyle(TabButtonStyle(selected: projectView == tab))
                }
                Spacer()
                if let intelligence { evidenceTag(intelligence.purpose.confidence) }
            }.overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)

            switch projectView {
            case .requirements:
                projectRequirementSupervisor(project, evolution: evolution,
                                             projectIncidents: projectIncidents)
            case .ask:
                projectQuestionView(project, evolution: evolution)
            case .security:
                projectSecurityView(projectIncidents)
            }

            Text(L("LIVE AGENT WORK")).micro(cyan)
            if liveSessions.isEmpty {
                empty(language.language == .english ? "No Agent task has current execution evidence" : "当前没有具备实时执行证据的智能体任务")
            } else {
                ForEach(liveSessions.prefix(4)) { session in
                    globalTaskRow(session, incidents: projectIncidents.filter { incident in
                        incident.events.contains { $0.sessionId == session.id }
                    }, changeSet: evolution?.changeSets.first { $0.sessionId == session.id })
                }
            }
        }
    }

    private func projectTabLabel(_ tab: ProjectView, kind: SupervisedWorkspaceKind) -> String {
        if tab == .ask && kind != .repository {
            return language.language == .english ? "Ask Task" : "询问任务"
        }
        return L(tab.rawValue)
    }

    private func projectQuestionView(_ project: ProjectMission,
                                     evolution: ProjectEvolutionSnapshot?) -> some View {
        let relevantChanges = matchingChanges(question: projectQuestion,
                                              changes: evolution?.changeSets ?? [])
        return VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text(project.kind == .repository
                     ? (language.language == .english ? "ASK THIS PROJECT" : "向项目提问")
                     : (language.language == .english ? "ASK THIS TASK" : "向任务提问")).micro(cyan)
                Text(language.language == .english
                     ? "Ask how a requirement was implemented, which Agent or model worked on it, what changed, whether memory was touched, and how the result was verified."
                     : "可以询问某项需求如何实现、由哪个 Agent 或模型执行、改了什么、是否动过记忆，以及最终如何验证。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }

            HStack(spacing: 9) {
                Image(systemName: "sparkle.magnifyingglass").foregroundStyle(cyan)
                TextField(language.language == .english
                          ? "What happened when we added ZCode collection?"
                          : "例如：接入 ZCode 时是否修改了记忆体？",
                          text: $projectQuestion)
                    .textFieldStyle(.plain).font(.system(size: 13))
                    .onSubmit { askProject(project) }
                if projectQuestionLoading { ProgressView().controlSize(.small).tint(cyan) }
                Button(language.language == .english ? "Ask" : "查询") { askProject(project) }
                    .buttonStyle(.borderedProminent).tint(cyan).disabled(projectQuestion.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }.padding(11).background(raised, in: RoundedRectangle(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(cyan.opacity(0.38)))

            HStack(spacing: 7) {
                projectQuestionSuggestion(language.language == .english ? "Who implemented this feature?" : "这个功能是谁实现的？", project: project)
                projectQuestionSuggestion(language.language == .english ? "Did it change Agent memory?" : "是否修改了 Agent 记忆？", project: project)
                projectQuestionSuggestion(language.language == .english ? "Which tools and files were involved?" : "调用了哪些工具、修改了哪些文件？", project: project)
                projectQuestionSuggestion(language.language == .english ? "Was the result independently verified?" : "结果是否经过独立验证？", project: project)
            }

            if let error = projectQuestionError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11)).foregroundStyle(amber)
            } else if projectQuestionPath == project.path && !projectQuestion.isEmpty && !projectQuestionLoading {
                projectGroundedAnswer(project: project, changes: relevantChanges,
                                      records: projectQuestionResults)
            }
        }
    }

    private func projectQuestionSuggestion(_ text: String, project: ProjectMission) -> some View {
        Button(text) {
            projectQuestion = text
            askProject(project)
        }.buttonStyle(.bordered).controlSize(.small)
    }

    private func askProject(_ project: ProjectMission) {
        let question = projectQuestion.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !question.isEmpty else { return }
        projectQuestionPath = project.path
        projectQuestionLoading = true
        projectQuestionError = nil
        projectQuestionResults = []
        selectedQuestionBatchID = nil
        eventStore.findFeatureProvenance(projectID: project.path, query: question, limit: 12) { result in
            guard projectQuestionPath == project.path else { return }
            projectQuestionLoading = false
            switch result {
            case .success(let records): projectQuestionResults = records
            case .failure(let error): projectQuestionError = error.localizedDescription
            }
        }
    }

    private func matchingChanges(question: String, changes: [ProjectChangeSet]) -> [ProjectChangeSet] {
        let terms = question.lowercased().split { !$0.isLetter && !$0.isNumber }.map(String.init)
            .filter { $0.count > 1 && !["需求", "上下文", "工具", "文件", "网络", "记忆", "验证",
                                      "哪些", "哪个", "什么", "调用", "修改", "context", "tool", "file"].contains($0) }
        guard !terms.isEmpty else { return Array(changes.prefix(5)) }
        var scored: [(change: ProjectChangeSet, score: Int)] = []
        for change in changes {
            var fields = [change.requirement, change.agent]
            fields.append(contentsOf: change.tools)
            fields.append(contentsOf: change.createdFiles)
            fields.append(contentsOf: change.modifiedFiles)
            fields.append(contentsOf: change.deletedFiles)
            fields.append(contentsOf: change.securityFindings)
            fields.append(contentsOf: change.contexts.compactMap(\.userInput))
            let corpus = fields.joined(separator: " ").lowercased()
            let score = terms.filter(corpus.contains).count
            if score > 0 { scored.append((change, score)) }
        }
        scored.sort {
            if $0.1 == $1.1 { return $0.0.lastActivityAt > $1.0.lastActivityAt }
            return $0.1 > $1.1
        }
        return scored.prefix(8).map(\.change)
    }

    private func projectGroundedAnswer(project: ProjectMission, changes: [ProjectChangeSet],
                                       records: [FeatureProvenanceRecord]) -> some View {
        // Resolve the entity first, then select evidence fields. Search results
        // can nominate a batch, but can never broaden its evidence boundary.
        let selectedBatch = changes.first { $0.id == selectedQuestionBatchID }
            ?? (changes.count == 1 ? changes.first : nil)
        let allowedTurnKeys = Set(selectedBatch?.contexts.map { "\($0.sessionId)\u{0}\($0.turnId)" } ?? [])
        let scopedRecords = selectedBatch.map { batch in
            records.filter { record in
                if let turn = record.turnID, !allowedTurnKeys.isEmpty {
                    return allowedTurnKeys.contains("\(record.sessionID)\u{0}\(turn)")
                }
                return batch.sessionIDs.contains(record.sessionID)
            }
        } ?? []
        let memoryReads = scopedRecords.reduce(0) { $0 + $1.memoryReads }
        let memoryWrites = scopedRecords.reduce(0) { $0 + $1.memoryWrites }
        let files = Array(Set(scopedRecords.flatMap(\.files))).sorted()
        let agents = Array(Set(scopedRecords.map { formattedAgentName($0.agentID) })).sorted()
        let verified = scopedRecords.flatMap(\.verification).contains { $0.outcome == .passed }
        let evidenceCount = Set(scopedRecords.flatMap(\.matchedEvidenceIDs)).count
        let intent = projectQuestionIntent(projectQuestion)

        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(language.language == .english ? "Evidence-grounded answer" : "基于证据的回答",
                      systemImage: "checkmark.seal.fill")
                    .font(.system(size: 12, weight: .bold)).foregroundStyle(cyan)
                Spacer()
                labelChip("\(evidenceCount) \(language.language == .english ? "EVIDENCE" : "条证据")",
                          color: evidenceCount > 0 ? green : amber)
            }
            if changes.isEmpty {
                Text(language.language == .english
                     ? "No change batch matches this question. AgentReins will not answer by mixing nearby session evidence."
                     : "没有找到与问题匹配的变更批次。AgentReins 不会混入同一 Session 中临近但无关的证据。")
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(amber)
            } else if selectedBatch == nil {
                Text(language.language == .english
                     ? "Multiple change batches match. Select one before inspecting evidence."
                     : "找到多个候选变更批次，请先选择一个，再查看其内部证据。")
                    .font(.system(size: 12, weight: .semibold)).foregroundStyle(amber)
                ForEach(changes) { batch in
                    Button {
                        selectedQuestionBatchID = batch.id
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(batch.requirement).font(.system(size: 11, weight: .bold)).lineLimit(2)
                                Text("\(batch.contextCount) context · \(batch.changedFileCount) files · \(formattedAgentName(batch.agent))")
                                    .font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(cyan)
                        }.padding(8).background(panel, in: RoundedRectangle(cornerRadius: 7))
                    }.buttonStyle(.plain)
                }
            } else {
                if let selectedBatch {
                    requirementEvidenceLine(language.language == .english ? "Change batch" : "变更批次",
                                            value: selectedBatch.requirement, icon: "square.stack.3d.up")
                }
                if !agents.isEmpty { requirementEvidenceLine("Agents", value: agents.joined(separator: ", "), icon: "person.2") }
                if intent == .memory || intent == .overview {
                    requirementEvidenceLine(language.language == .english ? "Memory" : "记忆",
                                        value: "\(memoryReads) read(s), \(memoryWrites) write(s) " + (memoryWrites == 0
                                            ? (language.language == .english ? "— no write observed" : "— 未观察到写入")
                                            : (language.language == .english ? "— persistent write observed" : "— 观察到持久化写入")), icon: "brain")
                }
                if intent == .tools || intent == .overview {
                    projectToolCallEvidence(scopedRecords)
                }
                if (intent == .files || intent == .overview), !files.isEmpty {
                    projectFileEvidence(files, projectPath: project.path)
                }
                if intent == .network {
                    Text(language.language == .english
                         ? "Network evidence is not yet part of this turn-scoped query record. Open the batch network evidence instead of inferring destinations."
                         : "当前按 Turn 检索的记录尚未携带网络明细；请查看批次网络证据，系统不会在这里推测目的地。")
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(amber)
                }
                if intent == .verification || intent == .overview {
                    requirementEvidenceLine(language.language == .english ? "Verification" : "验证",
                                        value: verified
                                            ? (language.language == .english ? "Independent verification passed" : "独立验证已通过")
                                            : (language.language == .english ? "No passing independent verification was found" : "未发现通过的独立验证"),
                                        icon: verified ? "checkmark.shield.fill" : "exclamationmark.shield")
                }
                if intent == .context || intent == .overview {
                    if let selectedBatch {
                        ForEach(selectedBatch.contexts.prefix(12)) { context in
                            VStack(alignment: .leading, spacing: 3) {
                                if let input = context.userInput {
                                    Text((language.language == .english ? "User: " : "用户：") + input)
                                        .font(.system(size: 12, weight: .semibold)).lineLimit(5)
                                }
                                if let response = context.modelResponse {
                                    Text((language.language == .english ? "Agent: " : "Agent：") + response)
                                        .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(5)
                                }
                                Text("session \(context.sessionId) · turn \(context.turnId)")
                                    .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                            }.padding(8).background(panel, in: RoundedRectangle(cornerRadius: 7))
                        }
                    } else {
                    ForEach(scopedRecords.prefix(8)) { record in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(record.userPrompt ?? (language.language == .english ? "Prompt was not captured" : "未捕获提示词"))
                            .font(.system(size: 12, weight: .semibold)).lineLimit(3)
                        Text("\(formattedAgentName(record.agentID)) · \(record.model ?? "model unknown") · session \(record.sessionID)")
                            .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                    }.padding(8).background(panel, in: RoundedRectangle(cornerRadius: 7))
                    }
                    }
                }
            }
            Text(language.language == .english
                 ? "Answers are assembled from local evidence. The analysis model may improve query terms, but it cannot add unsupported facts."
                 : "回答由本地证据组合生成；分析模型可以改善检索词，但不能补充没有证据支持的事实。")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }.padding(12).background(panel, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(border))
    }

    private func projectQuestionIntent(_ question: String) -> ProjectQuestionIntent {
        let value = question.lowercased()
        if ["上下文", "提示词", "对话", "context", "prompt", "conversation"].contains(where: value.contains) { return .context }
        if ["工具", "mcp", "skill", "function", "tool", "调用"].contains(where: value.contains) { return .tools }
        if ["文件", "代码", "diff", "file", "code", "修改"].contains(where: value.contains) { return .files }
        if ["网络", "网站", "ip", "域名", "ssh", "network", "domain"].contains(where: value.contains) { return .network }
        if ["记忆", "memory", "remember"].contains(where: value.contains) { return .memory }
        if ["验证", "测试", "完成", "verify", "test", "pass"].contains(where: value.contains) { return .verification }
        return .overview
    }

    private func projectToolCallEvidence(_ records: [FeatureProvenanceRecord]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Label(language.language == .english ? "Tool calls in matched turns" : "匹配上下文中的工具调用",
                  systemImage: "wrench.and.screwdriver")
                .font(.system(size: 10, weight: .bold)).foregroundStyle(cyan)
            if records.allSatisfy({ $0.tools.isEmpty }) {
                Text(language.language == .english ? "No named tool call was captured" : "未捕获具名工具调用")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(amber)
            }
            ForEach(records) { record in
                ForEach(Array(record.tools.enumerated()), id: \.offset) { _, tool in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(tool.name).font(.system(size: 11, weight: .bold, design: .monospaced))
                                .foregroundStyle(.purple)
                            if let server = tool.server { labelChip(server, color: .purple) }
                            Spacer()
                            Text(tool.state.rawValue.uppercased()).micro(tool.state == .failed ? .red : green)
                        }
                        if let arguments = tool.arguments, !arguments.isEmpty {
                            Text((language.language == .english ? "Arguments: " : "参数：") + arguments)
                                .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(5)
                        }
                        if let result = tool.resultPreview, !result.isEmpty {
                            Text((language.language == .english ? "Result: " : "结果：") + result)
                                .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).lineLimit(5)
                        }
                        Text("\(formattedAgentName(record.agentID)) · session \(record.sessionID)\(record.turnID.map { " · turn \($0)" } ?? "")")
                            .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                    }.padding(8).background(panel, in: RoundedRectangle(cornerRadius: 7))
                }
            }
        }
    }

    private func projectToolEvidence(_ tools: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(language.language == .english ? "Tools used" : "实际调用工具",
                  systemImage: "wrench.and.screwdriver")
                .font(.system(size: 10, weight: .bold)).foregroundStyle(cyan)
            HStack(spacing: 6) {
                ForEach(Array(tools.prefix(8)), id: \.self) { tool in
                    Text(tool).font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .padding(.horizontal, 7).padding(.vertical, 4)
                        .background(Color.purple.opacity(0.12), in: RoundedRectangle(cornerRadius: 5))
                        .foregroundStyle(.purple)
                }
            }
        }
    }

    private func projectFileEvidence(_ files: [String], projectPath: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label(language.language == .english ? "Files evidenced in matched turns" : "匹配对话中的文件证据",
                      systemImage: "doc.badge.gearshape")
                    .font(.system(size: 10, weight: .bold)).foregroundStyle(cyan)
                Spacer()
                Text("\(files.count)").badge(.blue)
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 230), spacing: 7)], spacing: 7) {
                ForEach(Array(files.prefix(12)), id: \.self) { path in
                    let relative = path.hasPrefix(projectPath + "/")
                        ? String(path.dropFirst(projectPath.count + 1)) : path
                    HStack(spacing: 8) {
                        Image(systemName: "doc.text.fill").foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(URL(fileURLWithPath: path).lastPathComponent)
                                .font(.system(size: 11, weight: .bold)).lineLimit(1)
                            Text(relative).font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                    }.padding(8).background(raised, in: RoundedRectangle(cornerRadius: 7))
                        .overlay(RoundedRectangle(cornerRadius: 7).stroke(border.opacity(0.8)))
                }
            }
        }
    }

    private func projectRequirementSupervisor(_ project: ProjectMission,
                                              evolution: ProjectEvolutionSnapshot?,
                                              projectIncidents: [SecurityIncident]) -> some View {
        let changes = evolution?.changeSets ?? []
        let liveSessionIDs = Set(project.sessions.filter(sessionIsLive).map(\.id))
        let current = changes.first { liveSessionIDs.contains($0.sessionId) } ?? changes.first

        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(language.language == .english ? "OBSERVED CHANGE ACTIVITY" : "已观测变更活动")
                        .micro(cyan)
                    Text(language.language == .english
                         ? "Review each coherent project change with its surrounding conversations, tools, network, memory, and verification evidence."
                         : "以一次连续项目变更为索引，关联前后多轮上下文、工具、网络、记忆与验证证据。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer()
                labelChip("\(changes.count) \(language.language == .english ? "OBSERVED" : "个已观测批次")", color: cyan)
                labelChip("\(changes.filter { $0.verification == .verified }.count) \(language.language == .english ? "VERIFIED" : "已验证")", color: green)
                labelChip("\(projectIncidents.count) \(language.language == .english ? "FINDINGS" : "项风险")",
                          color: projectIncidents.isEmpty ? green : amber)
            }

            if let current {
                requirementHero(current, isLive: liveSessionIDs.contains(current.sessionId))
            } else {
                empty(language.language == .english
                      ? "No captured Agent activity has been attributed yet. This does not mean the project has no history."
                      : "尚未发现可归属的 Agent 活动；这不代表项目没有历史变更。")
            }

            if changes.count > 1 {
                Text(language.language == .english ? "CAPTURED ACTIVITY HISTORY" : "已采集活动历史").micro(cyan)
                ForEach(changes.dropFirst().prefix(12)) { change in
                    requirementHistoryRow(change)
                }
            }
        }
    }

    private func requirementHero(_ change: ProjectChangeSet, isLive: Bool) -> some View {
        let expanded = selectedRequirementID == change.id
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    Circle().fill((isLive ? cyan : verificationColor(change.verification)).opacity(0.14))
                    Image(systemName: isLive ? "waveform.path.ecg" : "checklist")
                        .foregroundStyle(isLive ? cyan : verificationColor(change.verification))
                }.frame(width: 42, height: 42)
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 7) {
                        Text(isLive
                             ? (language.language == .english ? "LIVE CHANGE BATCH" : "实时变更批次")
                             : (language.language == .english ? "LATEST CHANGE BATCH" : "最近变更批次"))
                            .micro(isLive ? cyan : .secondary)
                        labelChip(formattedAgentName(change.agent).uppercased(), color: .blue)
                    }
                    Text(change.requirement).font(.system(size: 16, weight: .bold)).lineLimit(expanded ? nil : 3)
                    Text("\(relativeAge(change.startedAt)) · \(change.summary)")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 5) {
                    Text(L(change.verification.rawValue).uppercased())
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundStyle(verificationColor(change.verification))
                    if change.verification == .agentReported {
                        Text(language.language == .english ? "Independent verification pending" : "等待独立验证")
                            .font(.system(size: 10)).foregroundStyle(amber)
                    }
                }
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 145), spacing: 8)], spacing: 8) {
                requirementImpact("Linked context", zh: "关联上下文", value: "\(change.contextCount)",
                                  detail: "\(change.sessionIDs.count) session(s) · \(change.turnCount) turn(s)",
                                  icon: "text.bubble", color: cyan)
                requirementImpact("Files changed", zh: "代码变更", value: "\(change.changedFileCount)",
                                  detail: "+\(change.createdFiles.count)  ~\(change.modifiedFiles.count)  −\(change.deletedFiles.count)",
                                  icon: "doc.badge.gearshape", color: .blue)
                requirementImpact("Memory activity", zh: "记忆活动",
                                  value: "\(change.memoryReads)R · \(change.memoryWrites)W",
                                  detail: change.memoryWrites == 0
                                    ? (language.language == .english ? "No write observed" : "未观察到写入")
                                    : (language.language == .english ? "Persistent writes observed" : "观察到持久化写入"),
                                  icon: "brain.head.profile", color: change.memoryWrites > 0 ? amber : cyan)
                requirementImpact("Tool calls", zh: "工具调用", value: "\(change.tools.count)",
                                  detail: change.tools.isEmpty
                                    ? (language.language == .english ? "No named tool captured" : "未捕获具名工具")
                                    : change.tools.prefix(2).joined(separator: ", "),
                                  icon: "wrench.and.screwdriver", color: .purple)
                requirementImpact("External access", zh: "外部访问", value: "\(change.externalDestinations.count)",
                                  detail: change.externalDestinations.isEmpty
                                    ? (language.language == .english ? "No destination observed" : "未观察到外部目的地")
                                    : change.externalDestinations.prefix(2).joined(separator: ", "),
                                  icon: "network", color: change.externalDestinations.isEmpty ? green : amber)
                requirementImpact("Security", zh: "安全发现", value: "\(change.securityFindings.count)",
                                  detail: change.securityFindings.first
                                    ?? (language.language == .english ? "No finding in captured evidence" : "已采集证据中无发现"),
                                  icon: "shield.lefthalf.filled", color: change.securityFindings.isEmpty ? green : .red)
            }

            if expanded {
                requirementEvidenceDetails(change)
            }
            Button {
                selectedRequirementID = expanded ? nil : change.id
            } label: {
                Label(expanded
                      ? (language.language == .english ? "Hide evidence" : "收起证据")
                      : (language.language == .english ? "Inspect batch evidence" : "查看批次证据"),
                      systemImage: expanded ? "chevron.up" : "chevron.down")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(cyan)
            }.buttonStyle(.plain)
        }
        .padding(14).background(raised.opacity(0.72), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(isLive ? cyan.opacity(0.55) : border))
    }

    private func requirementImpact(_ en: String, zh: String, value: String, detail: String,
                                   icon: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Image(systemName: icon).foregroundStyle(color)
                Text(language.language == .english ? en.uppercased() : zh)
                    .font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(.secondary)
                Spacer()
                Text(value).font(.system(size: 14, weight: .bold, design: .rounded)).foregroundStyle(color)
            }
            Text(detail).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2)
        }.padding(9).background(panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(color.opacity(0.22)))
    }

    private func requirementEvidenceDetails(_ change: ProjectChangeSet) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Divider().overlay(border)
            Text(language.language == .english ? "ATTRIBUTED BATCH EVIDENCE" : "批次关联证据").micro(.secondary)
            requirementEvidenceLine(language.language == .english ? "Sessions" : "关联会话",
                                    value: change.sessionIDs.joined(separator: " · "), icon: "rectangle.stack")
            requirementEvidenceLine(language.language == .english ? "Models" : "模型",
                                    value: change.modelNames.isEmpty
                                        ? (language.language == .english ? "Not captured" : "未捕获")
                                        : change.modelNames.joined(separator: " · "), icon: "brain")
            requirementEvidenceLine(language.language == .english ? "Changed files" : "变更文件",
                                    value: change.changedFileCount == 0
                                        ? (language.language == .english ? "No file mutation observed" : "未观察到文件变更")
                                        : (change.createdFiles + change.modifiedFiles + change.deletedFiles).prefix(6).joined(separator: " · "), icon: "doc.text")
            requirementEvidenceLine(language.language == .english ? "Read files" : "读取文件",
                                    value: change.readFiles.isEmpty
                                        ? (language.language == .english ? "No read evidence attributed" : "未归属到文件读取证据")
                                        : change.readFiles.prefix(6).joined(separator: " · "), icon: "eye")
            if !change.contexts.isEmpty {
                Text(language.language == .english ? "LINKED CONTEXT" : "关联上下文").micro(cyan)
                    .padding(.top, 4)
                ForEach(change.contexts.prefix(8)) { context in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Text(context.turnId).font(.system(size: 9, weight: .bold, design: .monospaced))
                                .foregroundStyle(cyan)
                            Text(relativeAge(context.occurredAt)).font(.system(size: 9)).foregroundStyle(.tertiary)
                            if let model = context.model {
                                Text(model).font(.system(size: 9, design: .monospaced)).foregroundStyle(.blue)
                            }
                        }
                        if let input = context.userInput, !input.isEmpty {
                            Text((language.language == .english ? "User: " : "用户：") + input)
                                .font(.system(size: 10, weight: .semibold)).lineLimit(4)
                        }
                        if let response = context.modelResponse, !response.isEmpty {
                            Text((language.language == .english ? "Agent: " : "Agent：") + response)
                                .font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(4)
                        }
                    }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(panel, in: RoundedRectangle(cornerRadius: 7))
                }
            }
            Text(language.language == .english
                 ? "‘Not observed’ describes current evidence coverage; it does not prove the action never happened."
                 : "“未观察到”仅描述当前证据覆盖范围，并不等于证明该行为从未发生。")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
    }

    private func requirementEvidenceLine(_ label: String, value: String, icon: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(cyan).frame(width: 16)
            Text(label).font(.system(size: 10, weight: .bold)).frame(width: 90, alignment: .leading)
            Text(value).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                .textSelection(.enabled).lineLimit(3)
        }
    }

    private func requirementHistoryRow(_ change: ProjectChangeSet) -> some View {
        Button {
            selectedRequirementID = selectedRequirementID == change.id ? nil : change.id
        } label: {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 9) {
                    Circle().fill(verificationColor(change.verification)).frame(width: 7, height: 7)
                    Text(change.requirement).font(.system(size: 12, weight: .semibold)).lineLimit(2)
                    Spacer()
                    Text(formattedAgentName(change.agent)).font(.system(size: 10, weight: .bold)).foregroundStyle(.blue)
                    Text(relativeAge(change.lastActivityAt)).font(.system(size: 10)).foregroundStyle(.tertiary)
                    Image(systemName: selectedRequirementID == change.id ? "chevron.up" : "chevron.down")
                        .font(.system(size: 9)).foregroundStyle(.secondary)
                }
                HStack(spacing: 7) {
                    changeChip("\(change.changedFileCount)", language.language == .english ? "files" : "文件", .blue)
                    changeChip("\(change.memoryReads)R/\(change.memoryWrites)W", language.language == .english ? "memory" : "记忆", cyan)
                    changeChip("\(change.externalDestinations.count)", language.language == .english ? "external" : "外联", amber)
                    changeChip("\(change.securityFindings.count)", language.language == .english ? "findings" : "风险", change.securityFindings.isEmpty ? green : .red)
                    Spacer()
                    Text(L(change.verification.rawValue)).font(.system(size: 10, weight: .bold))
                        .foregroundStyle(verificationColor(change.verification))
                }
                if selectedRequirementID == change.id { requirementEvidenceDetails(change) }
            }.padding(10).background(panel, in: RoundedRectangle(cornerRadius: 8))
        }.buttonStyle(.plain)
    }

    private func loadProjectHistory(_ project: ProjectMission) {
        guard !projectHistoryLoading.contains(project.path),
              projectHistoricalIncidents[project.path] == nil else { return }
        let sessionIDs = project.sessions.map(\.id)
        guard !sessionIDs.isEmpty else { return }
        projectHistoryLoading.insert(project.path)
        projectHistoryErrors[project.path] = nil
        eventStore.loadProjectHistory(sessionIDs: sessionIDs, limitPerSession: 500) { result in
            projectHistoryLoading.remove(project.path)
            switch result {
            case .success(let rows):
                let policy = AgentPolicyAlertEngine.findings(events: rows, policies: alertPolicyStore.policies)
                let direct = rows.filter { event in
                    event.kind == "alert" || event.kind == "external-content"
                        || ["blocked", "restored"].contains(event.action.lowercased())
                        || (["cmd", "file", "memory"].contains(event.kind)
                            && ["critical", "high", "medium"].contains(event.severity.lowercased()))
                }
                projectHistoricalIncidents[project.path] = SecurityIncident.correlate(direct + policy)
                projectHistoryErrors[project.path] = nil
            case .failure(let error):
                projectHistoryErrors[project.path] = error.localizedDescription
            }
        }
    }

    private func mergeIncidents(_ first: [SecurityIncident], _ second: [SecurityIncident]) -> [SecurityIncident] {
        Array(Dictionary((first + second).map { ($0.id, $0) }, uniquingKeysWith: { live, _ in live }).values)
            .sorted { $0.lastTs > $1.lastTs }
    }

    private func projectSecurityView(_ incidents: [SecurityIncident]) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(L("PROJECT SECURITY SUPERVISOR")).micro(cyan)
                    Text(language.language == .english
                         ? "Live and historical findings are restored automatically from local evidence."
                         : "实时与历史问题会从本地证据自动还原，无需单独运行历史分析。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                labelChip("\(incidents.count) \(L("FINDINGS"))", color: incidents.isEmpty ? green : amber)
            }
            if incidents.isEmpty {
                empty(L("No project security finding is supported by current evidence"))
            } else {
                ForEach(incidents.prefix(30)) { incident in
                    SecurityIncidentCardView(incident: incident,
                        chinese: language.language == .simplifiedChinese,
                        density: .compact) { onIncident(incident) }
                }
            }
        }
    }

    private func projectBrief(_ project: ProjectMission, evolution: ProjectEvolutionSnapshot?,
                              intelligence: ProjectIntelligenceSnapshot,
                              projectIncidents: [SecurityIncident]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 7) {
                Text(L("PROJECT BRIEF")).micro(cyan)
                Text(intelligence.purpose.text).font(.system(size: 15, weight: .semibold)).lineLimit(3)
                HStack(spacing: 7) {
                    evidenceTag(intelligence.purpose.confidence)
                    Text(intelligence.purpose.source).font(.system(size: 11)).foregroundStyle(.tertiary)
                }
                if let goal = intelligence.currentGoal {
                    Divider().overlay(border)
                    Text(L("CURRENT GOAL")).micro(.secondary)
                    Text(goal.text).font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(3)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
            projectBriefMetric(L("CAPABILITIES"), "\(intelligence.capabilities.count)", cyan)
            projectBriefMetric(L("FILES SEEN"), "\(intelligence.observedFileCount)", .blue)
            projectBriefMetric(L("SYMBOLS"), "\(intelligence.indexedSymbolCount)", .purple)
            projectBriefMetric(L("Memory").uppercased(), "\(intelligence.memoryReads)R · \(intelligence.memoryWrites)W", cyan)
            projectBriefMetric(L("DRIFT"), "\(intelligence.drift.filter { $0.severity != .aligned }.count)",
                               intelligence.drift.contains { $0.severity == .conflict } ? .red : amber)
        }.padding(13).background(raised.opacity(0.55), in: RoundedRectangle(cornerRadius: 10))
            .overlay(alignment: .bottomLeading) {
                if let engine = intelligence.indexEngine {
                    Text(engine.uppercased()).font(.system(size: 9, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.tertiary).padding(.leading, 13).padding(.bottom, 4)
                }
            }
        if intelligence.atlasEventCount > 0 {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Image(systemName: "square.stack.3d.up.fill").foregroundStyle(.purple)
                    Text("ATLAS PROJECT EVIDENCE").font(.system(size: 9, weight: .bold, design: .monospaced))
                    Text("\(intelligence.atlasEventCount) events").font(.system(size: 10)).foregroundStyle(.secondary)
                    Spacer()
                    if intelligence.atlasLastFailure != nil { labelChip("REVIEW", color: amber) }
                }
                Text(intelligence.atlasLastFailure ?? "Atlas project lifecycle and agent binding events are available in evidence.")
                    .font(.system(size: 11)).foregroundStyle(intelligence.atlasLastFailure == nil ? .secondary : amber)
                    .lineLimit(2)
            }.padding(9).background(panel, in: RoundedRectangle(cornerRadius: 8))
        }
        }
    }

    private func taskWorkspaceBrief(_ project: ProjectMission, evolution: ProjectEvolutionSnapshot?,
                                    projectIncidents: [SecurityIncident]) -> some View {
        let changes = evolution?.changeSets ?? []
        let latest = changes.first
        let observedFiles = Set(changes.flatMap { $0.createdFiles + $0.modifiedFiles + $0.deletedFiles + $0.readFiles }).count
        let memoryReads = changes.reduce(0) { $0 + $1.memoryReads }
        let memoryWrites = changes.reduce(0) { $0 + $1.memoryWrites }
        return VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(language.language == .english ? "TASK BRIEF" : "任务摘要").micro(cyan)
                    Text(latest?.requirement ?? (language.language == .english
                         ? "Requirement evidence has not been captured"
                         : "尚未捕获需求证据"))
                        .font(.system(size: 15, weight: .semibold)).lineLimit(4)
                    Text(language.language == .english
                         ? "This is a temporary Agent task workspace. Requirement and security evidence are supervised without requiring a Git repository."
                         : "这是临时 Agent 任务空间；无需建立 Git 仓库，仍会监督需求与安全证据。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
                projectBriefMetric(language.language == .english ? "OBSERVED BATCHES" : "已观测批次", "\(changes.count)", cyan)
                projectBriefMetric(language.language == .english ? "SESSIONS" : "会话", "\(project.sessions.count)", .blue)
                projectBriefMetric(language.language == .english ? "FILES OBSERVED" : "文件证据", "\(observedFiles)", .purple)
                projectBriefMetric(language.language == .english ? "MEMORY" : "记忆", "\(memoryReads)R · \(memoryWrites)W", cyan)
                projectBriefMetric(language.language == .english ? "FINDINGS" : "风险", "\(projectIncidents.count)",
                                   projectIncidents.isEmpty ? green : amber)
            }
        }.padding(13).background(raised.opacity(0.55), in: RoundedRectangle(cornerRadius: 10))
    }

    private func projectBriefMetric(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).micro(.secondary)
            Text(value).font(.system(size: 17, weight: .bold, design: .rounded)).foregroundStyle(color)
        }.frame(minWidth: 76, alignment: .leading).padding(10)
            .background(panel, in: RoundedRectangle(cornerRadius: 8))
    }

    private func projectCapabilityMap(_ intelligence: ProjectIntelligenceSnapshot) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 8) {
                Text(L("WHAT THIS PROJECT DOES")).micro(cyan)
                if intelligence.capabilities.isEmpty { empty(L("No capabilities can be grounded in recent evidence yet")) }
                ForEach(intelligence.capabilities) { capability in
                    HStack(spacing: 9) {
                        Image(systemName: capabilityIcon(capability.name)).foregroundStyle(cyan).frame(width: 25)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(capability.name).font(.system(size: 13, weight: .bold))
                            Text(capability.explanation).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text("\(capability.files.count) files").font(.system(size: 11)).foregroundStyle(.tertiary)
                        evidenceTag(capability.confidence)
                    }.padding(9).background(panel, in: RoundedRectangle(cornerRadius: 8))
                }
            }.frame(maxWidth: .infinity)
            projectDriftPanel(intelligence.drift).frame(width: 330)
        }
    }

    private func projectArchitectureMap(_ intelligence: ProjectIntelligenceSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("HOW THE PROJECT IS ORGANIZED")).micro(cyan)
            Text(language.language == .english ? "Responsibility areas derived from the local project index and Agent evidence. Select evidence before trusting inferred boundaries." : "职责区域来自本地项目索引和智能体证据；在信任推断边界前请查看证据。")
                .font(.system(size: 11)).foregroundStyle(.secondary)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 9)], spacing: 9) {
                ForEach(intelligence.architecture) { area in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: "cube.transparent").foregroundStyle(.blue)
                            Text(area.name).font(.system(size: 13, weight: .bold)).lineLimit(1)
                            Spacer(); Text("\(area.files.count)").badge(.blue)
                        }
                        Text(area.responsibility).font(.system(size: 11)).foregroundStyle(.secondary)
                        ForEach(area.files.prefix(3), id: \.self) { file in
                            Text(URL(fileURLWithPath: file).lastPathComponent)
                                .font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                        }
                    }.padding(11).frame(maxWidth: .infinity, minHeight: 100, alignment: .topLeading)
                        .background(panel, in: RoundedRectangle(cornerRadius: 9))
                        .overlay(RoundedRectangle(cornerRadius: 9).stroke(border))
                }
            }
        }
    }

    private func projectEvolutionView(_ evolution: ProjectEvolutionSnapshot?) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L("WHY THE PROJECT CHANGED")).micro(cyan)
            if let evolution {
                let families = TaskAttemptHistory.build(changeSets: evolution.changeSets)
                ForEach(families.prefix(6)) { family in
                    VStack(alignment: .leading, spacing: 7) {
                      HStack(alignment: .top, spacing: 10) {
                        Circle().fill(family.succeeded ? green : verificationColor(family.attempts.last?.verification ?? .pending))
                            .frame(width: 8, height: 8).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(family.requirement).font(.system(size: 13, weight: .semibold)).lineLimit(2)
                            Text(family.attempts.count == 1
                                 ? (family.attempts.first?.summary ?? "No activity summary")
                                 : "\(family.attempts.count) attempts · \(family.agents.joined(separator: ", ")) · \(family.succeeded ? "Latest attempt verified" : "Final deliverable not verified")")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if family.attempts.count > 1 {
                            Text(family.confidence.rawValue.uppercased()).font(.system(size: 9, weight: .bold))
                                .foregroundStyle(family.confidence == .confirmed ? green : amber)
                        }
                        Text(relativeAge(family.lastAttemptAt)).font(.system(size: 11)).foregroundStyle(.tertiary)
                      }
                      if family.attempts.count > 1 {
                        if family.hadEarlierVerifiedAttempt && !family.succeeded {
                            Label("Earlier success was superseded; the final attempt is not verified",
                                  systemImage: "arrow.uturn.backward.circle.fill")
                                .font(.system(size: 10, weight: .semibold)).foregroundStyle(amber)
                                .padding(.leading, 18)
                        }
                        ForEach(Array(family.attempts.enumerated()), id: \.element.id) { index, attempt in
                            HStack(spacing: 7) {
                                Text("#\(index + 1)").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(cyan)
                                Text(formattedAgentName(attempt.agent)).font(.system(size: 10, weight: .semibold))
                                Text(attempt.verification.rawValue).font(.system(size: 10)).foregroundStyle(verificationColor(attempt.verification))
                                Spacer()
                                Text(relativeAge(attempt.lastActivityAt)).font(.system(size: 10)).foregroundStyle(.tertiary)
                            }.padding(.leading, 18)
                        }
                      }
                    }.padding(9).background(panel, in: RoundedRectangle(cornerRadius: 8))
                }
            } else { empty(L("No project evolution has been attributed yet")) }
        }
    }

    private func projectUnderstandingView(_ intelligence: ProjectIntelligenceSnapshot) -> some View {
        HStack(alignment: .top, spacing: 10) {
            knowledgeColumn(L("AGENT'S PROJECT MODEL"), icon: "brain.head.profile", rows:
                ([intelligence.currentGoal].compactMap { $0 } + intelligence.constraints + intelligence.decisions))
            knowledgeColumn(L("UNRESOLVED & UNVERIFIED"), icon: "questionmark.diamond",
                            rows: intelligence.openQuestions)
            projectDriftPanel(intelligence.drift)
        }
    }

    private func knowledgeColumn(_ title: String, icon: String, rows: [ProjectKnowledgeItem]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon).font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
            if rows.isEmpty { Text(L("No grounded knowledge captured yet")).font(.system(size: 12)).foregroundStyle(.tertiary) }
            ForEach(rows.prefix(7)) { row in
                VStack(alignment: .leading, spacing: 3) {
                    Text(row.text).font(.system(size: 12, weight: .medium)).lineLimit(3)
                    HStack { evidenceTag(row.confidence); Text(row.source).font(.system(size: 10)).foregroundStyle(.tertiary).lineLimit(1) }
                }.padding(8).background(panel, in: RoundedRectangle(cornerRadius: 7))
            }
        }.frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private func projectDriftPanel(_ findings: [ProjectDriftFinding]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(L("REALITY VS AGENT UNDERSTANDING"), systemImage: "arrow.left.arrow.right.square")
                .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
            ForEach(findings) { finding in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Circle().fill(driftColor(finding.severity)).frame(width: 7, height: 7)
                        Text(L(finding.title)).font(.system(size: 12, weight: .bold)).lineLimit(2)
                    }
                    Text(finding.detail).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(4)
                }.padding(9).background(driftColor(finding.severity).opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(driftColor(finding.severity).opacity(0.35)))
            }
        }.frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private func evidenceTag(_ confidence: ProjectKnowledgeConfidence) -> some View {
        let color: Color = confidence == .observed ? green : (confidence == .declared ? cyan : .blue)
        return Text(L(confidence.rawValue).uppercased()).font(.system(size: 9, weight: .bold)).foregroundStyle(color)
            .padding(.horizontal, 5).padding(.vertical, 2).background(color.opacity(0.11), in: Capsule())
    }

    private func driftColor(_ severity: ProjectDriftSeverity) -> Color {
        switch severity { case .aligned: return green; case .review: return amber; case .conflict: return .red }
    }

    private func capabilityIcon(_ name: String) -> String {
        if name.contains("Network") { return "network" }
        if name.contains("Memory") { return "brain" }
        if name.contains("Web") { return "globe" }
        if name.contains("Evidence") { return "externaldrive" }
        if name.contains("Code") { return "chevron.left.forwardslash.chevron.right" }
        if name.contains("Runtime") { return "point.3.connected.trianglepath.dotted" }
        return "rectangle.3.group"
    }

    private func globalTaskRow(_ session: AgentSessionSnapshot, incidents: [SecurityIncident],
                               changeSet: ProjectChangeSet?) -> some View {
        let turn = session.turns.last
        let stage = liveStage(for: session)
        let risk = incidents.max { severityRank($0.severity) < severityRank($1.severity) }
        return Button {
            didUserSelectAgent = true
            selectedAgent = session.agentDisplayName
            centerTab = .overview
            followingLive = true
        } label: {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 9) {
                    Circle().fill(stage.color).frame(width: 8, height: 8)
                    Text(session.agentDisplayName).font(.system(size: 14, weight: .bold))
                    Text(String((turn?.userInput ?? session.latestIntent ?? "Active Agent task").prefix(90)))
                        .font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    if let risk { labelChip(risk.severity.uppercased(), color: incidentColor(risk.severity)) }
                    Text(stage.label.uppercased()).font(.system(size: 11, weight: .bold)).foregroundStyle(stage.color)
                    Text(clock(session.lastActivityAt)).font(.system(size: 12, design: .monospaced)).foregroundStyle(.tertiary)
                    Image(systemName: "chevron.right").font(.system(size: 11)).foregroundStyle(.secondary)
                }
                taskStageRail(session)
                if let changeSet {
                    HStack(spacing: 7) {
                        changeChip("+\(changeSet.createdFiles.count)", "new", green)
                        changeChip("~\(changeSet.modifiedFiles.count)", "modified", .blue)
                        changeChip("−\(changeSet.deletedFiles.count)", "deleted", .red)
                        if !changeSet.externalDestinations.isEmpty {
                            changeChip("\(changeSet.externalDestinations.count)", "external", amber)
                        }
                        if changeSet.memoryReads + changeSet.memoryWrites > 0 {
                            changeChip("\(changeSet.memoryReads + changeSet.memoryWrites)", "memory", cyan)
                        }
                        Text(changeSet.summary).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                        Spacer()
                        Text(changeSet.verification.rawValue.uppercased())
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(verificationColor(changeSet.verification))
                    }
                    if let file = (changeSet.modifiedFiles + changeSet.createdFiles + changeSet.deletedFiles).first {
                        Text("Latest project change · \(file)")
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                    }
                }
                if let risk {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.shield.fill").foregroundStyle(incidentColor(risk.severity))
                        Text(risk.title).font(.system(size: 12, weight: .semibold)).lineLimit(1)
                        Text("· \(risk.summary)").font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }.padding(12).background(raised.opacity(0.72), in: RoundedRectangle(cornerRadius: 9))
        }.buttonStyle(HoverCardButtonStyle())
    }

    private func changeChip(_ value: String, _ label: String, _ color: Color) -> some View {
        HStack(spacing: 3) {
            Text(value).font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(color)
            Text(label).font(.system(size: 10)).foregroundStyle(.secondary)
        }.padding(.horizontal, 6).padding(.vertical, 3)
            .background(color.opacity(0.09), in: RoundedRectangle(cornerRadius: 5))
    }

    private func verificationColor(_ state: ProjectVerificationState) -> Color {
        switch state {
        case .verified: return green
        case .failed: return .red
        case .agentReported: return amber
        case .pending: return .secondary
        }
    }

    private func relativeAge(_ date: Date) -> String {
        let seconds = max(0, Date().timeIntervalSince(date))
        if seconds < 60 { return "just now" }
        if seconds < 3_600 { return "\(Int(seconds / 60))m ago" }
        if seconds < 86_400 { return "\(Int(seconds / 3_600))h ago" }
        return "\(Int(seconds / 86_400))d ago"
    }

    private func taskStageRail(_ session: AgentSessionSnapshot) -> some View {
        let rows = session.events
        let turn = session.turns.last
        let stages: [(String, Bool, Bool)] = [
            ("Request", turn?.userInput != nil, false),
            ("Context", rows.contains { $0.kind == "context" || $0.modelPrompt != nil }, false),
            ("Model", rows.contains { $0.kind == "model" && $0.op == "response" }, false),
            ("Tools", !((turn?.toolCalls ?? []).isEmpty), turn?.toolCalls.contains { $0.completedAt == nil } == true),
            ("Changes", rows.contains { $0.kind == "file" && $0.op != "read" }, false),
            ("Verified", rows.contains { $0.kind == "verification" && ["passed", "verified", "success"].contains($0.action.lowercased()) }, false)
        ]
        return HStack(spacing: 0) {
            ForEach(Array(stages.enumerated()), id: \.offset) { index, item in
                HStack(spacing: 5) {
                    Circle().fill(item.2 ? amber : (item.1 ? green : Color.gray.opacity(0.45)))
                        .frame(width: 7, height: 7)
                    Text(item.0).font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(item.1 || item.2 ? .primary : .tertiary)
                    if index < stages.count - 1 {
                        Rectangle().fill(item.1 ? green.opacity(0.55) : border).frame(height: 1)
                    }
                }.frame(maxWidth: .infinity)
            }
        }
    }

    private var globalAgentsView: some View {
        LazyVStack(spacing: 9) {
            ForEach(discoveredAgents) { item in
                let related = sessions.filter { normalizedAgentKey($0.agent) == normalizedAgentKey(item.product) }
                let latest = related.max { $0.lastActivityAt < $1.lastActivityAt }
                fleetRow(name: item.product, title: latest.map { readableActivity($0.turns.last) } ?? "No active task",
                         detail: latest?.workspace ?? "No project attributed", live: item.presence == .running)
            }
        }
    }

    private var globalEgressView: some View {
        let reports = AgentEgressAudit.build(sessions: sessions)
        let critical = reports.filter { $0.risk == .critical || $0.risk == .high }.count
        let incomplete = reports.filter { $0.coverage != .complete }.count
        let sensitive = reports.reduce(0) { $0 + $1.sensitiveFindings.count }
        return LazyVStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                egressMetric(language.language == .english ? "OUTBOUND TURNS" : "出站轮次",
                             value: reports.count.formatted(), color: cyan)
                egressMetric(language.language == .english ? "HIGH RISK" : "高风险",
                             value: critical.formatted(), color: critical > 0 ? .red : green)
                egressMetric(language.language == .english ? "SENSITIVE ITEMS" : "敏感项",
                             value: sensitive.formatted(), color: sensitive > 0 ? amber : green)
                egressMetric(language.language == .english ? "EVIDENCE GAPS" : "证据缺口",
                             value: incomplete.formatted(), color: incomplete > 0 ? amber : green)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(language.language == .english ? "AGENT EGRESS AUDIT" : "智能体出站审计")
                    .font(.system(size: 12, weight: .bold)).foregroundStyle(cyan)
                Text(language.language == .english
                     ? "One turn, one accountable record: who sent what, to which provider or relay, with which sensitive context and evidence gaps."
                     : "一轮一次可追责记录：谁向哪个模型、网站或中转发送了什么，包含哪些敏感上下文，以及证据是否完整。")
                    .font(.system(size: 12)).foregroundStyle(.secondary)
            }
            if reports.isEmpty {
                empty(language.language == .english
                    ? "No outbound request has been correlated to an Agent turn"
                    : "尚未发现能够关联到智能体轮次的出站请求")
            } else {
                ForEach(reports.prefix(80)) { report in egressSummaryCard(report) }
            }
        }
    }

    private func egressMetric(_ title: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 22, weight: .bold, design: .monospaced)).foregroundStyle(color)
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(border))
    }

    private func egressSummaryCard(_ report: AgentEgressAudit) -> some View {
        let riskColor: Color = report.risk == .critical ? .red
            : report.risk == .high ? amber
            : report.risk == .medium || report.risk == .unknown ? .yellow : green
        let evidence = report.dataClassifications.flatMap(\.evidence).sorted { $0.sequence < $1.sequence }
        let categoryNames = Array(Set(evidence.map { egressCategoryName($0.category) })).prefix(4)
        return Button {
            selectedEgressCategory = nil
            egressReaderMode = .organized
            egressReaderPage = 0
            selectedEgressAudit = report
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "arrow.up.right.circle.fill")
                        .font(.system(size: 21)).foregroundStyle(riskColor)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(report.agent) → \(report.primaryDestination)")
                            .font(.system(size: 16, weight: .bold)).foregroundStyle(.primary)
                        Text(report.userIntent ?? (language.language == .english ? "User intent not captured" : "未捕获用户意图"))
                            .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer()
                    labelChip(report.risk.rawValue.uppercased(), color: riskColor)
                    Text(relativeAge(report.occurredAt)).micro(.secondary)
                }
                if let first = evidence.first {
                    HStack(alignment: .top, spacing: 8) {
                        Text(language.language == .english ? "Starts with" : "上下文开头")
                            .font(.system(size: 10, weight: .bold)).foregroundStyle(cyan)
                        Text(first.content.replacingOccurrences(of: "\n", with: " "))
                            .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
                    }
                }
                HStack(spacing: 8) {
                    Text(categoryNames.joined(separator: " · "))
                        .font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    Label(language.language == .english ? "Read uploaded context" : "阅读上传上下文",
                          systemImage: "doc.text.magnifyingglass")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                }
            }
            .padding(15).background(panel, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(riskColor.opacity(0.55)))
        }.buttonStyle(.plain)
    }

    private func egressReader(_ report: AgentEgressAudit) -> some View {
        let allEvidence = report.dataClassifications.flatMap(\.evidence).sorted { $0.sequence < $1.sequence }
        let visibleEvidence = selectedEgressCategory.map { selected in
            allEvidence.filter { $0.category == selected }
        } ?? allEvidence
        let evidencePages = pagedEgressEvidence(visibleEvidence)
        let rawPages = pagedText(visibleEvidence.map(\.content).joined(separator: "\n\n"))
        let reasoningPages = pagedReasoning(report.capturedModelReasoning)
        let pageCount = egressReaderMode == .organized ? evidencePages.count
            : egressReaderMode == .raw ? rawPages.count : reasoningPages.count
        let page = min(egressReaderPage, max(0, pageCount - 1))
        let categories = EgressDataCategory.allCases.filter { category in
            category != .notCaptured && allEvidence.contains { $0.category == category }
        }
        let riskColor: Color = report.risk == .critical ? .red
            : report.risk == .high ? amber
            : report.risk == .medium || report.risk == .unknown ? .yellow : green
        return VStack(spacing: 0) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(language.language == .english ? "UPLOADED CONTEXT" : "发送给大模型的上下文")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                    Text("\(report.agent) → \(report.primaryDestination)")
                        .font(.system(size: 18, weight: .bold))
                    Text(report.userIntent ?? (language.language == .english ? "User intent not captured" : "未捕获用户意图"))
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Picker("", selection: $egressReaderMode) {
                    Text(language.language == .english ? "Sent context" : "发送内容").tag(EgressReaderMode.organized)
                    Text(language.language == .english ? "Raw input" : "输入原文").tag(EgressReaderMode.raw)
                    Text(language.language == .english ? "Model reasoning" : "模型思考").tag(EgressReaderMode.reasoning)
                }.pickerStyle(.segmented).frame(width: 330)
                    .onChange(of: egressReaderMode) { _ in egressReaderPage = 0 }
                Button { selectedEgressAudit = nil } label: {
                    Image(systemName: "xmark").frame(width: 28, height: 28)
                }.buttonStyle(.plain)
            }.padding(18).background(panel)

            Divider().overlay(border)
            HStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        egressReaderCategoryButton(nil,
                            title: language.language == .english ? "Complete context" : "完整上下文",
                            preview: report.userIntent ?? "")
                        ForEach(categories, id: \.rawValue) { category in
                            let first = allEvidence.first { $0.category == category }
                            egressReaderCategoryButton(category, title: egressCategoryName(category),
                                preview: first?.content.replacingOccurrences(of: "\n", with: " ") ?? "")
                        }
                    }.padding(12)
                }.frame(width: 250).background(panel.opacity(0.72))

                Divider().overlay(border)
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        if egressReaderMode == .reasoning {
                            modelReasoningEvidence(reasoningPages.isEmpty ? nil : reasoningPages[page])
                        } else if egressReaderMode == .raw {
                            Text(rawPages.isEmpty ? "" : rawPages[page])
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        } else {
                            if !evidencePages.isEmpty {
                                egressContextSegment(evidencePages[page].evidence,
                                                     content: evidencePages[page].content)
                            }
                        }
                        if egressReaderMode != .reasoning && visibleEvidence.isEmpty {
                            empty(language.language == .english ? "No captured text in this category" : "该分类没有已捕获原文")
                        }
                        if pageCount > 1 { egressPagination(page: page, count: pageCount) }
                    }.padding(20)
                }.frame(maxWidth: .infinity)

                Divider().overlay(border)
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(language.language == .english ? "SECURITY ASSESSMENT" : "安全判断")
                            .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                        Text(egressRiskSummary(report)).font(.system(size: 13, weight: .bold)).foregroundStyle(riskColor)
                        ForEach(report.findings, id: \.self) { finding in
                            Text("• \(finding)").font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        if !report.sensitiveFindings.isEmpty {
                            Divider().overlay(border)
                            Text(language.language == .english ? "Sensitive content found" : "发现的敏感内容")
                                .font(.system(size: 11, weight: .bold)).foregroundStyle(.red)
                            ForEach(Array(report.sensitiveFindings.enumerated()), id: \.offset) { _, finding in
                                Text("\(sensitiveCategoryName(finding.category)) · \(finding.source)")
                                    .font(.system(size: 11)).foregroundStyle(.red)
                            }
                        }
                        Divider().overlay(border)
                        Text(language.language == .english ? "TECHNICAL EVIDENCE" : "技术证据")
                            .font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
                        Text(report.inputTokens.map { "\($0.formatted()) input tokens" }
                             ?? (language.language == .english ? "Tokens not reported" : "Token 未报告"))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                        Text(formatBytes(report.capturedPromptBytes))
                            .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    }.padding(16)
                }.frame(width: 280).background(panel.opacity(0.72))
            }
        }
        .frame(minWidth: 1080, minHeight: 720)
        .background(canvas).environment(\.colorScheme, .dark)
    }

    private struct PagedEgressEvidence {
        let evidence: EgressDataEvidence
        let content: String
    }

    private struct PagedReasoning {
        let evidence: CapturedModelReasoning
        let content: String
    }

    private func pagedText(_ text: String, pageSize: Int = 20_000) -> [String] {
        guard !text.isEmpty else { return [] }
        var pages: [String] = []
        var start = text.startIndex
        while start < text.endIndex {
            let end = text.index(start, offsetBy: pageSize, limitedBy: text.endIndex) ?? text.endIndex
            pages.append(String(text[start..<end]))
            start = end
        }
        return pages
    }

    private func pagedEgressEvidence(_ rows: [EgressDataEvidence]) -> [PagedEgressEvidence] {
        rows.flatMap { row in
            pagedText(row.content).map { PagedEgressEvidence(evidence: row, content: $0) }
        }
    }

    private func pagedReasoning(_ rows: [CapturedModelReasoning]) -> [PagedReasoning] {
        rows.flatMap { row in
            pagedText(row.content).map { PagedReasoning(evidence: row, content: $0) }
        }
    }

    private func egressPagination(page: Int, count: Int) -> some View {
        HStack(spacing: 10) {
            Button { egressReaderPage = max(0, page - 1) } label: {
                Image(systemName: "chevron.left").frame(width: 28, height: 28)
            }.buttonStyle(.plain).disabled(page == 0)
            Text("\(page + 1) / \(count)")
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
            Button { egressReaderPage = min(count - 1, page + 1) } label: {
                Image(systemName: "chevron.right").frame(width: 28, height: 28)
            }.buttonStyle(.plain).disabled(page + 1 >= count)
            Spacer()
            Text(language.language == .english ? "20,000 characters per page" : "每页最多 20,000 字符")
                .font(.system(size: 10)).foregroundStyle(.secondary)
        }.padding(.top, 8)
    }

    private func modelReasoningEvidence(_ page: PagedReasoning?) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 5) {
                Text(language.language == .english ? "MODEL → AGENT" : "大模型 → Agent")
                    .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                Text(language.language == .english
                     ? "Reasoning recorded locally by the Agent"
                     : "Agent 本地记录中实际捕获的思考内容")
                    .font(.system(size: 15, weight: .bold))
                Text(language.language == .english
                     ? "This is returned model content, not data uploaded in the current request. It becomes outbound data only if a later request includes it."
                     : "这是模型返回内容，不计入本次上传；只有后续请求再次携带它时，才属于新的出境数据。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if let page {
                VStack(alignment: .leading, spacing: 7) {
                    HStack {
                        Image(systemName: "brain.head.profile").foregroundStyle(cyan)
                        Text(page.evidence.source).font(.system(size: 11, weight: .bold))
                        Spacer()
                        Text(page.evidence.occurredAt.formatted(date: .omitted, time: .standard))
                            .font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    Text(page.content).font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    if let detail = page.evidence.captureDetail, !detail.isEmpty {
                        Text(detail).font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }.padding(12).background(panel, in: RoundedRectangle(cornerRadius: 7))
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(border))
            } else {
                empty(language.language == .english
                      ? "No locally recorded model reasoning for this turn"
                      : "本轮没有本地记录的模型思考内容")
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func egressReaderCategoryButton(_ category: EgressDataCategory?, title: String,
                                            preview: String) -> some View {
        let selected = selectedEgressCategory == category
        return Button {
            selectedEgressCategory = category
            egressReaderPage = 0
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(selected ? cyan : .primary)
                if !preview.isEmpty {
                    Text(preview).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(2)
                }
            }.padding(9).frame(maxWidth: .infinity, alignment: .leading)
                .background(selected ? cyan.opacity(0.10) : Color.clear,
                            in: RoundedRectangle(cornerRadius: 6))
        }.buttonStyle(.plain)
    }

    private func egressContextSegment(_ evidence: EgressDataEvidence, content: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Image(systemName: egressCategoryIcon(evidence.category))
                    .frame(width: 18).foregroundStyle(egressCategoryColor(evidence.category))
                Text(egressCategoryName(evidence.category))
                    .font(.system(size: 12, weight: .bold)).foregroundStyle(egressCategoryColor(evidence.category))
                Text(evidence.source).font(.system(size: 10)).foregroundStyle(.secondary)
                Spacer()
            }
            Text(content ?? evidence.content)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.leading, 26)
        }
    }

    private func egressCategoryName(_ category: EgressDataCategory) -> String {
        if language.language == .english {
            switch category {
            case .userInput: return "User instructions"
            case .systemInstructions: return "System instructions"
            case .developerInstructions: return "Developer instructions"
            case .identityAndPreferences: return "Identity and preferences"
            case .memory: return "Memory"
            case .agentRules: return "Agent rules and skills"
            case .projectContent: return "Project context"
            case .sourceCode: return "Source code"
            case .toolCalls: return "Tool calls and arguments"
            case .toolResults: return "Tool results"
            case .deviceEnvironment: return "Device and environment"
            case .connectors: return "Connectors and services"
            case .permissions: return "Permissions and sandbox"
            case .conversationHistory: return "Conversation history"
            case .attachments: return "Attachments"
            case .otherCaptured: return "Other captured content"
            case .notCaptured: return "Not captured / unclassified"
            }
        }
        switch category {
        case .userInput: return "用户指令"
        case .systemInstructions: return "系统指令"
        case .developerInstructions: return "开发者指令"
        case .identityAndPreferences: return "身份与个人偏好"
        case .memory: return "长期记忆"
        case .agentRules: return "智能体规则与技能"
        case .projectContent: return "项目上下文"
        case .sourceCode: return "源代码"
        case .toolCalls: return "工具调用与参数"
        case .connectors: return "连接器与外部服务状态"
        case .permissions: return "权限与沙箱配置"
        case .conversationHistory: return "历史对话与摘要"
        case .attachments: return "附件与图片"
        case .toolResults: return "工具执行结果"
        case .deviceEnvironment: return "设备与运行环境"
        case .otherCaptured: return "其他已捕获内容"
        case .notCaptured: return "未捕获 / 无法分类"
        }
    }

    private func egressCategoryColor(_ category: EgressDataCategory) -> Color {
        switch category {
        case .notCaptured: return amber
        case .identityAndPreferences, .memory, .sourceCode, .toolResults, .attachments: return .red
        case .userInput: return green
        default: return cyan
        }
    }

    private func egressCategoryIcon(_ category: EgressDataCategory) -> String {
        switch category {
        case .identityAndPreferences: return "person.text.rectangle"
        case .memory, .conversationHistory: return "brain.head.profile"
        case .projectContent: return "folder.fill"
        case .sourceCode: return "chevron.left.forwardslash.chevron.right"
        case .toolCalls: return "hammer.fill"
        case .toolResults: return "terminal.fill"
        case .attachments: return "paperclip"
        case .deviceEnvironment, .permissions: return "desktopcomputer"
        case .connectors: return "network"
        case .agentRules, .systemInstructions, .developerInstructions: return "doc.text.fill"
        case .userInput: return "text.bubble.fill"
        case .otherCaptured: return "doc.plaintext"
        case .notCaptured: return "eye.slash.fill"
        }
    }

    private func sensitiveCategoryName(_ category: SensitiveExposureCategory) -> String {
        if language.language == .english { return category.rawValue }
        switch category {
        case .apiCredential: return "API 凭据"
        case .password: return "密码"
        case .privateKey: return "私钥"
        case .bankCard: return "银行卡号"
        case .nationalID: return "身份证号"
        case .email: return "电子邮箱"
        }
    }

    private func egressRiskSummary(_ report: AgentEgressAudit) -> String {
        if language.language == .english {
            switch report.risk {
            case .critical: return "Critical: sensitive data and an unverified or relayed destination were both found"
            case .high: return "High risk: sensitive data or a model relay was found"
            case .medium: return "Needs review: evidence is incomplete or destination identity is unverified"
            case .low: return "Low risk: no sensitive data found and the route is consistent"
            case .unknown: return "Unknown: there is not enough evidence for a safety verdict"
            }
        }
        switch report.risk {
        case .critical: return "严重风险：同时发现敏感数据和未经验证或经中转的接收方"
        case .high: return "高风险：发现敏感数据或模型中转服务"
        case .medium: return "需要审查：证据不完整或无法确认接收方身份"
        case .low: return "低风险：未发现敏感数据，且传输路径与声明一致"
        case .unknown: return "无法判断：现有证据不足以得出安全结论"
        }
    }

    private var globalSecurityView: some View {
        let visible = scopedIncidents.filter { $0.severity != "info" }
        return LazyVStack(alignment: .leading, spacing: 12) {
            SecurityPostureSummaryView(incidents: visible, sessions: sessions, health: health,
                                       evidenceCoverage: evidenceCoverage,
                                       analysisConfigured: semanticAnalyzer.configured,
                                       analysisModel: semanticAnalyzer.model,
                                       latestAIReview: semanticAnalyzer.historicalAnalysis,
                                       chinese: language.language == .simplifiedChinese)
            if let analysis = semanticAnalyzer.historicalAnalysis {
                aiHistoricalFindings(analysis)
            }
            if visible.isEmpty {
                empty(language.language == .english
                    ? "No action is needed in the live window"
                    : "当前实时范围内没有需要处理的风险")
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    Text(language.language == .english ? "PRIORITIZED SECURITY CASES" : "按优先级排列的安全案件")
                        .font(.system(size: 12, weight: .bold)).foregroundStyle(cyan)
                    Text(language.language == .english
                         ? "Each case states what happened, why it matters, what remains unknown, and what to do next."
                         : "每个案件先说明发生了什么、为什么重要、哪些尚未确认，以及下一步怎么做。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }.padding(.bottom, 2)
            }
            ForEach(visible.sorted { severityRank($0.severity) > severityRank($1.severity) }) { incident in
                SecurityIncidentCardView(incident: incident,
                    chinese: language.language == .simplifiedChinese,
                    density: .standard) { onIncident(incident) }
            }
        }
    }

    private var aiHistoryControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(language.language == .english ? "AI HISTORICAL REVIEW" : "AI 历史安全复核")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(cyan)
                    Text(language.language == .english
                         ? "Two-pass review: discovery first, independent llm_self_examine second."
                         : "两阶段复核：先发现风险，再由独立的 llm_self_examine 二次审查。")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    guard semanticAnalyzer.canStartHistoricalAnalysis() else { return }
                    eventStore.loadHistoricalSecurityEvidence { result in
                        switch result {
                        case .success(let rows):
                            Task {
                                await semanticAnalyzer.analyzeHistory(rows, policies: alertPolicyStore.policies)
                                if let analysis = semanticAnalyzer.historicalAnalysis {
                                    alertPolicyStore.ingestAIProposals(analysis, events: rows)
                                }
                            }
                        case .failure(let error): semanticAnalyzer.lastError = error.localizedDescription
                        }
                    }
                } label: {
                    Label(semanticAnalyzer.analyzingHistory
                          ? (language.language == .english ? "Analyzing…" : "分析中…")
                          : (language.language == .english ? "Analyze history" : "分析历史"),
                          systemImage: "brain.head.profile")
                }.buttonStyle(.borderedProminent).tint(cyan)
                    .disabled(!semanticAnalyzer.configured || semanticAnalyzer.analyzingHistory)
            }
            if let error = semanticAnalyzer.lastError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11)).foregroundStyle(amber)
            } else if semanticAnalyzer.configured {
                Text("\(semanticAnalyzer.model) · API configuration ready")
                    .font(.system(size: 10, design: .monospaced)).foregroundStyle(green)
            } else {
                Text(language.language == .english
                     ? "Configure and verify an analysis model before scanning history."
                     : "请先配置并验证分析模型，再扫描历史证据。")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }.padding(13).background(raised, in: RoundedRectangle(cornerRadius: 10))
    }

    private func aiHistoricalFindings(_ analysis: HistoricalSecurityAnalysis) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(language.language == .english ? "HISTORICAL AI FINDINGS" : "AI 历史发现")
                    .font(.system(size: 11, weight: .bold)).foregroundStyle(.purple)
                Spacer()
                Text("\(analysis.findings.count) findings · \(analysis.rules.count) rules · \(analysis.examinationPasses ?? 0) passes")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            ForEach(analysis.findings) { finding in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(finding.title).font(.system(size: 14, weight: .bold))
                        Spacer()
                        labelChip(finding.severity.uppercased(), color: incidentColor(finding.severity))
                    }
                    Text(finding.summary).font(.system(size: 12)).foregroundStyle(.secondary)
                    Text(finding.recommendedAction).font(.system(size: 12, weight: .semibold))
                    HStack {
                        Text("llm_self_examine · \(finding.llmSelfExamine.verdict)")
                        Text("· \(Int(finding.llmSelfExamine.confidence * 100))%")
                        Text("· \(finding.evidenceEventIds.count) evidence")
                    }.font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary)
                    Text(finding.llmSelfExamine.rationale).font(.system(size: 11)).foregroundStyle(.secondary)
                }.padding(13).background(panel, in: RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.purple.opacity(0.5)))
            }
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(analysis.rules) { rule in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 8) {
                                Text(rule.name).font(.system(size: 12, weight: .semibold))
                                labelChip(rule.origin == "built_in"
                                          ? (language.language == .english ? "BUILT-IN" : "内置")
                                          : (language.language == .english ? "AI PROPOSED" : "AI 建议"),
                                          color: rule.origin == "built_in" ? cyan : .purple)
                                Spacer()
                                Text("\(rule.llmSelfExamine.verdict) · \(Int(rule.llmSelfExamine.confidence * 100))%")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(rule.llmSelfExamine.verdict == "rejected" ? amber : green)
                            }
                            Text(rule.condition).font(.system(size: 11)).foregroundStyle(.secondary)
                            Text(rule.llmSelfExamine.rationale).font(.system(size: 10)).foregroundStyle(.tertiary)
                        }
                        .padding(10)
                        .background(raised, in: RoundedRectangle(cornerRadius: 8))
                    }
                }.padding(.top, 8)
            } label: {
                Text(language.language == .english
                     ? "Rule self-examination (\(analysis.rules.count))"
                     : "规则自检（\(analysis.rules.count)）")
                    .font(.system(size: 12, weight: .semibold))
            }
        }
    }

    private func liveStage(for session: AgentSessionSnapshot) -> (label: String, color: Color) {
        guard let turn = session.turns.last else { return ("Monitoring", .gray) }
        if session.events.contains(where: { $0.kind == "verification" && ["passed", "verified", "success"].contains($0.action.lowercased()) }) {
            return ("Verified", green)
        }
        if turn.finalResponse != nil { return ("Reported complete", cyan) }
        if sessionIsLive(session) { return (readableActivity(turn), amber) }
        return ("Last observed", .gray)
    }

    private func incidentColor(_ severity: String) -> Color {
        switch severity.lowercased() {
        case "critical": return .red
        case "high", "medium": return amber
        default: return cyan
        }
    }

    private func severityRank(_ severity: String) -> Int {
        ["info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4][severity.lowercased()] ?? 0
    }

    private var taskHeader: some View {
        VStack(alignment: .leading, spacing: 12) {
            AgentLiveTaskHeaderView(
                agentName: activeSession?.agentDisplayName ?? L("Waiting for agent activity"),
                headline: liveHeadline, active: activeSession != nil,
                pid: rootPID, model: activeSession?.model,
                openTitle: L("Open session…"),
                onOpen: activeSession.map { session in { onSession(session) } },
                jsonTitle: language.language == .english ? "View task JSON" : "查看任务 JSON",
                onJSON: activeSession.map { session in
                    { showTaskJSON(session: session, turnID: activeTurn?.id) }
                }
            )
            if let sessionID = activeSession?.id, let turnID = activeTurn?.id,
               let progress = eventStore.taskProgress["\(sessionID)\u{0}\(turnID)"] {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let fresh = context.date.timeIntervalSince(progress.lastActivityAt) < 30
                    let end = fresh ? context.date : progress.lastActivityAt
                    let elapsed = max(0, Int(end.timeIntervalSince(progress.startedAt)))
                    HStack(spacing: 14) {
                        Text(fresh ? progress.phase.rawValue : "最后观测：\(progress.phase.rawValue)")
                        Text("观测耗时 \(elapsed / 60)m \(elapsed % 60)s")
                        Text("模型 \(progress.modelRequests.count) 请求 · \(progress.modelResponses.count) 响应")
                        Text("工具 \(progress.toolResults.count)/\(progress.toolCalls.count) 完成")
                        Text("Token \(progress.inputTokens + progress.outputTokens) 已确认")
                        if !progress.riskEvents.isEmpty { Text("风险 \(progress.riskEvents.count)").foregroundStyle(.orange) }
                    }
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func showTaskJSON(session: AgentSessionSnapshot, turnID: String?) {
        // The live dashboard keeps only 500 recent events. Always rebuild the
        // requested task from SQLite so a long task's early steps are present.
        eventStore.loadSession(session.id) { result in
            do {
                let fullSession = try result.get()
                let export = AgentTaskJSONExport.build(session: fullSession, turnID: turnID)
                selectedTaskJSON = TaskJSONDocument(
                    title: "\(fullSession.agentDisplayName) · \(turnID ?? fullSession.id)",
                    json: try export.prettyJSON(), snapshot: export)
                taskReaderShowsJSON = false
            } catch {
                projectionError = "任务 JSON 生成失败：\(error.localizedDescription)"
            }
        }
    }

    private func taskJSONReader(_ document: TaskJSONDocument) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(language.language == .english ? "COMPLETE TASK JSON" : "完整任务 JSON")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundStyle(cyan)
                    Text(document.title).font(.system(size: 17, weight: .bold))
                }
                Spacer()
                Picker("视图", selection: $taskReaderShowsJSON) {
                    Text("执行链路").tag(false)
                    Text("原始 JSON").tag(true)
                }.pickerStyle(.segmented).frame(width: 190)
                Button(language.language == .english ? "Copy JSON" : "复制 JSON") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(document.json, forType: .string)
                }.buttonStyle(.borderedProminent).tint(cyan)
            }
            if taskReaderShowsJSON {
                TextEditor(text: .constant(document.json))
                    .font(.system(size: 11, design: .monospaced))
                    .scrollContentBackground(.hidden)
                    .padding(8).background(canvas, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
            } else {
                AgentTaskJourneyView(snapshot: document.snapshot)
                    .background(canvas, in: RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
            }
        }
        .padding(18).frame(minWidth: 900, minHeight: 680)
        .background(panel).environment(\.colorScheme, .dark)
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(CenterTab.allCases) { tab in
                    Button {
                        centerTab = tab
                        if tab != .memory { selectedMemoryCommitID = nil }
                    } label: {
                        Text(tab.rawValue)
                            .font(.system(size: 13, weight: centerTab == tab ? .bold : .medium))
                            .foregroundStyle(centerTab == tab ? cyan : .secondary)
                            .padding(.horizontal, 12).padding(.vertical, 8)
                    }.buttonStyle(TabButtonStyle(selected: centerTab == tab))
                }
            }
        }
        .padding(.bottom, 2)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)
    }

    @ViewBuilder
    private var centerContent: some View {
        switch centerTab {
        case .overview:
            missionOverview
        case .processes:
            processPanel
        case .network:
            networkPanel
        case .files:
            listPanel("FILE ACTIVITY", "What the Agent read or changed in this task") {
                let files = liveTaskFiles
                if files.isEmpty { empty("No file activity observed in this task") }
                if !files.isEmpty {
                    HStack(spacing: 6) {
                        fileCountChip("READ", files.filter { $0.op == "read" }.count, cyan)
                        fileCountChip("CREATED", files.filter { $0.op == "create" }.count, green)
                        fileCountChip("UPDATED", files.filter { ["update", "modify"].contains($0.op) }.count, .blue)
                        fileCountChip("DELETED", files.filter { $0.op == "delete" }.count, amber)
                    }.padding(.bottom, 6)
                }
                ForEach(Array(files)) { event in
                    Button { selectedEvent = event; selectedProcess = nil; selectedProcessGroup = [] } label: {
                        HStack(spacing: 9) {
                            Image(systemName: fileOperationIcon(event.op)).foregroundStyle(fileOperationColor(event))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(fileActivitySentence(event)).font(.system(size: 13, weight: .semibold))
                                Text(fileChangeDescription(event))
                                    .font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(2)
                                Text("\(event.toolName ?? "AgentReins observation") · \(fileResultLabel(event)) · \(clock(event.startedAt ?? event.ts))")
                                    .font(.system(size: 12)).foregroundStyle(.tertiary).lineLimit(1)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text((event.attributionConfidence?.rawValue ?? "unknown").uppercased())
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundStyle(confidenceColor(event.attributionConfidence))
                                Image(systemName: "chevron.right").font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }.node(selectedEvent?.id == event.id)
                    }.buttonStyle(HoverCardButtonStyle())
                }
            }
        case .memory:
            memoryCommitPanel
        case .code:
            listPanel("GENERATED CODE", "Code findings from the active window") {
                let findings = liveTaskCodeFindings
                if findings.isEmpty { empty("No generated-code findings") }
                ForEach(Array(findings)) { finding in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "checkmark.shield").foregroundStyle(amber)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(finding.title).font(.system(size: 13, weight: .semibold))
                            Text("\(finding.ruleId) · line \(finding.line)")
                                .font(.system(size: 13)).foregroundStyle(.secondary)
                            Text(finding.evidence).font(.system(size: 13, design: .monospaced))
                                .foregroundStyle(.secondary).lineLimit(3)
                        }
                        Spacer()
                    }.node(false)
                }
            }
        case .tools:
            listPanel("TOOL CALLS", "Tools and MCP activity for the live turn") {
                let calls = liveTaskTools
                if calls.isEmpty { empty("No tool calls yet") }
                ForEach(calls) { call in
                    let related = activeSession?.events.last {
                        $0.kind == "tool" && ($0.toolCallId == call.id || $0.toolName == call.name)
                    }
                    Button { selectedEvent = related; selectedProcess = nil; selectedProcessGroup = [] } label: { HStack(spacing: 8) {
                        Image(systemName: "terminal").foregroundStyle(cyan)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(call.friendlyName).font(.system(size: 13, weight: .semibold))
                            Text(String((call.arguments ?? call.name).prefix(120)))
                                .font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                        Text(call.friendlyStatus).font(.system(size: 13, weight: .bold))
                            .foregroundStyle(call.completedAt == nil ? amber : green)
                    }.node(selectedEvent?.id == related?.id && related != nil) }
                    .buttonStyle(HoverCardButtonStyle())
                }
            }
        case .timeline:
            journeyPanel
        }
    }

    private var memoryCommitPanel: some View {
        listPanel("PERSISTENT MEMORY CHANGES", "What this Agent attempted to carry into future sessions") {
            if memoryCommits.isEmpty {
                empty("No persistent memory change was observed in the live turn")
            } else {
                HStack(spacing: 6) {
                    fileCountChip("COMMITS", memoryCommits.count, cyan)
                    fileCountChip("REVIEW", memoryCommits.filter { $0.risk == "high" }.count, amber)
                    fileCountChip("CONFIRMED", memoryCommits.filter { $0.confidence == .confirmed }.count, green)
                }.padding(.bottom, 6)
                ForEach(memoryCommits, id: \.commitId) { commit in
                    Button {
                        selectedMemoryCommitID = commit.commitId
                        selectedEvent = nil
                        selectedProcess = nil
                        selectedProcessGroup = []
                        selectedStageID = nil
                        followingLive = false
                    } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: commit.risk == "high" ? "exclamationmark.shield.fill" : "externaldrive.badge.plus")
                                .foregroundStyle(commit.risk == "high" ? amber : cyan)
                                .frame(width: 28, height: 28)
                                .background((commit.risk == "high" ? amber : cyan).opacity(0.10),
                                            in: RoundedRectangle(cornerRadius: 7))
                            VStack(alignment: .leading, spacing: 3) {
                                Text(commit.summary).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                                Text(memoryChangePreview(commit))
                                    .font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                                Text("\(formattedAgentName(commit.agent)) · Turn \(commit.turnId) · \(clock(commit.observedAt))")
                                    .font(.system(size: 12)).foregroundStyle(.tertiary).lineLimit(1)
                            }
                            Spacer(minLength: 8)
                            VStack(alignment: .trailing, spacing: 3) {
                                Text(commit.risk == "high" ? "REVIEW" : "OBSERVED")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundStyle(commit.risk == "high" ? amber : cyan)
                                Text(commit.confidence.rawValue.uppercased())
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundStyle(confidenceColor(commit.confidence))
                                Image(systemName: "chevron.right").font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }.node(selectedMemoryCommitID == commit.commitId)
                    }.buttonStyle(HoverCardButtonStyle())
                }
            }
        }
    }

    private func memoryChangePreview(_ commit: MemoryCommitEvidence) -> String {
        let additions = (commit.contentDiff ?? "").components(separatedBy: .newlines)
            .filter { $0.hasPrefix("+") && !$0.hasPrefix("+++") }
            .map { String($0.dropFirst()).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if let first = additions.first { return String(first.prefix(180)) }
        if commit.changeKind == .delete { return "Persistent memory was removed." }
        if commit.changeKind == .toolReported { return "The Agent reported a memory write; file contents were not observed." }
        return "Content changed; open evidence to inspect the recorded diff."
    }

    private var missionOverview: some View {
        Group {
            if isWebAISelected {
                webAIMissionOverview
            } else {
                nativeAgentMissionOverview
            }
        }
    }

    private var nativeAgentMissionOverview: some View {
        VStack(spacing: 12) {
            overviewProcessPanel
                .frame(maxWidth: .infinity, minHeight: 390, alignment: .top)
            HStack(alignment: .top, spacing: 10) {
                journeyPanel
                    .frame(minWidth: 440, maxWidth: .infinity, minHeight: 430, alignment: .top)
                networkPanel
                    .frame(minWidth: 280, maxWidth: 360)
                    .frame(minHeight: 430, alignment: .top)
            }
        }
    }

    private var webAIMissionOverview: some View {
        VStack(spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                journeyPanel.frame(maxWidth: .infinity, alignment: .top)
                networkPanel.frame(minWidth: 300, maxWidth: 380, alignment: .top)
            }
            modelRequestDetail
        }
    }

    private var overviewProcessPanel: some View {
        posturePanel("AGENT RUNTIME GRAPH", "Observed runtime depth · solid = real PPID · dashed = explicitly labeled logical relationship") {
            if processes.isEmpty {
                empty("Waiting for the live Agent runtime")
            } else {
                runtimeGraphView(height: 320)
            }
        }
    }

    private func runtimeRelationshipRow(_ edge: RuntimeRelationship) -> some View {
        let source = processes.first { $0.pid == edge.sourcePID }
        let target = processes.first { $0.pid == edge.targetPID }
        let sourceName = source.map { runtimeComponent($0).displayName } ?? "PID \(edge.sourcePID)"
        let targetName = target.map { runtimeComponent($0).displayName } ?? "PID \(edge.targetPID)"
        return Button {
            selectedProcess = target
            selectedProcessGroup = target.map { [$0] } ?? []
            followingLive = false
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "point.3.connected.trianglepath.dotted").foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(sourceName) ↝ \(targetName)").font(.system(size: 13, weight: .semibold))
                    Text("\(edge.kind.rawValue) · \(edge.confidence.rawValue) · no PPID relationship claimed")
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
            }.padding(.vertical, 5)
        }.buttonStyle(HoverCardButtonStyle()).help(edge.evidence)
    }

    // MARK: - Panels

    private var processPanel: some View {
        posturePanel("AGENT RUNTIME GRAPH", "Observed runtime depth with evidence-backed relationships; raw PID and PPID remain in node details") {
            if processes.isEmpty { empty("No live Agent runtime") }
            else { runtimeGraphView(height: 560) }
        }
    }

    private struct RuntimeGraphPresentation {
        let groups: [OverviewProcessGroup]
        let edges: [RuntimeDisplayEdge]
    }

    /// Builds the complete graph presentation from one immutable process snapshot.
    /// SwiftUI may evaluate a view body many times; keeping grouping, classification,
    /// and PID-edge projection in one pass prevents multiplicative recomputation.
    private func makeRuntimeGraphPresentation(processes: [ProcessSnapshotRecord],
                                              selectedAgent: String) -> RuntimeGraphPresentation {
        let snapshot = processes
        let visible = Self.buildTree(snapshot).filter { !isOverviewInfrastructureNoise($0.process) }
        let parentPIDs = Set(visible.map { $0.process.ppid })
        let visiblePIDs = Set(visible.map { $0.process.pid })
        let parentByPID = Dictionary(uniqueKeysWithValues: visible.map { ($0.process.pid, $0.process.ppid) })
        func observedDepth(_ process: ProcessSnapshotRecord, capability: RuntimeCapability) -> Int {
            var depth = 0
            var parent = process.ppid
            var visited = Set<String>()
            while visiblePIDs.contains(parent), visited.insert(parent).inserted {
                depth += 1
                parent = parentByPID[parent] ?? ""
            }
            // Sandbox/storage services launched by the OS are separate roots,
            // but belong on the service side of the semantic graph. Their
            // dashed edges still state that no PPID claim is being made.
            if depth == 0, [.sandbox, .memory, .storage].contains(capability) { return 2 }
            return min(depth, 3)
        }
        var groups: [OverviewProcessGroup] = []
        var indexes: [String: Int] = [:]
        for node in visible {
            let info = AgentRuntimeProfileRegistry.classify(node.process, agentHint: node.agentHint)
            let executable = URL(fileURLWithPath: node.process.command.split(separator: " ").first.map(String.init) ?? node.process.command).lastPathComponent
            // Only collapse repeated sibling leaves. Merging equal roles from
            // different roots destroys WorkBuddy's real multi-runtime topology.
            let componentKey = info.componentId == "unknown" ? "unknown:\(executable)" : info.componentId
            let key = parentPIDs.contains(node.process.pid)
                ? "pid:\(node.process.pid)"
                : "parent:\(node.process.ppid):\(componentKey)"
            if let index = indexes[key] { groups[index].processes.append(node.process) }
            else {
                indexes[key] = groups.count
                groups.append(OverviewProcessGroup(id: key, node: node, processes: [node.process],
                                                   classification: info,
                                                   lane: observedDepth(node.process, capability: info.capability)))
            }
        }
        groups.sort { $0.lane == $1.lane ? $0.id < $1.id : $0.lane < $1.lane }

        let pidGroup = Dictionary(uniqueKeysWithValues: groups.flatMap { group in
            group.processes.map { ($0.pid, group.id) }
        })
        var seen = Set<String>()
        let edges = AgentRuntimeGraph.build(processes: snapshot, agent: selectedAgent).relationships.compactMap { edge -> RuntimeDisplayEdge? in
            guard let source = pidGroup[edge.sourcePID], let target = pidGroup[edge.targetPID], source != target else { return nil }
            let id = "\(edge.kind.rawValue):\(source):\(target)"
            guard seen.insert(id).inserted else { return nil }
            return RuntimeDisplayEdge(id: id, source: source, target: target,
                                      kind: edge.kind, confidence: edge.confidence)
        }
        return RuntimeGraphPresentation(groups: groups, edges: edges)
    }

    private func refreshRuntimeGraph() {
        cachedRuntimeGraph = makeRuntimeGraphPresentation(processes: processes,
            selectedAgent: selectedAgent)
    }

    private struct RuntimeDisplayEdge: Identifiable {
        let id: String
        let source: String
        let target: String
        let kind: RuntimeRelationshipKind
        let confidence: EvidenceConfidence
    }

    private func graphLane(_ capability: RuntimeCapability) -> Int {
        switch capability {
        case .interface, .agentCore: return 0
        case .context, .memory, .storage: return 1
        case .modelConnection, .mcp, .toolRuntime, .sandbox, .sourceControl: return 2
        case .network, .unknown: return 3
        }
    }

    private func graphPositions(_ groups: [OverviewProcessGroup], size: CGSize) -> [String: CGPoint] {
        let columns = 4
        let columnWidth = size.width / CGFloat(columns)
        var indexes = Array(repeating: 0, count: columns)
        var positions: [String: CGPoint] = [:]
        for group in groups {
            let lane = group.lane
            let y = CGFloat(indexes[lane]) * 92 + 50
            positions[group.id] = CGPoint(x: columnWidth * (CGFloat(lane) + 0.5), y: y)
            indexes[lane] += 1
        }
        return positions
    }

    private func runtimeGraphView(height: CGFloat) -> some View {
        let presentation = cachedRuntimeGraph
        let groups = presentation.groups
        let edges = presentation.edges
        let activePIDs = focusedProcessIDs
        let laneCounts = Dictionary(grouping: groups, by: \.lane).values.map(\.count)
        let requiredHeight = max(height, CGFloat(laneCounts.max() ?? 1) * 92 + 18)
        return GeometryReader { geometry in
            let positions = graphPositions(groups, size: geometry.size)
            ZStack {
                Canvas { context, _ in
                    for edge in edges {
                        guard let start = positions[edge.source], let end = positions[edge.target] else { continue }
                        var path = Path()
                        if abs(start.x - end.x) < 2 {
                            let from = CGPoint(x: start.x, y: start.y + 39)
                            let destination = CGPoint(x: end.x, y: end.y - 39)
                            path.move(to: from)
                            path.addCurve(to: destination,
                                control1: CGPoint(x: from.x + 24, y: from.y + 14),
                                control2: CGPoint(x: destination.x + 24, y: destination.y - 14))
                        } else {
                            let from = CGPoint(x: start.x + (end.x > start.x ? 80 : -80), y: start.y)
                            let destination = CGPoint(x: end.x + (end.x > start.x ? -80 : 80), y: end.y)
                            path.move(to: from)
                            let middle = (from.x + destination.x) / 2
                            path.addCurve(to: destination,
                                          control1: CGPoint(x: middle, y: from.y),
                                          control2: CGPoint(x: middle, y: destination.y))
                        }
                        let color = edge.kind == .processParent ? cyan.opacity(0.75) : Color.blue.opacity(0.8)
                        context.stroke(path, with: .color(color),
                                       style: StrokeStyle(lineWidth: edge.kind == .processParent ? 1.5 : 1.2,
                                                          dash: edge.kind == .processParent ? [] : [5, 4]))
                    }
                }
                ForEach(groups) { group in
                    graphNode(group, focusedProcessIDs: activePIDs)
                        .frame(width: 160, height: 78)
                        .position(positions[group.id] ?? .zero)
                }
            }
        }.frame(height: requiredHeight)
    }

    private func graphNode(_ group: OverviewProcessGroup, focusedProcessIDs: Set<String>) -> some View {
        let info = group.classification
        let tint = capabilityColor(info.capability)
        let active = group.processes.contains { focusedProcessIDs.contains($0.pid) }
        let selected = selectedProcessGroup.map(\.pid) == group.processes.map(\.pid)
        return Button {
            selectedProcess = group.node.process
            selectedProcessGroup = group.processes
            selectedEvent = nil
            selectedStageID = nil
            followingLive = false
        } label: {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 5) {
                    Image(systemName: info.icon).foregroundStyle(tint)
                    Text(info.displayName).font(.system(size: 13, weight: .bold)).lineLimit(1)
                    Spacer(minLength: 2)
                    if group.processes.count > 1 { Text("×\(group.processes.count)").mono() }
                }
                Text(info.responsibility).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                HStack {
                    Text(info.capability.rawValue.uppercased()).font(.system(size: 12, weight: .bold)).foregroundStyle(tint)
                    Spacer()
                    Circle().fill(active ? green : confidenceColor(info.confidence)).frame(width: active ? 8 : 6, height: active ? 8 : 6)
                }
            }
            .padding(8).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            .background(active ? tint.opacity(0.20) : raised, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(selected || active ? tint : border, lineWidth: active ? 1.8 : 1))
            .shadow(color: active ? tint.opacity(0.35) : .clear, radius: 7)
        }.buttonStyle(HoverCardButtonStyle())
    }

    private func compactTreeRow(_ group: OverviewProcessGroup) -> some View {
        let node = group.node
        let selected = selectedProcessGroup.map(\.pid) == group.processes.map(\.pid) ||
            (group.processes.count == 1 && selectedProcess?.pid == node.process.pid)
        let info = AgentRuntimeProfileRegistry.classify(node.process, agentHint: node.agentHint)
        let active = group.processes.contains { focusedProcessIDs.contains($0.pid) }
        let tint = capabilityColor(info.capability)
        return Button {
            selectedProcess = node.process
            selectedProcessGroup = group.processes
            selectedEvent = nil
            selectedStageID = nil
            followingLive = false
        } label: {
            HStack(spacing: 0) {
                HStack(spacing: 0) {
                    ForEach(0..<max(node.depth, 0), id: \.self) { level in
                        let continues = level < node.guides.count && node.guides[level]
                        let isElbow = level == node.depth - 1
                        Canvas { context, size in
                            var path = Path()
                            let x: CGFloat = 7
                            if isElbow {
                                path.move(to: CGPoint(x: x, y: 0))
                                path.addLine(to: CGPoint(x: x, y: size.height / 2))
                                path.addLine(to: CGPoint(x: size.width, y: size.height / 2))
                                if continues {
                                    path.move(to: CGPoint(x: x, y: size.height / 2))
                                    path.addLine(to: CGPoint(x: x, y: size.height))
                                }
                            } else if continues {
                                path.move(to: CGPoint(x: x, y: 0))
                                path.addLine(to: CGPoint(x: x, y: size.height))
                            }
                            context.stroke(path, with: .color(Color.gray.opacity(0.65)), lineWidth: 1)
                        }.frame(width: 17, height: 65)
                    }
                }
                HStack(spacing: 8) {
                    Image(systemName: info.icon)
                        .font(.system(size: 13, weight: .semibold)).foregroundStyle(tint)
                        .frame(width: 32, height: 32)
                        .background(tint.opacity(0.13), in: RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 5) {
                            Text(info.displayName + (group.processes.count > 1 ? " ×\(group.processes.count)" : ""))
                                .font(.system(size: 12, weight: .bold)).lineLimit(1)
                            Spacer(minLength: 2)
                            Text(group.processes.count > 1 ? "\(group.processes.count) PIDS" : "PID \(node.process.pid)").mono()
                        }
                        Text(info.responsibility).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                        Text("\(info.capability.rawValue.uppercased()) · \(info.confidence.rawValue.uppercased())")
                            .font(.system(size: 12, weight: .bold)).foregroundStyle(tint)
                    }
                    Circle().fill(active ? green : Color.gray.opacity(0.7)).frame(width: 7, height: 7)
                }
                .padding(.horizontal, 9).padding(.vertical, 7)
                .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
                .background(selected ? tint.opacity(0.16) : raised, in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(selected ? tint : border))
            }
            .padding(.vertical, 3)
        }.buttonStyle(HoverCardButtonStyle())
    }

    private func isOverviewInfrastructureNoise(_ process: ProcessSnapshotRecord) -> Bool {
        let command = process.command.lowercased()
        return ["crashpad", "bare-modifier-monitor", "gpu-process", "audio.mojom.audioservice", "--type=renderer"]
            .contains(where: command.contains)
    }

    private func isOverviewCoreComponent(_ node: TreeNode) -> Bool {
        let info = AgentRuntimeProfileRegistry.classify(node.process, agentHint: node.agentHint)
        if node.depth == 0 { return true }
        if info.componentId == "codex-node-repl",
           let parent = processInventory.first(where: { $0.pid == node.process.ppid }),
           AgentRuntimeProfileRegistry.classify(parent, agentHint: node.agentHint).componentId == "codex-computer-use-runtime" {
            return false
        }
        let coreCapabilities: Set<RuntimeCapability> = [
            .agentCore, .memory, .modelConnection, .mcp, .sandbox, .storage, .network
        ]
        if coreCapabilities.contains(info.capability) { return true }
        return ["codex-code-mode-host", "workbuddy-host"]
            .contains(info.componentId)
    }

    private var overviewProcessGroups: [OverviewProcessGroup] {
        let visible = processTree.filter {
            !isOverviewInfrastructureNoise($0.process) && isOverviewCoreComponent($0)
        }
        let parents = Set(processTree.map { $0.process.ppid })
        var groups: [OverviewProcessGroup] = []
        var indexByKey: [String: Int] = [:]
        for node in visible {
            let info = AgentRuntimeProfileRegistry.classify(node.process, agentHint: node.agentHint)
            let isLeaf = !parents.contains(node.process.pid)
            let key = isLeaf ? "\(node.process.ppid)|\(info.componentId)" : "pid|\(node.process.pid)"
            if let index = indexByKey[key] {
                groups[index].processes.append(node.process)
            } else {
                indexByKey[key] = groups.count
                groups.append(OverviewProcessGroup(id: key, node: node, processes: [node.process],
                                                   classification: info, lane: graphLane(info.capability)))
            }
        }
        return groups
    }

    private func treeRow(_ node: TreeNode) -> some View {
        let selected = selectedProcess?.pid == node.process.pid
        let info = AgentRuntimeProfileRegistry.classify(node.process, agentHint: node.agentHint)
        let active = focusedProcessIDs.contains(node.process.pid)
        let tint = capabilityColor(info.capability)
        return Button {
            selectedProcess = node.process
            selectedProcessGroup = []
            selectedEvent = nil
            selectedStageID = nil
            followingLive = false
        } label: {
            HStack(spacing: 0) {
                HStack(spacing: 0) {
                    ForEach(0..<max(node.depth, 0), id: \.self) { level in
                        let continues = level < node.guides.count && node.guides[level]
                        let isElbow = level == node.depth - 1
                        Canvas { context, size in
                            var path = Path()
                            let x: CGFloat = 8
                            if isElbow {
                                path.move(to: CGPoint(x: x, y: 0))
                                path.addLine(to: CGPoint(x: x, y: size.height * 0.45))
                                path.addLine(to: CGPoint(x: size.width - 1, y: size.height * 0.45))
                                if continues {
                                    path.move(to: CGPoint(x: x, y: size.height * 0.45))
                                    path.addLine(to: CGPoint(x: x, y: size.height))
                                }
                            } else if continues {
                                path.move(to: CGPoint(x: x, y: 0))
                                path.addLine(to: CGPoint(x: x, y: size.height))
                            }
                            context.stroke(path, with: .color(cyan.opacity(0.55)), lineWidth: 1.5)
                        }
                        .frame(width: 24, height: node.depth == 0 ? 86 : 74)
                    }
                }
                HStack(spacing: 9) {
                    Image(systemName: info.icon)
                        .font(.system(size: node.depth == 0 ? 18 : 14, weight: .semibold))
                        .foregroundStyle(tint)
                        .frame(width: node.depth == 0 ? 42 : 36, height: node.depth == 0 ? 42 : 36)
                        .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 7) {
                            Text(info.displayName).font(.system(size: node.depth == 0 ? 15 : 13, weight: .bold)).lineLimit(1)
                            Text(info.capability.rawValue.uppercased())
                                .font(.system(size: 12, weight: .bold))
                                .foregroundStyle(tint)
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(tint.opacity(0.12), in: Capsule())
                        }
                        Text(info.responsibility)
                            .font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(1)
                        HStack(spacing: 5) {
                            Text("PID \(node.process.pid)").mono()
                            Text(info.confidence.rawValue.uppercased())
                                .font(.system(size: 12, weight: .bold))
                                .foregroundStyle(confidenceColor(info.confidence))
                        }
                    }
                    Spacer(minLength: 4)
                    VStack(spacing: 4) {
                        Circle().fill(active ? green : tint).frame(width: active ? 10 : 7, height: active ? 10 : 7)
                            .shadow(color: active ? green.opacity(0.9) : .clear, radius: 5)
                        Text(active ? "ACTIVE" : "LIVE").font(.system(size: 12, weight: .bold))
                            .foregroundStyle(active ? green : .secondary)
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 9)
                .frame(minHeight: node.depth == 0 ? 80 : 68)
                .background(
                    LinearGradient(colors: [selected ? tint.opacity(0.25) : raised,
                                            panel.opacity(0.92)], startPoint: .topLeading, endPoint: .bottomTrailing),
                    in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(selected ? tint : border, lineWidth: selected ? 1.8 : 1))
                .shadow(color: tint.opacity(node.depth == 0 ? 0.18 : 0.08), radius: node.depth == 0 ? 10 : 5, x: 0, y: 3)
            }
            .padding(.vertical, 4)
        }.buttonStyle(HoverCardButtonStyle())
    }

    private var journeyPanel: some View {
        posturePanel("LIVE TASK", "Request → context → model → tools → result") {
            VStack(alignment: .leading, spacing: 0) {
                let stages = taskStages
                let currentStage = stages.last { $0.status == .active }
                HStack(spacing: 7) {
                    Circle().fill(currentStage == nil ? Color.gray : green).frame(width: 7, height: 7)
                    Text(liveTaskStateHeadline(currentStage: currentStage))
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(liveTaskStateColor(currentStage: currentStage))
                    Spacer()
                    if !followingLive {
                        Button("Return to live") {
                            followingLive = true
                            selectedStageID = currentStage?.id
                            selectedEvent = currentStage?.event
                            selectedProcessGroup = []
                        }.buttonStyle(TextActionButtonStyle())
                            .font(.system(size: 12, weight: .semibold)).foregroundStyle(cyan)
                    }
                }.padding(.bottom, 10)
                if stages.isEmpty {
                    empty("Waiting for task evidence")
                } else {
                    ForEach(Array(stages.enumerated()), id: \.offset) { index, stage in
                        timelineRow(stage, isLast: index == stages.count - 1,
                                    currentStageID: currentStage?.id)
                    }
                }
            }
        }
    }

    private func timelineRow(_ stage: TaskStage, isLast: Bool, currentStageID: String?) -> some View {
        let selected = selectedStageID == stage.id ||
            (selectedStageID == nil && selectedEvent?.id == stage.event?.id && stage.event != nil)
        let isCurrent = currentStageID == stage.id
        let stageColor = stage.status == .failed ? Color.red :
            (isCurrent ? green : (stage.status == .completed ? confidenceColor(stage.event?.attributionConfidence) : Color.gray))
        return Button {
            selectedStageID = stage.id
            followingLive = false
            selectedEvent = stage.event
            selectedProcess = nil
            selectedProcessGroup = []
        } label: {
            HStack(alignment: .top, spacing: 10) {
                VStack(spacing: 0) {
                    Circle()
                        .fill(stageColor.opacity(stage.status == .pending ? 0.45 : 1))
                        .frame(width: isCurrent ? 11 : 9, height: isCurrent ? 11 : 9)
                        .shadow(color: isCurrent ? green.opacity(0.9) : .clear, radius: 5)
                        .padding(.top, 5)
                    if !isLast {
                        Rectangle().fill(border).frame(width: 1).frame(maxHeight: .infinity)
                    }
                }
                .frame(width: 10)
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(stage.title).font(.system(size: 13, weight: .semibold))
                        Spacer()
                        Text(stage.status.label.uppercased())
                            .font(.system(size: 12, weight: .bold)).foregroundStyle(stageColor)
                        if let ts = stage.timestamp {
                            Text(clock(ts)).mono()
                        }
                    }
                    Text(stage.detail)
                        .font(.system(size: 13,
                                      design: stage.monospace ? .monospaced : .default))
                        .foregroundStyle(stage.status == .pending ? Color.gray : Color.secondary)
                        .lineLimit(3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(8)
                .background((selected || isCurrent) ? stageColor.opacity(0.14) : raised, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(selected || isCurrent ? stageColor : border))
            }
            .padding(.bottom, isLast ? 0 : 5)
        }.buttonStyle(HoverCardButtonStyle())
    }

    private var networkPanel: some View {
        posturePanel("NETWORK EVIDENCE", "Model routes, Agent web access, remote operations, and infrastructure") {
            VStack(alignment: .leading, spacing: 10) {
                if networkFlows.isEmpty {
                    empty("No Agent-owned network evidence captured")
                } else {
                    HStack(spacing: 8) {
                        networkMetric("MODEL", .model, cyan)
                        networkMetric("WEB", .web, .blue)
                        networkMetric("REMOTE", .remote, amber)
                        networkMetric("UNKNOWN", .unknown, .gray)
                    }
                    ForEach(NetworkTrafficCategory.allCases, id: \.self) { category in
                        let flows = networkFlows.filter { $0.category == category }
                        if !flows.isEmpty {
                            HStack {
                                Text(category.rawValue).micro(networkCategoryColor(category))
                                Spacer()
                                Text("\(flows.count)").mono()
                            }.padding(.top, 5)
                            ForEach(flows) { flow in networkFlowRow(flow) }
                        }
                    }
                }
            }
        }
    }

    private func networkMetric(_ title: String, _ category: NetworkTrafficCategory, _ color: Color) -> some View {
        let count = networkFlows.filter { $0.category == category }.count
        return VStack(alignment: .leading, spacing: 2) {
            Text("\(count)").font(.system(size: 16, weight: .bold)).foregroundStyle(color)
            Text(title).font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 9).padding(.vertical, 7).frame(maxWidth: .infinity, alignment: .leading)
        .background(raised, in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(border))
    }

    private func networkFlowRow(_ flow: NetworkFlowEvidence) -> some View {
        let color = networkCategoryColor(flow.category)
        let geo = flow.ip.flatMap { ipGeolocation.records[$0] }
        return Button {
            selectedEvent = flow.sourceEvent
            selectedProcess = nil
            selectedProcessGroup = []
            selectedStageID = nil
            followingLive = false
        } label: {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 9) {
                    Image(systemName: networkCategoryIcon(flow.category))
                        .foregroundStyle(color).frame(width: 26, height: 26)
                        .background(color.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(flow.destination)\(flow.port.map { ":\($0)" } ?? "")")
                            .font(.system(size: 13, weight: .semibold, design: .monospaced)).lineLimit(1)
                        Text(flow.purpose).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer(minLength: 4)
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(flow.grade.rawValue.uppercased()).font(.system(size: 11, weight: .bold))
                            .foregroundStyle(networkGradeColor(flow.grade))
                        Text("\(formattedAgentName(flow.agent)) · \(flow.connectionCount) observed")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                }
                HStack(spacing: 12) {
                    if let ip = flow.ip { Label(ip, systemImage: "number").lineLimit(1) }
                    if let geo { Label(geo.locationLabel, systemImage: "mappin.and.ellipse").lineLimit(1) }
                    if let owner = geo?.ownerLabel { Label(owner, systemImage: "building.2").lineLimit(1) }
                    if flow.ip != nil && geo == nil {
                        Text(ipGeolocation.pending.contains(flow.ip!) ? "Resolving IP intelligence…" : "IP intelligence unavailable")
                    }
                }.font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 9).padding(.vertical, 8)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(selectedEvent?.id == flow.sourceEvent.id ? color : border))
        }.buttonStyle(HoverCardButtonStyle())
    }

    private func networkCategoryColor(_ category: NetworkTrafficCategory) -> Color {
        switch category {
        case .model: return cyan
        case .web: return .blue
        case .remote: return amber
        case .infrastructure: return .purple
        case .unknown: return .gray
        }
    }

    private func networkCategoryIcon(_ category: NetworkTrafficCategory) -> String {
        switch category {
        case .model: return "sparkles"
        case .web: return "globe"
        case .remote: return "terminal.fill"
        case .infrastructure: return "server.rack"
        case .unknown: return "questionmark.circle"
        }
    }

    private func networkGradeColor(_ grade: NetworkEvidenceGrade) -> Color {
        switch grade {
        case .correlated: return green
        case .observed: return cyan
        case .inferred: return .blue
        case .unknown: return .gray
        }
    }

    private var evidencePanel: some View {
        posturePanel("TASK EVIDENCE", "Measured from the active evidence window") {
            HStack(spacing: 8) {
                metric("Prompt", activeTurn.map { formatBytes($0.contextBytes) } ?? "—", "doc.text")
                metric("Response", activeTurn.map { formatBytes($0.responseCharacters) } ?? "—", "text.bubble")
                metric("Commands", "\(activeTurn?.toolCalls.count ?? 0)", "terminal")
                metric("Files", "\(scopedEvents.filter { $0.kind == "file" }.count)", "doc.badge.gearshape")
                metric("Memory", memoryCommits.isEmpty ? "None" : "\(memoryCommits.count)",
                       "externaldrive.badge.plus", tint: memoryCommits.contains { $0.risk == "high" } ? amber : cyan)
                metric("Code findings", findingCount == 0 ? "None observed" : "\(findingCount)", "checkmark.shield",
                       tint: findingCount == 0 ? green : amber)
            }
        }
    }

    private var flowLegend: some View {
        HStack(spacing: 18) {
            legendMark(border, "Process spawning")
            legendMark(cyan.opacity(0.7), "Data flow")
            legendMark(green.opacity(0.7), "File / result flow")
            legendMark(amber.opacity(0.7), "Attention flow")
            Spacer()
            legend(green, "Confirmed")
            legend(.blue, "Inferred")
            legend(.gray, "Unknown")
        }
        .padding(.horizontal, 4)
    }

    private func legendMark(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            Capsule().fill(color).frame(width: 14, height: 2)
            Text(text).font(.system(size: 13)).foregroundStyle(.secondary)
        }
    }

    // MARK: - Inspector

    private var inspector: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("SECURITY SUMMARY").micro(cyan)
                .padding(14).frame(maxWidth: .infinity, alignment: .leading).background(raised)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    securitySummary
                    Divider().overlay(border)
                    if let commit = selectedMemoryCommit {
                        memoryCommitDetail(commit)
                    } else if selectedStageID == "context" {
                        contextPreparedDetail
                    } else if selectedStageID == "model" {
                        modelRequestDetail
                    } else if selectedProcessGroup.count > 1 {
                        processGroupResponsibility(selectedProcessGroup)
                    } else if let p = selectedProcess {
                        processResponsibility(p)
                    } else if let e = selectedEvent {
                        eventDetail(e)
                    } else {
                        defaultDetail
                    }
                }.padding(14)
            }
        }
        .background(panel)
        .overlay(Rectangle().fill(border).frame(width: 1), alignment: .leading)
    }

    private var securitySummary: some View {
        VStack(alignment: .leading, spacing: 10) {
            summaryRow(verificationEvent == nil ? amber : resultColor,
                       verificationEvent == nil ? "Execution not independently verified" : "Execution verification",
                       verificationEvent == nil ? "Unknown" : resultHeadline)
            summaryRow(scopedIncidents.isEmpty ? cyan : amber,
                       scopedIncidents.isEmpty ? "No alerts observed" : "Relay / items to review",
                       scopedIncidents.isEmpty ? "Observed only" : "\(scopedIncidents.count)")
            summaryRow(findingCount == 0 ? cyan : amber,
                       findingCount == 0 ? "No code findings observed" : "Code findings",
                       findingCount == 0 ? "Not a pass" : "\(findingCount)")
            if !memoryCommits.isEmpty {
                let highRisk = memoryCommits.filter { $0.risk == "high" }.count
                summaryRow(highRisk == 0 ? cyan : amber, "Persistent memory changes",
                           highRisk == 0 ? "\(memoryCommits.count) observed" : "\(highRisk) need review")
            }
            summaryRow(cyan, "Evidence coverage", evidenceCoverage)
            if !scopedIncidents.isEmpty {
                Button { onIncident(scopedIncidents[0]) } label: {
                    Text("Open top finding")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(amber)
                }.buttonStyle(TextActionButtonStyle()).padding(.top, 2)
            }
        }
    }

    private func memoryCommitDetail(_ commit: MemoryCommitEvidence) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("MEMORY COMMIT EVIDENCE").micro(cyan)
            Text("What will survive this task").font(.system(size: 17, weight: .bold))
            HStack(spacing: 7) {
                labelChip(commit.changeKind.rawValue.uppercased(), color: cyan)
                labelChip(commit.confidence.rawValue.uppercased(), color: confidenceColor(commit.confidence))
                labelChip(commit.risk == "high" ? "NEEDS REVIEW" : "OBSERVED",
                          color: commit.risk == "high" ? amber : green)
            }
            field("Agent", formattedAgentName(commit.agent))
            field("Session / turn", "\(commit.sessionId) / \(commit.turnId)")
            field("Observed", commit.observedAt.formatted(date: .abbreviated, time: .standard))
            field("Memory store", commit.storagePath ?? "Path not captured")
            field("Tool call", commit.toolCallId ?? "Not captured")
            field("Writer PID", commit.processId.map(String.init) ?? "Not captured")
            field("Why linked", commit.attributionMethod)

            Divider().overlay(border)
            Text("CONTENT CHANGE").micro(.secondary)
            if let diff = commit.contentDiff, !diff.isEmpty {
                Text(memoryDisplayDiff(diff)).font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.secondary).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(canvas.opacity(0.7), in: RoundedRectangle(cornerRadius: 7))
            } else {
                Text("Content-level before/after evidence was not captured.")
                    .font(.system(size: 13)).foregroundStyle(.secondary)
            }
            field("Before hash", commit.beforeHash ?? "Unavailable")
            field("After hash", commit.afterHash ?? "Unavailable")

            Divider().overlay(border)
            Text("SECURITY ASSESSMENT").micro(.secondary)
            if commit.riskReasons.isEmpty {
                Text("No high-signal memory risk was detected. This is an observation, not a safety guarantee.")
                    .font(.system(size: 13)).foregroundStyle(.secondary)
            } else {
                ForEach(commit.riskReasons, id: \.self) { reason in
                    Label(reason, systemImage: "exclamationmark.triangle.fill")
                        .font(.system(size: 13)).foregroundStyle(amber)
                }
            }
            field("Evidence records", "\(commit.evidenceEventIds.count)")
        }
    }

    private func memoryDisplayDiff(_ diff: String) -> String {
        guard diff.count > 12_000 else { return diff }
        return String(diff.prefix(12_000)) + "\n… display truncated; complete evidence remains in SQLite …"
    }

    private func processResponsibility(_ p: ProcessSnapshotRecord) -> some View {
        let info = runtimeComponent(p)
        let linked = processes.contains { $0.pid == p.ppid }
        let processEvents = scopedEvents.filter { $0.processId == Int32(p.pid) }
        return VStack(alignment: .leading, spacing: 12) {
            Text("PROCESS RESPONSIBILITY").micro(.secondary)
            HStack(spacing: 8) {
                Image(systemName: info.icon).foregroundStyle(cyan)
                    .frame(width: 30, height: 30)
                    .background(cyan.opacity(0.12), in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 2) {
                    Text(info.displayName).font(.system(size: 17, weight: .bold))
                    Text("PID \(p.pid)").mono()
                }
            }
            Text(info.responsibility)
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            labelChip("\(info.capability.rawValue) · \(info.confidence.rawValue.capitalized)",
                      color: confidenceColor(info.confidence))
            if !info.securitySurface.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("SECURITY SURFACE").micro(.secondary)
                    ForEach(info.securitySurface, id: \.self) { item in
                        Label(item, systemImage: "shield.lefthalf.filled")
                            .font(.system(size: 13)).foregroundStyle(.secondary)
                    }
                }
            }
            if let latest = processEvents.first {
                VStack(alignment: .leading, spacing: 4) {
                    Text("LATEST OBSERVED ACTIVITY").micro(.secondary)
                    Text(eventTitle(latest)).font(.system(size: 12, weight: .semibold))
                    Text("\(latest.kind) / \(latest.op) · \(clock(latest.ts))")
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("TECHNICAL EVIDENCE").micro(.secondary)
                field("PPID", p.ppid)
                field("Executable", executable(p.command))
                field("Command", p.command)
                field("Relationship", linked ? "Observed PID/PPID child relationship" : "Agent root or external parent")
                field("Runtime Profile", "\(info.profileId) v\(info.profileVersion)")
                field("Capability", info.capability.rawValue)
                field("Responsibility confidence", info.confidence.rawValue.capitalized)
                field("Profile evidence", info.matchedEvidence.joined(separator: "; "))
                field("Attribution", "Observed inside \(activeSession?.agentDisplayName ?? selectedAgent) process tree")
            }
            .padding(11)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
        }
    }

    private func processGroupResponsibility(_ group: [ProcessSnapshotRecord]) -> some View {
        let representative = group[0]
        let info = runtimeComponent(representative)
        let pids = group.map(\.pid).sorted { (Int($0) ?? 0) < (Int($1) ?? 0) }
        return VStack(alignment: .leading, spacing: 12) {
            Text("PROCESS GROUP RESPONSIBILITY").micro(.secondary)
            HStack(spacing: 8) {
                Image(systemName: info.icon).foregroundStyle(cyan)
                    .frame(width: 30, height: 30)
                    .background(cyan.opacity(0.12), in: RoundedRectangle(cornerRadius: 7))
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(info.displayName) ×\(group.count)").font(.system(size: 17, weight: .bold))
                    Text("\(group.count) observed leaf processes").mono()
                }
            }
            Text(info.responsibility)
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            labelChip("\(info.capability.rawValue) · \(info.confidence.rawValue.capitalized)",
                      color: confidenceColor(info.confidence))
            VStack(alignment: .leading, spacing: 8) {
                Text("TECHNICAL EVIDENCE").micro(.secondary)
                field("PIDs", pids.joined(separator: ", "))
                field("Parent PID", representative.ppid)
                field("Runtime Profile", "\(info.profileId) v\(info.profileVersion)")
                field("Aggregation", "Same parent, component, responsibility, and leaf status")
                field("Attribution", "Observed inside \(activeSession?.agentDisplayName ?? selectedAgent) process tree")
            }
            .padding(11)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
        }
    }

    private var defaultDetail: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("SELECT A NODE").micro(.secondary)
            Text("Click a process, task stage, or external service to inspect its responsibility and complete evidence.")
                .font(.system(size: 13)).foregroundStyle(.secondary)
            Text("Collector coverage").font(.system(size: 14, weight: .semibold)).padding(.top, 8)
            ForEach(health, id: \.source) { h in
                HStack {
                    Circle().fill(h.state == .healthy ? green : amber).frame(width: 6, height: 6)
                    Text(h.source).font(.system(size: 12))
                    Spacer()
                    Text(h.state.rawValue).mono()
                }
            }
        }
    }

    private func eventDetail(_ e: GuardEvent) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let ssh = sshSessions.first(where: { $0.sourceEvent.id == e.id }) {
                sshSessionDetail(ssh)
                Divider().overlay(border)
            }
            if let flow = networkFlows.first(where: { $0.sourceEvent.id == e.id }) {
                networkFlowDetail(flow)
                Divider().overlay(border)
            }
            Text("NODE DETAILS").micro(.secondary)
            Text(eventTitle(e)).font(.system(size: 15, weight: .semibold))
            field("Observed", e.ts.formatted(date: .abbreviated, time: .standard))
            if let started = e.startedAt { field("Started", started.formatted(date: .abbreviated, time: .standard)) }
            if let ended = e.endedAt { field("Ended", ended.formatted(date: .abbreviated, time: .standard)) }
            if let duration = e.durationMS { field("Duration", formatDuration(duration)) }
            field("Result status", e.action.capitalized)
            field("Agent / operation", "\(e.agent ?? "Unknown") · \(e.kind)/\(e.op)")
            field("Evidence confidence", e.attributionConfidence?.rawValue ?? "unknown")
            field("Why linked", e.attributionMethod ?? "No attribution method")
            if let v = e.userIntent { field("User request", v) }
            if let v = e.modelPrompt { field("Model context", v) }
            if let v = e.modelResponse { field("Result / response", v) }
            if let v = e.command { field("Arguments / command", v) }
            if e.path != "-" { field("File", e.path) }
            if let related = e.relatedPath { field("Destination file", related) }
            if let host = e.remoteDomain ?? e.remoteHost {
                let assessment = NetworkDestinationAssessment.assess(domain: host, host: host)
                field("Destination class", assessment.kind.rawValue)
                field("Review reason", assessment.reason)
            }
        }
    }

    private func networkFlowDetail(_ flow: NetworkFlowEvidence) -> some View {
        let geo = flow.ip.flatMap { ipGeolocation.records[$0] }
        return VStack(alignment: .leading, spacing: 9) {
            Text("NETWORK ATTRIBUTION").micro(networkCategoryColor(flow.category))
            Text("\(flow.destination)\(flow.port.map { ":\($0)" } ?? "")")
                .font(.system(size: 16, weight: .bold, design: .monospaced))
            HStack(spacing: 7) {
                labelChip(flow.category.rawValue, color: networkCategoryColor(flow.category))
                labelChip(flow.grade.rawValue.uppercased(), color: networkGradeColor(flow.grade))
            }
            field("Agent", formattedAgentName(flow.agent))
            field("Purpose", flow.purpose)
            field("Attribution evidence", flow.reason)
            field("Observed connections", "\(flow.connectionCount)")
            if let domain = flow.domain { field("Domain", domain) }
            if let ip = flow.ip { field("IP address", ip) }
            field("Estimated location", geo?.locationLabel ?? "Not resolved")
            field("ASN / network owner", geo?.ownerLabel ?? "Not resolved")
            field("First observed", flow.firstObservedAt.formatted(date: .abbreviated, time: .standard))
            field("Last observed", flow.lastObservedAt.formatted(date: .abbreviated, time: .standard))
            Text("Location and network ownership are third-party IP intelligence estimates. Network evidence proves the connection; encrypted payload contents require separate local Agent/tool evidence.")
                .font(.system(size: 11)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func sshSessionDetail(_ session: SSHSessionEvidence) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("SSH SESSION SECURITY").micro(cyan)
            Text("\(session.username.map { "\($0)@" } ?? "")\(session.host):\(session.port)")
                .font(.system(size: 16, weight: .bold, design: .monospaced))
            labelChip(session.risk.uppercased(), color: session.risk == "review required" ? amber : cyan)
            field("Agent", formattedAgentName(session.agent))
            field("Authentication", session.authentication)
            field("Credential", session.credentialEntered ? "Detected · hidden by default" : "Not observed")
            field("Host key policy", session.hostKeyPolicy)
            field("PID-owned socket", session.socketObserved ? "Observed" : "Not captured")
            field("Remote commands", "\(session.remoteCommandCount) observed through Agent tool input")
            field("Transfers", session.transfers.isEmpty ? "No SCP/rsync transfer reconstructed" : "\(session.transfers.count) reconstructed")
            ForEach(Array(session.transfers.enumerated()), id: \.offset) { _, transfer in
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(transfer.tool.uppercased()) · \(transfer.direction.uppercased())").micro(.secondary)
                    field("Local files", transfer.localPaths.isEmpty ? "Not resolved" : transfer.localPaths.joined(separator: ", "))
                    field("Remote path", transfer.remotePath ?? "Not resolved")
                }.padding(8).background(raised, in: RoundedRectangle(cornerRadius: 6))
            }
            ForEach(session.findings, id: \.self) { finding in
                HStack(alignment: .top, spacing: 6) {
                    Circle().fill(amber).frame(width: 5, height: 5).padding(.top, 4)
                    Text(finding).font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            Text("SSH payloads are encrypted. Commands, credentials, and transfers shown here come from local Agent/tool evidence; the socket proves the connection, not its plaintext contents.")
                .font(.system(size: 12)).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var activeTurnEvidenceEvents: [GuardEvent] {
        guard let session = activeSession else { return [] }
        let turnID = activeTurn?.id
        return session.events.filter { event in
            if turnID == "unattributed" { return event.turnId == nil }
            return event.turnId == turnID || (event.turnId == nil && event.kind == "context")
        }
    }

    private var modelRequestDetail: some View {
        let rows = activeTurnEvidenceEvents
        let economics = ModelEconomicsReport.build(events: rows)
        let exposure = ContextExposureReport.build(events: rows)
        let traffic = AgentTrafficAnalyzer.build(events: rows)
        let relay = RelaySecurityAssessment.build(events: rows)
        let knownRoute = traffic.first { $0.classification == .modelRelay || $0.classification == .modelProvider }
        let routeStatus = knownRoute.map { $0.classification.rawValue } ?? "Unknown"
        let routeColor = knownRoute?.classification == .modelProvider ? green : amber
        return VStack(alignment: .leading, spacing: 12) {
            Text("MODEL REQUEST FORENSICS").micro(cyan)
            Text("What was sent, where it went, and what was reported")
                .font(.system(size: 17, weight: .bold))
            HStack(spacing: 7) {
                contextMetric("REPORTED MODEL", activeTurn?.modelNames ?? "Not captured")
                contextMetric("ROUTE", routeStatus)
            }
            HStack(spacing: 7) {
                contextMetric("REQUESTS", economics.map { $0.requestCount.formatted() } ?? "Not reported")
                contextMetric("COST", economics.flatMap { $0.totalCostUSD > 0 ? String(format: "$%.6f", $0.totalCostUSD) : nil }
                    ?? "Not reported")
            }

            HStack(spacing: 7) {
                Circle().fill(routeColor).frame(width: 7, height: 7)
                Text(knownRoute == nil ? "The actual model endpoint was not identified" :
                    "Destination classified as \(routeStatus.lowercased())")
                    .font(.system(size: 12, weight: .semibold))
            }
            Text(knownRoute == nil
                 ? "Socket candidates were observed, but no hostname or configured endpoint evidence proves which connection carried this model request."
                 : "Classification is based on recorded destination evidence; a relay can still misreport its upstream model.")
                .font(.system(size: 13)).foregroundStyle(.secondary)

            if let relay {
                Divider().overlay(border)
                Text("RELAY SECURITY VERDICT").micro(.secondary)
                field("Risk", relay.risk.uppercased())
                field("Configured gateway", relay.configuredGateways.isEmpty
                      ? "Not captured" : relay.configuredGateways.joined(separator: ", "))
                field("Claimed upstream", relay.claimedModels.isEmpty
                      ? "Not reported" : relay.claimedModels.joined(separator: ", "))
                field("Independent identity", relay.upstreamIdentity)
                field("Route consistency", relay.routeConsistency)
                field("Inspection coverage", relay.contentCoverage)
                ForEach(relay.findings, id: \.self) { finding in
                    HStack(alignment: .top, spacing: 6) {
                        Circle().fill(amber).frame(width: 5, height: 5).padding(.top, 4)
                        Text(finding).font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
                ForEach(Array(relay.sensitiveFindings.enumerated()), id: \.offset) { _, finding in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(finding.category.rawValue.uppercased()) · \(finding.severity.uppercased())")
                            .font(.system(size: 12, weight: .bold)).foregroundStyle(Color.red)
                        Text(finding.source).font(.system(size: 12)).foregroundStyle(.secondary)
                        Text(finding.evidence).mono().lineLimit(3)
                    }.padding(7).background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                }
            }

            if let economics {
                Divider().overlay(border)
                Text("TOKEN AND COST EVIDENCE").micro(.secondary)
                field("Input", "\(economics.cumulativeInputTokens.formatted()) tokens")
                field("Cached", "\(economics.cumulativeCachedTokens.formatted()) tokens")
                field("Output", "\(economics.cumulativeOutputTokens.formatted()) tokens")
                field("Reasoning", "\(economics.cumulativeReasoningTokens.formatted()) tokens")
                field("Repeated input load", "\(economics.subsequentRequestInputLoad.formatted()) tokens")
                Text("Token and cost values are provider-reported. A zero or absent cost is displayed as not reported, not free.")
                    .font(.system(size: 12)).foregroundStyle(.tertiary)
            }

            if let exposure {
                Divider().overlay(border)
                Text("DATA EXPOSED TO THE MODEL ROUTE").micro(.secondary)
                field("Captured prompt", formatBytes(exposure.capturedPromptBytes))
                ForEach(exposure.items.filter(\.present), id: \.category.rawValue) { item in
                    HStack(alignment: .top, spacing: 7) {
                        Circle().fill(amber).frame(width: 5, height: 5).padding(.top, 4)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.category.rawValue).font(.system(size: 13, weight: .semibold))
                            if !item.evidence.isEmpty {
                                Text(item.evidence.joined(separator: " · ")).mono()
                            }
                        }
                    }
                }
            }

            Divider().overlay(border)
            Text("OBSERVED NETWORK CANDIDATES").micro(.secondary)
            if traffic.isEmpty {
                Text("No turn-linked destination evidence was captured.")
                    .font(.system(size: 13)).foregroundStyle(.secondary)
            } else {
                ForEach(traffic, id: \.destination) { destination in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(destination.destination).font(.system(size: 13, weight: .semibold, design: .monospaced))
                            Spacer()
                            Text(destination.classification.rawValue.uppercased())
                                .font(.system(size: 12, weight: .bold)).foregroundStyle(
                                    destination.classification == .modelProvider ? green : amber)
                        }
                        Text("\(destination.confidence.rawValue.capitalized) · PID " +
                             (destination.processIds.isEmpty ? "not captured" : destination.processIds.map(String.init).joined(separator: ", ")))
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        if let models = destination.claimedModels, !models.isEmpty {
                            Text("Claimed model · \(models.joined(separator: ", "))")
                                .font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary)
                        }
                        if let relayType = destination.relayType {
                            Text(relayType.uppercased())
                                .font(.system(size: 12, weight: .bold))
                                .foregroundStyle(amber)
                        }
                        if destination.classification == .networkCandidate {
                            Text("Observed in the same turn; not proven to carry the model request.")
                                .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                        }
                        if let status = destination.identityStatus, status != "not_applicable" {
                            Text("MODEL IDENTITY · \(status.replacingOccurrences(of: "_", with: " ").uppercased())")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundStyle(status == "consistent" ? green : amber)
                        }
                        if let reason = destination.identityReason, destination.identityStatus != "not_applicable" {
                            Text(reason).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(3)
                        }
                    }
                    .padding(8).background(raised, in: RoundedRectangle(cornerRadius: 7))
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(border))
                }
            }
        }
    }

    private struct ContextInspectorItem: Identifiable {
        let id: String
        let title: String
        let source: String
        let status: String
        let detail: String
        let confirmed: Bool
    }

    private var contextEvidenceEvents: [GuardEvent] {
        activeTurnEvidenceEvents
    }

    private var contextPreparedDetail: some View {
        let rows = contextInspectorItems
        let captured = rows.filter { $0.status != "Not observed" }.count
        let report = ContextExposureReport.build(events: contextEvidenceEvents)
        return VStack(alignment: .leading, spacing: 12) {
            Text("CONTEXT PREPARED").micro(cyan)
            Text("What the Agent assembled before asking the model")
                .font(.system(size: 17, weight: .bold))
            Text("This view shows recorded input evidence. It does not claim access to hidden model reasoning.")
                .font(.system(size: 12)).foregroundStyle(.secondary)

            HStack(spacing: 7) {
                contextMetric("MODEL", activeTurn?.modelNames ?? activeSession?.model ?? "Not captured")
                contextMetric("INPUT", activeTurn?.inputTokens.map { "\($0.formatted()) tokens" }
                    ?? formatBytes(report?.capturedPromptBytes ?? activeTurn?.contextBytes ?? 0))
            }
            HStack(spacing: 7) {
                contextMetric("LAYERS", "\(captured) / \(rows.count) observed")
                contextMetric("EVIDENCE", report == nil ? "Partial" : "Recorded")
            }

            Divider().overlay(border)
            Text("CONTEXT COMPOSITION").micro(.secondary)
            ForEach(rows) { row in
                contextInspectorRow(row)
            }

            if let growth = activeTurn?.contextGrowth {
                Divider().overlay(border)
                Text("CONTEXT GROWTH").micro(.secondary)
                field("Latest request", "\(growth.latestInputTokens.formatted()) input tokens")
                field("Growth this turn", "\(growth.growthTokens.formatted()) tokens")
                field("Repeated input load", "\(growth.cumulativeInputTokens.formatted()) cumulative tokens")
            }
        }
    }

    private func contextMetric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).micro(.secondary)
            Text(value).font(.system(size: 13, weight: .semibold)).lineLimit(2)
        }
        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
        .background(raised, in: RoundedRectangle(cornerRadius: 7))
        .overlay(RoundedRectangle(cornerRadius: 7).stroke(border))
    }

    private func contextInspectorRow(_ row: ContextInspectorItem) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Circle().fill(row.status == "Not observed" ? Color.gray : (row.confirmed ? green : amber))
                    .frame(width: 6, height: 6)
                Text(row.title).font(.system(size: 13, weight: .semibold))
                Spacer()
                Text(row.status).font(.system(size: 12, weight: .bold))
                    .foregroundStyle(row.status == "Not observed" ? .secondary : (row.confirmed ? green : amber))
            }
            if row.status != "Not observed" {
                Text(row.detail).font(.system(size: 13, design: .monospaced))
                    .foregroundStyle(.secondary).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Source · \(row.source)").font(.system(size: 12)).foregroundStyle(.tertiary)
            }
        }
        .padding(9)
        .background(raised.opacity(row.status == "Not observed" ? 0.45 : 1), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(border.opacity(row.status == "Not observed" ? 0.55 : 1)))
    }

    private var contextInspectorItems: [ContextInspectorItem] {
        let rows = contextEvidenceEvents
        let prompts = rows.compactMap(\.modelPrompt)
        let joined = prompts.joined(separator: "\n")
        let lower = joined.lowercased()
        let user = activeTurn?.userInput ?? rows.compactMap(\.userIntent).last
        let base = rows.first { $0.op == "base_instructions" }?.modelPrompt
        let developer = rows.filter { $0.op == "developer_instructions" }.compactMap(\.modelPrompt).joined(separator: "\n")
        let turnContext = rows.last { $0.op == "turn_context" }?.command
        let attachments = rows.filter { $0.op == "attachment" }.compactMap(\.command).joined(separator: "\n")
        let compacted = rows.last { $0.op == "context_compaction" }?.command
        let toolResults = rows.filter { $0.kind == "tool" && $0.op == "result" }.compactMap(\.modelResponse).joined(separator: "\n")

        func direct(_ id: String, _ title: String, _ value: String?, source: String) -> ContextInspectorItem {
            let clean = value?.trimmingCharacters(in: .whitespacesAndNewlines)
            return ContextInspectorItem(id: id, title: title, source: source,
                status: clean?.isEmpty == false ? "Captured" : "Not observed",
                detail: contextPreview(clean ?? ""), confirmed: true)
        }
        func detected(_ id: String, _ title: String, needles: [String], source: String) -> ContextInspectorItem {
            guard let needle = needles.first(where: { lower.contains($0.lowercased()) }) else {
                return ContextInspectorItem(id: id, title: title, source: source,
                    status: "Not observed", detail: "", confirmed: false)
            }
            return ContextInspectorItem(id: id, title: title, source: source,
                status: "Detected", detail: contextExcerpt(joined, around: needle), confirmed: false)
        }
        return [
            direct("user", "User request", user, source: "turn prompt"),
            direct("base", "Base / system instructions", base, source: "session metadata"),
            direct("developer", "Developer instructions", developer.isEmpty ? nil : developer,
                   source: "developer message"),
            detected("project", "Project and workspace context",
                     needles: ["<project_context", "<project_layout", "workspace folder"], source: "model prompt"),
            detected("memory", "Memory and identity", needles: ["USER.md", "IDENTITY.md", "SOUL.md", "memory"],
                     source: "model prompt"),
            detected("skills", "Skills and Agent policy", needles: ["SKILL.md", "skills", "agent policy"],
                     source: "model prompt"),
            detected("mcp", "MCP and connectors", needles: ["connector-status", "serverNames", "MCP"],
                     source: "model prompt"),
            direct("permissions", "Runtime permissions", turnContext, source: "turn context"),
            direct("attachments", "Images and attachments", attachments.isEmpty ? nil : attachments,
                   source: "attachment events"),
            direct("history", "Tool results in context", toolResults.isEmpty ? nil : toolResults,
                   source: "tool result events"),
            direct("compaction", "Compacted conversation history", compacted,
                   source: "context compaction event")
        ]
    }

    private func contextPreview(_ value: String, limit: Int = 280) -> String {
        let compact = value.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return compact.count > limit ? String(compact.prefix(limit)) + "…" : compact
    }

    private func contextExcerpt(_ text: String, around needle: String) -> String {
        guard let range = text.range(of: needle, options: .caseInsensitive) else { return contextPreview(text) }
        let start = text.index(range.lowerBound, offsetBy: -90, limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(range.upperBound, offsetBy: 190, limitedBy: text.endIndex) ?? text.endIndex
        let prefix = start == text.startIndex ? "" : "…"
        let suffix = end == text.endIndex ? "" : "…"
        return prefix + contextPreview(String(text[start..<end]), limit: 300) + suffix
    }

    private func fileOperationIcon(_ operation: String) -> String {
        switch operation {
        case "create": return "doc.badge.plus"
        case "read": return "doc.text.magnifyingglass"
        case "delete": return "trash"
        case "rename": return "arrow.right.doc.on.clipboard"
        default: return "doc.badge.gearshape"
        }
    }

    private func fileOperationColor(_ event: GuardEvent) -> Color {
        if event.action == "failed" { return .red }
        return event.op == "delete" ? amber : cyan
    }

    private func fileCountChip(_ label: String, _ count: Int, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Text("\(count)").font(.system(size: 12, weight: .bold))
            Text(label).font(.system(size: 12, weight: .bold))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 7).padding(.vertical, 5)
        .background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
    }

    private func fileActivitySentence(_ event: GuardEvent) -> String {
        let agent = event.agent?.capitalized ?? "Agent"
        let file = URL(fileURLWithPath: event.path).lastPathComponent
        let verb: String
        switch event.op {
        case "create": verb = "created"
        case "read": verb = "read"
        case "delete": verb = "deleted"
        case "rename": verb = "renamed"
        default: verb = "updated"
        }
        return "\(agent) \(verb) \(file)"
    }

    private func fileChangeDescription(_ event: GuardEvent) -> String {
        if event.op == "read" { return "Read the file contents for task context." }
        if event.op == "delete" { return "Removed the file from the workspace." }
        if event.op == "rename", let destination = event.relatedPath {
            return "Renamed it to \(URL(fileURLWithPath: destination).lastPathComponent)."
        }
        let patch = event.fileDiff ?? event.command ?? ""
        let lines = patch.components(separatedBy: .newlines)
        let additions = lines.filter { $0.hasPrefix("+") && !$0.hasPrefix("+++") }
        let removals = lines.filter { $0.hasPrefix("-") && !$0.hasPrefix("---") }
        if !additions.isEmpty || !removals.isEmpty {
            var counts: [String] = []
            if !additions.isEmpty { counts.append("added \(additions.count) line\(additions.count == 1 ? "" : "s")") }
            if !removals.isEmpty { counts.append("removed \(removals.count) line\(removals.count == 1 ? "" : "s")") }
            let sample = additions.first.map { String($0.dropFirst()).trimmingCharacters(in: .whitespaces) }
            let readable = sample.flatMap { $0.isEmpty ? nil : String($0.prefix(90)) }
            return counts.joined(separator: ", ").capitalized + (readable.map { " · \($0)" } ?? ".")
        }
        return event.op == "create" ? "Created a new file for this task." : "Changed the file through the Agent tool path."
    }

    private func fileResultLabel(_ event: GuardEvent) -> String {
        switch event.action {
        case "completed": return "Completed"
        case "failed": return "Failed"
        case "running": return "In progress"
        case "unverified": return "Result unverified"
        case "requested": return "Requested"
        default: return event.action.capitalized
        }
    }

    private func formatDuration(_ milliseconds: Double) -> String {
        milliseconds < 1_000 ? "\(Int(milliseconds)) ms" : String(format: "%.1f s", milliseconds / 1_000)
    }

    // MARK: - Task stages

    private enum TaskStageStatus {
        case pending, active, completed, failed
        var label: String {
            switch self {
            case .pending: return "Pending"
            case .active: return "Active"
            case .completed: return "Observed"
            case .failed: return "Failed"
            }
        }
    }

    private struct TaskStage: Identifiable {
        let id: String
        let title: String
        let detail: String
        let timestamp: Date?
        let event: GuardEvent?
        let status: TaskStageStatus
        let monospace: Bool
    }

    private func liveTaskStateHeadline(currentStage: TaskStage?) -> String {
        if let currentStage { return "CURRENT · \(currentStage.title.uppercased())" }
        if verificationEvent != nil { return "INDEPENDENTLY VERIFIED" }
        if activeTurn?.finalResponse != nil { return "AGENT REPORTED COMPLETE · AWAITING VERIFICATION" }
        if activeTurn != nil { return "WAITING FOR THE NEXT OBSERVED ACTION" }
        return "WAITING FOR LIVE EVIDENCE"
    }

    private func liveTaskStateColor(currentStage: TaskStage?) -> Color {
        if currentStage != nil || verificationEvent != nil { return green }
        if activeTurn?.finalResponse != nil { return amber }
        return .secondary
    }

    private var taskStages: [TaskStage] {
        var stages: [TaskStage] = []
        let promptEvent = activeSession?.events.last { $0.kind == "model" && $0.op == "prompt" }
        let responseEvent = activeSession?.events.last { $0.kind == "model" && $0.op == "response" }
        let contextEvent = activeSession?.events.last { $0.kind == "context" }
        let verificationEvent = activeSession?.events.last { $0.kind == "verification" }
        let tools = activeTurn?.toolCalls ?? []
        let mcpCalls = tools.filter { toolKind($0) == "mcp" }
        let shellCalls = tools.filter { toolKind($0) == "shell" }
        let writeCalls = tools.filter { toolKind($0) == "write" }
        let buildCalls = tools.filter { toolKind($0) == "build" }
        let testCalls = tools.filter { toolKind($0) == "test" }

        stages.append(TaskStage(
            id: "request",
            title: "User request",
            detail: activeTurn?.userInput ?? "Waiting for a user request",
            timestamp: promptEvent?.ts ?? activeTurn?.startedAt,
            event: promptEvent,
            status: activeTurn?.userInput == nil ? .pending : .completed,
            monospace: false))

        stages.append(TaskStage(
            id: "context",
            title: "Context prepared",
            detail: contextDetail ?? "Waiting for context evidence",
            timestamp: contextEvent?.ts ?? promptEvent?.ts,
            event: contextEvent ?? promptEvent,
            status: contextDetail != nil ? .completed : (activeTurn?.userInput != nil ? .active : .pending),
            monospace: false))

        stages.append(TaskStage(
            id: "model",
            title: responseEvent == nil && promptEvent != nil ? "Requesting model" : "Model response",
            detail: activeTurn?.finalResponse.map { String($0.prefix(160)) } ??
                (activeSession?.model.map { "Waiting for \($0)" } ?? "Waiting for model output"),
            timestamp: responseEvent?.ts,
            event: responseEvent,
            status: responseEvent != nil ? .completed : (promptEvent != nil ? .active : .pending),
            monospace: false))

        stages.append(toolStage(id: "mcp", title: "MCP / Skill", calls: mcpCalls,
                                pending: "No MCP or Skill call observed"))
        stages.append(toolStage(id: "shell", title: "Shell execution", calls: shellCalls,
                                pending: "No shell command observed"))
        stages.append(toolStage(id: "write", title: "Writing code", calls: writeCalls,
                                pending: "No file write observed"))
        stages.append(toolStage(id: "build", title: "Build", calls: buildCalls,
                                pending: "No build process observed"))
        stages.append(toolStage(id: "test", title: "Testing", calls: testCalls,
                                pending: "No test process observed"))

        stages.append(TaskStage(
            id: "reported",
            title: "Agent reported completion",
            detail: activeTurn?.finalResponse.map { String($0.prefix(160)) } ?? "Agent has not reported completion",
            timestamp: responseEvent?.ts,
            event: responseEvent,
            status: activeTurn?.finalResponse == nil ? .pending : .completed,
            monospace: false))

        stages.append(TaskStage(
            id: "verified",
            title: "Independent verification",
            detail: verificationDetail ?? "Not independently verified",
            timestamp: verificationEvent?.ts,
            event: verificationEvent,
            status: verificationEvent == nil ? .pending :
                (verificationEvent?.action.lowercased().contains("fail") == true ? .failed : .completed),
            monospace: false))
        return stages
    }

    private func toolStage(id: String, title: String, calls: [AgentToolCall], pending: String) -> TaskStage {
        guard let call = calls.last else {
            return TaskStage(id: id, title: title, detail: pending, timestamp: nil,
                             event: nil, status: .pending, monospace: false)
        }
        let event = activeSession?.events.last {
            $0.kind == "tool" && ($0.toolCallId == call.id || $0.toolName == call.name)
        }
        let failed = call.status.lowercased().contains("fail") || call.status.lowercased().contains("error")
        return TaskStage(id: id, title: title,
                         detail: String((call.arguments ?? call.name).prefix(160)),
                         timestamp: call.startedAt, event: event,
                         status: failed ? .failed : (call.completedAt == nil ? .active : .completed),
                         monospace: true)
    }

    private func toolKind(_ call: AgentToolCall) -> String {
        let value = "\(call.name) \(call.arguments ?? "")".lowercased()
        if value.contains("mcp") || value.contains("skill") { return "mcp" }
        if ["swift test", "npm test", "pytest", "cargo test", "go test", "xcodebuild test", " test "]
            .contains(where: value.contains) { return "test" }
        if ["swift build", "npm run build", "cargo build", "xcodebuild", " gcc ", " clang ", "compile"]
            .contains(where: value.contains) { return "build" }
        if ["apply_patch", "write", "edit", "create_file", "delete_file", "rename"]
            .contains(where: value.contains) { return "write" }
        if ["exec", "shell", "bash", "/bin/zsh", "/bin/sh", "terminal"]
            .contains(where: value.contains) { return "shell" }
        return "mcp"
    }

    // MARK: - Helpers

    private func listPanel<C: View>(_ title: String, _ subtitle: String, @ViewBuilder content: () -> C) -> some View {
        EvidencePanelView(title, subtitle: subtitle, stacked: true, content: content)
    }

    private func posturePanel<C: View>(_ title: String, _ subtitle: String, @ViewBuilder content: () -> C) -> some View {
        EvidencePanelView(title, subtitle: subtitle, content: content)
    }

    private var contextDetail: String? {
        activeTurn.map { $0.inputTokens.map { "\($0) input tokens" } ?? "\($0.contextBytes) bytes captured" }
    }
    private func missionEvent(kind: String, op: String? = nil) -> GuardEvent? {
        activeSession?.events.last { event in event.kind == kind && (op == nil || event.op == op) }
    }
    private var modelDestination: GuardEvent? {
        activeSession?.events.last { event in
            guard event.kind == "network", let host = event.remoteDomain ?? event.remoteHost else { return false }
            let kind = NetworkDestinationAssessment.assess(domain: host, host: host).kind
            return kind == .modelProvider || kind == .modelRelay
        }
    }
    private var latestToolEvent: GuardEvent? { missionEvent(kind: "tool") }
    private var latestFileEvent: GuardEvent? { missionEvent(kind: "file") }
    private var verificationEvent: GuardEvent? { missionEvent(kind: "verification") }
    private var resultHeadline: String {
        if let event = verificationEvent { return event.action.capitalized }
        if activeTurn?.finalResponse != nil { return "Agent reported complete" }
        return "Waiting"
    }
    private var resultDetail: String {
        if let event = verificationEvent { return event.op.replacingOccurrences(of: "_", with: " ") }
        if let file = latestFileEvent, file.path != "-" { return URL(fileURLWithPath: file.path).lastPathComponent }
        return activeTurn?.finalResponse.map { String($0.prefix(86)) } ?? "No independent result yet"
    }
    private var resultColor: Color {
        guard let event = verificationEvent else { return activeTurn?.finalResponse == nil ? .gray : amber }
        return event.action.lowercased().contains("fail") ? .red :
            event.action.lowercased().contains("partial") ? amber : green
    }
    private var verificationDetail: String? {
        activeSession?.events.last(where: { $0.kind == "verification" }).map {
            "\($0.action.capitalized) · \($0.op.replacingOccurrences(of: "_", with: " "))"
        }
    }

    private func metric(_ title: String, _ value: String, _ icon: String, tint: Color? = nil) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon).foregroundStyle(tint ?? cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text(value).font(.system(size: 15, weight: .bold)).foregroundStyle(tint ?? .primary)
                Text(title).font(.system(size: 12)).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(raised, in: RoundedRectangle(cornerRadius: 8))
    }

    private func summaryRow(_ color: Color, _ title: String, _ value: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: color == amber ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(color).font(.system(size: 13))
            Text(title).font(.system(size: 13))
            Spacer()
            Text(value).font(.system(size: 12, weight: .semibold)).foregroundStyle(color)
        }
    }

    private func field(_ name: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(name.uppercased()).micro(.secondary)
            Text(value)
                .font(.system(size: 13, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func labelChip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
    }

    private func legend(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(.system(size: 13)).foregroundStyle(.secondary)
        }
    }

    private func empty(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity)
            .padding(24)
            .background(raised.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    private func confidenceColor(_ v: EvidenceConfidence?) -> Color {
        v == .confirmed ? green : (v == .inferred ? .blue : .gray)
    }

    private func capabilityColor(_ capability: RuntimeCapability) -> Color {
        switch capability {
        case .agentCore: return cyan
        case .context, .modelConnection: return .purple
        case .memory, .storage: return .indigo
        case .toolRuntime, .mcp: return amber
        case .sandbox: return .orange
        case .network: return .blue
        case .sourceControl: return green
        case .interface: return .teal
        case .unknown: return .gray
        }
    }

    private func eventTitle(_ e: GuardEvent) -> String {
        e.toolName ?? e.remoteDomain ?? e.remoteHost ?? (e.path == "-" ? e.ruleId : URL(fileURLWithPath: e.path).lastPathComponent)
    }

    private func executable(_ command: String) -> String {
        command.split(separator: " ").first.map(String.init) ?? command
    }

    private func clock(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .standard)
    }

    private func formatBytes(_ value: Int) -> String {
        if value >= 1024 { return String(format: "%.1f KB", Double(value) / 1024) }
        return "\(value) B"
    }

    private func serviceTitle(_ host: String) -> String {
        let base = host.split(separator: ".").prefix(1).first.map(String.init) ?? host
        return base.prefix(1).uppercased() + base.dropFirst()
    }

    private func networkPurpose(_ event: GuardEvent?, assessment: NetworkDestinationAssessment) -> String {
        guard let event else { return assessment.kind.rawValue }
        if event.kind == "model" { return "Configured model route · \(event.model ?? "model not reported")" }
        if let tool = event.toolName { return "Tool access · \(tool)" }
        if event.command?.lowercased().contains("ssh ") == true { return "Remote deployment · SSH" }
        if event.command?.lowercased().contains("git ") == true { return "Source control · Git" }
        if assessment.kind == .unknown { return "Observed with Agent; request purpose is not proven" }
        return assessment.kind.rawValue
    }

    private func networkActor(_ event: GuardEvent) -> String {
        let agent = event.agent?.capitalized ?? "Unknown agent"
        if let pid = event.processId { return "\(agent) · PID \(pid)" }
        return agent
    }

    private func serviceIcon(_ kind: NetworkDestinationKind) -> String {
        switch kind {
        case .modelRelay: return "arrow.triangle.branch"
        case .modelProvider: return "sparkles"
        case .developerService: return "chevron.left.forwardslash.chevron.right"
        case .externalContent: return "globe"
        case .telemetry: return "waveform.path.ecg"
        case .localInfrastructure: return "internaldrive"
        case .unknown: return "network"
        }
    }

    private func runtimeComponent(_ process: ProcessSnapshotRecord) -> RuntimeComponentClassification {
        AgentRuntimeProfileRegistry.classify(process, agentHint: runtimeAgent(for: process))
    }

    private func runtimeAgent(for process: ProcessSnapshotRecord) -> String? {
        let byPID = Dictionary(uniqueKeysWithValues: processInventory.map { ($0.pid, $0) })
        var current: ProcessSnapshotRecord? = process
        var visited = Set<String>()
        while let node = current, visited.insert(node.pid).inserted {
            if let profile = AgentRuntimeProfileRegistry.profile(agentHint: nil, command: node.command) {
                return profile.agent
            }
            current = byPID[node.ppid]
        }
        return selectedAgent == "All agents" ? activeSession?.agent : selectedAgent
    }

    private var statusBar: some View {
        HStack(spacing: 18) {
            Label("RAW EVIDENCE \(events.count)", systemImage: "waveform.path.ecg").foregroundStyle(cyan)
            Text("Processes \(processInventory.count)")
            Text("Sessions \(sessions.count)")
            Text("Tools \(events.filter { $0.kind == "tool" }.count)")
            Text("Hosts \(currentProjection?.hostCount ?? 0)")
            Spacer()
            Text("Evidence stored locally · external analysis is optional").foregroundStyle(.secondary)
        }
        .font(.system(size: 13, weight: .medium))
        .padding(.horizontal, 15)
        .frame(height: 38)
        .background(raised)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .top)
        .fixedSize(horizontal: false, vertical: true)
        .layoutPriority(10)
    }

    // MARK: - Tree model

    private struct TreeNode: Identifiable {
        let id: String
        let process: ProcessSnapshotRecord
        let depth: Int
        let guides: [Bool]
        let agentHint: String?
    }

    private struct OverviewProcessGroup: Identifiable {
        let id: String
        let node: TreeNode
        var processes: [ProcessSnapshotRecord]
        let classification: RuntimeComponentClassification
        let lane: Int
    }

    private static func buildTree(_ processes: [ProcessSnapshotRecord]) -> [TreeNode] {
        guard !processes.isEmpty else { return [] }
        let byParent = Dictionary(grouping: processes, by: \.ppid)
        let ids = Set(processes.map(\.pid))
        let roots = processes.filter { !ids.contains($0.ppid) }.sorted {
            let left = rootDisplayPriority($0)
            let right = rootDisplayPriority($1)
            return left == right ? (Int($0.pid) ?? 0) < (Int($1.pid) ?? 0) : left < right
        }
        var result: [TreeNode] = []
        func walk(_ process: ProcessSnapshotRecord, depth: Int, ancestorOpen: [Bool], inheritedAgent: String?) {
            let agent = process.agent ?? inheritedAgent ??
                AgentRuntimeProfileRegistry.profile(agentHint: nil, command: process.command)?.agent
            result.append(TreeNode(id: "\(process.pid)-\(depth)", process: process, depth: depth,
                                   guides: ancestorOpen, agentHint: agent))
            let children = (byParent[process.pid] ?? []).sorted {
                let left = AgentRuntimeProfileRegistry.classify($0, agentHint: agent)
                let right = AgentRuntimeProfileRegistry.classify($1, agentHint: agent)
                let leftPriority = runtimeDisplayPriority(left.capability)
                let rightPriority = runtimeDisplayPriority(right.capability)
                return leftPriority == rightPriority
                    ? (Int($0.pid) ?? 0) < (Int($1.pid) ?? 0)
                    : leftPriority < rightPriority
            }
            for (index, child) in children.enumerated() {
                let hasMoreSiblings = index < children.count - 1
                walk(child, depth: depth + 1, ancestorOpen: ancestorOpen + [hasMoreSiblings], inheritedAgent: agent)
            }
        }
        let seed = roots.isEmpty
            ? Array(processes.sorted { (Int($0.pid) ?? 0) < (Int($1.pid) ?? 0) }.prefix(1))
            : roots
        for root in seed { walk(root, depth: 0, ancestorOpen: [], inheritedAgent: nil) }
        return result
    }

    private static func runtimeDisplayPriority(_ capability: RuntimeCapability) -> Int {
        switch capability {
        case .agentCore: return 0
        case .context: return 1
        case .memory: return 2
        case .modelConnection: return 3
        case .mcp: return 4
        case .sandbox: return 5
        case .network: return 6
        case .toolRuntime: return 7
        case .sourceControl: return 8
        case .storage: return 9
        case .interface: return 10
        case .unknown: return 11
        }
    }

    private static func rootDisplayPriority(_ process: ProcessSnapshotRecord) -> Int {
        let info = AgentRuntimeProfileRegistry.classify(process, agentHint: process.agent)
        if info.displayName.contains("Desktop Host") || info.capability == .agentCore { return 0 }
        if info.capability == .sandbox { return 1 }
        if process.command.lowercased().contains("crashpad") { return 9 }
        return 4
    }
}

private struct FleetRowButtonStyle: ButtonStyle {
    let selected: Bool

    func makeBody(configuration: Configuration) -> some View {
        FleetRowButtonBody(label: configuration.label, selected: selected,
                           pressed: configuration.isPressed)
    }
}

private struct FleetRowButtonBody<Label: View>: View {
    let label: Label
    let selected: Bool
    let pressed: Bool
    @State private var hovering = false

    var body: some View {
        label
            .frame(maxWidth: .infinity, minHeight: 28, alignment: .leading)
            .contentShape(.interaction, Rectangle())
            .background(selected ? Color.cyan.opacity(0.10) :
                (hovering ? Color.white.opacity(0.055) : Color.clear))
            .overlay(Rectangle().fill(Color.cyan).frame(width: 2)
                .opacity(selected ? 1 : 0), alignment: .leading)
            .opacity(pressed ? 0.78 : 1)
            .accessibilityAddTraits(selected ? .isSelected : [])
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

private struct TabButtonStyle: ButtonStyle {
    let selected: Bool

    func makeBody(configuration: Configuration) -> some View {
        TabButtonBody(label: configuration.label, selected: selected,
                      pressed: configuration.isPressed)
    }
}

private struct TabButtonBody<Label: View>: View {
    let label: Label
    let selected: Bool
    let pressed: Bool
    @State private var hovering = false

    var body: some View {
        label
            .frame(minHeight: 28)
            .contentShape(.interaction, Capsule())
            .background(selected ? Color.cyan.opacity(0.12) :
                (hovering ? Color.white.opacity(0.065) : Color.clear), in: Capsule())
            .overlay(Capsule().stroke(hovering && !selected ? Color.cyan.opacity(0.35) : Color.clear))
            .opacity(pressed ? 0.76 : 1)
            .accessibilityAddTraits(selected ? .isSelected : [])
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

private struct HoverCardButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        HoverCardButtonBody(label: configuration.label, pressed: configuration.isPressed)
    }
}

private struct HoverCardButtonBody<Label: View>: View {
    let label: Label
    let pressed: Bool
    @State private var hovering = false

    var body: some View {
        label
            .frame(maxWidth: .infinity, minHeight: 28)
            .contentShape(.interaction, RoundedRectangle(cornerRadius: 8))
            .background(hovering ? Color.white.opacity(0.045) : Color.clear,
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8)
                .stroke(hovering ? Color.cyan.opacity(0.42) : Color.clear))
            .opacity(pressed ? 0.76 : 1)
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

private struct PillActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        PillActionButtonBody(label: configuration.label, pressed: configuration.isPressed)
    }
}

private struct PillActionButtonBody<Label: View>: View {
    let label: Label
    let pressed: Bool
    @State private var hovering = false

    var body: some View {
        label
            .frame(minHeight: 28)
            .contentShape(.interaction, Capsule())
            .overlay(Capsule().stroke(hovering ? Color.cyan.opacity(0.55) : Color.clear))
            .brightness(hovering ? 0.08 : 0)
            .opacity(pressed ? 0.74 : 1)
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

private struct TextActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        TextActionButtonBody(label: configuration.label, pressed: configuration.isPressed)
    }
}

private struct TextActionButtonBody<Label: View>: View {
    let label: Label
    let pressed: Bool
    @State private var hovering = false

    var body: some View {
        label
            .padding(.horizontal, 7).padding(.vertical, 5)
            .frame(minHeight: 28)
            .contentShape(.interaction, RoundedRectangle(cornerRadius: 6))
            .background(hovering ? Color.cyan.opacity(0.10) : Color.clear,
                        in: RoundedRectangle(cornerRadius: 6))
            .opacity(pressed ? 0.72 : 1)
            .onHover { hovering = $0 }
            .animation(.easeOut(duration: 0.12), value: hovering)
            .animation(.easeOut(duration: 0.08), value: pressed)
    }
}

private extension View {
    func node(_ selected: Bool) -> some View {
        padding(10)
            .background(selected ? Color.cyan.opacity(0.12) : Color(red: 13/255, green: 36/255, blue: 59/255),
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8)
                .stroke(selected ? Color.cyan : Color(red: 27/255, green: 66/255, blue: 96/255)))
    }
}

private extension Text {
    func micro(_ color: Color) -> some View {
        font(.system(size: 12, weight: .bold)).tracking(0.8).foregroundStyle(color)
    }
    func mono() -> some View {
        font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary)
    }
    func badge(_ color: Color) -> some View {
        font(.system(size: 12, weight: .bold))
            .foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
    }
}
