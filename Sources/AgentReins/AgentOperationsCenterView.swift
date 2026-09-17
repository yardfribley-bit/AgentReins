import SwiftUI

/// Live agent posture first; complete evidence appears only after node selection.
struct AgentOperationsCenterView: View {
    @EnvironmentObject private var webAgentSight: WebAgentSight
    @EnvironmentObject private var semanticAnalyzer: SemanticAnalyzer
    @EnvironmentObject private var language: AppLanguageStore
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
    @StateObject private var ipGeolocation = IPGeolocationStore()
    @StateObject private var projectIndex = ProjectIndexStore()
    @State private var cachedRuntimeGraph = RuntimeGraphPresentation(groups: [], edges: [])
    @State private var agentProjection: AgentDashboardProjection?
    @State private var projectionError: String?
    @State private var globalTab: GlobalTab = .projects
    @State private var selectedProjectPath: String?
    @State private var projectView: ProjectView = .capabilities

    private enum GlobalTab: String, CaseIterable, Identifiable {
        case projects = "Projects"
        case agents = "Agents"
        case security = "Security"
        var id: String { rawValue }
    }

    private enum ProjectView: String, CaseIterable, Identifiable {
        case capabilities = "Capabilities"
        case architecture = "Architecture"
        case evolution = "Evolution"
        case memory = "Understanding"
        var id: String { rawValue }
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
    private var activeTurn: AgentTurn? { activeSession?.turns.last }
    private var scopedEvents: [GuardEvent] { currentProjection?.events ?? [] }
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
        let sessions: [AgentSessionSnapshot]
        var lastActivity: Date { sessions.map(\.lastActivityAt).max() ?? .distantPast }
    }
    private var projectMissions: [ProjectMission] {
        let grouped = Dictionary(grouping: sessions) { session -> String in
            guard let workspace = session.workspace, workspace != "-", !workspace.isEmpty else { return "Unassigned" }
            let url = URL(fileURLWithPath: workspace)
            return url.pathExtension.isEmpty ? url.standardized.path : url.deletingLastPathComponent().standardized.path
        }
        return grouped.map { path, rows in
            let name = path == "Unassigned" ? "Unassigned activity" : URL(fileURLWithPath: path).lastPathComponent
            return ProjectMission(id: path, name: name.isEmpty ? path : name, path: path,
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
                     title: L("Project mission control"),
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
            HStack(alignment: .top, spacing: 16) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(L("LIVE MISSION CONTROL")).micro(cyan)
                    Text(globalHeadline).font(.system(size: 24, weight: .bold))
                    Text(L("Track every project, task and safety decision across your AI agents."))
                        .font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                globalMetric(L("PROJECTS"), projectMissions.count, cyan)
                globalMetric(L("ACTIVE TASKS"), activeTaskCount, .blue)
                globalMetric(L("REVIEW"), scopedIncidents.filter { $0.severity != "info" }.count, amber)
                globalMetric(L("EVIDENCE"), evidenceCoverage, green)
            }
            .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(border))

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

    private func globalMetric(_ label: String, _ value: Int, _ color: Color) -> some View {
        globalMetric(label, String(value), color)
    }

    private func globalMetric(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).micro(.secondary)
            Text(value).font(.system(size: 20, weight: .bold, design: .rounded)).foregroundStyle(color)
        }
        .padding(.horizontal, 13).padding(.vertical, 9)
        .background(raised, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(border.opacity(0.8)))
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
        let projectIncidents = incidents.filter { incident in
            project.sessions.contains { session in
                incident.events.contains { $0.sessionId == session.id }
            }
        }
        let changedFiles = evolution?.changedFileCount ?? 0
        let isSelected = selectedProjectPath == project.id
        let latestGoal = project.sessions.max { $0.lastActivityAt < $1.lastActivityAt }?.latestIntent
        return VStack(alignment: .leading, spacing: 13) {
            Button {
                selectedProjectPath = isSelected ? nil : project.id
                if !isSelected { projectIndex.request(path: project.path) }
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "square.3.layers.3d.top.filled").font(.system(size: 21)).foregroundStyle(cyan)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(project.name).font(.system(size: 18, weight: .bold))
                        Text(project.path).font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary).lineLimit(1)
                        Text(String((index?.purpose ?? "Open the project to index tracked files").prefix(150)))
                            .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer()
                    labelChip("\(project.sessions.count) AGENT\(project.sessions.count == 1 ? "" : "S")", color: cyan)
                    labelChip("\(changedFiles) CHANGED", color: changedFiles > 0 ? .blue : .gray)
                    labelChip(L(projectIncidents.isEmpty ? "MONITORING" : "REVIEW REQUIRED"),
                              color: projectIncidents.isEmpty ? green : amber)
                    Image(systemName: isSelected ? "chevron.up" : "chevron.down")
                        .foregroundStyle(.secondary).padding(.top, 4)
                }
            }.buttonStyle(.plain)
            if isSelected {
                HStack {
                    projectIndexControl(project.path, snapshot: index)
                    if let error = projectIndex.error(for: project.path) {
                        Text(error).font(.system(size: 10)).foregroundStyle(.red).lineLimit(2)
                    } else {
                        Text(language.language == .english
                             ? "Only Git-tracked files are indexed on request"
                             : "仅在请求时索引 Git 已跟踪文件")
                            .font(.system(size: 10)).foregroundStyle(.tertiary)
                    }
                    Spacer()
                }
                Divider().overlay(border)
                let intelligence = ProjectIntelligence.build(projectPath: project.path,
                    sessions: project.sessions, evolution: evolution, index: index)
                projectCockpit(project, evolution: evolution, intelligence: intelligence,
                               projectIncidents: projectIncidents)
            } else {
                HStack(spacing: 8) {
                    Text(latestGoal ?? "No active goal captured")
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

    private func projectCockpit(_ project: ProjectMission, evolution: ProjectEvolutionSnapshot?,
                                intelligence: ProjectIntelligenceSnapshot,
                                projectIncidents: [SecurityIncident]) -> some View {
        let liveSessions = project.sessions.filter(sessionIsLive)
        return VStack(alignment: .leading, spacing: 12) {
            projectBrief(project, evolution: evolution, intelligence: intelligence,
                         projectIncidents: projectIncidents)

            HStack(spacing: 4) {
                ForEach(ProjectView.allCases) { tab in
                    Button { projectView = tab } label: {
                        Text(L(tab.rawValue).uppercased()).font(.system(size: 11, weight: .bold))
                            .foregroundStyle(projectView == tab ? cyan : .secondary)
                            .padding(.horizontal, 12).padding(.vertical, 7)
                    }.buttonStyle(TabButtonStyle(selected: projectView == tab))
                }
                Spacer()
                evidenceTag(intelligence.purpose.confidence)
            }.overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)

            switch projectView {
            case .capabilities:
                projectCapabilityMap(intelligence)
            case .architecture:
                projectArchitectureMap(intelligence)
            case .evolution:
                projectEvolutionView(evolution)
            case .memory:
                projectUnderstandingView(intelligence)
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

    private func projectBrief(_ project: ProjectMission, evolution: ProjectEvolutionSnapshot?,
                              intelligence: ProjectIntelligenceSnapshot,
                              projectIncidents: [SecurityIncident]) -> some View {
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
            projectBriefMetric(L("Memory").uppercased(), "\(intelligence.memoryReads)R · \(intelligence.memoryWrites)W", cyan)
            projectBriefMetric(L("DRIFT"), "\(intelligence.drift.filter { $0.severity != .aligned }.count)",
                               intelligence.drift.contains { $0.severity == .conflict } ? .red : amber)
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
                ForEach(evolution.changeSets.prefix(6)) { change in
                    HStack(alignment: .top, spacing: 10) {
                        Circle().fill(verificationColor(change.verification)).frame(width: 8, height: 8).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(change.requirement).font(.system(size: 13, weight: .semibold)).lineLimit(2)
                            Text("\(change.summary) · \(change.verification.rawValue)")
                                .font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        Spacer(); Text(relativeAge(change.lastActivityAt)).font(.system(size: 11)).foregroundStyle(.tertiary)
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

    private var globalSecurityView: some View {
        LazyVStack(spacing: 9) {
            if scopedIncidents.isEmpty { empty("No security story requires attention in the live window") }
            ForEach(scopedIncidents.filter { $0.severity != "info" }) { incident in
                Button { onIncident(incident) } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundStyle(incidentColor(incident.severity)).font(.system(size: 18))
                        VStack(alignment: .leading, spacing: 4) {
                            Text(incident.title).font(.system(size: 14, weight: .bold))
                            Text(incident.summary).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                            Text("\(formattedAgentName(incident.agent ?? "Unknown Agent")) · \(clock(incident.ts)) · \(incident.events.count) evidence records")
                                .font(.system(size: 11)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        labelChip(incident.severity.uppercased(), color: incidentColor(incident.severity))
                        Image(systemName: "chevron.right").foregroundStyle(.secondary)
                    }.padding(13).background(panel, in: RoundedRectangle(cornerRadius: 10))
                        .overlay(RoundedRectangle(cornerRadius: 10).stroke(incidentColor(incident.severity).opacity(0.55)))
                }.buttonStyle(HoverCardButtonStyle())
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
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 10) {
                    Circle().fill(activeSession == nil ? Color.gray : green).frame(width: 9, height: 9)
                    Text(activeSession?.agentDisplayName ?? "Waiting for agent activity")
                        .font(.system(size: 20, weight: .bold))
                    if activeSession != nil {
                        Text("Running").font(.system(size: 13, weight: .bold)).foregroundStyle(green)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(green.opacity(0.12), in: Capsule())
                    }
                    if let pid = rootPID {
                        Text("PID \(pid)").font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    if let model = activeSession?.model {
                        Text(model).badge(.blue)
                    }
                }
                Text(liveHeadline)
                    .font(.system(size: 14)).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            if let session = activeSession {
                Button("Open session…") { onSession(session) }
                    .buttonStyle(.bordered)
            }
        }
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
                let files = scopedEvents.filter { $0.kind == "file" }
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
                let findings = scopedEvents.compactMap(\.codeFindings).flatMap { $0 }
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
                let calls = activeTurn?.toolCalls ?? []
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
        posturePanel(title, subtitle) {
            VStack(spacing: 8) { content() }
        }
    }

    private func posturePanel<C: View>(_ title: String, _ subtitle: String, @ViewBuilder content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).micro(cyan)
                Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            content()
        }
        .padding(13)
        .background(panel, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(border))
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
