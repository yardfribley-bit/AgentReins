import SwiftUI

/// Live agent posture first; complete evidence appears only after node selection.
struct AgentOperationsCenterView: View {
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
    @State private var followingLive = true

    private enum CenterTab: String, CaseIterable, Identifiable {
        case overview = "Overview"
        case processes = "Processes"
        case network = "Network"
        case files = "Files"
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

    private var scopedSessions: [AgentSessionSnapshot] {
        sessions.filter { selectedAgent == "All agents" || $0.agent.caseInsensitiveCompare(selectedAgent) == .orderedSame }
    }
    private var activeSession: AgentSessionSnapshot? { scopedSessions.max { $0.lastActivityAt < $1.lastActivityAt } }
    private var activeTurn: AgentTurn? { activeSession?.turns.last }
    private var scopedEvents: [GuardEvent] {
        let base = events.filter { selectedAgent == "All agents" || $0.agent?.caseInsensitiveCompare(selectedAgent) == .orderedSame }
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return base }
        return base.filter {
            [$0.agent, $0.toolName, $0.remoteDomain, $0.remoteHost, $0.command, $0.path, $0.userIntent, $0.modelResponse]
                .compactMap { $0?.lowercased() }
                .contains { $0.contains(q) }
        }
    }
    private var processes: [ProcessSnapshotRecord] {
        let agents = selectedAgent == "All agents"
            ? discoveredAgents.filter { $0.presence == .running }.map(\.product)
            : [selectedAgent]
        let list = processInventory.filter { process in
            guard let owner = process.agent else { return false }
            return agents.contains { owner.caseInsensitiveCompare($0) == .orderedSame }
        }
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return list }
        return list.filter { $0.command.lowercased().contains(q) || $0.pid.contains(q) }
    }
    private var processTree: [TreeNode] { Self.buildTree(processes) }
    private var activeProcessTree: [TreeNode] {
        guard let agent = activeSession?.agent else { return processTree }
        return Self.buildTree(processInventory.filter {
            $0.agent?.caseInsensitiveCompare(agent) == .orderedSame
        })
    }
    private var externalServices: [(host: String, event: GuardEvent?)] {
        let hosts = Array(Set(scopedEvents.compactMap { $0.remoteDomain ?? $0.remoteHost })).sorted()
        let visibleHosts = centerTab == .network ? hosts : Array(hosts.prefix(6))
        return visibleHosts.map { host in
            (host, scopedEvents.first { ($0.remoteDomain ?? $0.remoteHost) == host })
        }
    }
    private var findingCount: Int { scopedEvents.compactMap(\.codeFindings).flatMap { $0 }.count }
    private var focusedTaskEvent: GuardEvent? {
        followingLive ? currentTaskStage?.event : selectedEvent
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
    private var evidenceCoverage: String {
        let confirmed = scopedEvents.filter { $0.attributionConfidence == .confirmed }.count
        guard !scopedEvents.isEmpty else { return "—" }
        return "\(Int(Double(confirmed) / Double(scopedEvents.count) * 100))%"
    }
    private var rootPID: String? {
        activeProcessTree.first?.process.pid ?? activeSession?.events.compactMap(\.processId).first.map(String.init)
    }
    private var liveHeadline: String {
        readableActivity(activeTurn)
    }

    private func selectInitialAgentIfNeeded() {
        guard !didUserSelectAgent else { return }
        let running = Set(discoveredAgents.filter { $0.presence == .running }.map { $0.product.lowercased() })
        guard !running.isEmpty else { return }
        if didSelectInitialAgent && running.contains(selectedAgent.lowercased()) { return }
        if let latest = sessions.filter({ running.contains($0.agent.lowercased()) })
            .max(by: { $0.lastActivityAt < $1.lastActivityAt }) {
            selectedAgent = latest.agent.capitalized
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
        VStack(spacing: 0) {
            header
            HStack(spacing: 0) {
                fleet.frame(width: 248)
                Rectangle().fill(border).frame(width: 1)
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        taskHeader
                        tabBar
                        centerContent
                        evidencePanel
                        flowLegend
                    }.padding(16)
                }
                inspector.frame(width: 318)
            }
            statusBar
        }
        .background(canvas).environment(\.colorScheme, .dark)
        .onAppear { selectInitialAgentIfNeeded() }
        .onChange(of: sessions.count) { _ in selectInitialAgentIfNeeded() }
        .onChange(of: discoveredAgents.count) { _ in selectInitialAgentIfNeeded() }
        .onChange(of: discoveredAgents.map { "\($0.product):\($0.presence.rawValue)" }.joined(separator: "|")) { _ in
            selectInitialAgentIfNeeded()
        }
    }

    // MARK: - Chrome

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled").font(.system(size: 26)).foregroundStyle(cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("AgentReins").font(.system(size: 20, weight: .bold))
                Text("See what your AI agents are doing — and whether it is safe.")
                    .font(.system(size: 11)).foregroundStyle(cyan.opacity(0.9)).lineLimit(1)
            }
            Spacer(minLength: 18)
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search agents, processes, or domains", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
            }
            .padding(.horizontal, 12).frame(width: 280, height: 34)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))
            Label(observing ? "MONITORING LIVE" : "PAUSED", systemImage: "circle.fill")
                .font(.system(size: 9, weight: .bold)).foregroundStyle(observing ? green : amber)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background((observing ? green : amber).opacity(0.12), in: Capsule())
        }
        .padding(.horizontal, 18).frame(height: 64).background(panel)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)
    }

    private var fleet: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("AI AGENT FLEET").micro(cyan)
                Spacer()
                Text("\(discoveredAgents.count)").badge(cyan)
            }.padding(16)
            fleetRow(name: "All agents",
                     title: "Unified live posture",
                     detail: observing ? "Monitoring connected adapters" : "Paused",
                     live: observing)
            ForEach(discoveredAgents) { item in
                let session = sessions.filter { $0.agent.caseInsensitiveCompare(item.product) == .orderedSame }
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
                Text("NODE STATUS").micro(.secondary)
                legend(green, "Confirmed"); legend(.blue, "Inferred"); legend(.gray, "Unknown")
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
            followingLive = true
            centerTab = .overview
        } label: {
            HStack(spacing: 11) {
                Circle().fill(live ? green : Color.gray.opacity(0.55)).frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text(name).font(.system(size: 13, weight: .semibold))
                        Text(live ? "Running" : "Idle")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(live ? green : .secondary)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background((live ? green : Color.gray).opacity(0.12), in: Capsule())
                    }
                    Text(title).font(.system(size: 10)).foregroundStyle(.secondary).lineLimit(1)
                    Text(detail).font(.system(size: 9)).foregroundStyle(.tertiary).lineLimit(1)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .background(selected ? cyan.opacity(0.10) : .clear)
            .overlay(Rectangle().fill(cyan).frame(width: 2).opacity(selected ? 1 : 0), alignment: .leading)
        }.buttonStyle(.plain)
    }

    private var taskHeader: some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 10) {
                    Circle().fill(activeSession == nil ? Color.gray : green).frame(width: 9, height: 9)
                    Text(activeSession?.agent.capitalized ?? "Waiting for agent activity")
                        .font(.system(size: 20, weight: .bold))
                    if activeSession != nil {
                        Text("Running").font(.system(size: 9, weight: .bold)).foregroundStyle(green)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(green.opacity(0.12), in: Capsule())
                    }
                    if let pid = rootPID {
                        Text("PID \(pid)").font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                    }
                    if let model = activeSession?.model {
                        Text(model).badge(.blue)
                    }
                }
                Text(liveHeadline)
                    .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            if let session = activeSession {
                Button("Open session") { onSession(session) }
                    .buttonStyle(.bordered)
            }
        }
    }

    private var tabBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(CenterTab.allCases) { tab in
                    Button { centerTab = tab } label: {
                        Text(tab.rawValue)
                            .font(.system(size: 11, weight: centerTab == tab ? .bold : .medium))
                            .foregroundStyle(centerTab == tab ? cyan : .secondary)
                            .padding(.horizontal, 12).padding(.vertical, 8)
                            .background(centerTab == tab ? cyan.opacity(0.12) : .clear, in: Capsule())
                    }.buttonStyle(.plain)
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
            listPanel("FILES", "Observed file activity") {
                let files = scopedEvents.filter { $0.kind == "file" }
                if files.isEmpty { empty("No file events in this window") }
                ForEach(Array(files)) { event in
                    Button { selectedEvent = event; selectedProcess = nil; selectedProcessGroup = [] } label: {
                        HStack {
                            Image(systemName: "doc").foregroundStyle(cyan)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(URL(fileURLWithPath: event.path).lastPathComponent)
                                    .font(.system(size: 11, weight: .semibold))
                                Text(event.path).font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Spacer()
                            Text(clock(event.ts)).mono()
                        }.node(selectedEvent?.id == event.id)
                    }.buttonStyle(.plain)
                }
            }
        case .code:
            listPanel("GENERATED CODE", "Code findings from the active window") {
                let findings = scopedEvents.compactMap(\.codeFindings).flatMap { $0 }
                if findings.isEmpty { empty("No generated-code findings") }
                ForEach(Array(findings)) { finding in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "checkmark.shield").foregroundStyle(amber)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(finding.title).font(.system(size: 11, weight: .semibold))
                            Text("\(finding.ruleId) · line \(finding.line)")
                                .font(.system(size: 9)).foregroundStyle(.secondary)
                            Text(finding.evidence).font(.system(size: 9, design: .monospaced))
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
                            Text(call.friendlyName).font(.system(size: 11, weight: .semibold))
                            Text(String((call.arguments ?? call.name).prefix(120)))
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                        }
                        Spacer()
                        Text(call.friendlyStatus).font(.system(size: 9, weight: .bold))
                            .foregroundStyle(call.completedAt == nil ? amber : green)
                    }.node(selectedEvent?.id == related?.id && related != nil) }.buttonStyle(.plain)
                }
            }
        case .timeline:
            journeyPanel
        }
    }

    private var missionOverview: some View {
        VStack(spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                overviewProcessPanel
                    .frame(minWidth: 330, maxWidth: .infinity, minHeight: 520, alignment: .top)
                journeyPanel
                    .frame(minWidth: 300, maxWidth: .infinity, minHeight: 520, alignment: .top)
                networkPanel
                    .frame(width: 230)
                    .frame(minHeight: 520, alignment: .top)
            }
        }
    }

    private var overviewProcessPanel: some View {
        posturePanel("AGENT INTERNALS", "Real process lineage and component responsibilities") {
            VStack(alignment: .leading, spacing: 0) {
                if processTree.isEmpty {
                    empty("Waiting for the live Agent process tree")
                } else {
                    let overviewNodes = overviewProcessGroups
                    let limit = 8
                    ForEach(Array(overviewNodes.prefix(limit))) { node in compactTreeRow(node) }
                    if processTree.count > overviewNodes.prefix(limit).count {
                        Button { centerTab = .processes } label: {
                            HStack {
                                Text("View complete process tree")
                                Spacer()
                                Text("+\(processTree.count - overviewNodes.prefix(limit).count)")
                                Image(systemName: "arrow.right")
                            }
                            .font(.system(size: 9, weight: .semibold)).foregroundStyle(cyan)
                            .padding(.top, 8)
                        }.buttonStyle(.plain)
                    }
                }
            }
        }
    }

    // MARK: - Panels

    private var processPanel: some View {
        posturePanel("AGENT RUNTIME MAP", "Real PID lineage · Runtime Profile responsibilities · security surfaces") {
            VStack(alignment: .leading, spacing: 0) {
                if processTree.isEmpty {
                    empty("No live process tree")
                } else {
                    let limit = centerTab == .processes ? processTree.count : 9
                    ForEach(Array(processTree.prefix(limit))) { node in
                        if node.depth == 0 {
                            HStack(spacing: 7) {
                                Image(systemName: "circle.hexagongrid.fill").foregroundStyle(cyan)
                                Text((node.agentHint ?? "Agent") + " RUNTIME")
                                    .font(.system(size: 9, weight: .bold)).foregroundStyle(cyan)
                                Rectangle().fill(border).frame(height: 1)
                            }.padding(.top, 6).padding(.bottom, 2)
                        }
                        treeRow(node)
                    }
                    if centerTab != .processes && processTree.count > limit {
                        Button { centerTab = .processes } label: {
                            Text("Open complete process tree · \(processTree.count - limit) more processes")
                                .font(.system(size: 10, weight: .semibold)).foregroundStyle(cyan)
                        }.buttonStyle(.plain).padding(.top, 8)
                    }
                }
            }
        }
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
                        }.frame(width: 17, height: 55)
                    }
                }
                HStack(spacing: 8) {
                    Image(systemName: info.icon)
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(tint)
                        .frame(width: 28, height: 28)
                        .background(tint.opacity(0.13), in: RoundedRectangle(cornerRadius: 6))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 5) {
                            Text(info.displayName + (group.processes.count > 1 ? " ×\(group.processes.count)" : ""))
                                .font(.system(size: 10, weight: .bold)).lineLimit(1)
                            Spacer(minLength: 2)
                            Text(group.processes.count > 1 ? "\(group.processes.count) PIDS" : "PID \(node.process.pid)").mono()
                        }
                        Text(info.responsibility).font(.system(size: 8)).foregroundStyle(.secondary).lineLimit(1)
                        Text("\(info.capability.rawValue.uppercased()) · \(info.confidence.rawValue.uppercased())")
                            .font(.system(size: 6.5, weight: .bold)).foregroundStyle(tint)
                    }
                    Circle().fill(active ? green : Color.gray.opacity(0.7)).frame(width: 7, height: 7)
                }
                .padding(.horizontal, 9).padding(.vertical, 7)
                .frame(maxWidth: .infinity, minHeight: 47, alignment: .leading)
                .background(selected ? tint.opacity(0.16) : raised, in: RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(selected ? tint : border))
            }
            .padding(.vertical, 3)
        }.buttonStyle(.plain)
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
                groups.append(OverviewProcessGroup(id: key, node: node, processes: [node.process]))
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
                        .frame(width: 24, height: node.depth == 0 ? 74 : 64)
                    }
                }
                HStack(spacing: 9) {
                    Image(systemName: info.icon)
                        .font(.system(size: node.depth == 0 ? 16 : 12, weight: .semibold))
                        .foregroundStyle(tint)
                        .frame(width: node.depth == 0 ? 38 : 32, height: node.depth == 0 ? 38 : 32)
                        .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 7) {
                            Text(info.displayName).font(.system(size: node.depth == 0 ? 13 : 11, weight: .bold)).lineLimit(1)
                            Text(info.capability.rawValue.uppercased())
                                .font(.system(size: 7, weight: .bold))
                                .foregroundStyle(tint)
                                .padding(.horizontal, 5).padding(.vertical, 2)
                                .background(tint.opacity(0.12), in: Capsule())
                        }
                        Text(info.responsibility)
                            .font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1)
                        HStack(spacing: 5) {
                            Text("PID \(node.process.pid)").mono()
                            Text(info.confidence.rawValue.uppercased())
                                .font(.system(size: 7, weight: .bold))
                                .foregroundStyle(confidenceColor(info.confidence))
                        }
                    }
                    Spacer(minLength: 4)
                    VStack(spacing: 4) {
                        Circle().fill(active ? green : tint).frame(width: active ? 10 : 7, height: active ? 10 : 7)
                            .shadow(color: active ? green.opacity(0.9) : .clear, radius: 5)
                        Text(active ? "ACTIVE" : "LIVE").font(.system(size: 6, weight: .bold))
                            .foregroundStyle(active ? green : .secondary)
                    }
                }
                .padding(.horizontal, 12).padding(.vertical, 9)
                .frame(minHeight: node.depth == 0 ? 68 : 58)
                .background(
                    LinearGradient(colors: [selected ? tint.opacity(0.25) : raised,
                                            panel.opacity(0.92)], startPoint: .topLeading, endPoint: .bottomTrailing),
                    in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(selected ? tint : border, lineWidth: selected ? 1.8 : 1))
                .shadow(color: tint.opacity(node.depth == 0 ? 0.18 : 0.08), radius: node.depth == 0 ? 10 : 5, x: 0, y: 3)
            }
            .padding(.vertical, 4)
        }.buttonStyle(.plain)
    }

    private var journeyPanel: some View {
        posturePanel("LIVE TASK", "Request → context → model → tools → result") {
            VStack(alignment: .leading, spacing: 0) {
                let stages = taskStages
                HStack(spacing: 7) {
                    Circle().fill(currentTaskStage == nil ? Color.gray : green).frame(width: 7, height: 7)
                    Text(liveTaskStateHeadline)
                        .font(.system(size: 8, weight: .bold)).foregroundStyle(liveTaskStateColor)
                    Spacer()
                    if !followingLive {
                        Button("Return to live") {
                            followingLive = true
                            selectedStageID = currentTaskStage?.id
                            selectedEvent = currentTaskStage?.event
                            selectedProcessGroup = []
                        }.buttonStyle(.plain).font(.system(size: 8, weight: .semibold)).foregroundStyle(cyan)
                    }
                }.padding(.bottom, 10)
                if stages.isEmpty {
                    empty("Waiting for task evidence")
                } else {
                    ForEach(Array(stages.enumerated()), id: \.offset) { index, stage in
                        timelineRow(stage, isLast: index == stages.count - 1)
                    }
                }
            }
        }
    }

    private func timelineRow(_ stage: TaskStage, isLast: Bool) -> some View {
        let selected = selectedStageID == stage.id ||
            (selectedStageID == nil && selectedEvent?.id == stage.event?.id && stage.event != nil)
        let isCurrent = currentTaskStage?.id == stage.id
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
                        Text(stage.title).font(.system(size: 11, weight: .semibold))
                        Spacer()
                        Text(stage.status.label.uppercased())
                            .font(.system(size: 6.5, weight: .bold)).foregroundStyle(stageColor)
                        if let ts = stage.timestamp {
                            Text(clock(ts)).mono()
                        }
                    }
                    Text(stage.detail)
                        .font(.system(size: stage.monospace ? 9 : 10,
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
        }.buttonStyle(.plain)
    }

    private var networkPanel: some View {
        posturePanel("EXTERNAL SERVICES", "Providers and data flows") {
            VStack(spacing: 9) {
                if externalServices.isEmpty {
                    empty("No external destination captured")
                }
                ForEach(externalServices, id: \.host) { item in
                    let assessment = NetworkDestinationAssessment.assess(domain: item.host, host: item.host)
                    Button {
                        selectedEvent = item.event
                        selectedProcess = nil
                        selectedProcessGroup = []
                        selectedStageID = nil
                        followingLive = false
                    } label: {
                        VStack(alignment: .leading, spacing: 7) {
                            HStack(spacing: 8) {
                                Image(systemName: serviceIcon(assessment.kind))
                                    .foregroundStyle(assessment.needsAttention ? amber : cyan)
                                    .frame(width: 28, height: 28)
                                    .background((assessment.needsAttention ? amber : cyan).opacity(0.12),
                                                in: RoundedRectangle(cornerRadius: 7))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(serviceTitle(item.host)).font(.system(size: 11, weight: .semibold)).lineLimit(1)
                                    Text(assessment.kind.rawValue).font(.system(size: 8)).foregroundStyle(.secondary)
                                }
                                Spacer(minLength: 0)
                            }
                            Text(item.host).font(.system(size: 8, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                            if assessment.needsAttention {
                                Text("Needs review")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundStyle(amber)
                                    .padding(.horizontal, 7).padding(.vertical, 3)
                                    .background(amber.opacity(0.12), in: Capsule())
                            }
                        }
                        .node(focusedTaskEvent?.id == item.event?.id && item.event != nil)
                    }.buttonStyle(.plain)
                }
            }
        }
    }

    private var evidencePanel: some View {
        posturePanel("TASK EVIDENCE", "Measured from the active evidence window") {
            HStack(spacing: 8) {
                metric("Prompt", activeTurn.map { formatBytes($0.contextBytes) } ?? "—", "doc.text")
                metric("Response", activeTurn.map { formatBytes($0.responseCharacters) } ?? "—", "text.bubble")
                metric("Commands", "\(activeTurn?.toolCalls.count ?? 0)", "terminal")
                metric("Files", "\(scopedEvents.filter { $0.kind == "file" }.count)", "doc.badge.gearshape")
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
            Text(text).font(.system(size: 9)).foregroundStyle(.secondary)
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
                    if selectedProcessGroup.count > 1 {
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
            summaryRow(incidents.isEmpty ? cyan : amber,
                       incidents.isEmpty ? "No alerts observed" : "Relay / items to review",
                       incidents.isEmpty ? "Observed only" : "\(incidents.count)")
            summaryRow(findingCount == 0 ? cyan : amber,
                       findingCount == 0 ? "No code findings observed" : "Code findings",
                       findingCount == 0 ? "Not a pass" : "\(findingCount)")
            summaryRow(cyan, "Evidence coverage", evidenceCoverage)
            if !incidents.isEmpty {
                Button { onIncident(incidents[0]) } label: {
                    Text("Open top finding")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(amber)
                }.buttonStyle(.plain).padding(.top, 2)
            }
        }
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
                    Text(info.displayName).font(.system(size: 15, weight: .bold))
                    Text("PID \(p.pid)").mono()
                }
            }
            Text(info.responsibility)
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            labelChip("\(info.capability.rawValue) · \(info.confidence.rawValue.capitalized)",
                      color: confidenceColor(info.confidence))
            if !info.securitySurface.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("SECURITY SURFACE").micro(.secondary)
                    ForEach(info.securitySurface, id: \.self) { item in
                        Label(item, systemImage: "shield.lefthalf.filled")
                            .font(.system(size: 9)).foregroundStyle(.secondary)
                    }
                }
            }
            if let latest = processEvents.first {
                VStack(alignment: .leading, spacing: 4) {
                    Text("LATEST OBSERVED ACTIVITY").micro(.secondary)
                    Text(eventTitle(latest)).font(.system(size: 10, weight: .semibold))
                    Text("\(latest.kind) / \(latest.op) · \(clock(latest.ts))")
                        .font(.system(size: 9)).foregroundStyle(.secondary)
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
                field("Attribution", "Observed inside \(activeSession?.agent.capitalized ?? selectedAgent) process tree")
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
                    Text("\(info.displayName) ×\(group.count)").font(.system(size: 15, weight: .bold))
                    Text("\(group.count) observed leaf processes").mono()
                }
            }
            Text(info.responsibility)
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            labelChip("\(info.capability.rawValue) · \(info.confidence.rawValue.capitalized)",
                      color: confidenceColor(info.confidence))
            VStack(alignment: .leading, spacing: 8) {
                Text("TECHNICAL EVIDENCE").micro(.secondary)
                field("PIDs", pids.joined(separator: ", "))
                field("Parent PID", representative.ppid)
                field("Runtime Profile", "\(info.profileId) v\(info.profileVersion)")
                field("Aggregation", "Same parent, component, responsibility, and leaf status")
                field("Attribution", "Observed inside \(activeSession?.agent.capitalized ?? selectedAgent) process tree")
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
                .font(.system(size: 11)).foregroundStyle(.secondary)
            Text("Collector coverage").font(.system(size: 12, weight: .semibold)).padding(.top, 8)
            ForEach(health, id: \.source) { h in
                HStack {
                    Circle().fill(h.state == .healthy ? green : amber).frame(width: 6, height: 6)
                    Text(h.source).font(.system(size: 10))
                    Spacer()
                    Text(h.state.rawValue).mono()
                }
            }
        }
    }

    private func eventDetail(_ e: GuardEvent) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("NODE DETAILS").micro(.secondary)
            Text(eventTitle(e)).font(.headline)
            field("Observed", e.ts.formatted(date: .abbreviated, time: .standard))
            field("Agent / operation", "\(e.agent ?? "Unknown") · \(e.kind)/\(e.op)")
            field("Evidence confidence", e.attributionConfidence?.rawValue ?? "unknown")
            field("Why linked", e.attributionMethod ?? "No attribution method")
            if let v = e.userIntent { field("User request", v) }
            if let v = e.modelPrompt { field("Model context", v) }
            if let v = e.modelResponse { field("Result / response", v) }
            if let v = e.command { field("Arguments / command", v) }
            if e.path != "-" { field("File", e.path) }
            if let host = e.remoteDomain ?? e.remoteHost {
                let assessment = NetworkDestinationAssessment.assess(domain: host, host: host)
                field("Destination class", assessment.kind.rawValue)
                field("Review reason", assessment.reason)
            }
        }
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

    private var currentTaskStage: TaskStage? {
        taskStages.last { $0.status == .active }
    }

    private var liveTaskStateHeadline: String {
        if let currentTaskStage { return "CURRENT · \(currentTaskStage.title.uppercased())" }
        if verificationEvent != nil { return "INDEPENDENTLY VERIFIED" }
        if activeTurn?.finalResponse != nil { return "AGENT REPORTED COMPLETE · AWAITING VERIFICATION" }
        if activeTurn != nil { return "WAITING FOR THE NEXT OBSERVED ACTION" }
        return "WAITING FOR LIVE EVIDENCE"
    }

    private var liveTaskStateColor: Color {
        if currentTaskStage != nil || verificationEvent != nil { return green }
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
                Text(subtitle).font(.system(size: 9)).foregroundStyle(.secondary)
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
                Text(value).font(.system(size: 13, weight: .bold)).foregroundStyle(tint ?? .primary)
                Text(title).font(.system(size: 8)).foregroundStyle(.secondary)
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
                .foregroundStyle(color).font(.system(size: 11))
            Text(title).font(.system(size: 11))
            Spacer()
            Text(value).font(.system(size: 10, weight: .semibold)).foregroundStyle(color)
        }
    }

    private func field(_ name: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(name.uppercased()).micro(.secondary)
            Text(value)
                .font(.system(size: 9, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func labelChip(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 5)
            .background(color.opacity(0.12), in: Capsule())
    }

    private func legend(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text).font(.system(size: 9)).foregroundStyle(.secondary)
        }
    }

    private func empty(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10))
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
            Text("Hosts \(externalServices.count)")
            Spacer()
            Text("Local evidence · no cloud dependency").foregroundStyle(.secondary)
        }
        .font(.system(size: 9, weight: .medium))
        .padding(.horizontal, 15)
        .frame(height: 32)
        .background(raised)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .top)
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
        font(.system(size: 9, weight: .bold)).tracking(0.8).foregroundStyle(color)
    }
    func mono() -> some View {
        font(.system(size: 8, design: .monospaced)).foregroundStyle(.secondary)
    }
    func badge(_ color: Color) -> some View {
        font(.system(size: 8, weight: .bold))
            .foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 4)
            .background(color.opacity(0.1), in: Capsule())
    }
}
