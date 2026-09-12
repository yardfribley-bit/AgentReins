import SwiftUI

/// Evidence-first situational awareness. Summary rows never replace raw data:
/// selecting one opens every captured field in the evidence drawer.
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

    @State private var agent = "All agents"
    @State private var section = Section.activity
    @State private var selectedEvent: GuardEvent?
    @State private var selectedProcess: ProcessSnapshotRecord?

    private let canvas = Color(red: 7/255, green: 16/255, blue: 29/255)
    private let panel = Color(red: 13/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 18/255, green: 35/255, blue: 57/255)
    private let border = Color(red: 39/255, green: 62/255, blue: 89/255)
    private let cyan = Color(red: 55/255, green: 211/255, blue: 199/255)

    enum Section: String, CaseIterable, Identifiable {
        case activity = "Live chain", processes = "Process tree", context = "Model context"
        case tools = "Tools & MCP", network = "Network", files = "Files & code", health = "Coverage"
        var id: String { rawValue }
    }

    private var visibleEvents: [GuardEvent] {
        events.filter { agent == "All agents" || $0.agent?.caseInsensitiveCompare(agent) == .orderedSame }.sorted { $0.ts > $1.ts }
    }
    private var visibleSessions: [AgentSessionSnapshot] {
        sessions.filter { agent == "All agents" || $0.agent.caseInsensitiveCompare(agent) == .orderedSame }
    }
    private var visibleProcesses: [ProcessSnapshotRecord] {
        let markers = agent == "All agents" ? discoveredAgents.map { $0.product.lowercased() } : [agent.lowercased()]
        let roots = Set(processInventory.filter { item in markers.contains { item.command.lowercased().contains($0) } }.map(\.pid))
        var ids = roots; var changed = true
        while changed {
            changed = false
            for item in processInventory where ids.contains(item.ppid) && !ids.contains(item.pid) { ids.insert(item.pid); changed = true }
        }
        return processInventory.filter { ids.contains($0.pid) }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            HStack(spacing: 0) {
                agentRail
                divider
                VStack(spacing: 0) { metrics; tabs; content }
                if selectedEvent != nil || selectedProcess != nil { divider; inspector.frame(width: 370) }
            }
            statusBar
        }.background(canvas).environment(\.colorScheme, .dark)
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled").font(.title2).foregroundStyle(cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("AGENTREINS / LIVE POSTURE").micro(cyan)
                Text("AI Agent Situational Awareness").font(.system(size: 20, weight: .semibold))
            }
            Spacer()
            Label(observing ? "COLLECTING" : "PAUSED", systemImage: "circle.fill").font(.system(size: 10, weight: .bold)).foregroundStyle(observing ? cyan : .orange)
            Text(Date(), style: .time).mono()
        }.padding(.horizontal, 20).frame(height: 66).background(panel).overlay(divider.frame(height: 1), alignment: .bottom)
    }

    private var agentRail: some View {
        VStack(alignment: .leading, spacing: 0) {
            barTitle("AGENT ASSETS", "\(discoveredAgents.count) detected")
            agentButton("All agents", "Unified evidence", observing)
            ForEach(discoveredAgents) { item in
                agentButton(item.product, "\(item.connection.rawValue) · \(item.processIds.count) processes", item.presence == .running)
            }
            Spacer()
            VStack(alignment: .leading, spacing: 8) {
                Text("EVIDENCE STATUS").micro(cyan)
                legend(.green, "Confirmed")
                legend(.orange, "Inferred")
                legend(.secondary, "Unknown")
                Text("Unknown evidence is never presented as fact.").font(.system(size: 9)).foregroundStyle(.secondary)
            }.padding(15)
        }.frame(width: 230).background(panel)
    }

    private func agentButton(_ name: String, _ detail: String, _ live: Bool) -> some View {
        Button { agent = name; selectedEvent = nil; selectedProcess = nil } label: {
            HStack(spacing: 10) {
                Text(String(name.prefix(1))).font(.callout.bold()).foregroundStyle(cyan).frame(width: 32, height: 32).background(cyan.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 3) {
                    HStack { Text(name).font(.system(size: 12, weight: .semibold)); Circle().fill(live ? .green : .secondary).frame(width: 6, height: 6) }
                    Text(detail).font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1)
                }; Spacer()
            }.padding(.horizontal, 14).frame(height: 54).background(agent.caseInsensitiveCompare(name) == .orderedSame ? cyan.opacity(0.09) : .clear)
        }.buttonStyle(.plain)
    }

    private var metrics: some View {
        HStack(spacing: 0) {
            metric("ACTIVE TASKS", "\(visibleSessions.filter { Date().timeIntervalSince($0.lastActivityAt) < 180 }.count)", "live sessions", cyan)
            metric("PROCESS NODES", "\(visibleProcesses.count)", "PID / PPID observed", .blue)
            metric("MODEL EXCHANGES", "\(visibleSessions.reduce(0) { $0 + $1.exchanges.count })", "prompt and response", .purple)
            metric("EXTERNAL HOSTS", "\(Set(visibleEvents.compactMap { $0.remoteDomain ?? $0.remoteHost }).count)", "agent destinations", .orange)
            metric("OPEN FINDINGS", "\(incidents.count)", "require review", incidents.isEmpty ? .green : .red)
        }.frame(height: 92)
    }

    private func metric(_ title: String, _ value: String, _ note: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).micro(.secondary); Text(value).font(.system(size: 25, weight: .semibold, design: .rounded)).foregroundStyle(color)
            Text(note).font(.system(size: 9)).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 16).overlay(divider, alignment: .trailing)
    }

    private var tabs: some View {
        HStack(spacing: 0) {
            ForEach(Section.allCases) { item in
                Button(item.rawValue) { section = item; selectedEvent = nil; selectedProcess = nil }.buttonStyle(.plain)
                    .font(.system(size: 11, weight: section == item ? .semibold : .regular)).foregroundStyle(section == item ? cyan : .secondary)
                    .padding(.horizontal, 13).frame(height: 40)
                    .overlay(Rectangle().fill(cyan).frame(height: 2).opacity(section == item ? 1 : 0), alignment: .bottom)
            }; Spacer()
        }.background(panel).overlay(divider.frame(height: 1), alignment: .bottom)
    }

    @ViewBuilder private var content: some View {
        switch section {
        case .activity: eventTable(visibleEvents)
        case .processes: processTable
        case .context: contextTable
        case .tools: eventTable(visibleEvents.filter { $0.kind == "tool" || $0.toolName != nil })
        case .network: eventTable(visibleEvents.filter { $0.kind == "network" || $0.remoteHost != nil })
        case .files: eventTable(visibleEvents.filter { $0.kind == "file" || $0.fileDiff != nil || $0.codeFindings != nil })
        case .health: healthTable
        }
    }

    private func eventTable(_ rows: [GuardEvent]) -> some View {
        VStack(spacing: 0) {
            tableHeader([("TIME", 68), ("AGENT / SOURCE", 130), ("STAGE", 112), ("OBSERVED EVIDENCE", 0), ("LINK", 88)])
            if rows.isEmpty { empty("No evidence captured for this view") }
            else { ScrollView { LazyVStack(spacing: 0) { ForEach(rows) { eventRow($0) } } } }
        }
    }

    private func eventRow(_ e: GuardEvent) -> some View {
        Button { selectedEvent = e; selectedProcess = nil } label: {
            HStack(spacing: 0) {
                Text(e.ts, style: .time).mono().frame(width: 68, alignment: .leading)
                VStack(alignment: .leading, spacing: 2) { Text(e.agent?.capitalized ?? "Unattributed").font(.system(size: 11, weight: .semibold)); Text(e.source ?? "source unknown").font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1) }.frame(width: 130, alignment: .leading)
                Text(stage(e)).font(.system(size: 9, weight: .bold)).foregroundStyle(e.severity == "info" ? cyan : .orange).frame(width: 112, alignment: .leading)
                VStack(alignment: .leading, spacing: 3) { Text(primary(e)).font(.system(size: 11, weight: .medium)).lineLimit(1); Text(secondary(e)).font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1) }.frame(maxWidth: .infinity, alignment: .leading)
                confidence(e.attributionConfidence).frame(width: 88, alignment: .leading)
            }.padding(.horizontal, 14).frame(height: 52).background(selectedEvent?.id == e.id ? cyan.opacity(0.07) : .clear)
        }.buttonStyle(.plain).overlay(divider.opacity(0.55).frame(height: 1), alignment: .bottom)
    }

    private var processTable: some View {
        VStack(spacing: 0) {
            tableHeader([("PID", 70), ("PPID", 70), ("PROCESS / SERVICE", 190), ("FULL COMMAND LINE", 0), ("RELATION", 100)])
            if visibleProcesses.isEmpty { empty("No live agent process tree in the current snapshot") }
            else { ScrollView { LazyVStack(spacing: 0) { ForEach(visibleProcesses, id: \.pid) { p in
                Button { selectedProcess = p; selectedEvent = nil } label: {
                    HStack(spacing: 0) {
                        Text(p.pid).mono().frame(width: 70, alignment: .leading); Text(p.ppid).mono().frame(width: 70, alignment: .leading)
                        Text(processName(p.command)).font(.system(size: 11, weight: .semibold)).frame(width: 190, alignment: .leading)
                        Text(p.command).font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                        Text(visibleProcesses.contains { $0.pid == p.ppid } ? "child" : "root / external").font(.system(size: 9, weight: .medium)).foregroundStyle(cyan).frame(width: 100, alignment: .leading)
                    }.padding(.horizontal, 14).frame(height: 42).background(selectedProcess?.pid == p.pid ? cyan.opacity(0.07) : .clear)
                }.buttonStyle(.plain).overlay(divider.opacity(0.5).frame(height: 1), alignment: .bottom)
            } } } }
        }
    }

    private var contextTable: some View {
        VStack(spacing: 0) {
            tableHeader([("TURN", 64), ("AGENT / MODEL", 155), ("USER REQUEST", 0), ("INPUT", 82), ("GROWTH", 82)])
            if visibleSessions.flatMap(\.turns).isEmpty { empty("No model context captured") }
            else { ScrollView { LazyVStack(spacing: 0) { ForEach(visibleSessions) { session in ForEach(session.turns) { turn in
                Button { if let e = session.events.first(where: { $0.turnId == turn.id }) { selectedEvent = e } } label: {
                    HStack(spacing: 0) {
                        Text("#\(turn.index)").mono().frame(width: 64, alignment: .leading)
                        VStack(alignment: .leading) { Text(session.agent.capitalized).font(.system(size: 11, weight: .semibold)); Text(turn.modelNames).font(.system(size: 9)).foregroundStyle(.secondary).lineLimit(1) }.frame(width: 155, alignment: .leading)
                        Text(turn.userInput ?? "User input not captured").font(.system(size: 11)).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                        Text(turn.inputTokens.map(String.init) ?? "—").mono().frame(width: 82, alignment: .leading)
                        Text(turn.contextGrowth.map { String(format: "%+.0f%%", $0.growthPercent) } ?? "—").mono().foregroundStyle(turn.contextGrowth?.needsAttention == true ? .orange : .secondary).frame(width: 82, alignment: .leading)
                    }.padding(.horizontal, 14).frame(height: 52)
                }.buttonStyle(.plain).overlay(divider.opacity(0.5).frame(height: 1), alignment: .bottom)
            } } } } }
        }
    }

    private var healthTable: some View {
        VStack(spacing: 0) {
            tableHeader([("SOURCE", 140), ("STATE", 80), ("LAST SUCCESS", 145), ("OK", 65), ("BAD", 65), ("DROP", 65), ("DETAIL / BLIND SPOT", 0)])
            if health.isEmpty { empty("Collector checkpoints have not been loaded") }
            else { ScrollView { LazyVStack(spacing: 0) { ForEach(health, id: \.source) { h in
                HStack(spacing: 0) {
                    Text(h.source).font(.system(size: 11, weight: .semibold)).frame(width: 140, alignment: .leading)
                    Text(h.state.rawValue.uppercased()).font(.system(size: 9, weight: .bold)).foregroundStyle(h.state == .healthy ? .green : .orange).frame(width: 80, alignment: .leading)
                    Text(h.lastSuccess.map { $0.formatted(date: .omitted, time: .standard) } ?? "Never").mono().frame(width: 145, alignment: .leading)
                    Text("\(h.accepted)").mono().frame(width: 65, alignment: .leading); Text("\(h.malformed)").mono().frame(width: 65, alignment: .leading); Text("\(h.dropped)").mono().frame(width: 65, alignment: .leading)
                    Text(h.detail ?? "No reported blind spot").font(.system(size: 9)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                }.padding(.horizontal, 14).frame(height: 46).overlay(divider.opacity(0.5).frame(height: 1), alignment: .bottom)
            } } } }
        }
    }

    private var inspector: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack { Text("COMPLETE EVIDENCE").micro(cyan); Spacer(); Button { selectedEvent = nil; selectedProcess = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain) }.padding(.horizontal, 16).frame(height: 42).background(raised)
            ScrollView { VStack(alignment: .leading, spacing: 14) {
                if let e = selectedEvent { ForEach(eventFields(e), id: \.0) { field($0.0, $0.1) } }
                if let p = selectedProcess {
                    field("Process / service", processName(p.command)); field("PID", p.pid); field("Parent PID", p.ppid); field("Full command", p.command)
                    field("Relationship", visibleProcesses.contains { $0.pid == p.ppid } ? "Directly observed parent-child relationship" : "Parent outside selected tree or no longer live")
                    field("Role", "Unknown unless identified by executable or native agent evidence")
                }
            }.padding(16) }
        }.background(panel)
    }

    private func eventFields(_ e: GuardEvent) -> [(String, String)] {
        let values: [(String, String?)] = [
            ("Event ID", e.id.uuidString), ("Observed at", e.ts.formatted(date: .abbreviated, time: .standard)), ("Kind / operation", "\(e.kind) / \(e.op)"),
            ("Rule", e.ruleId), ("Severity / action", "\(e.severity) / \(e.action)"), ("Agent", e.agent), ("Session", e.sessionId), ("Trace", e.traceId), ("Turn", e.turnId), ("Tool call ID", e.toolCallId),
            ("User request", e.userIntent), ("Model", e.model), ("Model prompt", e.modelPrompt), ("Model decision", e.modelDecision), ("Recorded reasoning", e.modelReasoning), ("Model response", e.modelResponse),
            ("Tool / MCP", e.toolName), ("Command / arguments", e.command), ("Path", e.path == "-" ? nil : e.path), ("Before content", e.beforeContent), ("After content", e.afterContent), ("File diff", e.fileDiff),
            ("Code findings", e.codeFindings.map { $0.map { "[\($0.severity)] line \($0.line) · \($0.title): \($0.evidence)" }.joined(separator: "\n") }),
            ("Input tokens", e.inputTokens.map(String.init)), ("Output tokens", e.outputTokens.map(String.init)), ("Cached tokens", e.cachedTokens.map(String.init)), ("Reasoning tokens", e.reasoningTokens.map(String.init)), ("Cost USD", e.costUSD.map { String(format: "$%.6f", $0) }),
            ("Process ID", e.processId.map(String.init)), ("Parent process ID", e.parentProcessId.map(String.init)), ("Local address", e.localAddress), ("Remote host", e.remoteHost), ("Remote port", e.remotePort.map(String.init)), ("Remote domain", e.remoteDomain),
            ("Evidence source", e.source), ("Attribution confidence", e.attributionConfidence?.rawValue), ("Attribution method", e.attributionMethod)
        ]
        return values.compactMap { name, value in value.map { (name, $0) } }
    }

    private func field(_ title: String, _ value: String) -> some View { VStack(alignment: .leading, spacing: 5) { Text(title.uppercased()).micro(.secondary); Text(value).font(.system(size: 10, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }.frame(maxWidth: .infinity, alignment: .leading) }
    private var statusBar: some View { HStack(spacing: 18) { Label("RAW EVIDENCE \(events.count)", systemImage: "waveform.path.ecg").foregroundStyle(cyan); Text("Processes \(processInventory.count)"); Text("Sessions \(sessions.count)"); Text("Tools \(events.filter { $0.toolName != nil }.count)"); Text("Network \(events.filter { $0.remoteHost != nil }.count)"); Text("Files \(events.filter { $0.kind == "file" }.count)"); Spacer(); Text("Local evidence · no cloud dependency").foregroundStyle(.secondary) }.font(.system(size: 9, weight: .medium)).padding(.horizontal, 16).frame(height: 34).background(raised).overlay(divider.frame(height: 1), alignment: .top) }
    private var divider: some View { Rectangle().fill(border).frame(width: 1) }
    private func barTitle(_ title: String, _ detail: String) -> some View { HStack { Text(title).micro(.secondary); Spacer(); Text(detail).font(.system(size: 9)).foregroundStyle(.secondary) }.padding(.horizontal, 14).frame(height: 40).background(raised) }
    private func legend(_ color: Color, _ title: String) -> some View { HStack { Circle().fill(color).frame(width: 6, height: 6); Text(title).font(.system(size: 10)) } }
    private func tableHeader(_ columns: [(String, CGFloat)]) -> some View {
        HStack(spacing: 0) {
            ForEach(Array(columns.enumerated()), id: \.offset) { _, column in
                headerCell(column.0, width: column.1)
            }
        }.padding(.horizontal, 14).frame(height: 34).background(raised)
    }
    @ViewBuilder private func headerCell(_ title: String, width: CGFloat) -> some View {
        if width == 0 { Text(title).micro(.secondary).frame(maxWidth: .infinity, alignment: .leading) }
        else { Text(title).micro(.secondary).frame(width: width, alignment: .leading) }
    }
    private func empty(_ text: String) -> some View { Text(text).font(.callout).foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity) }
    private func processName(_ command: String) -> String { URL(fileURLWithPath: command.split(separator: " ").first.map(String.init) ?? command).lastPathComponent }
    private func stage(_ e: GuardEvent) -> String { if e.kind == "context" || e.kind == "model" { return e.op == "response" ? "MODEL RESPONSE" : "MODEL INPUT" }; if e.toolName != nil || e.kind == "tool" { return "TOOL / MCP" }; if e.kind == "network" { return "NETWORK" }; if e.kind == "file" { return "FILE / CODE" }; if e.kind == "memory" { return "MEMORY" }; return e.kind.uppercased() }
    private func primary(_ e: GuardEvent) -> String { e.userIntent ?? e.toolName ?? e.remoteDomain ?? e.remoteHost ?? (e.path != "-" ? e.path : e.ruleId) }
    private func secondary(_ e: GuardEvent) -> String { e.command ?? e.modelResponse ?? e.modelPrompt ?? e.attributionMethod ?? "No additional payload captured" }
    private func confidence(_ value: EvidenceConfidence?) -> some View { let color: Color = value == .confirmed ? .green : (value == .inferred ? .orange : .secondary); return HStack(spacing: 5) { Circle().fill(color).frame(width: 6, height: 6); Text(value?.rawValue.uppercased() ?? "UNKNOWN").font(.system(size: 8, weight: .bold)).foregroundStyle(color) } }
}

private extension Text {
    func micro(_ color: Color) -> some View { font(.system(size: 9, weight: .bold)).tracking(0.8).foregroundStyle(color) }
    func mono() -> some View { font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary) }
}
