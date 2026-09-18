import SwiftUI

/// Single-purpose shell for the live situation-awareness experience. Legacy
/// dashboards are removed so unrelated state cannot invalidate the live graph.
struct ContentView: View {
    @EnvironmentObject private var fileGuard: FileGuard
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore
    @EnvironmentObject private var agentDiscovery: AgentDiscoveryManager
    @StateObject private var liveDashboard = LiveDashboardViewModel()

    @State private var selectedSession: AgentSessionSnapshot?
    @State private var selectedIncident: SecurityIncident?
    private let healthTimer = Timer.publish(every: 10, on: .main, in: .common).autoconnect()

    private var observing: Bool { fileGuard.running || processGuard.running }
    var body: some View {
        AgentOperationsCenterView(
            dataRevision: liveDashboard.snapshot.evidenceRevision,
            sessions: liveDashboard.snapshot.sessions,
            events: liveDashboard.snapshot.events,
            incidents: liveDashboard.snapshot.incidents,
            health: liveDashboard.snapshot.health,
            observing: observing,
            processInventory: liveDashboard.snapshot.processInventory,
            discoveredAgents: liveDashboard.snapshot.discoveredAgents,
            onSession: { selectedSession = $0 },
            onIncident: { selectedIncident = $0 }
        )
        .frame(minWidth: 1100, minHeight: 720)
        .task {
            refreshLiveDashboard()
            liveDashboard.publishImmediately()
            if !fileGuard.running { fileGuard.start() }
            if !processGuard.running { processGuard.start() }
        }
        .onReceive(eventStore.$revision) { _ in refreshEvidence() }
        .onReceive(processGuard.$processInventory) { liveDashboard.updateProcesses($0) }
        .onReceive(agentDiscovery.$agents) { liveDashboard.updateAgents($0) }
        .onReceive(healthTimer) { _ in eventStore.refreshCollectorHealth(publish: true) }
        .sheet(item: $selectedSession) { SessionEvidenceSheet(session: $0) }
        .sheet(item: $selectedIncident) { IncidentEvidenceSheet(incident: $0) }
    }

    private func refreshLiveDashboard() {
        refreshEvidence()
        liveDashboard.updateProcesses(processGuard.processInventory)
        liveDashboard.updateAgents(agentDiscovery.agents)
    }

    private func refreshEvidence() {
        liveDashboard.updateEvidence(sessions: eventStore.sessions, events: eventStore.events,
            incidents: eventStore.incidents, health: eventStore.collectorHealth)
    }
}

private struct SessionEvidenceSheet: View {
    let session: AgentSessionSnapshot
    @EnvironmentObject private var eventStore: EventStore
    @Environment(\.dismiss) private var dismiss
    @State private var completeSession: AgentSessionSnapshot?
    @State private var loadError: String?

    private var visibleSession: AgentSessionSnapshot { completeSession ?? session }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(visibleSession.agentDisplayName).font(.title2.bold())
                    if let loadError {
                        Text(loadError).foregroundStyle(.red)
                    } else {
                        Text(completeSession == nil ? "Loading complete local evidence…" : "Complete captured session evidence")
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(visibleSession.turns) { turn in
                        DisclosureGroup("Turn \(turn.index) · \(turn.startedAt.formatted(date: .abbreviated, time: .standard))") {
                            evidence("USER REQUEST", turn.userInput)
                            evidence("MODEL INPUT", turn.fullPrompt)
                            evidence("MODEL RESPONSE", turn.finalResponse)
                            evidence("RECORDED REASONING SUMMARY", turn.recordedReasoning)
                            ForEach(turn.toolCalls) { call in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("TOOL / MCP · \(call.name)").font(.system(size: 12, weight: .bold)).foregroundStyle(.cyan)
                                    evidence("ARGUMENTS", call.arguments)
                                    evidence("RESULT", call.result)
                                }.padding(.vertical, 5)
                            }
                        }
                        .padding(12)
                        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                    }
                }
            }
        }
        .padding(18).frame(minWidth: 820, minHeight: 620)
        .onAppear {
            eventStore.loadSession(session.id) { result in
                switch result {
                case .success(let loaded):
                    completeSession = loaded
                    loadError = nil
                case .failure(let error):
                    loadError = error.localizedDescription
                }
            }
        }
    }

    private func evidence(_ title: String, _ value: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 13, weight: .bold)).foregroundStyle(.secondary)
            Text(value ?? "Not captured").font(.system(size: 13, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }.padding(.top, 8)
    }
}

private struct IncidentEvidenceSheet: View {
    let incident: SecurityIncident
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var language: AppLanguageStore

    private var copy: SecurityIncidentPresentation {
        SecurityIncidentPresentation.make(incident, chinese: language.language == .simplifiedChinese)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text(copy.title).font(.title2.bold()); Spacer(); Button(language.text("Done")) { dismiss() } }
            HStack(spacing: 8) {
                Text(copy.status.uppercased()).font(.system(size: 11, weight: .bold)).foregroundStyle(.orange)
                Text("·")
                Text(copy.confidence).foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 10) {
                explanation(language.language == .english ? "WHAT WE OBSERVED" : "已观察到 / 尚未确认", copy.whyItMatters)
                explanation(language.language == .english ? "NEXT DECISION" : "下一步判断", copy.recommendedAction)
            }.padding(14).background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    Text(language.language == .english ? "TECHNICAL EVIDENCE" : "技术证据")
                        .font(.system(size: 12, weight: .bold)).foregroundStyle(.secondary)
                    ForEach(incident.events) { event in
                        VStack(alignment: .leading, spacing: 5) {
                            Text("\(event.kind.uppercased()) · \(event.op)").font(.system(size: 12, weight: .bold))
                            Text(event.command ?? event.modelResponse ?? event.modelPrompt ?? event.path)
                                .font(.system(size: 13, design: .monospaced)).textSelection(.enabled)
                            Text(event.attributionMethod ?? "Attribution unavailable")
                                .font(.system(size: 12)).foregroundStyle(.secondary)
                            Text("Rule · \(event.ruleId)")
                                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.tertiary)
                        }.padding(11).background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                    }
                }
            }
        }.padding(18).frame(minWidth: 760, minHeight: 520)
    }

    private func explanation(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
