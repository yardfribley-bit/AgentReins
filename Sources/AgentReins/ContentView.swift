import SwiftUI

/// Single-purpose shell for the live situation-awareness experience. Legacy
/// dashboards are removed so unrelated state cannot invalidate the live graph.
struct ContentView: View {
    @EnvironmentObject private var fileGuard: FileGuard
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore
    @EnvironmentObject private var agentDiscovery: AgentDiscoveryManager

    @State private var selectedSession: AgentSessionSnapshot?
    @State private var selectedIncident: SecurityIncident?
    private let healthTimer = Timer.publish(every: 10, on: .main, in: .common).autoconnect()

    private var observing: Bool { fileGuard.running || processGuard.running }
    var body: some View {
        AgentOperationsCenterView(
            sessions: eventStore.sessions,
            events: eventStore.events,
            incidents: eventStore.incidents.filter { $0.severity != "info" },
            health: eventStore.collectorHealth,
            observing: observing,
            processInventory: processGuard.processInventory,
            discoveredAgents: agentDiscovery.agents,
            onSession: { selectedSession = $0 },
            onIncident: { selectedIncident = $0 }
        )
        .frame(minWidth: 1500, minHeight: 780)
        .task {
            if !fileGuard.running { fileGuard.start() }
            if !processGuard.running { processGuard.start() }
        }
        .onReceive(healthTimer) { _ in eventStore.refreshCollectorHealth() }
        .sheet(item: $selectedSession) { SessionEvidenceSheet(session: $0) }
        .sheet(item: $selectedIncident) { IncidentEvidenceSheet(incident: $0) }
    }
}

private struct SessionEvidenceSheet: View {
    let session: AgentSessionSnapshot
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(session.agent.capitalized).font(.title2.bold())
                    Text("Complete captured session evidence").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(session.turns) { turn in
                        DisclosureGroup("Turn \(turn.index) · \(turn.startedAt.formatted(date: .abbreviated, time: .standard))") {
                            evidence("USER REQUEST", turn.userInput)
                            evidence("MODEL INPUT", turn.fullPrompt)
                            evidence("MODEL RESPONSE", turn.finalResponse)
                            evidence("RECORDED REASONING SUMMARY", turn.recordedReasoning)
                            ForEach(turn.toolCalls) { call in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("TOOL / MCP · \(call.name)").font(.caption.bold()).foregroundStyle(.cyan)
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
    }

    private func evidence(_ title: String, _ value: String?) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
            Text(value ?? "Not captured").font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }.padding(.top, 8)
    }
}

private struct IncidentEvidenceSheet: View {
    let incident: SecurityIncident
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Text(incident.title).font(.title2.bold()); Spacer(); Button("Done") { dismiss() } }
            Text(incident.summary).foregroundStyle(.secondary)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(incident.events) { event in
                        VStack(alignment: .leading, spacing: 5) {
                            Text("\(event.kind.uppercased()) · \(event.op)").font(.caption.bold())
                            Text(event.command ?? event.modelResponse ?? event.modelPrompt ?? event.path)
                                .font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                            Text(event.attributionMethod ?? "Attribution unavailable")
                                .font(.caption2).foregroundStyle(.secondary)
                        }.padding(11).background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                    }
                }
            }
        }.padding(18).frame(minWidth: 760, minHeight: 520)
    }
}
