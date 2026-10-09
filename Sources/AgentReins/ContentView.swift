import SwiftUI

/// Single-purpose shell for the live situation-awareness experience. Legacy
/// dashboards are removed so unrelated state cannot invalidate the live graph.
struct ContentView: View {
    @EnvironmentObject private var fileGuard: FileGuard
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore
    @StateObject private var realtime = RealtimeWorkspaceState()
    private let healthTimer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()
    var body: some View {
        RealtimeWorkspaceView(payload: realtime.payload(processes: processGuard.processInventory,
            health: eventStore.collectorHealth, observing: fileGuard.running || processGuard.running,
            error: eventStore.persistenceError))
        .frame(minWidth: 1100, minHeight: 720)
        .task {
            realtime.ingest(eventStore.events)
            realtime.updateProcesses(processGuard.processInventory)
            if !fileGuard.running { fileGuard.start() }
            if !processGuard.running { processGuard.start() }
        }
        .onReceive(eventStore.$revision) { _ in realtime.ingest(eventStore.events) }
        .onReceive(processGuard.$processInventory) { realtime.updateProcesses($0) }
        .onReceive(healthTimer) { _ in eventStore.refreshCollectorHealth(publish: true) }
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
