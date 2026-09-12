import SwiftUI

/// 菜单栏安全应用关闭窗口后继续运行，退出时清理扫描子进程。
final class AgentReinsAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        AppNotifier.requestAuthorization()
        if let url = Bundle.main.url(forResource: "AgentReins", withExtension: "icns"),
           let icon = NSImage(contentsOf: url) {
            NSApplication.shared.applicationIconImage = icon
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag, let window = sender.windows.first(where: { $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        }
        sender.activate(ignoringOtherApps: true)
        return true
    }
    func applicationWillTerminate(_ notification: Notification) {
        MemoryScanManager.cleanupOnTerminate()
    }
}

@main
struct AgentReinsApp: App {
    @NSApplicationDelegateAdaptor(AgentReinsAppDelegate.self) private var appDelegate
    @StateObject private var store = RuleStore()
    // Open and verify the durable evidence spine before individual collectors
    // create their own SQLite connections.
    @StateObject private var eventStore = EventStore()
    @StateObject private var fileGuard = FileGuard()
    @StateObject private var processGuard = ProcessGuard()
    @StateObject private var turnJournalStore = TurnJournalStore()
    @StateObject private var workBuddySight = WorkBuddySight()
    @StateObject private var codexSight = CodexSight()
    @StateObject private var qoderSight = QoderSight()
    @StateObject private var cursorSight = CursorSight()
    @StateObject private var webAgentSight = WebAgentSight()
    @StateObject private var agentDiscovery = AgentDiscoveryManager()
    @StateObject private var semanticAnalyzer = SemanticAnalyzer()
    @StateObject private var memoryScan = MemoryScanManager()
    @StateObject private var memoryRuleStore = MemoryRuleStore()
    @StateObject private var attributionResolver = EventAttributionResolver()
    @StateObject private var activityProjector = ToolActivityEvidenceProjector()

    var body: some Scene {
        WindowGroup("AgentReins", id: "security-center") {
            ContentView()
                .environmentObject(store)
                .environmentObject(fileGuard)
                .environmentObject(processGuard)
                .environmentObject(eventStore)
                .environmentObject(turnJournalStore)
                .environmentObject(workBuddySight)
                .environmentObject(codexSight)
                .environmentObject(qoderSight)
                .environmentObject(cursorSight)
                .environmentObject(webAgentSight)
                .environmentObject(agentDiscovery)
                .environmentObject(semanticAnalyzer)
                .environmentObject(memoryScan)
                .environmentObject(memoryRuleStore)
                .onReceive(store.$rules) { rules in
                    fileGuard.setRules(rules)
                    processGuard.setRules(rules)
                }
                .onReceive(workBuddySight.$connected) { agentDiscovery.setAdapterConnected("workbuddy", connected: $0) }
                .onReceive(codexSight.$connected) { agentDiscovery.setAdapterConnected("codex", connected: $0) }
                .onReceive(qoderSight.$connected) { agentDiscovery.setAdapterConnected("qoder", connected: $0) }
                .onReceive(cursorSight.$connected) { agentDiscovery.setAdapterConnected("cursor", connected: $0) }
                .onReceive(webAgentSight.$connected) { agentDiscovery.setAdapterConnected("grok-web", connected: $0) }
                .onReceive(processGuard.$processInventory) { inventory in
                    agentDiscovery.observe(processes: inventory)
                }
                .task {
                    fileGuard.onEvent = { eventStore.record(attributionResolver.resolve($0)) }
                    processGuard.onEvent = { eventStore.record(attributionResolver.resolve($0)) }
                    processGuard.onEvents = { events in
                        eventStore.record(events.map { attributionResolver.resolve($0) })
                    }
                    memoryScan.onFindings = { findings, date in
                        eventStore.recordMemoryFindings(findings, scannedAt: date)
                    }
                    workBuddySight.onEvents = { events in
                        let fresh = attributionResolver.labelNative(eventStore.unrecorded(events))
                        let projected = activityProjector.project(fresh)
                        attributionResolver.observe(fresh + projected)
                        refineRecentNetworkEvents()
                        turnJournalStore.ingest(journalEvents(from: fresh))
                        eventStore.record(fresh + projected)
                    }
                    workBuddySight.start()
                    codexSight.onEvents = { events in
                        let fresh = attributionResolver.labelNative(eventStore.unrecorded(events))
                        let projected = activityProjector.project(fresh)
                        attributionResolver.observe(fresh + projected)
                        refineRecentNetworkEvents()
                        turnJournalStore.ingest(journalEvents(from: fresh))
                        eventStore.record(fresh + projected)
                    }
                    codexSight.start()
                    qoderSight.onEvents = { events in
                        let fresh = attributionResolver.labelNative(eventStore.unrecorded(events))
                        let projected = activityProjector.project(fresh)
                        attributionResolver.observe(fresh + projected)
                        refineRecentNetworkEvents()
                        turnJournalStore.ingest(journalEvents(from: fresh))
                        eventStore.record(fresh + projected)
                    }
                    qoderSight.start()
                    cursorSight.onEvents = { events in
                        let fresh = eventStore.unrecorded(events)
                        let projected = activityProjector.project(fresh)
                        attributionResolver.observe(fresh + projected)
                        refineRecentNetworkEvents()
                        turnJournalStore.ingest(journalEvents(from: fresh))
                        eventStore.record(fresh + projected)
                    }
                    cursorSight.start()
                    webAgentSight.onEvents = { events in
                        let fresh = eventStore.unrecorded(events)
                        attributionResolver.observe(fresh)
                        turnJournalStore.ingest(journalEvents(from: fresh))
                        eventStore.record(fresh)
                    }
                    webAgentSight.start()
                    agentDiscovery.start()
                    memoryScan.startAuto { memoryRuleStore.enabledRules }
                }
        }

        MenuBarExtra {
            StatusMenuView()
                .environmentObject(fileGuard)
                .environmentObject(processGuard)
                .environmentObject(eventStore)
                .environmentObject(workBuddySight)
        } label: {
            Image(systemName: "shield.lefthalf.filled")
        }
    }

    private func journalEvents(from events: [GuardEvent]) -> [GuardEvent] {
        events.filter { event in
            if event.kind == "tool" { return true }
            if event.kind != "model" { return false }
            if event.op == "prompt" { return true }
            if event.op != "response" { return false }
            return event.source != "agentsight:codex-local-compat" || event.action == "final_answer"
        }
    }

    private func refineRecentNetworkEvents() {
        let refined = eventStore.events.prefix(200)
            .filter { $0.kind == "network" && $0.toolName == nil }
            .map { attributionResolver.resolve($0) }
            .filter { $0.toolName != nil }
        eventStore.record(refined)
    }
}

struct StatusMenuView: View {
    @Environment(\.openWindow) private var openWindow
    @EnvironmentObject private var fileGuard: FileGuard
    @EnvironmentObject private var processGuard: ProcessGuard
    @EnvironmentObject private var eventStore: EventStore

    private var isRunning: Bool { fileGuard.running || processGuard.running }
    private var eventCount: Int { eventStore.events.count }

    var body: some View {
        Text(isRunning ? "AgentReins is protecting you" : "AgentReins is paused")
        Text("\(eventCount) important activities recorded")
        Divider()
        Button("Open AgentReins") {
            openWindow(id: "security-center")
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
        Button(isRunning ? "Pause protection" : "Resume protection") {
            if isRunning { fileGuard.stop(); processGuard.stop() }
            else { fileGuard.start(); processGuard.start() }
        }
        Divider()
        Button("Quit AgentReins") { NSApplication.shared.terminate(nil) }
    }
}
