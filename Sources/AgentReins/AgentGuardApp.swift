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
    @StateObject private var fileGuard = FileGuard()
    @StateObject private var processGuard = ProcessGuard()
    @StateObject private var eventStore = EventStore()
    @StateObject private var workBuddySight = WorkBuddySight()
    @StateObject private var semanticAnalyzer = SemanticAnalyzer()
    @StateObject private var memoryScan = MemoryScanManager()
    @StateObject private var memoryRuleStore = MemoryRuleStore()

    var body: some Scene {
        WindowGroup("AgentReins", id: "security-center") {
            ContentView()
                .environmentObject(store)
                .environmentObject(fileGuard)
                .environmentObject(processGuard)
                .environmentObject(eventStore)
                .environmentObject(workBuddySight)
                .environmentObject(semanticAnalyzer)
                .environmentObject(memoryScan)
                .environmentObject(memoryRuleStore)
                .onReceive(store.$rules) { rules in
                    fileGuard.setRules(rules)
                    processGuard.setRules(rules)
                }
                .task {
                    fileGuard.onEvent = { eventStore.record($0) }
                    processGuard.onEvent = { eventStore.record($0) }
                    memoryScan.onFindings = { findings, date in
                        eventStore.recordMemoryFindings(findings, scannedAt: date)
                    }
                    workBuddySight.onEvents = { eventStore.record($0) }
                    workBuddySight.start()
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
