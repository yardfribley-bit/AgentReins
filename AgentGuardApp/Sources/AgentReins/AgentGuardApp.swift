import SwiftUI

/// 让「关闭窗口 = 退出程序」。macOS SwiftUI 默认关窗只是隐藏，进程仍在后台跑监控，
/// 表现为"无法关闭"。这里改为关最后一个窗口即终止，并在终止前清理定时器与残留子进程。
final class AgentReinsAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
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
    @StateObject private var memoryScan = MemoryScanManager()
    @StateObject private var memoryRuleStore = MemoryRuleStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                .environmentObject(fileGuard)
                .environmentObject(processGuard)
                .environmentObject(memoryScan)
                .environmentObject(memoryRuleStore)
                .onReceive(store.$rules) { rules in
                    fileGuard.setRules(rules)
                    processGuard.setRules(rules)
                }
                .task { memoryScan.startAuto { memoryRuleStore.enabledRules } }
                .frame(minWidth: 900, minHeight: 620)
        }
    }
}
