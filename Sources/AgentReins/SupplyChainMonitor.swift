import AgentReinsCore
import Darwin
import Foundation

/// Watches the known MCP and skill locations. A vnode event triggers one
/// bounded rescan. A slow timer is only the fallback, and it backs off when
/// the main process is hot or nothing changed. Session trees are not walked.
final class SupplyChainMonitor {
    static let shared = SupplyChainMonitor()
    private let queue = DispatchQueue(label: "com.agentreins.supply", qos: .utility)
    private var sources: [DispatchSourceFileSystemObject] = []
    private var timer: DispatchSourceTimer?
    private var debounce: DispatchWorkItem?
    private var watched: [String] = []
    private var announced = Set<String>()
    private var lastChanged = false

    func start() {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil else { return }
        queue.async { [weak self] in
            self?.refresh()
        }
    }

    func stop() {
        queue.sync {
            debounce?.cancel()
            timer?.cancel()
            timer = nil
            for source in sources { source.cancel() }
            sources.removeAll()
            watched = []
        }
    }

    private func refresh() {
        let home = SupplyChainCheck.homeURL()
        let projects = SupplyChainCheck.projectURLs()
        let explicit = projects.isEmpty ? nil : projects
        let doc = SupplyChainCheck.observe(home: home, store: SupplyChainCheck.storeURL(), projects: explicit)
        let pending = (doc["pending"] as? [String]) ?? []
        lastChanged = !pending.isEmpty
        let entries = (doc["entries"] as? [[String: Any]]) ?? []
        var summaries: [String: String] = [:]
        for entry in entries {
            guard let id = entry["id"] as? String else { continue }
            summaries[id] = String(((entry["summary"] as? String) ?? id).prefix(180))
        }
        for id in pending where announced.insert(id).inserted {
            let body = summaries[id] ?? id
            DispatchQueue.main.async {
                AppNotifier.send(title: "有新的 MCP 或技能还没看", body: body)
            }
        }
        let paths = SupplyChainCheck.watchPaths(home: home, projects: projects)
        if paths != watched { installWatchers(paths) }
        if timer == nil { armTimer() }
    }

    private func schedule() {
        debounce?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.refresh() }
        debounce = work
        queue.asyncAfter(deadline: .now() + 1, execute: work)
    }

    private func installWatchers(_ paths: [String]) {
        for source in sources { source.cancel() }
        sources.removeAll()
        watched = paths
        for path in paths {
            let fd = path.withCString { open($0, O_EVTONLY) }
            guard fd >= 0 else { continue }
            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .rename, .delete, .extend, .attrib],
                queue: queue)
            source.setEventHandler { [weak self] in self?.schedule() }
            source.setCancelHandler { close(fd) }
            source.resume()
            sources.append(source)
        }
    }

    private func armTimer() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            guard RuntimeBudget.shared.allowMainLoop(
                lane: "supply-chain", base: 60, previousChanged: self.lastChanged,
                now: Date(), maxInterval: 180) else { return }
            self.refresh()
        }
        timer.resume()
        self.timer = timer
    }
}
