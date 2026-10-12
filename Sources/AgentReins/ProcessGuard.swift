import AppKit
import Foundation
import SwiftUI

struct CollectionHealth: Equatable {
    var lastProcessSuccess: Date?
    var lastNetworkSuccess: Date?
    var lastProcessDurationMS: Double = 0
    var lastNetworkDurationMS: Double = 0
    var processFailures = 0
    var networkFailures = 0
    var skippedProcessSnapshots = 0
    var skippedNetworkSnapshots = 0
    var acceptedProcessEvents = 0
    var acceptedNetworkEvents = 0
}

/// 命令层监测规则（正则 + 严重级 + 说明）。
struct CmdRule {
    let id: String
    let regex: NSRegularExpression
    let severity: String   // critical | high | medium | info
    let message: String
}

/// 命令层护栏：轮询进程列表，匹配高危命令并归属到具体 agent，事件汇入统一时间线。
/// 本类只做「可视化」（看到 agent 在跑什么命令），不拦截；硬拦截见 agentguard-esf 的 ESF。
@MainActor
final class ProcessGuard: ObservableObject {
    // Internal bounded diagnostic buffer. The product UI consumes the unified
    // EventStore, so publishing this duplicate buffer only invalidates the
    // entire dashboard a second time for every process event.
    private(set) var events: [GuardEvent] = []
    @Published var running = false
    private(set) var activeAgents: [String] = []
    /// Complete live process inventory. This is intentionally separate from
    /// `events`: long-running helpers (Storage Service, NodePeer, MCP servers,
    /// renderers) are evidence even when they are not risky or user actions.
    @Published private(set) var processInventory: [ProcessSnapshotRecord] = []
    // Persisted for Collector Health diagnostics. It is deliberately not
    // published: no live view consumes this value, and duration changes every
    // five seconds previously invalidated the entire situation-awareness UI.
    private(set) var collectionHealth = CollectionHealth()
    var onEvent: ((GuardEvent) -> Void)?
    var onEvents: (([GuardEvent]) -> Void)?

    private var applicationObservers: [NSObjectProtocol] = []
    private var previousProcesses: [String: SnapshotProcess] = [:]
    private var processTimer: Timer?
    private var networkTimer: Timer?
    private var observationTimer: Timer?
    private var observationInFlight = false
    private let hookCorrelation = HookProcessCorrelation()
    private var receivedHookIDs: [UUID: Date] = [:]
    private var pendingResourceTriggers: [String: Date] = [:]
    private var pendingNetworkTriggers: [String: Date] = [:]
    private let observationCoordinator = ProcessObservationCoordinator()
    private var observedProcesses: [ProcessSnapshotRecord] = []
    private var processSnapshotInFlight = false
    private var networkSnapshotInFlight = false
    private typealias SnapshotProcess = (pid: String, ppid: String, cmd: String, agent: String?, birth: UInt64?, executable: String?)
    private var latestProcesses: [SnapshotProcess] = []
    private var seen: Set<String> = []
    private var seenConnections: [String: Date] = [:]
    private var currentCmdRules: [CmdRule] = []
    // ChatGPT is the macOS desktop host of the Codex runtime. Keeping the host
    // root is required to preserve the real ChatGPT -> Codex services PID tree.
    private let agentMarkers = ["chatgpt", "codex", "workbuddy"]
    private let snapshotProvider: any ProcessSnapshotting
    private let networkProvider: any NetworkSnapshotting
    private let proxyDestinationProvider: any ProxyDestinationSnapshotting
    private var recentProxyDestinations: [Int: ProxyDestinationRecord] = [:]
    private let evidenceDatabase = try? EvidenceDatabase.shared()
    private var lastHealthPersist: [String: Date] = [:]
    private var workingCollectionHealth = CollectionHealth()
    private var lastHealthPublish = Date.distantPast
    private var lastInventoryPublish = Date.distantPast

    /// 内置默认高危命令监测集（对齐 agentguard/rules.json 的命令层规则）。
    static let builtin: [CmdRule] = {
        func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p, options: .caseInsensitive) }
        return [
            CmdRule(id: "cmd_rm_rf", regex: re("\\brm\\s+-(rf|fr|r\\s*-f|f\\s*-r)\\b"),
                    severity: "critical", message: "递归强制删除"),
            CmdRule(id: "cmd_curl_pipe_sh", regex: re("(curl|wget)[\\s\\S]*\\|\\s*(ba)?sh"),
                    severity: "critical", message: "下载即执行 (curl|bash)"),
            CmdRule(id: "cmd_read_secret", regex: re("(id_rsa|\\.ssh|\\.aws|credentials|\\.env)"),
                    severity: "high", message: "读取敏感凭据/配置"),
            CmdRule(id: "cmd_git_force", regex: re("git\\s+push\\s+.*(--force|\\s-f\\b)"),
                    severity: "high", message: "强制推送"),
            CmdRule(id: "cmd_sudo", regex: re("\\bsudo\\s"),
                    severity: "medium", message: "提权执行"),
        ]
    }()

    init(snapshotProvider: (any ProcessSnapshotting)? = nil,
         networkProvider: (any NetworkSnapshotting)? = nil,
         proxyDestinationProvider: (any ProxyDestinationSnapshotting)? = nil) {
        currentCmdRules = ProcessGuard.builtin
        self.snapshotProvider = snapshotProvider ?? ResilientProcessSnapshotProvider(agentMarkers: agentMarkers)
        self.networkProvider = networkProvider ?? LsofNetworkSnapshotProvider()
        self.proxyDestinationProvider = proxyDestinationProvider ?? V2rayUProxyDestinationProvider()
    }

    /// 规则变化时由 UI 同步进来：内置集 + 用户在 App 里配置的 cmd 类规则。
    func setRules(_ rules: [Rule]) {
        var extra: [CmdRule] = []
        for r in rules {
            guard r.kind == "cmd", let p = r.pattern else { continue }
            guard let re = try? NSRegularExpression(pattern: p, options: .caseInsensitive) else { continue }
            extra.append(CmdRule(id: r.id, regex: re,
                                 severity: r.severity.isEmpty ? "high" : r.severity, message: r.message))
        }
        currentCmdRules = ProcessGuard.builtin + extra
    }

    func start() {
        guard !running else { return }
        running = true
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didLaunchApplicationNotification, NSWorkspace.didTerminateApplicationNotification] {
            applicationObservers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] notification in
                let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
                let identity = [app?.bundleURL?.path, app?.bundleIdentifier, app?.localizedName]
                    .compactMap { $0 }.joined(separator: " ").lowercased()
                guard let self, self.agentMarkers.contains(where: identity.contains) else { return }
                Task { @MainActor [weak self] in
                    guard let self, self.running else { return }
                    self.snapshotProvider.invalidateDiscovery()
                    self.captureProcesses()
                }
            })
        }
        // Process and network collection deliberately have different cadences.
        // libproc is cheap enough to observe one-second children at 750 ms, while
        // spawning lsof at that rate caused severe recurring CPU spikes.
        processTimer = Timer.scheduledTimer(withTimeInterval: 0.75, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.captureProcesses()
            }
        }
        networkTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.captureNetwork()
            }
        }
        observationTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.captureProcessObservations() }
        }
        processTimer?.fire()
        networkTimer?.fire()
    }

    /// Native Hook notification arrives before the transcript/database hot path.
    /// It requests observation, never blocks execution or invents a tool PID.
    func observeHookSignals(_ hooks: [GuardEvent]) {
        let now = Date()
        receivedHookIDs = receivedHookIDs.filter { now.timeIntervalSince($0.value) < 600 }
        for hook in hooks where hook.source == "workbuddy-hook" && hook.op != "hook_capture_gap" {
            guard receivedHookIDs[hook.id] == nil else { continue }
            receivedHookIDs[hook.id] = now
            let links = hookCorrelation.observeHook(hook, now: now)
            let reason = "\(hook.id.uuidString):\(hook.op)"
            if running {
                pendingResourceTriggers[reason] = now
                pendingNetworkTriggers[reason] = now
            }
            let data: [String: Any] = ["hookEventID": hook.id.uuidString,
                "hookOperation": hook.op, "receivedAt": now.timeIntervalSince1970,
                "hookObservedAt": hook.ts.timeIntervalSince1970,
                "state": running ? "sampling_requested" : "process_monitor_inactive",
                "timing": "asynchronous; not an execution barrier",
                "identity": "native session/call IDs; executor PID remains unknown"]
            let encoded = (try? JSONSerialization.data(withJSONObject: data, options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) }
            let request = GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil,
                agent: "workbuddy", op: "hook_capture_request", severity: "info", ts: now, action: "requested",
                sessionId: hook.sessionId, toolCallId: hook.toolCallId, toolName: hook.toolName,
                afterContent: encoded, source: "hook-process-coordinator", attributionConfidence: .unknown,
                attributionMethod: "Hook requests sampling; not proof of tool execution")
            onEvents?(links + [request])
        }
        // Bound burst state. Signals are still preserved independently as raw Hook evidence.
        if receivedHookIDs.count > 512 {
            for old in receivedHookIDs.sorted(by: { $0.value < $1.value }).prefix(receivedHookIDs.count - 512) {
                receivedHookIDs.removeValue(forKey: old.key)
            }
        }
        for old in pendingResourceTriggers.sorted(by: { $0.value < $1.value }).prefix(max(0, pendingResourceTriggers.count - 32)) {
            pendingResourceTriggers.removeValue(forKey: old.key)
        }
        for old in pendingNetworkTriggers.sorted(by: { $0.value < $1.value }).prefix(max(0, pendingNetworkTriggers.count - 32)) {
            pendingNetworkTriggers.removeValue(forKey: old.key)
        }
        if running { captureProcesses() }
    }

    private func captureProcesses() {
        guard running, !processSnapshotInFlight else {
            if processSnapshotInFlight {
                workingCollectionHealth.skippedProcessSnapshots += 1
                publishHealthIfNeeded()
            }
            return
        }
        processSnapshotInFlight = true
        let started = Date()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let procs = self.excludingCollectorTree(self.getProcs())
            let scopedRecords = procs.compactMap { p -> ProcessSnapshotRecord? in
                guard let agent = p.agent, Self.isTargetAgent(agent) else { return nil }
                return ProcessSnapshotRecord(pid: p.pid, ppid: p.ppid, command: p.cmd,
                    agent: agent, birthIdentity: p.birth, executablePath: p.executable)
            }
            let armEvents = self.observationCoordinator.collect(processes: scopedRecords, includeSamples: false)
            let attachedPIDs = Set(armEvents.filter { $0.op == "process_watch_attached" }.compactMap { $0.processId.map(String.init) })
            let newlyAttached = scopedRecords.filter { attachedPIDs.contains($0.pid) }
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.processSnapshotInFlight = false
                self.workingCollectionHealth.lastProcessDurationMS = Date().timeIntervalSince(started) * 1_000
                if procs.isEmpty && self.snapshotProvider.snapshotFailed {
                    self.workingCollectionHealth.processFailures += 1
                    self.publishHealthIfNeeded()
                    self.persistHealth(source: "process", state: .failed,
                                       detail: "The process provider returned an empty snapshot")
                    return
                }
                self.workingCollectionHealth.lastProcessSuccess = Date()
                let byPid = Dictionary(uniqueKeysWithValues: procs.map {
                    ($0.pid, (ppid: $0.ppid, cmd: $0.cmd, agent: $0.agent))
                })
                let attributions = self.attributions(byPid: byPid)
                self.latestProcesses = procs.filter { attributions[$0.pid] != nil }
                let inventory = procs.filter { attributions[$0.pid] != nil }.map {
                    ProcessSnapshotRecord(pid: $0.pid, ppid: $0.ppid, command: $0.cmd,
                        agent: self.canonicalAgent(attributions[$0.pid]),
                        birthIdentity: $0.birth, executablePath: $0.executable)
                }.sorted { lhs, rhs in
                    (Int(lhs.pid) ?? 0) < (Int(rhs.pid) ?? 0)
                }
                self.observedProcesses = inventory
                // A process snapshot arrives every 750 ms so short-lived tools
                // are observable. Publishing an identical 500-process array at
                // that cadence forced SwiftUI to rebuild the entire posture
                // screen continuously and pinned a CPU core.
                if inventory != self.processInventory,
                   Date().timeIntervalSince(self.lastInventoryPublish) >= 2 {
                    self.processInventory = inventory
                    self.lastInventoryPublish = Date()
                }
                self.process(procs: procs, attributions: attributions)
                self.onEvents?(armEvents + self.hookCorrelation.observeProcesses(inventory))
                if !self.pendingResourceTriggers.isEmpty { self.captureProcessObservations() }
                if !self.pendingNetworkTriggers.isEmpty { self.captureNetwork() }
                // Socket queries run separately, so they cannot hold up process discovery.
                if !newlyAttached.isEmpty { self.captureNetwork(targets: newlyAttached) }
                self.persistHealth(source: "process", state: .healthy,
                    detail: "Scoped Agent-tree snapshots; processes shorter than the sampling interval may be missed")
                self.publishHealthIfNeeded()
            }
        }
    }

    private func captureProcessObservations() {
        guard running, !observationInFlight, !processSnapshotInFlight else { return }
        observationInFlight = true
        let trigger = pendingResourceTriggers.isEmpty ? nil : pendingResourceTriggers.keys.sorted().joined(separator: ",")
        pendingResourceTriggers.removeAll()
        let processes = trigger == nil ? observedProcesses : hookCorrelation.samplingTargets(observedProcesses)
        let coordinator = observationCoordinator
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let events = coordinator.collect(processes: processes, trigger: trigger)
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.observationInFlight = false
                guard self.running else { return }
                self.onEvents?(events)
                if !self.pendingResourceTriggers.isEmpty { self.captureProcessObservations() }
                self.persistHealth(source: "process-observation", state: .healthy,
                    detail: "Per-process resource and open-file samples; permission gaps recorded in evidence; no memory content or file-read syscall capture")
            }
        }
    }

    private func captureNetwork(targets: [ProcessSnapshotRecord]? = nil) {
        guard running, !networkSnapshotInFlight else {
            if networkSnapshotInFlight {
                workingCollectionHealth.skippedNetworkSnapshots += 1
                publishHealthIfNeeded()
            }
            return
        }
        networkSnapshotInFlight = true
        let started = Date()
        let hookTrigger = pendingNetworkTriggers.isEmpty ? nil : pendingNetworkTriggers.keys.sorted().joined(separator: ",")
        let trigger = hookTrigger ?? (targets == nil ? nil : "new_process_attached")
        pendingNetworkTriggers.removeAll()
        let sampledProcesses = hookTrigger == nil ? (targets ?? observedProcesses) : hookCorrelation.samplingTargets(observedProcesses)
        guard !sampledProcesses.isEmpty else { networkSnapshotInFlight = false; return }
        let agentPIDs = sampledProcesses.map(\.pid)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let connections = self.networkProvider.snapshot(pids: agentPIDs)
            let observedAt = Date()
            let validatedProcesses = sampledProcesses.filter {
                guard let pid = Int32($0.pid), let birth = $0.birthIdentity else { return false }
                return LibprocProcessActivitySampler.birthIdentity(pid) == birth
            }
            let socketEvents = self.observationCoordinator.observeSockets(processes: validatedProcesses, connections: connections, trigger: trigger)
            let ipcRecords = LsofUnixSocketSnapshotProvider().snapshot(pids: agentPIDs)
            let ipcProcesses = validatedProcesses.filter {
                guard let pid = Int32($0.pid), let birth = $0.birthIdentity else { return false }
                return LibprocProcessActivitySampler.birthIdentity(pid) == birth
            }
            let ipcEvents = self.observationCoordinator.observeIPC(processes: ipcProcesses, records: ipcRecords, trigger: trigger)
            // A newly attached Git/curl helper may finish before the ten-second
            // sweep. Its first scoped sample needs the same route and network
            // projection as a periodic sample.
            let proxyDestinations = self.proxyDestinationProvider.snapshot()
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.networkSnapshotInFlight = false
                guard self.running else { return }
                self.onEvents?(socketEvents + ipcEvents)
                if !self.pendingNetworkTriggers.isEmpty { self.captureNetwork() }
                self.workingCollectionHealth.lastNetworkDurationMS = Date().timeIntervalSince(started) * 1_000
                self.workingCollectionHealth.lastNetworkSuccess = Date()
                self.processNetwork(processes: validatedProcesses, connections: connections,
                                    proxyDestinations: proxyDestinations, observedAt: observedAt)
                self.persistHealth(source: "network", state: .healthy,
                                   detail: "Socket evidence is sampled and may miss short connections")
                self.publishHealthIfNeeded()
            }
        }
    }

    func stop() {
        running = false
        for observer in applicationObservers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
        applicationObservers.removeAll()
        previousProcesses.removeAll()
        processTimer?.invalidate()
        networkTimer?.invalidate()
        observationTimer?.invalidate()
        observationTimer = nil
        observedProcesses.removeAll()
        observationCoordinator.reset()
        hookCorrelation.reset(); receivedHookIDs.removeAll()
        pendingResourceTriggers.removeAll(); pendingNetworkTriggers.removeAll()
        processTimer = nil
        networkTimer = nil
        processSnapshotInFlight = false
        networkSnapshotInFlight = false
    }

    // MARK: - 内部

    /// AgentReins may be launched from an agent-owned terminal during
    /// development. Without this boundary the collector, its `lsof` helper and
    /// scanner children are attributed back to that agent, creating both false
    /// process lineage and a self-observation redraw loop.
    nonisolated private func excludingCollectorTree(
        _ processes: [SnapshotProcess]
    ) -> [SnapshotProcess] {
        var excluded: Set<String> = [String(ProcessInfo.processInfo.processIdentifier)]
        var changed = true
        while changed {
            changed = false
            for process in processes where excluded.contains(process.ppid) {
                if excluded.insert(process.pid).inserted { changed = true }
            }
        }
        return processes.filter { !excluded.contains($0.pid) }
    }

    /// 主线程执行：对后台取到的进程快照做匹配与事件上报（匹配很轻量，不会阻塞 UI）。
    private func process(procs: [SnapshotProcess],
                         attributions: [String: String]) {
        let detectedAgents = Array(Set(attributions.values)).sorted()
        if detectedAgents != activeAgents { activeAgents = detectedAgents }
        let agentProcesses = procs.filter { attributions[$0.pid] != nil }
        let liveKeys = Set(agentProcesses.map { "\($0.pid)|\($0.birth ?? 0)|\($0.cmd)" })
        seen.formIntersection(liveKeys)
        var newEvents: [GuardEvent] = []
        let currentProcesses = Dictionary(uniqueKeysWithValues: agentProcesses.map { ($0.pid, $0) })
        for (pid, previous) in previousProcesses where currentProcesses[pid] == nil || currentProcesses[pid]?.birth != previous.birth {
            newEvents.append(GuardEvent(kind: "activity", ruleId: "activity_process_exit", path: "-",
                command: previous.cmd, agent: previous.agent, op: "process_exit", severity: "info",
                ts: Date(), action: "observed", source: snapshotProvider.sourceID,
                attributionConfidence: .inferred, attributionMethod: "process disappeared from scoped snapshot",
                processId: Int32(pid), parentProcessId: Int32(previous.ppid)))
        }
        previousProcesses = currentProcesses
        for p in agentProcesses {
            let processKey = "\(p.pid)|\(p.birth ?? 0)|\(p.cmd)"
            if seen.contains(processKey) { continue }
            seen.insert(processKey)
            guard let agent = attributions[p.pid], Self.isTargetAgent(agent) else { continue }
            let matched = currentCmdRules.filter { $0.regex.firstMatch(in: p.cmd,
                range: NSRange(p.cmd.startIndex..., in: p.cmd)) != nil }
            for r in matched {
                newEvents.append(makeEvent(rule: r, command: p.cmd, agent: agent,
                                           pid: p.pid, ppid: p.ppid))
                notify(title: "AgentReins observed a command", body: "\(r.message) · \(p.cmd)")
            }
            if matched.isEmpty {
                newEvents.append(makeActivityEvent(command: p.cmd, agent: agent,
                                                   pid: p.pid, ppid: p.ppid))
            }
        }
        guard !newEvents.isEmpty else { return }
        workingCollectionHealth.acceptedProcessEvents += newEvents.count
        events.insert(contentsOf: newEvents, at: 0)
        if events.count > 300 { events.removeLast(events.count - 300) }
        onEvents?(newEvents)
    }

    private func processNetwork(processes: [ProcessSnapshotRecord],
                                connections: [NetworkConnectionRecord],
                                proxyDestinations: [ProxyDestinationRecord], observedAt: Date) {
        for destination in proxyDestinations {
            if let existing = recentProxyDestinations[destination.clientPort],
               existing.timestamp >= destination.timestamp { continue }
            recentProxyDestinations[destination.clientPort] = destination
        }
        let cutoff = Date().addingTimeInterval(-300)
        recentProxyDestinations = recentProxyDestinations.filter { $0.value.timestamp >= cutoff }
        let connectionCutoff = Date().addingTimeInterval(-300)
        seenConnections = seenConnections.filter { $0.value >= connectionCutoff }
        let projected = NetworkSocketEvidenceProjector.project(processes: processes,
            connections: connections, proxyDestinations: Array(recentProxyDestinations.values),
            observedAt: observedAt, source: networkProvider.sourceID)
        let networkEvents = projected.filter { event in
            let identity = event.id.uuidString
            guard seenConnections[identity] == nil else { return false }
            seenConnections[identity] = Date(); return true
        }
        guard !networkEvents.isEmpty else { return }
        workingCollectionHealth.acceptedNetworkEvents += networkEvents.count
        events.insert(contentsOf: networkEvents, at: 0)
        if events.count > 300 { events.removeLast(events.count - 300) }
        onEvents?(networkEvents)
    }

    /// 过滤 Agent 自身常驻服务，只保留能帮助用户理解“它正在做什么”的短生命周期命令。
    private func isUserActivity(_ command: String) -> Bool {
        let text = command.lowercased()
        let noise = ["crashpad", "mcp-server", "--prewarm", "electron framework", "agentreins", "ps -eo"]
        if noise.contains(where: text.contains) { return false }
        let activity = ["/bin/zsh", "/bin/bash", "python", "node ", "git ", "curl ", "wget ", "swift ", "npm ", "npx ", "make "]
        return activity.contains(where: text.contains)
    }

    private nonisolated func getProcs() -> [SnapshotProcess] {
        snapshotProvider.snapshot().map { ($0.pid, $0.ppid, $0.command, $0.agent, $0.birthIdentity, $0.executablePath) }
    }

    /// The OS snapshot is only a transient discovery index. Find explicit
    /// agent roots first, then walk downward through their children. Unrelated
    /// machine processes are neither attributed, retained, nor published.
    private func attributions(byPid: [String: (ppid: String, cmd: String, agent: String?)]) -> [String: String] {
        var children: [String: [String]] = [:]
        for (pid, node) in byPid { children[node.ppid, default: []].append(pid) }

        var result: [String: String] = [:]
        var queue: [(pid: String, owner: String)] = []
        for (pid, node) in byPid {
            if let owner = node.agent, Self.isTargetAgent(owner) {
                result[pid] = owner
                queue.append((pid, owner))
                continue
            }
            if let marker = Self.targetExecutableOwner(node.cmd) {
                result[pid] = marker
                queue.append((pid, marker))
            }
        }
        var index = 0
        while index < queue.count {
            let current = queue[index]
            index += 1
            for child in children[current.pid] ?? [] where result[child] == nil {
                result[child] = current.owner
                queue.append((child, current.owner))
            }
        }
        return result
    }

    nonisolated static func targetExecutableOwner(_ command: String) -> String? {
        // Arguments/project paths mentioning an agent are not ownership evidence.
        guard let executable = command.split(whereSeparator: { $0.isWhitespace }).first else { return nil }
        let name = URL(fileURLWithPath: String(executable)).lastPathComponent.lowercased()
        if name == "codex" || name.hasPrefix("codex-") { return "codex" }
        if name == "workbuddy" { return "workbuddy" }
        return nil
    }

    nonisolated static func isTargetAgent(_ agent: String) -> Bool {
        ["codex", "chatgpt", "workbuddy"].contains(agent.lowercased())
    }

    private func canonicalAgent(_ marker: String?) -> String? {
        switch marker {
        case "chatgpt", "codex": return "codex"
        default: return marker
        }
    }

    private func makeEvent(rule: CmdRule, command: String, agent: String?, pid: String, ppid: String) -> GuardEvent {
        GuardEvent(kind: "cmd", ruleId: rule.id, path: "-", command: command, agent: agent,
                            op: "exec", severity: rule.severity, ts: Date(), action: "seen",
                            source: evidenceSource.id, attributionConfidence: .unknown,
                            attributionMethod: "awaiting turn correlation",
                            processId: Int32(pid), parentProcessId: Int32(ppid))
    }

    private func makeActivityEvent(command: String, agent: String, pid: String, ppid: String) -> GuardEvent {
        GuardEvent(kind: "activity", ruleId: "activity_process", path: "-", command: command,
                            agent: agent, op: "exec", severity: "info", ts: Date(), action: "observed",
                            source: evidenceSource.id, attributionConfidence: .unknown,
                            attributionMethod: "awaiting turn correlation",
                            processId: Int32(pid), parentProcessId: Int32(ppid))
    }

    private func notify(title: String, body: String) {
        AppNotifier.send(title: title, body: body)
    }

    private func persistHealth(source: String, state: CollectorHealthRecord.State, detail: String?) {
        let now = Date()
        if state != .failed, let last = lastHealthPersist[source], now.timeIntervalSince(last) < 10 { return }
        lastHealthPersist[source] = now
        let isProcess = source == "process"
        evidenceDatabase?.enqueueHealth(CollectorHealthRecord(
            source: source, state: state,
            lastSuccess: isProcess ? workingCollectionHealth.lastProcessSuccess : workingCollectionHealth.lastNetworkSuccess,
            lagSeconds: nil,
            accepted: isProcess ? workingCollectionHealth.acceptedProcessEvents : workingCollectionHealth.acceptedNetworkEvents,
            malformed: isProcess ? workingCollectionHealth.processFailures : workingCollectionHealth.networkFailures,
            dropped: isProcess ? workingCollectionHealth.skippedProcessSnapshots : workingCollectionHealth.skippedNetworkSnapshots,
            detail: detail))
    }

    private func publishHealthIfNeeded(force: Bool = false) {
        guard force || Date().timeIntervalSince(lastHealthPublish) >= 5 else { return }
        lastHealthPublish = Date()
        if collectionHealth != workingCollectionHealth {
            collectionHealth = workingCollectionHealth
        }
    }
}
