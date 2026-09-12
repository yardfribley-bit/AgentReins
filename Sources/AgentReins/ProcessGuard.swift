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

    private var processTimer: Timer?
    private var networkTimer: Timer?
    private var processSnapshotInFlight = false
    private var networkSnapshotInFlight = false
    private var latestProcesses: [(pid: String, ppid: String, cmd: String)] = []
    private var seen: Set<String> = []
    private var seenConnections: [String: Date] = [:]
    private var currentCmdRules: [CmdRule] = []
    private let agentMarkers = ["codex", "kiro", "cursor", "workbuddy", "qoder", "claude", "aider", "windsurf", "trae"]
    private let snapshotProvider: any ProcessSnapshotting
    private let networkProvider: any NetworkSnapshotting
    private let proxyDestinationProvider: any ProxyDestinationSnapshotting
    private var recentProxyDestinations: [Int: ProxyDestinationRecord] = [:]
    private let evidenceDatabase = try? EvidenceDatabase()
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
        processTimer?.fire()
        networkTimer?.fire()
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
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.processSnapshotInFlight = false
                self.workingCollectionHealth.lastProcessDurationMS = Date().timeIntervalSince(started) * 1_000
                guard !procs.isEmpty else {
                    self.workingCollectionHealth.processFailures += 1
                    self.publishHealthIfNeeded()
                    self.persistHealth(source: "process", state: .failed,
                                       detail: "The process provider returned an empty snapshot")
                    return
                }
                self.workingCollectionHealth.lastProcessSuccess = Date()
                self.latestProcesses = procs
                let byPid = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, (ppid: $0.ppid, cmd: $0.cmd)) })
                let attributions = self.attributions(byPid: byPid)
                let inventory = procs.filter { attributions[$0.pid] != nil }.map {
                    ProcessSnapshotRecord(pid: $0.pid, ppid: $0.ppid, command: $0.cmd)
                }.sorted { lhs, rhs in
                    (Int(lhs.pid) ?? 0) < (Int(rhs.pid) ?? 0)
                }
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
                self.persistHealth(source: "process", state: .healthy, detail: nil)
                self.publishHealthIfNeeded()
            }
        }
    }

    private func captureNetwork() {
        guard running, !networkSnapshotInFlight else {
            if networkSnapshotInFlight {
                workingCollectionHealth.skippedNetworkSnapshots += 1
                publishHealthIfNeeded()
            }
            return
        }
        networkSnapshotInFlight = true
        let started = Date()
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let connections = self.networkProvider.snapshot()
            let proxyDestinations = self.proxyDestinationProvider.snapshot()
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.networkSnapshotInFlight = false
                self.workingCollectionHealth.lastNetworkDurationMS = Date().timeIntervalSince(started) * 1_000
                self.workingCollectionHealth.lastNetworkSuccess = Date()
                self.processNetwork(procs: self.latestProcesses, connections: connections,
                                    proxyDestinations: proxyDestinations)
                self.persistHealth(source: "network", state: .healthy,
                                   detail: "Socket evidence is sampled and may miss short connections")
                self.publishHealthIfNeeded()
            }
        }
    }

    func stop() {
        running = false
        processTimer?.invalidate()
        networkTimer?.invalidate()
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
        _ processes: [(pid: String, ppid: String, cmd: String)]
    ) -> [(pid: String, ppid: String, cmd: String)] {
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
    private func process(procs: [(pid: String, ppid: String, cmd: String)],
                         attributions: [String: String]) {
        let detectedAgents = Array(Set(attributions.values)).sorted()
        if detectedAgents != activeAgents { activeAgents = detectedAgents }
        let agentProcesses = procs.filter { attributions[$0.pid] != nil }
        let liveKeys = Set(agentProcesses.map { "\($0.pid)|\($0.cmd)" })
        seen.formIntersection(liveKeys)
        var newEvents: [GuardEvent] = []
        for p in agentProcesses {
            let processKey = "\(p.pid)|\(p.cmd)"
            if seen.contains(processKey) { continue }
            seen.insert(processKey)
            let agent = attributions[p.pid]
            let matched = currentCmdRules.filter { $0.regex.firstMatch(in: p.cmd,
                range: NSRange(p.cmd.startIndex..., in: p.cmd)) != nil }
            for r in matched {
                newEvents.append(makeEvent(rule: r, command: p.cmd, agent: agent,
                                           pid: p.pid, ppid: p.ppid))
                notify(title: "AgentReins observed a command", body: "\(r.message) · \(p.cmd)")
            }
            if matched.isEmpty, let agent, isUserActivity(p.cmd) {
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

    private func processNetwork(procs: [(pid: String, ppid: String, cmd: String)],
                                connections: [NetworkConnectionRecord],
                                proxyDestinations: [ProxyDestinationRecord]) {
        let byPid = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, (ppid: $0.ppid, cmd: $0.cmd)) })
        let attributions = attributions(byPid: byPid)
        for destination in proxyDestinations {
            if let existing = recentProxyDestinations[destination.clientPort],
               existing.timestamp >= destination.timestamp { continue }
            recentProxyDestinations[destination.clientPort] = destination
        }
        let cutoff = Date().addingTimeInterval(-300)
        recentProxyDestinations = recentProxyDestinations.filter { $0.value.timestamp >= cutoff }
        let agentConnections = connections
            .filter { attributions[$0.pid] != nil }
            .compactMap(resolveProxyDestination)
        let connectionCutoff = Date().addingTimeInterval(-300)
        seenConnections = seenConnections.filter { $0.value >= connectionCutoff }
        var networkEvents: [GuardEvent] = []
        for connection in agentConnections where seenConnections[connection.identity] == nil {
            seenConnections[connection.identity] = Date()
            if let agent = attributions[connection.pid] {
                networkEvents.append(makeNetworkEvent(connection, agent: agent))
            }
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

    private nonisolated func getProcs() -> [(pid: String, ppid: String, cmd: String)] {
        snapshotProvider.snapshot().map { ($0.pid, $0.ppid, $0.command) }
    }

    /// The OS snapshot is only a transient discovery index. Find explicit
    /// agent roots first, then walk downward through their children. Unrelated
    /// machine processes are neither attributed, retained, nor published.
    private func attributions(byPid: [String: (ppid: String, cmd: String)]) -> [String: String] {
        var children: [String: [String]] = [:]
        for (pid, node) in byPid { children[node.ppid, default: []].append(pid) }

        var result: [String: String] = [:]
        var queue: [(pid: String, owner: String)] = []
        for (pid, node) in byPid {
            let command = node.cmd.lowercased()
            if let marker = agentMarkers.first(where: command.contains) {
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

    private func makeNetworkEvent(_ connection: NetworkConnectionRecord, agent: String) -> GuardEvent {
        let routeEvidence = connection.route.map { " + exact client-port join via \($0) access log" } ?? ""
        let domain = connection.route == nil ? nil : connection.remoteHost
        let destination = NetworkDestinationAssessment.assess(domain: domain, host: connection.remoteHost)
        return GuardEvent(kind: "network", ruleId: "network_connection", path: "-",
                   command: nil, agent: agent, op: "connect",
                   severity: destination.needsAttention ? "medium" : "info",
                   ts: Date(), action: "observed", source: networkProvider.sourceID,
                   attributionConfidence: .inferred,
                   attributionMethod: "lsof socket owner + process-tree agent\(routeEvidence)",
                   processId: Int32(connection.pid),
                   localAddress: connection.localAddress,
                   remoteHost: connection.remoteHost, remotePort: connection.remotePort,
                   remoteDomain: domain)
    }

    private func resolveProxyDestination(_ connection: NetworkConnectionRecord) -> NetworkConnectionRecord? {
        guard isLoopback(connection.remoteHost) else { return connection }
        guard let clientPort = endpointPort(connection.localAddress),
              let destination = recentProxyDestinations[clientPort] else { return nil }
        return NetworkConnectionRecord(pid: connection.pid, localAddress: connection.localAddress,
                                       remoteHost: destination.remoteHost,
                                       remotePort: destination.remotePort,
                                       route: destination.proxyName)
    }

    private func isLoopback(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "::1" || host == "localhost"
    }

    private func endpointPort(_ endpoint: String) -> Int? {
        guard let separator = endpoint.lastIndex(of: ":") else { return nil }
        return Int(endpoint[endpoint.index(after: separator)...])
    }

    private func notify(title: String, body: String) {
        AppNotifier.send(title: title, body: body)
    }

    private func persistHealth(source: String, state: CollectorHealthRecord.State, detail: String?) {
        let now = Date()
        if state != .failed, let last = lastHealthPersist[source], now.timeIntervalSince(last) < 10 { return }
        lastHealthPersist[source] = now
        let isProcess = source == "process"
        try? evidenceDatabase?.updateHealth(CollectorHealthRecord(
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
