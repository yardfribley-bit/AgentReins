import Foundation
import SwiftUI

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
    @Published var events: [GuardEvent] = []
    @Published var running = false
    @Published private(set) var activeAgents: [String] = []
    var onEvent: ((GuardEvent) -> Void)?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var snapshotInFlight = false
    private var seen: Set<String> = []
    private var seenConnections: Set<String> = []
    private var currentCmdRules: [CmdRule] = []
    private let agentMarkers = ["codex", "kiro", "cursor", "workbuddy", "claude", "aider", "windsurf", "trae"]
    private let snapshotProvider: any ProcessSnapshotting
    private let networkProvider: any NetworkSnapshotting

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
         networkProvider: (any NetworkSnapshotting)? = nil) {
        currentCmdRules = ProcessGuard.builtin
        self.snapshotProvider = snapshotProvider ?? ResilientProcessSnapshotProvider(agentMarkers: agentMarkers)
        self.networkProvider = networkProvider ?? LsofNetworkSnapshotProvider()
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
        // ps 的子进程调用放到后台线程，避免主线程阻塞（首次 ps 触发 TCC 时不会卡 UI）。
        // Native agent events provide the two-second live path. Process attribution
        // is a fallback and does not justify running a full ps snapshot that often.
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.snapshotInFlight else { return }
                self.snapshotInFlight = true
                DispatchQueue.global(qos: .utility).async {
                    let procs = self.getProcs()
                    let connections = self.networkProvider.snapshot()
                    Task { @MainActor in
                        self.process(procs: procs, connections: connections)
                        self.snapshotInFlight = false
                    }
                }
            }
        }
    }

    func stop() {
        running = false
        timer?.invalidate()
        timer = nil
        snapshotInFlight = false
    }

    // MARK: - 内部

    /// 主线程执行：对后台取到的进程快照做匹配与事件上报（匹配很轻量，不会阻塞 UI）。
    private func process(procs: [(pid: String, ppid: String, cmd: String)],
                         connections: [NetworkConnectionRecord]) {
        let byPid = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, (ppid: $0.ppid, cmd: $0.cmd)) })
        let attributions = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, attribute(byPid: byPid, pid: $0.pid)) })
        let detectedAgents = Array(Set(attributions.values.compactMap { $0 })).sorted()
        if detectedAgents != activeAgents { activeAgents = detectedAgents }
        let liveKeys = Set(procs.map { "\($0.pid)|\($0.cmd)" })
        seen.formIntersection(liveKeys)
        for p in procs {
            let processKey = "\(p.pid)|\(p.cmd)"
            if seen.contains(processKey) { continue }
            seen.insert(processKey)
            let agent = attributions[p.pid] ?? nil
            let matched = currentCmdRules.filter { $0.regex.firstMatch(in: p.cmd,
                range: NSRange(p.cmd.startIndex..., in: p.cmd)) != nil }
            for r in matched {
                emit(rule: r, command: p.cmd, agent: agent, pid: p.pid, ppid: p.ppid)
            }
            if matched.isEmpty, let agent, isUserActivity(p.cmd) {
                emitActivity(command: p.cmd, agent: agent, pid: p.pid, ppid: p.ppid)
            }
        }
        let agentConnections = connections.filter { (attributions[$0.pid] ?? nil) != nil }
        seenConnections.formIntersection(Set(agentConnections.map(\.identity)))
        var networkEvents: [GuardEvent] = []
        for connection in agentConnections where seenConnections.insert(connection.identity).inserted {
            if let agent = attributions[connection.pid] ?? nil {
                networkEvents.append(makeNetworkEvent(connection, agent: agent))
            }
        }
        guard !networkEvents.isEmpty else { return }
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

    /// 沿进程树向上回溯，找到包含 agent marker 的祖先进程，即命令的归属 agent。
    private func attribute(byPid: [String: (ppid: String, cmd: String)], pid: String) -> String? {
        var visited = Set<String>()
        var cur = pid
        while let node = byPid[cur], !visited.contains(cur) {
            visited.insert(cur)
            let cl = node.cmd.lowercased()
            for m in agentMarkers where cl.contains(m) { return m }
            cur = node.ppid
        }
        return nil
    }

    private func emit(rule: CmdRule, command: String, agent: String?, pid: String, ppid: String) {
        let ev = GuardEvent(kind: "cmd", ruleId: rule.id, path: "-", command: command, agent: agent,
                            op: "exec", severity: rule.severity, ts: Date(), action: "seen",
                            source: evidenceSource.id, attributionConfidence: .unknown,
                            attributionMethod: "awaiting turn correlation",
                            processId: Int32(pid), parentProcessId: Int32(ppid))
        events.insert(ev, at: 0)
        if events.count > 300 { events.removeLast() }
        onEvent?(ev)
        notify(title: "AgentReins 监测到命令", body: "\(rule.message) · \(command)")
    }

    private func emitActivity(command: String, agent: String, pid: String, ppid: String) {
        let ev = GuardEvent(kind: "activity", ruleId: "activity_process", path: "-", command: command,
                            agent: agent, op: "exec", severity: "info", ts: Date(), action: "observed",
                            source: evidenceSource.id, attributionConfidence: .unknown,
                            attributionMethod: "awaiting turn correlation",
                            processId: Int32(pid), parentProcessId: Int32(ppid))
        events.insert(ev, at: 0)
        if events.count > 300 { events.removeLast() }
        onEvent?(ev)
    }

    private func makeNetworkEvent(_ connection: NetworkConnectionRecord, agent: String) -> GuardEvent {
        GuardEvent(kind: "network", ruleId: "network_connection", path: "-",
                   command: nil, agent: agent, op: "connect", severity: "info",
                   ts: Date(), action: "observed", source: networkProvider.sourceID,
                   attributionConfidence: .inferred,
                   attributionMethod: "lsof socket owner + process-tree agent",
                   processId: Int32(connection.pid),
                   localAddress: connection.localAddress,
                   remoteHost: connection.remoteHost, remotePort: connection.remotePort)
    }

    private func notify(title: String, body: String) {
        AppNotifier.send(title: title, body: body)
    }
}
