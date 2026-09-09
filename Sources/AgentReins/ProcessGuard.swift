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

    private var timer: Timer?
    private var snapshotInFlight = false
    private var seen: Set<String> = []
    private var currentCmdRules: [CmdRule] = []
    private let agentMarkers = ["codex", "kiro", "cursor", "workbuddy", "claude", "aider", "windsurf", "trae"]

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

    init() { currentCmdRules = ProcessGuard.builtin }

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
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.snapshotInFlight else { return }
                self.snapshotInFlight = true
                DispatchQueue.global(qos: .utility).async {
                    let procs = self.getProcs()
                    Task { @MainActor in
                        self.process(procs: procs)
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
    private func process(procs: [(pid: String, ppid: String, cmd: String)]) {
        let byPid = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, (ppid: $0.ppid, cmd: $0.cmd)) })
        let attributions = Dictionary(uniqueKeysWithValues: procs.map { ($0.pid, attribute(byPid: byPid, pid: $0.pid)) })
        let detectedAgents = Array(Set(attributions.values.compactMap { $0 })).sorted()
        if detectedAgents != activeAgents { activeAgents = detectedAgents }
        for p in procs {
            if seen.contains(p.cmd) { continue }
            seen.insert(p.cmd)
            let agent = attributions[p.pid] ?? nil
            let matched = currentCmdRules.filter { $0.regex.firstMatch(in: p.cmd,
                range: NSRange(p.cmd.startIndex..., in: p.cmd)) != nil }
            for r in matched {
                emit(rule: r, command: p.cmd, agent: agent)
            }
            if matched.isEmpty, let agent, isUserActivity(p.cmd) {
                emitActivity(command: p.cmd, agent: agent)
            }
        }
        if seen.count > 5000 { seen.removeAll() }
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
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-axo", "pid=,ppid=,command="]
        let pipe = Pipe()
        proc.standardOutput = pipe
        do {
            try proc.run()
        } catch {
            return []
        }
        // Drain stdout while ps is running. Waiting first can deadlock once verbose
        // agent command lines fill the pipe buffer.
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        guard let out = String(data: data, encoding: .utf8) else { return [] }
        var result: [(pid: String, ppid: String, cmd: String)] = []
        for line in out.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 3 else { continue }
            let pid = String(parts[0]); let ppid = String(parts[1])
            let cmd = parts[2...].joined(separator: " ")
            result.append((pid: pid, ppid: ppid, cmd: cmd))
        }
        return result
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

    private func emit(rule: CmdRule, command: String, agent: String?) {
        let ev = GuardEvent(kind: "cmd", ruleId: rule.id, path: "-", command: command, agent: agent,
                            op: "exec", severity: rule.severity, ts: Date(), action: "seen")
        events.insert(ev, at: 0)
        if events.count > 300 { events.removeLast() }
        onEvent?(ev)
        notify(title: "AgentReins 监测到命令", body: "\(rule.message) · \(command)")
    }

    private func emitActivity(command: String, agent: String) {
        let ev = GuardEvent(kind: "activity", ruleId: "activity_process", path: "-", command: command,
                            agent: agent, op: "exec", severity: "info", ts: Date(), action: "observed")
        events.insert(ev, at: 0)
        if events.count > 300 { events.removeLast() }
        onEvent?(ev)
    }

    private func notify(title: String, body: String) {
        AppNotifier.send(title: title, body: body)
    }
}
