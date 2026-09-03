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

    private var timer: Timer?
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
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self else { return }
            DispatchQueue.global(qos: .utility).async {
                let procs = self.getProcs()
                Task { @MainActor in self.process(procs: procs) }
            }
        }
    }

    func stop() {
        running = false
        timer?.invalidate()
        timer = nil
    }

    // MARK: - 内部

    /// 主线程执行：对后台取到的进程快照做匹配与事件上报（匹配很轻量，不会阻塞 UI）。
    private func process(procs: [(pid: String, ppid: String, cmd: String)]) {
        for p in procs {
            if seen.contains(p.cmd) { continue }
            seen.insert(p.cmd)
            for r in currentCmdRules where r.regex.firstMatch(in: p.cmd,
                    range: NSRange(p.cmd.startIndex..., in: p.cmd)) != nil {
                let agent = attribute(procs: procs, pid: p.pid)
                emit(rule: r, command: p.cmd, agent: agent)
            }
        }
        if seen.count > 5000 { seen.removeAll() }
    }

    private nonisolated func getProcs() -> [(pid: String, ppid: String, cmd: String)] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-eo", "pid,ppid,user,command"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            return []
        }
        guard let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) else { return [] }
        var result: [(pid: String, ppid: String, cmd: String)] = []
        for line in out.split(whereSeparator: \.isNewline).dropFirst() {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 4 else { continue }
            let pid = String(parts[0]); let ppid = String(parts[1])
            let cmd = parts[3...].joined(separator: " ")
            result.append((pid: pid, ppid: ppid, cmd: cmd))
        }
        return result
    }

    /// 沿进程树向上回溯，找到包含 agent marker 的祖先进程，即命令的归属 agent。
    private func attribute(procs: [(pid: String, ppid: String, cmd: String)], pid: String) -> String? {
        var byPid: [String: (ppid: String, cmd: String)] = [:]
        for p in procs { byPid[p.pid] = (p.ppid, p.cmd) }
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
        notify(title: "AgentReins 监测到命令", body: "\(rule.message) · \(command)")
    }

    private func notify(title: String, body: String) {
        let n = NSUserNotification()
        n.title = title
        n.informativeText = body
        NSUserNotificationCenter.default.deliver(n)
    }
}
