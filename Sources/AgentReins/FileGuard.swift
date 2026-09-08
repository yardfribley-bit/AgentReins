import Foundation
import SwiftUI

/// 文件护栏：轮询受保护文件，命中删除/修改则按规则从备份还原 + 通知。
/// （MVP 用轮询；生产级实时拦截见 agentguard-esf 的 Endpoint Security Framework。）
///
/// 注意：所有文件 I/O（fileExists / copyItem / attributesOfItem）都放到后台串行队列执行，
/// 绝不在主线程同步等待——否则访问 ~/.ssh、~/Library/Application Support/Kiro 等受 TCC
/// 保护的目录时，macOS 弹权限窗会让主线程挂起，导致整个 App 转圈圈卡死。
/// UI 相关的 @Published 属性只在主线程写回。
final class FileGuard: ObservableObject {
    @Published var events: [GuardEvent] = []
    @Published var running = false
    var currentRules: [Rule] = []
    var onEvent: ((GuardEvent) -> Void)?
    private let backupRoot: URL
    private let bgQueue = DispatchQueue(label: "com.agentspec.fileguard.bg", qos: .utility)
    private var timer: Timer?
    private var lastMtime: [String: Date] = [:]
    private var lastContent: [String: String] = [:]
    private let lock = NSLock()

    static func defaultBackupRoot() -> URL {
        let appSup = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSup.appendingPathComponent("AgentGuard/backups", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    init(backupRoot: URL = FileGuard.defaultBackupRoot()) { self.backupRoot = backupRoot }

    /// 规则变化时由 UI 同步进来（主线程调用）。后台建立备份，不阻塞 UI。
    func setRules(_ r: [Rule]) {
        currentRules = r
        bgQueue.async { self.ensureBackups() }
    }

    func start() {
        guard !running else { return }
        DispatchQueue.main.async { self.running = true }
        bgQueue.async { self.ensureBackups() }
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.bgQueue.async { self?.poll() }
        }
    }

    func stop() {
        DispatchQueue.main.async { self.running = false }
        timer?.invalidate()
        timer = nil
    }

    // MARK: - 后台文件 I/O（均在 bgQueue 串行执行，不碰主线程）

    private func ensureBackups() {
        let fm = FileManager.default
        let rules = currentRules
        for rule in rules where rule.isProtect {
            for w in rule.watch ?? [] {
                let url = URL(fileURLWithPath: (w as NSString).expandingTildeInPath)
                let backup = backupURL(url: url, ruleId: rule.id)
                if fm.fileExists(atPath: url.path), !fm.fileExists(atPath: backup.path) {
                    try? fm.copyItem(at: url, to: backup)
                }
                if fm.fileExists(atPath: url.path) {
                    lock.lock(); defer { lock.unlock() }
                    lastMtime[url.path] = mtime(of: url.path)
                    lastContent[url.path] = textContent(at: url)
                }
            }
        }
    }

    private func poll() {
        let fm = FileManager.default
        let rules = currentRules
        var pending: [(rule: Rule, path: String, op: String, action: String, before: String?, after: String?, diff: String?, findings: [CodeFinding])] = []
        for rule in rules where rule.isProtect {
            for w in rule.watch ?? [] {
                let url = URL(fileURLWithPath: (w as NSString).expandingTildeInPath)
                let exists = fm.fileExists(atPath: url.path)
                let backup = backupURL(url: url, ruleId: rule.id)
                if !exists {
                    if (rule.opsSet.contains("delete") || rule.opsSet.contains("modify")),
                       fm.fileExists(atPath: backup.path) {
                        lock.lock()
                        let before = lastContent[url.path]
                        lastContent[url.path] = nil
                        lock.unlock()
                        try? fm.copyItem(at: backup, to: url)   // 还原
                        lock.lock()
                        lastMtime[url.path] = mtime(of: url.path)
                        lastContent[url.path] = textContent(at: url)
                        lock.unlock()
                        pending.append((rule, url.path, "delete", "restored", before, nil,
                                        makeDiff(before: before, after: nil), []))
                    }
                } else {
                    let now = mtime(of: url.path)
                    let current = textContent(at: url)
                    lock.lock()
                    let last = lastMtime[url.path]
                    let before = lastContent[url.path]
                    lastMtime[url.path] = now
                    lastContent[url.path] = current
                    lock.unlock()
                    if let last, last < now {
                        if rule.opsSet.contains("modify") {
                            let diff = makeDiff(before: before, after: current)
                            let findings = CodeSecurityScanner.scan(path: url.path, before: before, after: current)
                            if rule.restore == true, fm.fileExists(atPath: backup.path) {
                                try? fm.removeItem(at: url)
                                try? fm.copyItem(at: backup, to: url)   // 还原修改
                                lock.lock()
                                lastMtime[url.path] = mtime(of: url.path)
                                lastContent[url.path] = textContent(at: url)
                                lock.unlock()
                                pending.append((rule, url.path, "modify", "restored", before, current, diff, findings))
                            } else {
                                pending.append((rule, url.path, "modify", "alert", before, current, diff, findings))
                            }
                        }
                    }
                    if !fm.fileExists(atPath: backup.path) {
                        try? fm.copyItem(at: url, to: backup)
                    }
                }
            }
        }
        if !pending.isEmpty {
            DispatchQueue.main.async {
                for item in pending {
                    self.emit(rule: item.rule, path: item.path, op: item.op, action: item.action,
                              before: item.before, after: item.after, diff: item.diff, findings: item.findings)
                }
            }
        }
    }

    private func backupURL(url: URL, ruleId: String) -> URL {
        let name = url.path.replacingOccurrences(of: "/", with: "_")
        return backupRoot.appendingPathComponent("\(ruleId)__\(name)")
    }

    private func mtime(of path: String) -> Date {
        (try? FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date) ?? Date.distantPast
    }

    private func textContent(at url: URL) -> String? {
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey]), values.isRegularFile == true,
              let data = try? Data(contentsOf: url), data.count <= 512_000 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func makeDiff(before: String?, after: String?) -> String? {
        guard before != after else { return nil }
        let oldLines = (before ?? "").components(separatedBy: .newlines)
        let newLines = (after ?? "").components(separatedBy: .newlines)
        var output = ["--- before", "+++ after"]
        let count = max(oldLines.count, newLines.count)
        for index in 0..<count {
            let old = index < oldLines.count ? oldLines[index] : nil
            let new = index < newLines.count ? newLines[index] : nil
            guard old != new else { continue }
            if let old { output.append("-\(old)") }
            if let new { output.append("+\(new)") }
            if output.count >= 2_000 { output.append("… diff truncated …"); break }
        }
        return output.joined(separator: "\n")
    }

    // MARK: - 主线程 UI 更新

    private func emit(rule: Rule, path: String, op: String, action: String,
                      before: String?, after: String?, diff: String?, findings: [CodeFinding]) {
        let rank = ["medium": 1, "high": 2, "critical": 3]
        let findingSeverity = findings.max { rank[$0.severity, default: 0] < rank[$1.severity, default: 0] }?.severity
        let sev = findingSeverity ?? (rule.severity.isEmpty ? "high" : rule.severity)
        let ev = GuardEvent(kind: "file", ruleId: rule.id, path: path, command: nil, agent: nil,
                            op: op, severity: sev, ts: Date(), action: action,
                            beforeContent: before, afterContent: after, fileDiff: diff,
                            codeFindings: findings,
                            source: "fileguard")
        events.insert(ev, at: 0)
        if events.count > 200 { events.removeLast() }
        onEvent?(ev)
        notify(title: "AgentReins 已干预", body: "\(action) · \(op) · \(path)")
    }

    private func notify(title: String, body: String) {
        AppNotifier.send(title: title, body: body)
    }
}
