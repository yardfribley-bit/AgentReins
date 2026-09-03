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
    private let backupRoot: URL
    private let bgQueue = DispatchQueue(label: "com.agentspec.fileguard.bg", qos: .utility)
    private var timer: Timer?
    private var lastMtime: [String: Date] = [:]
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
                }
            }
        }
    }

    private func poll() {
        let fm = FileManager.default
        let rules = currentRules
        var pending: [(Rule, String, String, String)] = []
        for rule in rules where rule.isProtect {
            for w in rule.watch ?? [] {
                let url = URL(fileURLWithPath: (w as NSString).expandingTildeInPath)
                let exists = fm.fileExists(atPath: url.path)
                let backup = backupURL(url: url, ruleId: rule.id)
                if !exists {
                    if (rule.opsSet.contains("delete") || rule.opsSet.contains("modify")),
                       fm.fileExists(atPath: backup.path) {
                        try? fm.copyItem(at: backup, to: url)   // 还原
                        pending.append((rule, url.path, "delete", "restored"))
                    }
                } else {
                    let now = mtime(of: url.path)
                    lock.lock()
                    let last = lastMtime[url.path]
                    lastMtime[url.path] = now
                    lock.unlock()
                    if let last, last < now {
                        if rule.opsSet.contains("modify") {
                            if rule.restore == true, fm.fileExists(atPath: backup.path) {
                                try? fm.copyItem(at: backup, to: url)   // 还原修改
                                pending.append((rule, url.path, "modify", "restored"))
                            } else {
                                pending.append((rule, url.path, "modify", "alert"))
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
                for (rule, path, op, action) in pending { self.emit(rule: rule, path: path, op: op, action: action) }
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

    // MARK: - 主线程 UI 更新

    private func emit(rule: Rule, path: String, op: String, action: String) {
        let sev = rule.severity.isEmpty ? "high" : rule.severity
        let ev = GuardEvent(kind: "file", ruleId: rule.id, path: path, command: nil, agent: nil,
                            op: op, severity: sev, ts: Date(), action: action)
        events.insert(ev, at: 0)
        if events.count > 200 { events.removeLast() }
        notify(title: "AgentReins 已干预", body: "\(action) · \(op) · \(path)")
    }

    private func notify(title: String, body: String) {
        let n = NSUserNotification()
        n.title = title
        n.informativeText = body
        NSUserNotificationCenter.default.deliver(n)
    }
}
