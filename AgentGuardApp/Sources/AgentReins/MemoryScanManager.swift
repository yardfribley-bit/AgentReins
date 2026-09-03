import Foundation
import SwiftUI

/// 记忆体审计发现项。
struct MemoryFinding: Identifiable {
    let id = UUID()
    let type: String
    let ruleId: String
    let severity: String
    let src: String
    let line: Int
    let preview: String
    let srcKind: String
    let match: String      // 原始命中文本，供精确打码/删行
}

/// 记忆体敏感信息审计：调起 agentguard-memory-scan.py，解析 --json 的 inventory(结构) + findings(命中)，
/// 并支持对命中片段做「打码 / 删行 / 编辑 / 还原」修正（改前自动备份 .bak）。规则由 MemoryRuleStore 配置。
@MainActor
final class MemoryScanManager: ObservableObject {
    @Published var findings: [MemoryFinding] = []
    @Published var files: [MemoryFile] = []      // 记忆体结构树（按 agent 分组在 UI 做）
    @Published var lastScan: Date?
    @Published var scanning = false
    @Published var autoScan = true
    private var timer: Timer?
    private let autoInterval: TimeInterval = 86400  // 24h
    private var currentRules: [MemoryRule] = []
    /// 当前正在运行的扫描子进程（用于退出时强杀，避免残留 python 进程）。
    private static var scanProcess: Process?

    /// 脚本优先从 App bundle 取，开发期回退到项目内脚本。
    private func scriptURL() -> URL? {
        if let u = Bundle.main.url(forResource: "agentguard-memory-scan", withExtension: "py") { return u }
        let dev = URL(fileURLWithPath: "/Users/jatsmith/AgentSpec/agentguard/agentguard-memory-scan.py")
        return FileManager.default.fileExists(atPath: dev.path) ? dev : nil
    }

    /// 立即扫描。rules 为 nil 时使用最近一次传入的规则（用于定时器）。
    func runScan(rules: [MemoryRule]? = nil) {
        if let r = rules { currentRules = r }
        guard !scanning else { return }
        guard let script = scriptURL() else {
            notify(title: "AgentReins 记忆体审计", body: "找不到扫描脚本 agentguard-memory-scan.py")
            return
        }
        let activeRules = currentRules.filter { $0.enabled }
        if activeRules.isEmpty {
            Task { @MainActor in
                self.findings = []
                self.files = []
                self.lastScan = Date()
            }
            return
        }
        guard let rulesFile = writeRulesFile(rules: activeRules) else {
            notify(title: "AgentReins 记忆体审计", body: "无法生成规则临时文件")
            return
        }
        scanning = true
        // 关键：子进程调用必须放后台，避免 TCC 权限弹窗阻塞主线程导致 App 转圈圈。
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let proc = Process()
            MemoryScanManager.scanProcess = proc
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            proc.arguments = [script.path, "--json", "--no-fail", "--rules-file", rulesFile.path]
            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = Pipe()
            do { try proc.run() }
            catch {
                Task { @MainActor in self?.scanning = false }
                return
            }
            // 超时强杀：TCC 弹窗未处理 / python 未安装 / 目录无权限卡住时，最多等 20s。
            let killer = DispatchWorkItem { proc.terminate() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: killer)
            proc.waitUntilExit()
            killer.cancel()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            var resultFindings: [MemoryFinding] = []
            var resultFiles: [MemoryFile] = []
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let fnd = obj["findings"] as? [[String: Any]] ?? []
                let inv = obj["inventory"] as? [[String: Any]] ?? []
                // findings 按 src 分组，便于挂到文件节点
                var hitsByPath: [String: [MemoryFinding]] = [:]
                for d in fnd {
                    guard let t = d["type"] as? String, let s = d["src"] as? String else { continue }
                    let f = MemoryFinding(
                        type: t,
                        ruleId: d["rule_id"] as? String ?? t,
                        severity: d["severity"] as? String ?? "high",
                        src: s,
                        line: d["line"] as? Int ?? 0,
                        preview: d["preview"] as? String ?? "",
                        srcKind: d["src_kind"] as? String ?? "file",
                        match: d["match"] as? String ?? "")
                    hitsByPath[s, default: []].append(f)
                    resultFindings.append(f)
                }
                for it in inv {
                    guard let p = it["path"] as? String else { continue }
                    resultFiles.append(MemoryFile(
                        agent: it["agent"] as? String ?? "Other",
                        path: p,
                        rel: it["rel"] as? String ?? p,
                        size: it["size"] as? Int ?? 0,
                        kind: it["kind"] as? String ?? "text",
                        sensitiveCount: it["sensitive_count"] as? Int ?? 0,
                        sensitiveTypes: it["sensitive_types"] as? [String] ?? [],
                        hits: hitsByPath[p] ?? [],
                        content: nil))
                }
            }
            Task { @MainActor in
                guard let self else { return }
                self.files = resultFiles
                self.findings = resultFindings
                self.lastScan = Date()
                self.scanning = false
                MemoryScanManager.scanProcess = nil
                if !resultFindings.isEmpty {
                    self.notify(title: "AgentReins 记忆体审计", body: "发现 \(resultFindings.count) 处敏感信息（密钥/令牌）")
                }
            }
        }
    }

    /// 读取文件内容（后台）。SQLite 等二进制返回 nil，由 UI 显示「仅展示命中」。
    func loadContent(path: String, completion: @escaping (String?) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let url = URL(fileURLWithPath: path)
            let ext = url.pathExtension.lowercased()
            if ["db", "sqlite", "sqlite3"].contains(ext) {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            guard let data = try? Data(contentsOf: url),
                  let s = String(data: data, encoding: .utf8) else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            DispatchQueue.main.async { completion(s) }
        }
    }

    /// 对命中片段打码：敏感片段 → ***（仅文本文件）。
    func redact(_ hit: MemoryFinding, completion: @escaping () -> Void) {
        guard hit.srcKind == "file" else { completion(); return }
        editFileLines(hit.src, line: hit.line, match: hit.match, mode: .redact, completion: completion)
    }

    /// 删除命中所在行（仅文本文件）。
    func deleteLine(_ hit: MemoryFinding, completion: @escaping () -> Void) {
        guard hit.srcKind == "file" else { completion(); return }
        editFileLines(hit.src, line: hit.line, match: "", mode: .delete, completion: completion)
    }

    /// 全文件编辑：备份后写回新内容。
    func editFile(path: String, content: String, completion: @escaping () -> Void) {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let url = URL(fileURLWithPath: path)
            self?.backupAndWrite(url: url, content: content)
            DispatchQueue.main.async {
                self?.runScan(rules: self?.currentRules)
                completion()
            }
        }
    }

    /// 从 .bak 还原（撤销最近一次编辑）。
    func restoreBackup(path: String, completion: @escaping () -> Void) {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let url = URL(fileURLWithPath: path)
            let bak = URL(fileURLWithPath: url.path + ".agentreins.bak")
            if FileManager.default.fileExists(atPath: bak.path) {
                try? FileManager.default.removeItem(at: url)
                try? FileManager.default.moveItem(at: bak, to: url)
            }
            DispatchQueue.main.async {
                self?.runScan(rules: self?.currentRules)
                completion()
            }
        }
    }

    func hasBackup(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path + ".agentreins.bak")
    }

    // MARK: - 内部

    private enum EditMode { case redact, delete }

    /// 读原文 → 按行号定位 → 打码或删行 → 备份写回 → 重扫。
    private func editFileLines(_ path: String, line: Int, match: String, mode: EditMode, completion: @escaping () -> Void) {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let url = URL(fileURLWithPath: path)
            guard let data = try? Data(contentsOf: url),
                  let content = String(data: data, encoding: .utf8) else {
                DispatchQueue.main.async { completion() }
                return
            }
            var lines = content.components(separatedBy: "\n")
            if line > 0 && line <= lines.count {
                let i = line - 1
                switch mode {
                case .redact:
                    if !match.isEmpty {
                        lines[i] = lines[i].replacingOccurrences(of: match, with: "***")
                    } else {
                        lines[i] = "***"
                    }
                case .delete:
                    lines.remove(at: i)
                }
            }
            self?.backupAndWrite(url: url, content: lines.joined(separator: "\n"))
            DispatchQueue.main.async {
                self?.runScan(rules: self?.currentRules)
                completion()
            }
        }
    }

    private func backupAndWrite(url: URL, content: String) {
        let bak = URL(fileURLWithPath: url.path + ".agentreins.bak")
        try? FileManager.default.removeItem(at: bak)
        try? FileManager.default.copyItem(at: url, to: bak)
        try? content.write(to: url, atomically: true, encoding: .utf8)
    }

    /// 退出时清理：停定时器并强杀可能残留的扫描子进程。
    static func cleanupOnTerminate() {
        scanProcess?.terminate()
        scanProcess = nil
    }

    /// 定期自动审计：UI 加载完成(延迟2s)后跑首扫，之后每 24h 一次。
    /// 每次触发前通过 rulesProvider 拉取最新的启用规则。
    func startAuto(rulesProvider: @escaping () -> [MemoryRule]) {
        guard autoScan else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.runScan(rules: rulesProvider())
        }
        timer = Timer.scheduledTimer(withTimeInterval: autoInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.runScan(rules: rulesProvider()) }
        }
    }

    func stopAuto() {
        timer?.invalidate()
        timer = nil
    }

    private func writeRulesFile(rules: [MemoryRule]) -> URL? {
        let items: [[String: Any]] = rules.map { [
            "id": $0.id,
            "name": $0.name,
            "description": $0.description,
            "pattern": $0.pattern,
            "severity": $0.severity,
            "enabled": $0.enabled
        ] }
        guard let data = try? JSONSerialization.data(withJSONObject: items, options: .prettyPrinted) else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agr_memory_rules_\(UUID().uuidString).json")
        do {
            try data.write(to: url)
            return url
        } catch {
            return nil
        }
    }

    private func notify(title: String, body: String) {
        let n = NSUserNotification()
        n.title = title
        n.informativeText = body
        NSUserNotificationCenter.default.deliver(n)
    }
}
