import Foundation

/// A presentation registry, not a new sampler. Retains vanished nodes without
/// treating absence from a snapshot as a confirmed process-exit event.
struct CollectionProcessNode: Identifiable {
    var process: ProcessSnapshotRecord
    let firstSeen: Date
    var lastSeen: Date
    var active: Bool
    var id: String { ProcessObservationCoordinator.identity(process) }
    var name: String { (process.executablePath as NSString?)?.lastPathComponent ?? process.command.components(separatedBy: " ").first ?? "未知进程" }

    var role: (title: String, basis: String) {
        let command = process.command.lowercased()
        let executable = name.lowercased()
        let electron = executable == "electron" || executable.hasPrefix("workbuddy helper")
        if electron && command.contains("--type=renderer") { return ("界面渲染进程", "启动参数含 --type=renderer；负责应用界面渲染") }
        if electron && command.contains("--type=gpu-process") { return ("图形辅助进程", "启动参数含 --type=gpu-process；负责图形处理") }
        if electron && command.contains("--utility-sub-type=network.mojom.networkservice") {
            return ("网络服务进程", "启动参数指定 Chromium NetworkService；负责应用网络服务，不代表所有 Agent 请求都由它发出")
        }
        if electron && command.contains("codebuddy") && command.contains("--serve") {
            return ("Agent 服务进程", "运行 codebuddy --serve；承担 Agent 会话服务，具体工具和模型通信仍按行为证据核对")
        }
        if electron && command.contains("/main/daemon-app-server-entry.js") {
            return ("应用后台服务", "运行 daemon-app-server-entry.js；后台服务入口，具体子功能按行为证据核对")
        }
        if electron && command.contains("/main/sidecar-entry.js") {
            return ("Sidecar 辅助服务", "运行 sidecar-entry.js；已识别辅助服务入口，内部具体职责尚未确认")
        }
        if electron && command.contains("/extensions/edge-sync/server/index.cjs") {
            return ("同步相关服务", "运行 edge-sync 扩展服务；同步对象和上传内容需网络、文件证据确认")
        }
        if executable == "chrome_crashpad_handler" {
            return ("崩溃报告组件", "可执行文件为 chrome_crashpad_handler；上传是否发生需另查网络证据")
        }
        if executable == "editor_sdk" {
            return ("文档编辑 SDK 服务", "可执行文件为 editor_sdk；文档内容是否读取或发送按实际证据判断")
        }
        if executable == "sandbox-center" {
            return ("安全 / 沙盒相关组件", "可执行文件为 sandbox-center；组件存在不等于工具执行受到沙盒隔离")
        }
        if executable == "betterleaks" {
            return ("敏感信息检测组件", "运行 betterleaks；stdin 和配置参数提示输入检测，具体检测结果需另查")
        }
        if executable == "agentreinshook" {
            return ("AgentReins 采集 Hook", "运行本产品 AgentReinsHook；采集回调辅助进程，不是 WorkBuddy 工具执行器")
        }
        if executable == "node" || electron {
            if command.contains("/plugins/cache/workbuddy-builtin/weixinpay/") && command.contains("/dist/mcp-server.mjs") {
                return ("微信支付插件 MCP 服务", "启动脚本位于 weixinpay 插件目录；服务身份已识别，不据此认定支付行为或 WorkBuddy 计费")
            }
            if command.contains("/plugins/cache/workbuddy-builtin/sheetagent/") && command.contains("/mcp/start.mjs") {
                return ("表格插件 MCP 服务", "运行 sheetagent 插件的 mcp/start.mjs；实际表格操作需工具证据确认")
            }
        }
        if executable == "ffmpeg" { return ("音视频处理工具", "可执行文件为 ffmpeg；具体转换、编码参数见对应命令记录") }
        if executable == "ffprobe" { return ("音视频检查工具", "可执行文件为 ffprobe；检查对象和项目见对应命令记录") }
        if ["zsh", "bash", "sh"].contains(executable) {
            return ("Shell 命令执行器", "已确认 Shell 可执行文件；属于哪次工具调用需会话和调用证据核对")
        }
        if command.contains("mcp") && (executable == "node" || electron) {
            return ("MCP 服务候选", "启动命令含 MCP 标识；服务用途和调用情况尚需确认")
        }
        if electron && command.contains("--type=utility") { return ("应用辅助进程", "启动参数含 --type=utility；具体用途尚未确认") }
        if process.executablePath == "/Applications/WorkBuddy.app/Contents/MacOS/Electron" && !command.contains("--") {
            return ("WorkBuddy 主程序", "WorkBuddy 应用可执行文件，未指定服务脚本或子进程类型")
        }
        if ["python", "python3", "node"].contains(executable) {
            return ("脚本运行进程", "已确认脚本运行时；业务用途需要脚本路径和行为证据")
        }
        return ("职责待确认", "已纳入 WorkBuddy 关联进程树；尚无充分职责证据")
    }
}

struct CollectionProcessRegistry {
    private(set) var nodes: [String: CollectionProcessNode] = [:]
    mutating func update(_ inventory: [ProcessSnapshotRecord], now: Date) {
        let relevant = inventory.filter { $0.agent?.lowercased() == "workbuddy" }
        let activeIDs = Set(relevant.map(ProcessObservationCoordinator.identity))
        for key in Array(nodes.keys) { nodes[key]?.active = activeIDs.contains(key) }
        for process in relevant {
            let key = ProcessObservationCoordinator.identity(process)
            if var node = nodes[key] {
                node.process = process; node.active = true; node.lastSeen = now; nodes[key] = node
            } else { nodes[key] = .init(process: process, firstSeen: now, lastSeen: now, active: true) }
        }
        // Only evict inactive presentation records. Sampling is unaffected.
        let inactive = nodes.values.filter { !$0.active }.sorted { $0.lastSeen > $1.lastSeen }
        for node in inactive.dropFirst(64) { nodes.removeValue(forKey: node.id) }
    }
    var ordered: [(node: CollectionProcessNode, depth: Int)] {
        let all = Array(nodes.values)
        func parent(of child: CollectionProcessNode) -> CollectionProcessNode? {
            guard child.process.ppid != child.process.pid, let birth = child.process.birthIdentity else { return nil }
            return all.filter {
                $0.process.pid == child.process.ppid && ($0.process.birthIdentity ?? UInt64.max) <= birth
            }.max { ($0.process.birthIdentity ?? 0) < ($1.process.birthIdentity ?? 0) }
        }
        let parents = Dictionary(uniqueKeysWithValues: all.compactMap { node in parent(of: node).map { (node.id, $0.id) } })
        var output: [(CollectionProcessNode, Int)] = []
        var visited = Set<String>()
        func visit(_ node: CollectionProcessNode, _ depth: Int) {
            guard visited.insert(node.id).inserted else { return }
            output.append((node, depth))
            for child in all.filter({ parents[$0.id] == node.id }).sorted(by: { $0.firstSeen < $1.firstSeen }) {
                visit(child, depth + 1)
            }
        }
        for root in all.filter({ parents[$0.id] == nil }).sorted(by: { $0.firstSeen < $1.firstSeen }) { visit(root, 0) }
        for remainder in all where !visited.contains(remainder.id) { visit(remainder, 0) }
        return output
    }
}
