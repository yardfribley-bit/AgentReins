import Foundation

/// 与 agentguard/rules.json 兼容的规则结构（扩展了 ops / restore 字段）。
struct Rule: Codable, Identifiable, Hashable {
    var id: String
    var kind: String                 // "file" | "cmd"
    var watch: [String]?             // file 类：受保护路径
    var pattern: String?             // cmd 类：正则
    var ops: [String]?               // file 类：要拦截的动作 delete/modify/read/move/rename/execute
    var severity: String
    var action: String               // "protect" | "alert" | "block"
    var restore: Bool?               // protect 时是否从备份还原
    var message: String
    var naturalLanguage: String?     // 原始自然语言

    var opsSet: Set<String> { Set(ops ?? []) }
    var isProtect: Bool { action == "protect" || action == "block" }
}

/// 本应用写入的 rules.json 格式（version + rules）。
struct RuleDocument: Codable {
    var version: Int = 1
    var rules: [Rule]
}

/// 兼容读取 agentguard/rules.json（其含 monitor 字段，忽略之，只取 rules）。
struct RuleWrapper: Decodable {
    let rules: [Rule]
}

/// 监控事件（文件层 / 命令层共用，用于 UI 统一时间线展示）。
struct GuardEvent: Identifiable {
    let id = UUID()
    let kind: String          // "file" | "cmd"
    let ruleId: String
    let path: String          // 文件层：受保护路径；命令层填 "-"
    let command: String?      // 命令层：命中的完整命令行
    let agent: String?        // 归属到的 agent（codex/cursor/kiro…），无则 nil
    let op: String            // 文件层：delete/modify；命令层：exec
    let severity: String      // critical | high | medium | info
    let ts: Date
    let action: String        // restored | alert | seen
}
