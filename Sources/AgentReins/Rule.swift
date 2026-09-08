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
struct GuardEvent: Identifiable, Codable {
    let id: UUID
    let kind: String          // "file" | "cmd"
    let ruleId: String
    let path: String          // 文件层：受保护路径；命令层填 "-"
    let command: String?      // 命令层：命中的完整命令行
    let agent: String?        // 归属到的 agent（codex/cursor/kiro…），无则 nil
    let op: String            // 文件层：delete/modify；命令层：exec
    let severity: String      // critical | high | medium | info
    let ts: Date
    let action: String        // restored | alert | seen
    let sessionId: String?
    let traceId: String?
    let turnId: String?
    let toolCallId: String?
    let userIntent: String?
    let modelDecision: String?
    let modelReasoning: String?
    let modelPrompt: String?
    let modelResponse: String?
    let toolName: String?
    let model: String?
    let inputTokens: Int?
    let outputTokens: Int?
    let cachedTokens: Int?
    let reasoningTokens: Int?
    let beforeContent: String?
    let afterContent: String?
    let fileDiff: String?
    let codeFindings: [CodeFinding]?
    let source: String?

    init(id: UUID = UUID(), kind: String, ruleId: String, path: String,
         command: String?, agent: String?, op: String, severity: String,
         ts: Date, action: String, sessionId: String? = nil, traceId: String? = nil, turnId: String? = nil,
         toolCallId: String? = nil, userIntent: String? = nil, modelDecision: String? = nil,
         modelReasoning: String? = nil, modelPrompt: String? = nil, modelResponse: String? = nil,
         toolName: String? = nil, model: String? = nil, inputTokens: Int? = nil,
         outputTokens: Int? = nil, cachedTokens: Int? = nil, reasoningTokens: Int? = nil,
         beforeContent: String? = nil, afterContent: String? = nil, fileDiff: String? = nil,
         codeFindings: [CodeFinding]? = nil,
         source: String? = nil) {
        self.id = id
        self.kind = kind
        self.ruleId = ruleId
        self.path = path
        self.command = command
        self.agent = agent
        self.op = op
        self.severity = severity
        self.ts = ts
        self.action = action
        self.sessionId = sessionId
        self.traceId = traceId
        self.turnId = turnId
        self.toolCallId = toolCallId
        self.userIntent = userIntent
        self.modelDecision = modelDecision
        self.modelReasoning = modelReasoning
        self.modelPrompt = modelPrompt
        self.modelResponse = modelResponse
        self.toolName = toolName
        self.model = model
        self.inputTokens = inputTokens
        self.outputTokens = outputTokens
        self.cachedTokens = cachedTokens
        self.reasoningTokens = reasoningTokens
        self.beforeContent = beforeContent
        self.afterContent = afterContent
        self.fileDiff = fileDiff
        self.codeFindings = codeFindings
        self.source = source
    }
}
