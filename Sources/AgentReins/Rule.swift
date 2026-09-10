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
    let attributionConfidence: EvidenceConfidence?
    let attributionMethod: String?
    let processId: Int32?
    let parentProcessId: Int32?
    let localAddress: String?
    let remoteHost: String?
    let remotePort: Int?

    init(id: UUID = UUID(), kind: String, ruleId: String, path: String,
         command: String?, agent: String?, op: String, severity: String,
         ts: Date, action: String, sessionId: String? = nil, traceId: String? = nil, turnId: String? = nil,
         toolCallId: String? = nil, userIntent: String? = nil, modelDecision: String? = nil,
         modelReasoning: String? = nil, modelPrompt: String? = nil, modelResponse: String? = nil,
         toolName: String? = nil, model: String? = nil, inputTokens: Int? = nil,
         outputTokens: Int? = nil, cachedTokens: Int? = nil, reasoningTokens: Int? = nil,
         beforeContent: String? = nil, afterContent: String? = nil, fileDiff: String? = nil,
         codeFindings: [CodeFinding]? = nil,
         source: String? = nil, attributionConfidence: EvidenceConfidence? = nil,
         attributionMethod: String? = nil, processId: Int32? = nil,
         parentProcessId: Int32? = nil, localAddress: String? = nil,
         remoteHost: String? = nil, remotePort: Int? = nil) {
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
        self.attributionConfidence = attributionConfidence
        self.attributionMethod = attributionMethod
        self.processId = processId
        self.parentProcessId = parentProcessId
        self.localAddress = localAddress
        self.remoteHost = remoteHost
        self.remotePort = remotePort
    }

    func attributed(sessionId: String, turnId: String, toolCallId: String?,
                    confidence: EvidenceConfidence, method: String) -> GuardEvent {
        GuardEvent(id: id, kind: kind, ruleId: ruleId, path: path, command: command,
                   agent: agent, op: op, severity: severity, ts: ts, action: action,
                   sessionId: sessionId, traceId: traceId, turnId: turnId,
                   toolCallId: toolCallId ?? self.toolCallId, userIntent: userIntent,
                   modelDecision: modelDecision, modelReasoning: modelReasoning,
                   modelPrompt: modelPrompt, modelResponse: modelResponse,
                   toolName: toolName, model: model, inputTokens: inputTokens,
                   outputTokens: outputTokens, cachedTokens: cachedTokens,
                   reasoningTokens: reasoningTokens, beforeContent: beforeContent,
                   afterContent: afterContent, fileDiff: fileDiff, codeFindings: codeFindings,
                   source: source, attributionConfidence: confidence,
                   attributionMethod: method, processId: processId,
                   parentProcessId: parentProcessId, localAddress: localAddress,
                   remoteHost: remoteHost, remotePort: remotePort)
    }

    func redactingSensitiveCommandArguments() -> GuardEvent {
        guard let command else { return self }
        let redacted = ProcessArgumentRedactor.redact(command)
        guard redacted != command else { return self }
        return GuardEvent(id: id, kind: kind, ruleId: ruleId, path: path, command: redacted,
                          agent: agent, op: op, severity: severity, ts: ts, action: action,
                          sessionId: sessionId, traceId: traceId, turnId: turnId,
                          toolCallId: toolCallId, userIntent: userIntent,
                          modelDecision: modelDecision, modelReasoning: modelReasoning,
                          modelPrompt: modelPrompt, modelResponse: modelResponse,
                          toolName: toolName, model: model, inputTokens: inputTokens,
                          outputTokens: outputTokens, cachedTokens: cachedTokens,
                          reasoningTokens: reasoningTokens, beforeContent: beforeContent,
                          afterContent: afterContent, fileDiff: fileDiff, codeFindings: codeFindings,
                          source: source, attributionConfidence: attributionConfidence,
                          attributionMethod: attributionMethod, processId: processId,
                          parentProcessId: parentProcessId, localAddress: localAddress,
                          remoteHost: remoteHost, remotePort: remotePort)
    }
}
