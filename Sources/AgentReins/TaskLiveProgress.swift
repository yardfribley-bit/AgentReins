import Foundation

/// A bounded, incremental summary. The raw event stream remains in SQLite;
/// this projection must not retain prompts, responses, or tool arguments.
struct TaskLiveProgress: Sendable {
    let sessionID: String
    let turnID: String
    var startedAt: Date
    var lastActivityAt: Date
    var phase: Phase
    var modelRequests = Set<UUID>()
    var modelResponses = Set<UUID>()
    var toolCalls = Set<String>()
    var toolResults = Set<String>()
    var usage: [UUID: Usage] = [:]
    var riskEvents = Set<UUID>()
    var lastTool: String?

    enum Phase: String, Sendable {
        case preparing = "准备上下文"
        case waitingForModel = "等待模型"
        case runningTool = "执行工具"
        case processingResult = "处理工具结果"
        case responding = "模型响应"
        case completed = "Agent 已报告完成"
        case failed = "执行失败"
    }

    struct Usage: Sendable {
        var input: Int
        var output: Int
    }

    var inputTokens: Int { usage.values.reduce(0) { $0 + $1.input } }
    var outputTokens: Int { usage.values.reduce(0) { $0 + $1.output } }

    func isCurrentTask(since boundary: Date) -> Bool {
        !modelRequests.isEmpty && startedAt >= boundary && lastActivityAt >= boundary
    }

    mutating func ingest(_ event: GuardEvent) {
        startedAt = min(startedAt, event.startedAt ?? event.ts)
        guard event.ts >= lastActivityAt else {
            updateCounts(event)
            return
        }
        lastActivityAt = event.ts
        updateCounts(event)
        if ["failed", "error"].contains(event.action.lowercased()) { phase = .failed }
        else if event.kind == "tool", event.op == "call" { phase = .runningTool }
        else if event.kind == "tool", event.op == "result" { phase = .processingResult }
        else if event.kind == "model", event.op == "prompt" { phase = .waitingForModel }
        else if event.kind == "model", event.op == "response" {
            phase = ["completed", "final_answer", "end_turn", "stop_sequence"].contains(event.action.lowercased())
                ? .completed : .responding
        }
    }

    private mutating func updateCounts(_ event: GuardEvent) {
        if event.kind == "model", event.op == "prompt" { modelRequests.insert(event.id) }
        if event.kind == "model", event.op == "response" { modelResponses.insert(event.id) }
        if event.kind == "tool", event.op == "call" {
            toolCalls.insert(event.toolCallId ?? event.id.uuidString)
            lastTool = event.toolName ?? lastTool
        }
        if event.kind == "tool", event.op == "result" {
            toolResults.insert(event.toolCallId ?? event.id.uuidString)
        }
        if event.inputTokens != nil || event.outputTokens != nil {
            let old = usage[event.id] ?? Usage(input: 0, output: 0)
            usage[event.id] = Usage(input: max(old.input, event.inputTokens ?? 0),
                                    output: max(old.output, event.outputTokens ?? 0))
        }
        if ["high", "critical"].contains(event.severity.lowercased()) { riskEvents.insert(event.id) }
    }
}
