import Foundation

/// 面向用户的安全事件：把同一次 Agent 操作触发的多个底层规则信号关联起来。
struct SecurityIncident: Identifiable {
    struct Stage: Identifiable {
        let id: String
        let title: String
        let value: String
        let evidence: String
        let captured: Bool
    }
    let id: UUID
    let events: [GuardEvent]

    var primary: GuardEvent { events[0] }
    var ts: Date { events.map(\.ts).min() ?? primary.ts }
    var lastTs: Date { events.map(\.ts).max() ?? primary.ts }
    var agent: String? { events.compactMap(\.agent).first }
    var command: String? { events.compactMap(\.command).min(by: { $0.count < $1.count }) }
    var severity: String {
        let rank = ["critical": 4, "high": 3, "medium": 2, "info": 1]
        return events.max { rank[$0.severity, default: 0] < rank[$1.severity, default: 0] }?.severity ?? "info"
    }
    var wasBlocked: Bool { events.contains { $0.action == "block" } }
    var wasRestored: Bool { events.contains { $0.action == "restored" } }
    var ruleIDs: [String] { Array(Set(events.map(\.ruleId))).sorted() }

    var title: String {
        if primary.kind == "model" { return primary.op == "prompt" ? "WorkBuddy 向模型发送了请求" : "模型向 WorkBuddy 返回了内容" }
        if primary.kind == "tool" { return "\((agent ?? "Agent").capitalized) 调用了 \(primary.toolName ?? "工具")" }
        if primary.kind == "activity" { return "\((agent ?? "Agent").capitalized) 正在执行任务" }
        if primary.kind == "memory" { return "Agent 记忆中发现敏感信息" }
        if wasRestored { return "受保护文件已自动恢复" }
        if ruleIDs.contains(where: { $0.contains("curl") }) { return "Agent 下载并执行了远程脚本" }
        if ruleIDs.contains(where: { $0.contains("rm") }) { return "Agent 尝试强制删除文件" }
        if ruleIDs.contains(where: { $0.contains("secret") || $0.contains("ssh") }) { return "Agent 访问了敏感凭据" }
        if ruleIDs.contains(where: { $0.contains("force") }) { return "Agent 尝试强制推送代码" }
        return primary.kind == "cmd" ? "Agent 执行了高风险命令" : "Agent 改动了受保护文件"
    }

    var summary: String {
        if primary.kind == "model" { return primary.op == "prompt" ? "模型上下文 · 请求已发送" : "模型上下文 · 响应已收到" }
        if primary.kind == "tool" { return "AgentSight 实时活动 · \(primary.action) · 会话已关联。" }
        if primary.kind == "activity" { return "正常活动 · 已记录工具进程，未发现风险规则命中。" }
        let outcome = wasBlocked ? "操作已阻止。" : (wasRestored ? "文件已自动恢复。" : "操作已记录，但未在执行前阻止。")
        let evidence = events.count > 1 ? "同一次操作关联到 \(events.count) 条风险信号。" : "检测到 1 条风险信号。"
        return outcome + evidence
    }

    /// 端到端因果链。只陈述采集到的事实；推断和缺失项明确标识。
    var causalChain: [Stage] {
        [
            Stage(id: "agent", title: "哪个 Agent",
                  value: agent?.capitalized ?? "未识别",
                  evidence: agent == nil ? "历史日志未保存进程归属" : "由命令进程树向上追溯",
                  captured: agent != nil),
            Stage(id: "intent", title: "用户意图",
                  value: primary.userIntent ?? "未采集",
                  evidence: primary.userIntent == nil ? "会话中没有可关联的用户消息" : "来自 WorkBuddy 原生会话记录",
                  captured: primary.userIntent != nil),
            Stage(id: "decision", title: "模型决策",
                  value: primary.modelDecision ?? "未采集",
                  evidence: primary.modelDecision == nil ? "没有结构化决策事件" : "根据结构化 function_call 记录",
                  captured: primary.modelDecision != nil),
            Stage(id: "reasoning", title: "模型推理记录",
                  value: primary.modelReasoning ?? "未记录",
                  evidence: primary.modelReasoning == nil ? "WorkBuddy 本次调用未落盘 reasoning 内容" : "来自用户本机 WorkBuddy reasoning 记录",
                  captured: primary.modelReasoning != nil),
            Stage(id: "tool", title: "工具执行",
                  value: toolDescription,
                  evidence: command == nil ? "没有工具调用证据" : "来自进程命令快照",
                  captured: command != nil),
            Stage(id: "kernel", title: "内核行为",
                  value: kernelDescription,
                  evidence: primary.kind == "file" ? "来自文件状态变化" : "当前仅观测进程，尚未接入 Endpoint Security",
                  captured: primary.kind == "file"),
            Stage(id: "flow", title: "数据流向",
                  value: dataFlowDescription.value,
                  evidence: dataFlowDescription.evidence,
                  captured: dataFlowDescription.captured),
            Stage(id: "result", title: "安全结果",
                  value: wasBlocked ? "已阻止" : (wasRestored ? "已恢复" : "仅记录，未阻止"),
                  evidence: "来自 AgentGuard 处置记录",
                  captured: true)
        ]
    }

    private var toolDescription: String {
        if let toolName = primary.toolName { return "调用 \(toolName)" }
        guard let command else { return primary.kind == "memory" ? "敏感信息扫描" : "未识别" }
        let first = command.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? "命令"
        return "执行 \((first as NSString).lastPathComponent)"
    }

    private var kernelDescription: String {
        if primary.kind == "file" { return "文件被\(primary.op == "delete" ? "删除" : "修改")" }
        if command != nil { return "观察到相关进程启动；系统调用未采集" }
        return "未采集"
    }

    private var dataFlowDescription: (value: String, evidence: String, captured: Bool) {
        let text = command?.lowercased() ?? ""
        if text.contains("curl ") || text.contains("wget ") {
            return ("外部网络 → 本机进程", "根据命令参数推断；网络字节流尚未采集", false)
        }
        if text.contains("id_rsa") || text.contains(".ssh") || text.contains("credentials") || primary.kind == "memory" {
            return ("本机敏感数据 → Agent 上下文风险", "发现敏感数据访问或存储证据；未发现外发证据", true)
        }
        return ("未确定", "需要网络与文件描述符级遥测", false)
    }

    static func correlate(_ source: [GuardEvent]) -> [SecurityIncident] {
        let sorted = source.sorted { $0.ts < $1.ts }
        var groups: [[GuardEvent]] = []
        var groupByKey: [String: Int] = [:]
        for event in sorted {
            let key = correlationKey(event)
            if let key, let index = groupByKey[key],
               let last = groups[index].last, abs(event.ts.timeIntervalSince(last.ts)) <= 5 {
                groups[index].append(event)
            } else {
                groups.append([event])
                if let key { groupByKey[key] = groups.count - 1 }
            }
        }
        return groups.map {
            let ordered = $0.sorted { severityRank($0.severity) > severityRank($1.severity) }
            return SecurityIncident(id: ordered[0].id, events: ordered)
        }.sorted { $0.lastTs > $1.lastTs }
    }

    private static func correlationKey(_ event: GuardEvent) -> String? {
        if let call = event.toolCallId { return "tool|\(event.sessionId ?? "")|\(call)" }
        if event.path != "-" { return "file|\(event.kind)|\(event.path)" }
        if let command = event.command { return "cmd|\(event.kind)|\(command)" }
        return nil
    }

    private static func severityRank(_ severity: String) -> Int {
        ["critical": 4, "high": 3, "medium": 2, "info": 1][severity, default: 0]
    }
}
