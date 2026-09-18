import Foundation

/// 面向用户的安全事件：把同一次 Agent 操作触发的多个底层规则信号关联起来。
struct SecurityIncident: Identifiable, Sendable {
    struct Stage: Identifiable, Sendable {
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
        if primary.kind == "alert" { return primary.command ?? "Agent policy violation" }
        if primary.kind == "external-content" {
            let source = primary.command ?? primary.toolName ?? "external content"
            return "Prompt injection detected · \(source)"
        }
        if primary.kind == "model" {
            let name = (agent ?? "Agent").capitalized
            return primary.op == "prompt" ? "\(name) 向模型发送了请求" : "模型向 \(name) 返回了内容"
        }
        if primary.kind == "tool" { return "\((agent ?? "Agent").capitalized) 调用了 \(primary.toolName ?? "工具")" }
        if primary.kind == "activity" { return "\((agent ?? "Agent").capitalized) 正在执行任务" }
        if primary.kind == "network", networkDestination.needsAttention,
           let site = primary.remoteDomain ?? primary.remoteHost {
            return "Untrusted website accessed · \(site)"
        }
        if primary.kind == "network", let tool = primary.toolName {
            return "\((agent ?? "Agent").capitalized) · \(tool) accessed the network"
        }
        if primary.kind == "network" { return "\((agent ?? "Agent").capitalized) established a network connection" }
        if primary.kind == "memory" { return "Agent 记忆中发现敏感信息" }
        if wasRestored { return "受保护文件已自动恢复" }
        if ruleIDs.contains(where: { $0.contains("curl") }) { return "Agent 下载并执行了远程脚本" }
        if ruleIDs.contains(where: { $0.contains("rm") }) { return "Agent 尝试强制删除文件" }
        if ruleIDs.contains(where: { $0.contains("secret") || $0.contains("ssh") }) { return "Agent 访问了敏感凭据" }
        if ruleIDs.contains(where: { $0.contains("force") }) { return "Agent 尝试强制推送代码" }
        return primary.kind == "cmd" ? "Agent 执行了高风险命令" : "Agent 改动了受保护文件"
    }

    var networkDestination: NetworkDestinationAssessment {
        NetworkDestinationAssessment.assess(domain: primary.remoteDomain, host: primary.remoteHost)
    }

    var summary: String {
        if primary.kind == "alert" {
            return "\(primary.ruleId.replacingOccurrences(of: "_", with: " ")) · review required · evidence \(primary.attributionConfidence?.rawValue ?? "unknown")"
        }
        if primary.kind == "external-content" {
            return "Untrusted content attempted to direct the Agent · \(primary.modelResponse ?? "Review captured evidence.")"
        }
        if primary.kind == "model" { return primary.op == "prompt" ? "模型上下文 · 请求已发送" : "模型上下文 · 响应已收到" }
        if primary.kind == "tool" { return "AgentSight 实时活动 · \(primary.action) · 会话已关联。" }
        if primary.kind == "activity" { return "正常活动 · 已记录工具进程，未发现风险规则命中。" }
        if primary.kind == "network" {
            let tool = primary.toolName.map { " · Tool \($0)" } ?? ""
            let destination = primary.remoteDomain ?? primary.remoteHost ?? "Unknown host"
            return "Network activity · \(destination):\(primary.remotePort.map(String.init) ?? "Unknown port") · PID \(primary.processId.map(String.init) ?? "Unknown")\(tool)."
        }
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
                  evidence: primary.userIntent == nil ? "会话中没有可关联的用户消息" : "来自本机 Agent 会话记录",
                  captured: primary.userIntent != nil),
            Stage(id: "decision", title: "模型决策",
                  value: primary.modelDecision ?? "未采集",
                  evidence: primary.modelDecision == nil ? "没有结构化决策事件" : "根据结构化 function_call 记录",
                  captured: primary.modelDecision != nil),
            Stage(id: "reasoning", title: "模型推理记录",
                  value: primary.modelReasoning ?? "未记录",
                  evidence: primary.modelReasoning == nil ? "本次调用未提供可审计的 reasoning 内容" : "来自用户本机 Agent reasoning 记录",
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
        if primary.kind == "network" { return "PID \(primary.processId.map(String.init) ?? "未知") 建立 TCP 连接" }
        if command != nil { return "观察到相关进程启动；系统调用未采集" }
        return "未采集"
    }

    private var dataFlowDescription: (value: String, evidence: String, captured: Bool) {
        if primary.kind == "network", let host = primary.remoteDomain ?? primary.remoteHost {
            return ("本机进程 → \(host):\(primary.remotePort.map(String.init) ?? "?")",
                    "来自 lsof socket owner；不包含 TLS 内容或传输载荷", true)
        }
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
        if event.kind == "network", let pid = event.processId, let host = event.remoteHost {
            return "network|\(pid)|\(host)|\(event.remotePort ?? 0)"
        }
        if event.path != "-" { return "file|\(event.kind)|\(event.path)" }
        if let command = event.command { return "cmd|\(event.kind)|\(command)" }
        return nil
    }

    private static func severityRank(_ severity: String) -> Int {
        ["critical": 4, "high": 3, "medium": 2, "info": 1][severity, default: 0]
    }
}

/// First-layer copy for people who need a decision, not a rule-engine dump.
/// Raw rule IDs and evidence stay available in the incident detail sheet.
struct SecurityIncidentPresentation: Sendable {
    let title: String
    let whyItMatters: String
    let recommendedAction: String
    let status: String
    let confidence: String

    static func make(_ incident: SecurityIncident, chinese: Bool) -> Self {
        let agent = (incident.agent?.isEmpty == false ? incident.agent! : (chinese ? "未识别的智能体" : "Unknown agent"))
        let rules = incident.ruleIDs
        let sensitiveRead = rules.contains("cross_project_sensitive_file_read")
        let outsideRead = rules.contains("cross_project_file_read")
        let credentialResult = rules.contains("credential_in_tool_result")
        let credentialArguments = rules.contains("credential_in_tool_arguments")
        let external = incident.primary.kind == "external-content" || rules.contains { $0.hasPrefix("external_content_") }
        let network = incident.primary.kind == "network"

        let title: String
        let why: String
        let action: String
        if sensitiveRead {
            title = chinese ? "\(agent) 读取了项目外的敏感文件" : "\(agent) read a sensitive file outside its project"
            why = chinese ? "文件内容可能包含账号、密钥或服务器配置，并可能进入智能体上下文。" : "The file may contain credentials, keys, or server configuration that could enter the agent context."
            action = chinese ? "确认这次读取是否必要；如果不必要，请撤销或轮换其中的凭据。" : "Confirm the read was necessary. If not, revoke or rotate any exposed credentials."
        } else if credentialArguments {
            title = chinese ? "\(agent) 把凭据放进了工具调用" : "\(agent) placed credentials in a tool call"
            why = chinese ? "已确认：工具参数匹配了密码、Token 或私钥特征。尚未确认：它是否为真实凭据，以及是否已经发送到模型或中转。" : "Confirmed: a tool argument matched a password, token, or private-key pattern. Not yet confirmed: whether it was real or sent to a model or relay."
            action = chinese ? "先查看匹配字段和调用链。只有确认是真实凭据并已暴露时才轮换；误报可标记为可信。" : "Inspect the matched field and call chain first. Rotate only if it is a real credential that was exposed; mark false positives as trusted."
        } else if credentialResult {
            let tool = incident.events.compactMap(\.toolName).first
            let toolLabel = tool.map { chinese ? "工具「\($0)」" : "tool “\($0)”" }
                ?? (chinese ? "工具结果" : "a tool result")
            title = chinese ? "\(agent) 的\(toolLabel)中出现疑似凭据" : "Possible credentials found in \(agent)'s \(toolLabel)"
            why = chinese ? "已确认：返回内容匹配了敏感凭据特征并进入本地会话。尚未确认：它是否为真实凭据，以及后续是否进入模型请求或外网连接。" : "Confirmed: returned content matched a credential pattern and entered the local session. Not yet confirmed: whether it was real or later entered a model request or network flow."
            action = chinese ? "打开证据核对匹配内容和后续数据流。确认真实外泄后再轮换；仅有本地命中时先限制继续传播。" : "Inspect the matched content and downstream data flow. Rotate after confirming real exposure; if it stayed local, first prevent onward propagation."
        } else if outsideRead {
            title = chinese ? "\(agent) 读取了当前项目之外的文件" : "\(agent) read a file outside its project"
            why = chinese ? "这可能是合理依赖，也可能表示智能体越过了当前任务边界。" : "This may be a valid dependency, or the agent may have crossed the current task boundary."
            action = chinese ? "检查文件路径与当前任务是否相关；不相关时收紧允许范围。" : "Check whether the file belongs to this task. Tighten the allowed scope if it does not."
        } else if external {
            let source = incident.primary.command ?? incident.primary.remoteDomain ?? (chinese ? "外部内容" : "external content")
            title = chinese ? "\(agent) 使用了不可信的外部内容" : "\(agent) used untrusted external content"
            why = chinese ? "网页、仓库或工具结果可能包含诱导智能体执行危险操作的指令。来源：\(source)" : "A page, repository, or tool result may contain instructions that manipulate the agent. Source: \(source)"
            action = chinese ? "在执行其中的命令或代码前，先查看内容与来源。" : "Review the content and its source before executing any command or code from it."
        } else if network {
            let destination = incident.primary.remoteDomain ?? incident.primary.remoteHost ?? (chinese ? "未知地址" : "an unknown destination")
            title = chinese ? "\(agent) 连接到 \(destination)" : "\(agent) connected to \(destination)"
            why = chinese ? "这是智能体与外部服务之间的数据通道，当前需要确认目的地是否符合任务预期。" : "This is a data path from the agent to an external service. The destination should match the task."
            action = chinese ? "确认该域名或 IP 属于预期的模型、代码仓库或服务器。" : "Confirm the domain or IP belongs to the expected model, repository, or server."
        } else {
            title = incident.title
            why = chinese ? "AgentReins 检测到需要人工确认的行为。" : "AgentReins found behavior that needs a human decision."
            action = chinese ? "打开证据，确认该行为是否符合你的任务。" : "Open the evidence and confirm that the behavior matches your task."
        }

        let status: String
        switch incident.severity {
        case "critical": status = chinese ? "立即处理" : "Act now"
        case "high": status = chinese ? "需要审查" : "Review"
        default: status = chinese ? "请留意" : "Be aware"
        }
        let confidenceValue = incident.events.compactMap(\.attributionConfidence).first?.rawValue ?? "unknown"
        let confidence: String
        switch confidenceValue.lowercased() {
        case "confirmed": confidence = chinese ? "归属已确认" : "Attribution confirmed"
        case "inferred": confidence = chinese ? "归属为推断" : "Attribution inferred"
        default: confidence = chinese ? "归属未知" : "Attribution unknown"
        }
        return Self(title: title, whyItMatters: why, recommendedAction: action,
                    status: status, confidence: confidence)
    }
}

/// Security-operations projection. Every field answers an investigation question;
/// missing telemetry stays explicitly unknown instead of becoming product copy.
struct SecurityIncidentAssessment: Sendable {
    enum EvidenceLevel: String, Sendable {
        case confirmed
        case inferred
        case unknown
    }

    struct Field: Identifiable, Sendable {
        let id: String
        let label: String
        let value: String
        let level: EvidenceLevel
    }

    let fields: [Field]
    let disposition: String

    static func make(_ incident: SecurityIncident, chinese: Bool) -> Self {
        let rows = incident.events
        let primary = incident.primary
        let agent = incident.agent ?? (chinese ? "未识别 Agent" : "Unknown agent")
        let pid = rows.compactMap(\.processId).first
        let subject = pid.map { "\(agent) · PID \($0)" } ?? agent
        let subjectLevel: EvidenceLevel = incident.agent == nil ? .unknown
            : (rows.contains { $0.attributionConfidence == .confirmed } ? .confirmed : .inferred)

        let behavior: String
        if let tool = rows.compactMap(\.toolName).first {
            behavior = chinese ? "调用工具 \(tool)" : "Called tool \(tool)"
        } else if primary.kind == "file" {
            behavior = chinese ? "\(fileOperation(primary.op))文件" : "\(primary.op.capitalized) file"
        } else if primary.kind == "network" {
            behavior = chinese ? "建立外部连接" : "Opened an external connection"
        } else if primary.kind == "model" {
            behavior = primary.op == "prompt"
                ? (chinese ? "向模型发送上下文" : "Sent context to a model")
                : (chinese ? "接收模型响应" : "Received a model response")
        } else {
            behavior = primary.command.map { ProcessArgumentRedactor.redact($0) }
                ?? (chinese ? "执行了受监控操作" : "Performed a monitored operation")
        }

        let path = rows.map(\.path).first { !$0.isEmpty && $0 != "-" }
        let endpoint = rows.compactMap { $0.remoteDomain ?? $0.remoteHost }.first
        let asset = path ?? endpoint ?? rows.compactMap(\.model).first
            ?? (chinese ? "未知资产" : "Unknown asset")

        let rules = Set(incident.ruleIDs)
        let dataType: String
        if rules.contains("credential_in_tool_arguments") || rules.contains("credential_in_tool_result") {
            dataType = chinese ? "疑似账号、密码、Token 或私钥" : "Possible credential, token, or private key"
        } else if rules.contains("cross_project_sensitive_file_read") {
            dataType = chinese ? "项目外敏感文件" : "Sensitive file outside the project"
        } else if primary.kind == "memory" {
            dataType = chinese ? "Agent 持久化记忆" : "Persistent agent memory"
        } else if primary.kind == "model" {
            dataType = chinese ? "模型上下文" : "Model context"
        } else if primary.kind == "file" {
            dataType = chinese ? "项目文件" : "Project file"
        } else {
            dataType = chinese ? "未分类" : "Unclassified"
        }

        let destination: String
        let destinationLevel: EvidenceLevel
        if let endpoint {
            destination = "\(endpoint):\(rows.compactMap(\.remotePort).first.map(String.init) ?? "?")"
            destinationLevel = .confirmed
        } else if rows.contains(where: { $0.kind == "model" && $0.op == "prompt" }) {
            destination = rows.compactMap(\.model).first
                ?? (chinese ? "模型（名称未采集）" : "Model (name not captured)")
            destinationLevel = rows.compactMap(\.model).first == nil ? .unknown : .confirmed
        } else if rows.contains(where: { $0.kind == "tool" }) {
            destination = chinese ? "仅确认进入本地工具会话；未发现外发证据" : "Confirmed in local tool session; no outbound evidence"
            destinationLevel = .confirmed
        } else {
            destination = chinese ? "未知：没有可关联的模型或网络证据" : "Unknown: no linked model or network evidence"
            destinationLevel = .unknown
        }

        let result: String
        if incident.wasBlocked { result = chinese ? "执行前已阻止" : "Blocked before execution" }
        else if incident.wasRestored { result = chinese ? "已执行，文件随后恢复" : "Executed; file subsequently restored" }
        else if rows.contains(where: { ["completed", "success", "ok", "sent"].contains($0.action.lowercased()) }) {
            result = chinese ? "执行成功" : "Execution succeeded"
        } else if rows.contains(where: { ["failed", "error", "denied"].contains($0.action.lowercased()) }) {
            result = chinese ? "执行失败" : "Execution failed"
        } else { result = chinese ? "已观察到尝试；最终结果未知" : "Attempt observed; final outcome unknown" }

        let disposition: String
        if rules.contains("credential_in_tool_arguments") || rules.contains("credential_in_tool_result") {
            disposition = chinese
                ? "核对匹配字段与后续数据流；确认真实外泄后轮换凭据，误报则标记可信。"
                : "Inspect the matched field and downstream flow. Rotate after confirmed exposure; mark false positives trusted."
        } else if primary.kind == "external-content" {
            disposition = chinese ? "暂停执行外部内容中的命令，核验来源与内容。" : "Pause commands from the external content and verify its source."
        } else if primary.kind == "network" {
            disposition = chinese ? "核对目标是否属于本次任务；不属于时阻断并检查发送内容。" : "Verify the destination belongs to the task; otherwise block it and inspect transmitted data."
        } else {
            disposition = chinese ? "查看原始证据，确认行为是否符合任务授权范围。" : "Inspect raw evidence and verify the behavior was authorized for this task."
        }

        return Self(fields: [
            Field(id: "subject", label: chinese ? "主体" : "Actor", value: subject, level: subjectLevel),
            Field(id: "behavior", label: chinese ? "行为" : "Action", value: behavior, level: .confirmed),
            Field(id: "asset", label: chinese ? "资产" : "Asset", value: asset, level: asset.contains("未知") || asset.contains("Unknown") ? .unknown : .confirmed),
            Field(id: "data", label: chinese ? "数据" : "Data", value: dataType, level: dataType.contains("疑似") || dataType.contains("Possible") ? .inferred : .confirmed),
            Field(id: "destination", label: chinese ? "流向" : "Destination", value: destination, level: destinationLevel),
            Field(id: "result", label: chinese ? "结果" : "Outcome", value: result, level: result.contains("未知") || result.contains("unknown") ? .unknown : .confirmed)
        ], disposition: disposition)
    }

    private static func fileOperation(_ op: String) -> String {
        ["read": "读取", "write": "写入", "modify": "修改", "delete": "删除", "move": "移动", "rename": "重命名"][op] ?? op
    }
}
