import Foundation

/// Presentation-only projection. Never reads historical tasks or guesses cross-turn causality.
struct RealtimeWorkspacePayload: Encodable {
    let tasks: [RealtimeTask]
    let collected: [RealtimeCollectedRecord]
    let unattributedCount: Int
    let processes: [RealtimeProcess]
    let health: [RealtimeHealth]
    let observing: Bool
    let persistenceError: String?
    let publishedAt: Date
    let truncated: Bool
    var collectedCount: Int = 0
    var contexts: [RealtimeContextExchange] = []
    var artifacts: [RealtimeArtifact] = []
    var readTaskIDs: [String] = []
    var continuityNotice: String? = nil
    var ipGeolocations: [RealtimeIPLocation] = []
}
struct RealtimeCollectedRecord: Encodable {
    let id: String, agent: String, source: String, kind: String, op: String, summary: String, preview: String
    let hasTaskIdentity: Bool
    var title: String = ""
    var category: String = ""
    var details: String = ""
    var pid: Int32? = nil
    var session: String? = nil
    var turn: String? = nil
    var call: String? = nil
    var timestamp: Date? = nil
}
struct RealtimeProcess: Encodable {
    let id: String, pid: String, parent: String, agent: String, name: String
    var executable: String = ""
    var command: String = ""
    var active: Bool = true
    var depth: Int = 0
}
struct RealtimeHealth: Encodable {
    let source: String, state: String
    let accepted: Int
    let detail: String?
}
struct RealtimeTask: Encodable, Identifiable {
    let id: String, agent: String, session: String, turn: String, title: String
    let startedAt: Date, lastActivity: Date
    let cards: [RealtimeCard]
    let model: String?
    let reportedComplete: Bool
    var isPrimaryTask: Bool = true
    var originalRequest: String? = nil
    var requestSource: String? = nil
    var requestEventID: String? = nil
    var lifecycleStatus: String = "observed"
    var currentStep: String = "等待任务证据"
    var currentCardID: String? = nil
    var statusBasis: String = "尚无状态证据"
    var coverage: [RealtimeCoverage] = []
    var lifecycle: RealtimeTaskLifecycle? = nil
}
struct RealtimeCard: Encodable, Identifiable {
    let id: String, kind: String, title: String, status: String, tag: String
    let summary: String, input: String, output: String, source: String, basis: String, confidence: String
    let call: String?, pid: Int32?, timestamp: Date
    let eventIDs: [String]
    var detailType: String = "evidence"
    var execution: RealtimeExecutionDetail? = nil
    var resource: RealtimeResourceDetail? = nil
    var inputTruncated: Bool = false
    var outputTruncated: Bool = false
    var phase: String = "recorded"
}

enum RealtimeWorkspaceProjector {
    static func canonicalAgent(_ value: String?) -> String? {
        guard let value = value?.lowercased() else { return nil }
        if value.contains("workbuddy") { return "WorkBuddy" }
        if value.contains("codex") { return "Codex" }
        return nil
    }
    static func tasks(events: [GuardEvent], since: Date) -> [RealtimeTask] {
        let fresh = events.filter { $0.ts >= since && canonicalAgent($0.agent) != nil && $0.sessionId != nil }
        // Only native call identity can bridge a missing turn. Session-only evidence
        // remains in its own lane; never assign it to the latest task by time.
        func callKey(_ e: GuardEvent) -> String { "\(canonicalAgent(e.agent)!)\u{0}\(e.sessionId!)\u{0}\(e.toolCallId ?? "")" }
        let callTurns = Dictionary(grouping: fresh.filter { $0.toolCallId != nil && $0.turnId != nil }, by: callKey)
            .mapValues { Set($0.compactMap(\.turnId)) }
        func turn(_ e: GuardEvent) -> String {
            if let turn = e.turnId { return turn }
            if e.toolCallId != nil, let matches = callTurns[callKey(e)], matches.count == 1 { return matches.first! }
            return ""
        }
        let grouped = Dictionary(grouping: fresh) { "\(canonicalAgent($0.agent)!)\u{0}\($0.sessionId!)\u{0}\(turn($0))" }
        return grouped.map { key, values in
            let ordered = values.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
            let first = ordered[0]
            let request = ordered.first { ["prompt", "hook_user_prompt"].contains($0.op) && $0.userIntent?.isEmpty == false }
                ?? ordered.first { $0.op == "network_prompt" && $0.userIntent?.isEmpty == false }
            let title = request?.userIntent ?? (turn(first).isEmpty ? "会话活动 · 轮次尚未关联" : "当前轮次 · 用户需求未采集")
            let projectedCards = cards(ordered)
            let state = RealtimeLifecycleProjector.project(events: ordered, cards: projectedCards, hasRequest: request != nil, hasTurn: !turn(first).isEmpty)
            return RealtimeTask(id: Data(key.utf8).base64EncodedString(), agent: canonicalAgent(first.agent)!, session: first.sessionId!, turn: turn(first),
                title: String(title.prefix(300)), startedAt: ordered.first!.ts, lastActivity: ordered.last!.ts,
                cards: projectedCards, model: ordered.compactMap(\.model).last,
                reportedComplete: state.status == "completed",
                isPrimaryTask: ordered.contains { $0.kind == "model" || $0.op == "hook_user_prompt" || $0.kind == "tool" || $0.source == "workbuddy-hook" },
                originalRequest: request?.userIntent, requestSource: request?.source, requestEventID: request?.id.uuidString,
                lifecycleStatus: state.status, currentStep: state.currentStep, currentCardID: state.currentCardID, statusBasis: state.basis,
                coverage: state.coverage, lifecycle: state.lifecycle)
        }.sorted { $0.lastActivity > $1.lastActivity }
    }
    static func cards(_ records: [GuardEvent]) -> [RealtimeCard] {
        let ordered = records.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
        var output: [RealtimeCard] = []
        // A call ID only pairs within the already isolated Agent/session/turn.
        let grouped = Dictionary(grouping: ordered.filter(isToolLifecycle)) { $0.toolCallId! }
        for (call, events) in grouped {
            let request = events.first { ["call", "hook_tool_start", "start", "started", "exec_start", "command_started"].contains($0.op) }
            let result = events.last { ["result", "hook_tool_end", "hook_tool_finish", "end", "completed", "command_completed"].contains($0.op) }
            let event = result ?? events.last!
            let rawInput = hookField(request, "tool_input") ?? request?.command ?? request?.modelPrompt
            let rawOutput = hookField(result, "tool_response") ?? result?.modelResponse ?? result?.afterContent
            let input = rawInput ?? "输入未采集", body = rawOutput ?? "结果尚未采集"
            let kind = toolKind(name: request?.toolName ?? event.toolName ?? "", input: input)
            let execution = kind == "command" ? RealtimeDetailProjector.execution(request: request, result: result, events: events, input: rawInput, output: rawOutput) : nil
            let failed = isFailure(event, result: rawOutput) || execution?.status == "failed"
            let waiting = ["approval_required", "awaiting_approval", "blocked"].contains(event.action.lowercased())
            let planned = ["planned", "queued"].contains(event.action.lowercased())
            let cancelled = ["cancelled", "canceled", "aborted"].contains(event.action.lowercased())
            let returned = result != nil && execution?.outputComplete != false
            let phase = failed ? "failed" : waiting ? "waiting" : cancelled ? "cancelled" : planned ? "pending" : returned ? "returned" : "running"
            let tag = failed ? "执行失败" : waiting ? "等待你确认" : cancelled ? "已取消" : planned ? "已记录计划" : returned ? "工具结果已返回" : execution?.status == "requested" ? "调用已提交，执行开始未采集" : "等待工具返回"
            let visibleOutput = rawOutput ?? execution?.stdout ?? execution?.stderr
            let summary = visibleOutput.map { String($0.prefix(220)) } ?? (execution?.status == "running" ? "执行中；中间输出按源记录显示。" : "已记录调用；尚未采到执行返回。")
            output.append(RealtimeCard(id: "call:\(call)", kind: kind, title: request?.toolName ?? event.toolName ?? "工具调用",
                status: failed || waiting || cancelled ? "attention" : planned ? "pending" : returned ? "returned" : "running",
                tag: tag, summary: summary, input: String(input.prefix(16000)), output: String((visibleOutput ?? body).prefix(16000)), source: event.source ?? "来源未标明",
                basis: "同 Agent、会话、轮次与调用 ID；\(event.attributionMethod ?? "未关联独立执行进程")",
                confidence: event.attributionConfidence?.rawValue ?? "unknown", call: call, pid: event.processId ?? request?.processId, timestamp: event.ts,
                eventIDs: events.map { $0.id.uuidString }, detailType: kind, execution: execution,
                resource: RealtimeDetailProjector.resource(event: event, input: rawInput, output: rawOutput, kind: kind),
                inputTruncated: RealtimeDetailProjector.truncated(rawInput), outputTruncated: RealtimeDetailProjector.truncated(visibleOutput), phase: phase))
        }
        for event in ordered where !isToolLifecycle(event) {
            guard ["model", "file", "network", "cmd", "tool", "activity", "memory", "context", "task"].contains(event.kind) else { continue }
            let kind: String, title: String
            if ["prompt", "hook_user_prompt"].contains(event.op), event.userIntent?.isEmpty == false {
                kind = "user"; title = "我的需求"
            } else if event.kind == "context" {
                kind = event.op == "turn_context" ? "environment" : "context"
                title = event.toolName ?? "上下文材料"
            } else if event.kind == "task" || event.op.hasPrefix("task_") || event.op == "hook_turn_stop" {
                kind = "task"; title = "任务状态记录"
            } else if event.kind == "activity" || event.kind == "memory" {
                kind = "process"; title = CollectionRecordPresentation(event, receivedAt: event.ts).title
            } else if event.kind == "model" {
                kind = "model"; title = ["prompt", "network_prompt"].contains(event.op) ? "Agent → 大模型" : event.op == "reasoning_summary" ? "模型返回的思考摘要" : "大模型 → Agent"
            } else if event.kind == "file" {
                kind = event.path.lowercased().hasSuffix("skill.md") ? "skill" : "files"
                title = "\(event.op) · \((event.path as NSString).lastPathComponent)"
            } else if event.kind == "network" {
                kind = "web"; title = "连接 · \(event.remoteDomain ?? event.remoteHost ?? "目标未知")"
            } else { kind = event.kind == "cmd" ? "command" : "tool"; title = event.toolName ?? event.op }
            let rawInput = kind == "user" ? event.userIntent : event.modelPrompt ?? event.command ?? event.beforeContent ?? (event.path == "-" ? nil : event.path)
            let rawBody = kind == "user" ? event.userIntent : event.modelResponse ?? event.fileDiff ?? event.afterContent ?? event.modelReasoning ?? event.command
            let body = rawBody ?? "正文未采集"
            let failed = isFailure(event, result: event.modelResponse)
            let waiting = ["approval_required", "awaiting_approval", "blocked"].contains(event.action.lowercased()) || ["approval_required", "awaiting_approval"].contains(event.op)
            let planned = ["planned", "queued"].contains(event.action.lowercased())
            let cancelled = ["cancelled", "canceled", "aborted"].contains(event.action.lowercased())
            let phase = failed ? "failed" : waiting ? "waiting" : cancelled ? "cancelled" : planned ? "pending" : "recorded"
            output.append(RealtimeCard(id: event.id.uuidString, kind: kind, title: title,
                status: failed || waiting || cancelled ? "attention" : planned ? "pending" : event.source == "tool-intent" && event.action == "requested" ? "running" : "returned",
                tag: failed ? "步骤失败" : waiting ? "等待你确认" : cancelled ? "已取消" : planned ? "已记录计划" : event.kind == "network" ? "网络证据已记录" : event.op == "prompt" ? "用户原话已记录" : "证据已记录",
                summary: String((kind == "user" ? event.userIntent ?? "" : body).prefix(220)), input: String((rawInput ?? "").prefix(16000)),
                output: String(body.prefix(16000)), source: event.source ?? "来源未标明",
                basis: event.attributionMethod ?? "当前会话 / 轮次记录；不推断工具因果关系",
                confidence: event.attributionConfidence?.rawValue ?? "unknown", call: event.toolCallId, pid: event.processId, timestamp: event.ts, eventIDs: [event.id.uuidString],
                detailType: kind, execution: kind == "command" ? RealtimeDetailProjector.execution(request: event, result: nil, events: [event], input: event.command, output: nil) : nil,
                resource: RealtimeDetailProjector.resource(event: event, input: rawInput, output: rawBody, kind: kind),
                inputTruncated: RealtimeDetailProjector.truncated(rawInput), outputTruncated: RealtimeDetailProjector.truncated(rawBody), phase: phase))
            if event.kind == "model", let decision = event.modelDecision, !decision.isEmpty {
                output.append(RealtimeCard(id: "decision:\(event.id.uuidString)", kind: "plan", title: "模型下发的工具指令", status: "pending", tag: "模型决策；执行状态另行核对",
                    summary: String(decision.prefix(220)), input: "", output: String(decision.prefix(16000)), source: event.source ?? "来源未标明",
                    basis: "模型返回中的工具指令；不等于工具已经执行", confidence: event.attributionConfidence?.rawValue ?? "unknown",
                    call: nil, pid: nil, timestamp: event.ts, eventIDs: [event.id.uuidString], detailType: "plan", outputTruncated: RealtimeDetailProjector.truncated(decision), phase: "recorded"))
            }
        }
        // Only an actual captured model request establishes a response wait. A
        // local user message alone is not proof that an HTTPS request was sent.
        if let last = ordered.last(where: { $0.kind == "model" && ["network_prompt", "network_response"].contains($0.op) }), last.op == "network_prompt",
           !ordered.contains(where: { RealtimeLifecycleProjector.terminalStatus($0, hasTurn: $0.turnId != nil) != nil }) {
            output.append(RealtimeCard(id: "waiting:\(last.id)", kind: "model", title: "等待模型返回", status: "running", tag: "已采到模型请求",
                summary: "已记录本轮请求，尚未观测到后续模型响应。", input: String((last.modelPrompt ?? "").prefix(16000)),
                output: "", source: last.source ?? "来源未标明", basis: "当前轮次最近的 HTTPS 模型记录为请求；不推断服务端内部进度",
                confidence: last.attributionConfidence?.rawValue ?? "unknown", call: last.traceId, pid: last.processId, timestamp: last.ts, eventIDs: [last.id.uuidString],
                detailType: "model", inputTruncated: RealtimeDetailProjector.truncated(last.modelPrompt), phase: "running"))
        }
        return output.sorted { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }
    }
    private static func isToolLifecycle(_ e: GuardEvent) -> Bool {
        e.toolCallId != nil && (e.kind == "tool" || (e.source == "workbuddy-hook" && ["hook_tool_start", "hook_tool_finish", "hook_tool_end"].contains(e.op)))
    }
    private static func hookField(_ event: GuardEvent?, _ key: String) -> String? {
        guard event?.source == "workbuddy-hook", let body = event?.afterContent,
              let record = RealtimeDetailProjector.object(body), let value = (record["payload"] as? [String: Any])?[key] else { return nil }
        if let text = value as? String { return text }
        return (try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys])).map { String(decoding: $0, as: UTF8.self) }
    }
    static func toolKind(name: String, input: String) -> String {
        let name = name.lowercased()
        if ["update_plan", "todowrite", "todo_write", "set_plan"].contains(where: name.contains) { return "plan" }
        if input.lowercased().contains("skill.md") && ["read", "file", "cat"].contains(where: name.contains) { return "skill" }
        if ["bash", "shell", "exec_command", "terminal", "write_stdin", "commandexecution"].contains(where: name.contains) { return "command" }
        if ["read_file", "write_file", "edit", "patch", "read", "write"].contains(where: name.contains) { return "files" }
        if ["fetch", "browse", "web", "search_query"].contains(where: name.contains) { return "web" }
        return name.contains("mcp") ? "mcp" : "tool"
    }
    static func isFailure(_ event: GuardEvent, result: String?) -> Bool {
        if ["failed", "error", "failure"].contains(event.action.lowercased()) { return true }
        if let object = RealtimeDetailProjector.resultObject(result) {
            if let code = RealtimeDetailProjector.integer(object["exit_code"] ?? object["exitCode"] ?? object["returncode"]), code != 0 { return true }
            return object["isError"] as? Bool == true || object["is_error"] as? Bool == true || ["failed", "error"].contains(object["status"] as? String ?? "")
        }
        if let result, let range = result.range(of: #"(?m)^Process exited with code (-?\d+)\s*$"#, options: .regularExpression),
           let code = Int(result[range].split(separator: " ").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "") { return code != 0 }
        return false
    }
}

/// Existing IP attribution cache, scoped to addresses actually seen in live tasks.
struct RealtimeIPLocation: Encodable {
    let ip: String
    let location: String?
    let owner: String?
    let source: String
    let updatedAt: Date?
    let state: String
    let error: String?
}
