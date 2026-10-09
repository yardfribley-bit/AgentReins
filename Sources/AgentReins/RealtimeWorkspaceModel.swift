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
}
struct RealtimeCollectedRecord: Encodable {
    let id: String, agent: String, source: String, kind: String, op: String, summary: String, preview: String
    let hasTaskIdentity: Bool
}
struct RealtimeProcess: Encodable {
    let id: String, pid: String, parent: String, agent: String, name: String
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
}
struct RealtimeCard: Encodable, Identifiable {
    let id: String, kind: String, title: String, status: String, tag: String
    let summary: String, input: String, output: String, source: String, basis: String, confidence: String
    let call: String?, pid: Int32?, timestamp: Date
    let eventIDs: [String]
}

enum RealtimeWorkspaceProjector {
    static func canonicalAgent(_ value: String?) -> String? {
        guard let value = value?.lowercased() else { return nil }
        if value.contains("workbuddy") { return "WorkBuddy" }
        if value.contains("codex") { return "Codex" }
        return nil
    }
    static func tasks(events: [GuardEvent], since: Date) -> [RealtimeTask] {
        let fresh = events.filter { $0.ts >= since && canonicalAgent($0.agent) != nil && $0.sessionId != nil && $0.turnId != nil }
        let grouped = Dictionary(grouping: fresh) { "\(canonicalAgent($0.agent)!)\u{0}\($0.sessionId!)\u{0}\($0.turnId!)" }
        return grouped.map { key, values in
            let ordered = values.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
            let first = ordered[0]
            let title = ordered.first { $0.op == "prompt" && $0.userIntent?.isEmpty == false }?.userIntent
                ?? ordered.compactMap(\.userIntent).first ?? "当前轮次 · 用户需求未采集"
            return RealtimeTask(id: Data(key.utf8).base64EncodedString(), agent: canonicalAgent(first.agent)!, session: first.sessionId!, turn: first.turnId!,
                title: String(title.prefix(300)), startedAt: ordered.first!.ts, lastActivity: ordered.last!.ts,
                cards: cards(ordered), model: ordered.compactMap(\.model).last,
                reportedComplete: ordered.contains { $0.kind == "model" && $0.op == "response" && ["completed", "final_answer", "end_turn", "stop_sequence"].contains($0.action.lowercased()) })
        }.sorted { $0.lastActivity > $1.lastActivity }
    }
    static func cards(_ ordered: [GuardEvent]) -> [RealtimeCard] {
        var output: [RealtimeCard] = []
        // A call ID only pairs within the already isolated Agent/session/turn.
        let toolEvents = ordered.filter { $0.kind == "tool" && $0.toolCallId != nil }
        let grouped = Dictionary(grouping: toolEvents) { $0.toolCallId! }
        for (call, events) in grouped {
            let request = events.first { ["call", "hook_tool_start"].contains($0.op) }
            let result = events.last { ["result", "hook_tool_end"].contains($0.op) }
            let event = result ?? events.last!
            let input = request?.command ?? request?.modelPrompt ?? event.command ?? "输入未采集"
            let body = result?.modelResponse ?? result?.afterContent ?? "结果尚未采集"
            let kind = toolKind(name: request?.toolName ?? event.toolName ?? "", input: input)
            let failed = isFailure(event, result: result == nil ? nil : body)
            let waiting = ["approval_required", "awaiting_approval", "blocked"].contains(event.action.lowercased())
            let planned = ["planned", "queued"].contains(event.action.lowercased())
            let cancelled = ["cancelled", "canceled", "aborted"].contains(event.action.lowercased())
            output.append(RealtimeCard(id: "call:\(call)", kind: kind, title: event.toolName ?? "工具调用",
                status: failed || waiting || cancelled ? "attention" : planned ? "pending" : result != nil ? "returned" : "running",
                tag: failed ? "执行失败" : waiting ? "等待授权 / 已阻塞" : cancelled ? "已取消" : planned ? "已记录计划" : result != nil ? "工具结果已返回" : "等待工具返回",
                summary: result != nil ? String(body.prefix(220)) : "已记录调用；未采到返回，不推断执行成功。",
                input: String(input.prefix(16000)), output: String(body.prefix(16000)), source: event.source ?? "来源未标明",
                basis: "同 Agent、会话、轮次与调用 ID；\(event.attributionMethod ?? "未关联独立执行进程")",
                confidence: event.attributionConfidence?.rawValue ?? "unknown", call: call, pid: event.processId ?? request?.processId, timestamp: event.ts,
                eventIDs: events.map { $0.id.uuidString }))
        }
        for event in ordered where !(event.kind == "tool" && event.toolCallId != nil) {
            guard ["model", "file", "network", "cmd", "tool"].contains(event.kind) else { continue }
            let kind: String
            let title: String
            if event.kind == "model" {
                kind = "model"; title = event.op == "prompt" ? "Agent → 大模型" : "大模型 → Agent"
            } else if event.kind == "file" {
                kind = event.path.lowercased().hasSuffix("skill.md") ? "skill" : "files"
                title = "\(event.op) · \((event.path as NSString).lastPathComponent)"
            } else if event.kind == "network" {
                kind = "web"; title = "连接 · \(event.remoteDomain ?? event.remoteHost ?? "目标未知")"
            } else { kind = event.kind == "cmd" ? "command" : "tool"; title = event.toolName ?? event.op }
            let body = event.modelResponse ?? event.fileDiff ?? event.afterContent ?? event.modelReasoning ?? event.command ?? "正文未采集"
            let failed = isFailure(event, result: event.modelResponse)
            let waiting = ["approval_required", "awaiting_approval", "blocked"].contains(event.action.lowercased())
            let planned = ["planned", "queued"].contains(event.action.lowercased())
            output.append(RealtimeCard(id: event.id.uuidString, kind: kind, title: title,
                status: failed || waiting ? "attention" : planned ? "pending" : event.kind == "model" && event.op == "prompt" ? "returned" : "returned",
                tag: failed ? "执行失败" : waiting ? "等待授权 / 已阻塞" : planned ? "已记录计划" : event.kind == "network" ? "连接已观测" : event.op == "prompt" ? "请求已记录" : "证据已记录",
                summary: String((event.userIntent ?? body).prefix(220)), input: String((event.modelPrompt ?? event.command ?? event.beforeContent ?? event.path).prefix(16000)),
                output: String(body.prefix(16000)), source: event.source ?? "来源未标明",
                basis: event.attributionMethod ?? "当前会话 / 轮次记录；不推断工具因果关系",
                confidence: event.attributionConfidence?.rawValue ?? "unknown", call: event.toolCallId, pid: event.processId, timestamp: event.ts, eventIDs: [event.id.uuidString]))
        }
        if let last = ordered.last(where: { $0.kind == "model" }), last.op == "prompt" {
            output.append(RealtimeCard(id: "waiting:\(last.id)", kind: "model", title: "等待模型返回", status: "running", tag: "最近记录为请求",
                summary: "已记录本轮请求，尚未观测到后续模型响应；不推断服务端执行状态。", input: String((last.modelPrompt ?? "请求正文未采集").prefix(16000)),
                output: "后续响应尚未采集", source: last.source ?? "来源未标明", basis: "当前轮次最后一条模型记录；不是请求响应的确定配对",
                confidence: last.attributionConfidence?.rawValue ?? "unknown", call: last.traceId, pid: last.processId, timestamp: last.ts, eventIDs: [last.id.uuidString]))
        }
        return output.sorted { $0.timestamp < $1.timestamp }
    }
    static func toolKind(name: String, input: String) -> String {
        let name = name.lowercased()
        if input.lowercased().contains("skill.md") && ["read", "file", "cat"].contains(where: name.contains) { return "skill" }
        if ["bash", "shell", "exec_command", "terminal", "write_stdin"].contains(where: name.contains) { return "command" }
        if ["read_file", "write_file", "edit", "patch", "read", "write"].contains(where: name.contains) { return "files" }
        if ["fetch", "browse", "web", "search_query"].contains(where: name.contains) { return "web" }
        return name.contains("mcp") ? "mcp" : "tool"
    }
    static func isFailure(_ event: GuardEvent, result: String?) -> Bool {
        if ["failed", "error", "failure"].contains(event.action.lowercased()) { return true }
        guard let result, let data = result.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        if let code = object["exit_code"] as? Int, code != 0 { return true }
        return object["isError"] as? Bool == true || object["is_error"] as? Bool == true
    }
}
