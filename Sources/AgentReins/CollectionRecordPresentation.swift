import Foundation

/// Small, immutable display records. Full evidence remains in the existing store.
struct CollectionRecordPresentation: Identifiable, Equatable {
    let id: UUID
    let receivedAt: Date
    let observedAt: Date
    let title: String
    let summary: String
    let origin: String
    let category: String
    let state: String
    let pid: Int32?
    let processIdentity: String?
    let details: [String]
    let preview: String

    init(_ e: GuardEvent, receivedAt: Date, toolRequest: GuardEvent? = nil) {
        id = e.id; self.receivedAt = receivedAt; observedAt = e.ts; pid = e.processId
        let source = e.source ?? "未标记来源"
        origin = source.contains("network-body") ? "HTTPS 正文" : source == "workbuddy-hook" ? "原生 Hook" : source.contains("process") ? "进程观察" : "本地日志 / 其他"
        // Parse small records only. Large model bodies are never reparsed by the UI.
        func object(_ value: String?) -> [String: Any]? {
            guard let value, value.utf8.count <= 1_000_000, let data = value.data(using: .utf8) else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        func short(_ value: String?, limit: Int = 160) -> String { String((value ?? "未采到").prefix(limit)) }
        let body = object(e.afterContent)
        processIdentity = body?["processIdentity"] as? String
        let payload = body?["payload"] as? [String: Any]
        let matchingRequest = toolRequest.flatMap { request -> GuardEvent? in
            guard let call = e.toolCallId, request.toolCallId == call, request.sessionId == e.sessionId else { return nil }
            return request
        }
        let requestPayload = object(matchingRequest?.afterContent)?["payload"] as? [String: Any]
        let metadata = object(e.command)
        var fields = ["记录时间：\(e.ts.formatted(date: .abbreviated, time: .standard))", "来源：\(source)", "采集动作：\(e.op) · \(e.action)", "进程归属：\(e.processId.map { "PID \($0)" } ?? "待确认，不按时间强行归属")"]
        if let call = e.toolCallId { fields.append("调用编号：\(call)") }
        if let attribution = e.attributionMethod { fields.append("关联依据：\(short(attribution, limit: 500))") }
        state = e.op.contains("gap") || e.op.contains("unavailable") ? "采集缺口" : e.action.contains("partial") ? "部分采集" : "已收到"
        if e.op.contains("gap") || e.op.contains("unavailable") {
            category = "缺口"; title = "采集存在缺口"
            summary = "\(e.processId.map { "PID \($0) · " } ?? "")\(short(payload?["reason"] as? String ?? e.attributionMethod ?? e.op))；缺失内容不会用推测补齐。"
        } else if let reasoning = e.modelReasoning, !reasoning.isEmpty {
            category = "思考内容"; title = "模型返回的思考内容"
            summary = "采到的文字：\(short(reasoning))"
            fields.append("仅包含模型或应用返回的 reasoning；没有读取未返回的内部思考。")
        } else if e.op == "network_prompt" || (e.kind == "model" && e.modelPrompt != nil) {
            category = "模型上下文"; title = "模型请求中的上下文"
            var pieces: [String] = []
            if let user = e.userIntent { pieces.append("本次输入：\(short(user))") }
            if let request = object(e.modelPrompt), let messages = request["messages"] as? [[String: Any]] {
                let counts = Dictionary(grouping: messages, by: { $0["role"] as? String ?? "unknown" }).mapValues(\.count)
                let names = [("system", "系统说明"), ("developer", "开发者说明"), ("user", "用户消息"), ("assistant", "助手消息"), ("tool", "工具结果")]
                let composition = names.compactMap { key, name in counts[key].map { "\(name) \($0) 条" } }.joined(separator: "、")
                pieces.append(composition)
                if let tools = request["tools"] as? [Any] { pieces.append("工具定义 \(tools.count) 项") }
                fields.append("字段组成：\(composition)。消息角色不等于已确认文件来源。")
            }
            summary = pieces.isEmpty ? "已收到请求正文 \(e.modelPrompt?.utf8.count ?? 0) 字节；具体字段尚未解析，请核对原文。" : pieces.joined(separator: "；")
            fields.append("正文大小：\(e.modelPrompt?.utf8.count ?? 0) 字节；完整性标记：\(e.action)")
        } else if e.toolName != nil || e.op.contains("tool") {
            category = "工具数据"; title = "工具 · \(e.toolName ?? e.op)"
            let input = payload?["tool_input"] ?? requestPayload?["tool_input"]
            let output = payload?["tool_response"]
            func display(_ value: Any?) -> String? {
                guard let value else { return nil }
                if let text = value as? String { return text }
                return (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])).map { String(decoding: $0, as: UTF8.self) }
            }
            let result = display(output) ?? e.modelResponse
            if let arguments = display(input), let result {
                summary = "参数：\(short(arguments, limit: 100))；结果：\(short(result, limit: 140))"
            } else {
                let content = result ?? display(input) ?? e.command ?? e.afterContent
                summary = "\(output != nil || e.op.contains("finish") || e.op.contains("result") ? "结果" : "参数 / 回调")：\(short(content))"
            }
            fields.append("调用与结果按调用编号核对；Hook 来源进程不等于工具执行进程。")
        } else if e.op == "process_watch_attached" || e.op == "process_watch_detached" {
            category = "进程身份"; title = e.op == "process_watch_attached" ? "新进程已纳入观察" : "进程离开观察范围"
            summary = "\(short(body?["executable"] as? String)) · PID \(e.processId.map(String.init) ?? "未知") · 父进程 \(e.parentProcessId.map(String.init) ?? "未知")"
            fields.append("移出观察范围不代表已确认退出原因。")
        } else if let sample = body?["sample"] as? [String: Any] {
            category = "文件与资源"; title = "进程资源与文件句柄"
            let files = sample["openFiles"] as? [[String: Any]] ?? []
            let bytes = (sample["residentBytes"] as? NSNumber)?.doubleValue
            let memory = bytes.map { String(format: "%.1f MB", $0 / 1_048_576) } ?? "未采到"
            let names = files.prefix(2).compactMap { $0["path"] as? String }.map { ($0 as NSString).lastPathComponent }
            summary = "常驻内存 \(memory)；文件句柄 \(files.count) 个\(names.isEmpty ? "" : "（\(names.joined(separator: "、"))）")。没有读取内存正文或文件全文。"
            fields.append("句柄路径：\(files.prefix(10).compactMap { $0["path"] as? String }.joined(separator: "\n"))")
        } else if e.kind == "network" || e.op.contains("socket") || e.op.contains("ipc") {
            category = "网络与通信"
            if let connections = body?["connections"] as? [[String:Any]], !connections.isEmpty {
                title = "进程 TCP 连接采样"
                summary = connections.prefix(4).map { row in
                    let local = row["local"] as? String ?? "本地端点未提供"
                    let host = row["remoteHost"] as? String ?? "", port = row["remotePort"] as? Int ?? 0
                    return "\(local) → \(host):\(port) · \(row["state"] as? String ?? "状态未提供")"
                }.joined(separator:"\n")
            } else if let destination = e.remoteDomain ?? e.remoteHost {
                title = "网络 / 本地通信记录"
                summary = "目标：\(destination):\(e.remotePort ?? 443)\(metadata?["requestPath"].map { " · \($0)" } ?? "")；\(e.modelPrompt == nil ? "本条未采请求正文" : "请求正文已采")。"
            } else { title = "网络 / 本地通信记录"; summary = "采到进程连接快照；地址和连接列表见详情，不据此推断发送内容。" }
        } else if let response = e.modelResponse {
            category = "模型响应"; title = "模型返回内容"; summary = short(response)
        } else {
            category = "其他记录"; title = "\(e.op)"; summary = short(e.userIntent ?? e.relatedPath ?? e.command ?? e.afterContent)
        }
        details = fields
        // A bounded preview prevents a large context from freezing a replay frame.
        preview = [e.userIntent, e.modelReasoning, e.modelPrompt, e.modelResponse, e.afterContent, matchingRequest?.afterContent, e.command, e.relatedPath]
            .compactMap { $0 }.filter { !$0.isEmpty }.map { String($0.prefix(2_000)) }.joined(separator: "\n\n")
    }
}

struct CollectionReplayFrame {
    let time: Date
    let registry: CollectionProcessRegistry
    let records: [CollectionRecordPresentation]
}

struct CollectionReplayBuffer {
    private(set) var frames: [CollectionReplayFrame] = []
    let capacity: Int
    init(capacity: Int = 60) { self.capacity = max(1, capacity) }
    mutating func append(_ frame: CollectionReplayFrame) {
        frames.append(frame)
        if frames.count > capacity { frames.removeFirst(frames.count - capacity) }
    }
    func frame(at index: Int) -> CollectionReplayFrame? { frames.indices.contains(index) ? frames[index] : nil }
}
