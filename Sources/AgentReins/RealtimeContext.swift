import CryptoKit
import Foundation

struct RealtimeContextBlock: Encodable {
    let id: String, role: String, label: String, content: String, fingerprint: String
    let characters: Int
    let callID: String?
    var change = "baseline"
    var toolEvidenceIDs: [String] = []
    var containsCurrentInput = false
}
struct RealtimeContextExchange: Encodable {
    let id: String, agent: String, session: String, turn: String, source: String, coverage: String
    let timestamp: Date
    let trace: String?
    let structured: Bool
    let characters: Int
    let counts: [String: Int]
    var blocks: [RealtimeContextBlock]
    let fingerprints: [String]
    let truncated: Bool
    var previousID: String? = nil
    var added: Int? = nil
    var removed: Int? = nil
    var retained: Int? = nil
    var response: String? = nil
    var responseID: String? = nil
    var toolInstructions: String? = nil
    var recordedReasoning: String? = nil
    var responseBasis = "响应尚未按原生标识配对"
    var inputTokens: Int? = nil
    var outputTokens: Int? = nil
}

enum RealtimeContextProjector {
    static func parse(_ event: GuardEvent) -> RealtimeContextExchange? {
        guard event.kind == "model", ["prompt", "network_prompt"].contains(event.op),
              let body = event.modelPrompt, let agent = RealtimeWorkspaceProjector.canonicalAgent(event.agent),
              let session = event.sessionId else { return nil }
        if event.source == "agentsight:codex-local-compat", event.op == "prompt" {
            let kinds = RealtimeDetailProjector.object(event.command)?["content_item_kinds"] as? [String] ?? []
            if CodexSight.isRuntimeUserContext(body, sourceKinds: kinds) { return nil }
        }
        let isTransport = event.op == "network_prompt"
        let labels = ["system":"系统说明", "developer":"开发者说明", "user":"用户消息", "assistant":"助手消息 / 工具指令", "tool":"工具返回", "tools":"可用工具定义", "instructions":"请求级指令", "unknown":"未识别内容"]
        var entries: [(String, Any, String?)] = []
        var structured = false
        let object: [String: Any]? = body.utf8.count <= 8 * 1024 * 1024
            ? body.data(using: .utf8).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } : nil
        if isTransport, let object {
            if let messages = object["messages"] as? [[String: Any]] {
                structured = true
                for row in messages { entries.append((row["role"] as? String ?? "unknown", row, row["tool_call_id"] as? String)) }
            } else if let input = object["input"] as? [[String: Any]] {
                structured = true
                for row in input {
                    let type = row["type"] as? String
                    entries.append((type == "function_call_output" ? "tool" : type == "function_call" ? "assistant" : row["role"] as? String ?? "unknown", row, row["call_id"] as? String))
                }
            } else if let input = object["input"] as? String { structured = true; entries.append(("user", input, nil)) }
            if let system = object["system"] { entries.insert(("system", system, nil), at: 0) }
            if let instructions = object["instructions"] { entries.insert(("instructions", instructions, nil), at: 0) }
            for tool in object["tools"] as? [Any] ?? [] { entries.append(("tools", tool, nil)) }
        }
        if !structured { entries = [(isTransport ? "unknown" : "user", body, nil)] }
        var blocks: [RealtimeContextBlock] = [], counts: [String: Int] = [:], fingerprints: [String] = []
        var remaining = 256_000
        for (index, entry) in entries.enumerated() {
            let (role, value, call) = entry
            let canonical: String
            if let text = value as? String { canonical = text }
            else if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]) { canonical = String(decoding: data, as: UTF8.self) }
            else { canonical = "内容未解码" }
            let hash = SHA256.hash(data: Data((role + "\u{0}" + canonical).utf8)).map { String(format: "%02x", $0) }.joined()
            fingerprints.append(hash); counts[role, default: 0] += 1
            guard blocks.count < 500, remaining > 0 else { continue }
            var text = readable(value)
            if text.isEmpty { text = canonical }
            let limit = min(16_000, remaining)
            let hasCurrentInput = role == "user" && event.userIntent.map { !$0.isEmpty && text.contains($0) } == true
            let preview: String
            if hasCurrentInput, text.count > limit, limit > 200 {
                let half = (limit - 100) / 2
                preview = String(text.prefix(half)) + "\n\n… 中间内容省略；完整正文保留在原始采集证据中 …\n\n" + String(text.suffix(half))
            } else { preview = String(text.prefix(limit)) }
            remaining -= preview.count
            blocks.append(RealtimeContextBlock(id: "\(event.id):\(index)", role: role, label: labels[role] ?? role,
                content: preview, fingerprint: hash, characters: text.count, callID: call, containsCurrentInput: hasCurrentInput))
        }
        let coverage = !isTransport ? "仅本地消息片段，不代表完整模型请求" : !structured ? "请求正文结构未识别或超过8 MiB解析预算" : event.action == "captured_complete" ? "完整请求正文已采集" : "已采请求正文，完整性待核对"
        return RealtimeContextExchange(id: event.id.uuidString, agent: agent, session: session, turn: event.turnId ?? "", source: event.source ?? "来源未知", coverage: coverage,
            timestamp: event.ts, trace: event.traceId, structured: structured, characters: body.count, counts: counts, blocks: blocks,
            fingerprints: fingerprints, truncated: blocks.count < entries.count || blocks.contains { $0.content.count < $0.characters })
    }

    private static func readable(_ value: Any) -> String {
        if let text = value as? String { return text }
        if let array = value as? [Any] { return array.map(readable).joined(separator: "\n\n") }
        guard let row = value as? [String: Any] else { return String(describing: value) }
        func json(_ value: Any) -> String { (try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed])).map { String(decoding: $0, as: UTF8.self) } ?? "未解码" }
        if let function = row["function"] as? [String: Any], row["type"] as? String == "function" {
            return "工具：\(function["name"] as? String ?? "名称未知")\n用途：\(function["description"] as? String ?? "未提供")\n参数定义：\n\(json(function["parameters"] ?? [:]))"
        }
        var parts: [String] = []
        if let content = row["content"] { parts.append(readable(content)) }
        if let text = row["text"] as? String { parts.append(text) }
        if let output = row["output"] { parts.append(readable(output)) }
        for call in row["tool_calls"] as? [[String: Any]] ?? [] {
            let function = call["function"] as? [String: Any] ?? [:]
            parts.append("模型工具指令：\(function["name"] as? String ?? "未知")\n调用编号：\(call["id"] as? String ?? "未提供")\n参数：\(function["arguments"] as? String ?? json(function["arguments"] ?? [:]))")
        }
        if let image = row["image_url"] { parts.append("图片引用（仅展示已采引用，不下载）：\(json(image))") }
        if let file = row["file"] { parts.append("文件引用（不代表文件全文已采）：\(json(file))") }
        return parts.isEmpty ? json(row) : parts.joined(separator: "\n\n")
    }

    static func assemble(_ parsed: [RealtimeContextExchange], events rawEvents: [GuardEvent]) -> [RealtimeContextExchange] {
        let events = RealtimeWorkspaceProjector.normalizedEvents(rawEvents)
        let byID = Dictionary(events.map { ($0.id.uuidString, $0) }, uniquingKeysWith: { _, last in last })
        // Native IDs are indexed once. Searching every event for each context
        // block made routine UI refreshes quadratic in long active sessions.
        var responses: [String: [GuardEvent]] = [:]
        var toolResults: [String: [GuardEvent]] = [:]
        for event in events {
            guard let agent = RealtimeWorkspaceProjector.canonicalAgent(event.agent) else { continue }
            if event.kind == "model", ["network_response", "response"].contains(event.op), let trace = event.traceId {
                responses[agent + "\u{0}" + trace, default: []].append(event)
            }
            if ["result", "hook_tool_finish"].contains(event.op), let session = event.sessionId, let call = event.toolCallId {
                toolResults[agent + "\u{0}" + session + "\u{0}" + call, default: []].append(event)
            }
        }
        let requestIDs = Set(events.map { $0.id.uuidString })
        let valid = parsed.compactMap { exchange -> RealtimeContextExchange? in
            guard requestIDs.contains(exchange.id), let event = byID[exchange.id], event.op != "recovered_context" else { return nil }
            if event.turnId != exchange.turn { return parse(event) }
            return exchange
        }
        // Local user messages are a fallback, never a second full model round.
        let transportTurns = Set(valid.filter { $0.trace?.hasPrefix("workbuddy-http:") == true }.map { "\($0.agent)\u{0}\($0.session)\u{0}\($0.turn)" })
        let selected = valid.filter { $0.trace?.hasPrefix("workbuddy-http:") == true || !transportTurns.contains("\($0.agent)\u{0}\($0.session)\u{0}\($0.turn)") }
        var output: [RealtimeContextExchange] = []
        for group in Dictionary(grouping: selected, by: { "\($0.agent)\u{0}\($0.session)" }).values {
            var previous: RealtimeContextExchange?
            for var exchange in group.sorted(by: { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }) {
                if let before = previous, before.structured, exchange.structured {
                    exchange.previousID = before.id
                    var oldCounts = Dictionary(grouping: before.fingerprints, by: { $0 }).mapValues(\.count)
                    var kept = 0
                    for hash in exchange.fingerprints {
                        if oldCounts[hash, default: 0] > 0 { kept += 1; oldCounts[hash, default: 0] -= 1 }
                    }
                    exchange.retained = kept; exchange.added = exchange.fingerprints.count - kept; exchange.removed = before.fingerprints.count - kept
                    var remaining = Dictionary(grouping: before.fingerprints, by: { $0 }).mapValues(\.count)
                    for index in exchange.blocks.indices {
                        let hash = exchange.blocks[index].fingerprint
                        exchange.blocks[index].change = remaining[hash, default: 0] > 0 ? "retained" : "added"
                        remaining[hash, default: 0] = max(0, remaining[hash, default: 0] - 1)
                    }
                }
                if let trace = exchange.trace {
                    let matching = (responses[exchange.agent + "\u{0}" + trace] ?? []).filter { $0.ts >= exchange.timestamp && (trace.hasPrefix("workbuddy-http:") || ($0.sessionId == exchange.session && $0.turnId == exchange.turn)) && $0.kind == "model" && ["network_response", "response"].contains($0.op) }
                    if let response = matching.max(by: { $0.ts < $1.ts }) {
                        exchange.response = response.modelResponse.map { String($0.prefix(16_000)) }
                        exchange.toolInstructions = response.modelDecision.map { String($0.prefix(16_000)) }
                        exchange.recordedReasoning = response.modelReasoning.map { String($0.prefix(16_000)) }
                        exchange.responseID = response.id.uuidString; exchange.responseBasis = "相同 Agent 与原生 trace / HTTPS flow；任务归属仍沿用原置信度"
                        exchange.inputTokens = response.inputTokens; exchange.outputTokens = response.outputTokens
                    }
                }
                for index in exchange.blocks.indices {
                    guard let call = exchange.blocks[index].callID else { continue }
                    let matches = (toolResults[exchange.agent + "\u{0}" + exchange.session + "\u{0}" + call] ?? []).filter { $0.ts <= exchange.timestamp }
                    if Set(matches.compactMap(\.turnId)).count <= 1 { exchange.blocks[index].toolEvidenceIDs = matches.map { $0.id.uuidString } }
                }
                output.append(exchange); previous = exchange
            }
        }
        return output.sorted { $0.timestamp < $1.timestamp }
    }
}
