import Foundation

struct AgentToolCall: Identifiable {
    let id: String
    let name: String
    let arguments: String?
    let status: String
    let startedAt: Date
    let completedAt: Date?
    let traceId: String?
    let result: String?

    var friendlyName: String {
        let key = name.lowercased()
        if key.contains("websearch") || key.contains("search") { return "Search the web" }
        if key.contains("webfetch") || key.contains("fetch") { return "Read a webpage" }
        if key == "read" || key.contains("read_file") { return "Read a file" }
        if key == "edit" || key.contains("write") { return "Modify a file" }
        if key == "bash" || key.contains("shell") { return "Run a command" }
        if key.contains("weather") { return "Check weather" }
        if key.contains("present") { return "Present a file" }
        return name
    }

    var friendlyStatus: String {
        switch status.lowercased() {
        case "completed", "success", "ok": return "Completed"
        case "failed", "error": return "Failed"
        case "requested", "running": return "In progress"
        default: return status
        }
    }

    var isMemoryOperation: Bool {
        let text = "\(name) \(arguments ?? "")".lowercased()
        return ["memory", "remember", "knowledge", ".workbuddy", "记忆"].contains(where: text.contains)
    }

    var isMemoryWrite: Bool {
        guard isMemoryOperation else { return false }
        let text = "\(name) \(arguments ?? "")".lowercased()
        return ["write", "edit", "update", "add", "append", "save", "commit", "remember", "写入", "更新"].contains(where: text.contains)
    }

    var isMemoryRead: Bool {
        guard isMemoryOperation else { return false }
        let text = "\(name) \(arguments ?? "")".lowercased()
        return ["read", "get", "search", "query", "retrieve", "load", "读取", "检索"].contains(where: text.contains) || !isMemoryWrite
    }
}

struct AgentTurn: Identifiable {
    let id: String
    let index: Int
    let userInput: String?
    let startedAt: Date
    let exchanges: [ModelExchange]
    let riskCount: Int

    var toolCalls: [AgentToolCall] { exchanges.flatMap(\.toolCalls) }
    var memoryOperations: [AgentToolCall] { toolCalls.filter(\.isMemoryOperation) }
    var finalResponse: String? { exchanges.compactMap(\.response).last }
    var fullPrompt: String? { exchanges.compactMap(\.prompt).first }
    var recordedReasoning: String? { exchanges.compactMap(\.reasoning).last }
    var modelNames: String {
        let names = Array(Set(exchanges.compactMap(\.model))).sorted()
        return names.isEmpty ? "Not captured" : names.joined(separator: ", ")
    }
    var contextCharacters: Int { fullPrompt?.count ?? 0 }
    var contextBytes: Int { fullPrompt?.utf8.count ?? 0 }
    var responseCharacters: Int { finalResponse?.count ?? 0 }
    var inputTokens: Int? { exchanges.compactMap(\.inputTokens).max() }
    var outputTokens: Int? { exchanges.compactMap(\.outputTokens).max() }
    var cachedTokens: Int? { exchanges.compactMap(\.cachedTokens).max() }
    var reasoningTokens: Int? { exchanges.compactMap(\.reasoningTokens).max() }
    var needsAttention: Bool { riskCount > 0 }
    var modelInstructionSummary: String {
        if !toolCalls.isEmpty {
            return toolCalls.map { call in
                let args = call.arguments?.replacingOccurrences(of: "\n", with: " ") ?? ""
                return "\(call.name) \(String(args.prefix(140)))"
            }.joined(separator: "\n")
        }
        return finalResponse == nil ? "No model response was captured" : "The model returned text without a recorded tool instruction"
    }
    var executionSummary: String {
        guard !toolCalls.isEmpty else { return "No Tool, Function call, or MCP invocation was recorded" }
        return toolCalls.map { "\($0.name) · \($0.friendlyStatus)" }.joined(separator: "\n")
    }
    var toolResultSummary: String {
        let outputs = toolCalls.compactMap { call in call.result.map { "\(call.name): \(String($0.prefix(500)))" } }
        return outputs.isEmpty ? "Tool results were not captured" : outputs.joined(separator: "\n\n")
    }
    var codeChangeSummary: String {
        let changes = toolCalls.filter {
            let value = "\($0.name) \($0.arguments ?? "")".lowercased()
            return ["edit", "write", "patch", "create", "delete", "move", "rename"].contains(where: value.contains)
        }
        guard !changes.isEmpty else { return "No file or code modification call was detected" }
        return changes.map { "\($0.name): \($0.arguments ?? "Arguments not captured")" }.joined(separator: "\n")
    }
    var memoryRetrievalSummary: String {
        let reads = toolCalls.filter(\.isMemoryRead)
        if !reads.isEmpty {
            return reads.map { "\($0.name): \($0.arguments ?? "Arguments not captured")" }.joined(separator: "\n")
        }
        let prompt = fullPrompt?.lowercased() ?? ""
        if prompt.contains("memory") || prompt.contains("user.md") || prompt.contains("identity.md") {
            return "Persistent memory or identity files appear in the captured model context. Review step 2 for the evidence."
        }
        return "No evidence of memory retrieval was detected"
    }
    var memoryCommitSummary: String {
        let writes = toolCalls.filter(\.isMemoryWrite)
        guard !writes.isEmpty else { return "No persistent memory write was detected" }
        return writes.map { call in
            let outcome = call.result.map { "\nResult: \(String($0.prefix(300)))" } ?? "\nResult: not captured"
            return "\(call.name): \(call.arguments ?? "Arguments not captured")\(outcome)"
        }.joined(separator: "\n\n")
    }
}

struct ModelExchange: Identifiable {
    let id: String
    let traceId: String?
    let turnId: String?
    let model: String?
    let userIntent: String?
    let reasoning: String?
    let prompt: String?
    let response: String?
    let decision: String?
    let startedAt: Date
    let toolCalls: [AgentToolCall]
    let inputTokens: Int?
    let outputTokens: Int?
    let cachedTokens: Int?
    let reasoningTokens: Int?
}

struct AgentSessionSnapshot: Identifiable {
    let id: String
    let agent: String
    let model: String?
    let workspace: String?
    let startedAt: Date
    let lastActivityAt: Date
    let exchanges: [ModelExchange]
    let turns: [AgentTurn]
    let events: [GuardEvent]

    var latestIntent: String? { exchanges.compactMap(\.userIntent).last }
    var toolCallCount: Int { exchanges.reduce(0) { $0 + $1.toolCalls.count } }
    var traceCount: Int { Set(exchanges.compactMap(\.traceId)).count }
    var riskCount: Int { events.filter { $0.severity != "info" }.count }
    var plainSummary: String {
        guard let call = exchanges.last?.toolCalls.last else { return latestIntent ?? "等待 Agent 活动" }
        return "\(call.friendlyName) · \(call.friendlyStatus)"
    }

    static func build(from events: [GuardEvent]) -> [AgentSessionSnapshot] {
        Dictionary(grouping: events.compactMap { event -> GuardEvent? in
            event.sessionId == nil ? nil : event
        }, by: { $0.sessionId! }).map { sessionId, sessionEvents in
            let ordered = sessionEvents.sorted { $0.ts < $1.ts }
            let exchanges = buildExchanges(ordered)
            let turns = buildTurns(ordered, exchanges: exchanges)
            return AgentSessionSnapshot(
                id: sessionId,
                agent: normalizedAgent(ordered.compactMap(\.agent).last),
                model: ordered.compactMap(\.model).last,
                workspace: ordered.map(\.path).last(where: { $0 != "-" }),
                startedAt: ordered.first?.ts ?? Date(),
                lastActivityAt: ordered.last?.ts ?? Date(),
                exchanges: exchanges,
                turns: turns,
                events: ordered)
        }.sorted { $0.lastActivityAt > $1.lastActivityAt }
    }

    private static func buildTurns(_ events: [GuardEvent], exchanges: [ModelExchange]) -> [AgentTurn] {
        let grouped = Dictionary(grouping: events) { $0.turnId ?? "unattributed" }
        let orderedGroups = grouped.map { id, turnEvents in
            (id, turnEvents.sorted { $0.ts < $1.ts })
        }.sorted { ($0.1.first?.ts ?? .distantPast) < ($1.1.first?.ts ?? .distantPast) }
        return orderedGroups.enumerated().map { offset, pair in
            let (id, turnEvents) = pair
            let matched = exchanges.filter { $0.turnId == id || (id == "unattributed" && $0.turnId == nil) }
            return AgentTurn(id: id, index: offset + 1,
                userInput: turnEvents.first(where: { $0.op == "prompt" })?.userIntent ?? turnEvents.compactMap(\.userIntent).first,
                startedAt: turnEvents.first?.ts ?? Date(), exchanges: matched,
                riskCount: turnEvents.filter { $0.severity != "info" }.count)
        }
    }

    private static func normalizedAgent(_ value: String?) -> String {
        guard let value, !value.isEmpty else { return "Agent" }
        return value.lowercased() == "cli" ? "workbuddy" : value
    }

    private static func buildExchanges(_ events: [GuardEvent]) -> [ModelExchange] {
        let grouped = Dictionary(grouping: events) { $0.traceId ?? "session:\($0.sessionId ?? "unknown")" }
        return grouped.map { key, traceEvents in
            let ordered = traceEvents.sorted { $0.ts < $1.ts }
            let calls = Dictionary(grouping: ordered.filter { $0.toolCallId != nil }, by: { $0.toolCallId! }).map { callId, callEvents in
                let call = callEvents.first(where: { $0.op == "call" }) ?? callEvents[0]
                let completion = callEvents.first(where: { $0.op == "result" })
                return AgentToolCall(id: callId, name: call.toolName ?? "工具", arguments: call.command,
                    status: completion?.action ?? call.action, startedAt: call.ts,
                    completedAt: completion?.ts, traceId: call.traceId,
                    result: completion?.modelResponse)
            }.sorted { $0.startedAt < $1.startedAt }
            return ModelExchange(id: key, traceId: ordered.compactMap(\.traceId).first,
                turnId: ordered.compactMap(\.turnId).first,
                model: ordered.compactMap(\.model).first,
                userIntent: ordered.compactMap(\.userIntent).first,
                reasoning: ordered.compactMap(\.modelReasoning).first,
                prompt: ordered.compactMap(\.modelPrompt).first,
                response: ordered.compactMap(\.modelResponse).last,
                decision: ordered.compactMap(\.modelDecision).first,
                startedAt: ordered.first?.ts ?? Date(), toolCalls: calls,
                inputTokens: ordered.compactMap(\.inputTokens).max(),
                outputTokens: ordered.compactMap(\.outputTokens).max(),
                cachedTokens: ordered.compactMap(\.cachedTokens).max(),
                reasoningTokens: ordered.compactMap(\.reasoningTokens).max())
        }.sorted { $0.startedAt < $1.startedAt }
    }
}
