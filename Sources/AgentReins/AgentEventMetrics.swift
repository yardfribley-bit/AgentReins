import Foundation

/// Shared metrics derived exclusively from canonical events. Adapters never
/// maintain their own dashboard totals, keeping definitions agent-neutral.
struct AgentEventMetrics: Codable, Equatable, Sendable {
    let eventCount: Int
    let sessionCount: Int
    let taskCount: Int
    let turnCount: Int
    let llmRequestCount: Int
    let llmResponseCount: Int
    let toolCallCount: Int
    let toolResultCount: Int
    let fileActivityCount: Int
    let commandExecutionCount: Int
    let networkActivityCount: Int
    let verificationCount: Int
    let findingCount: Int
    let inputTokens: Int
    let outputTokens: Int
    let totalCost: Double
    let eventsByKind: [AgentCanonicalEventKind: Int]

    static func build(events: [AgentEventEnvelope]) -> AgentEventMetrics {
        let sessions = Set(events.map(\.sessionID))
        let tasks = Set(events.map(\.effectiveTaskID))
        let turns = Set(events.compactMap { event in
            event.turnID.map { "\(event.sessionID):\($0)" }
        })
        var byKind: [AgentCanonicalEventKind: Int] = [:]
        var requestKeys = Set<String>()
        var toolCallIDs = Set<String>()
        var toolResultIDs = Set<String>()
        var commandIDs = Set<String>()
        // A trace can span multiple model steps (for example a tool decision
        // followed by a final answer). Source event identity is the stable
        // boundary for a usage record; repeated projections of that same
        // record take the largest values, while distinct records add up.
        var usageBySourceEvent: [String: (input: Int, output: Int, cost: Double)] = [:]

        for event in events {
            byKind[event.canonicalKind, default: 0] += 1
            switch event.payload {
            case .contextPrepared:
                requestKeys.insert(event.correlation?.requestID ?? event.id)
            case let .contextUsage(usage):
                let key = event.correlation?.sourceEventID ?? event.id
                let previous = usageBySourceEvent[key] ?? (0, 0, 0)
                usageBySourceEvent[key] = (
                    max(previous.input, usage.inputTokens ?? 0),
                    max(previous.output, usage.outputTokens ?? 0),
                    max(previous.cost, usage.cost ?? 0))
            case let .toolCall(call):
                toolCallIDs.insert(call.callID)
                if isCommandTool(call.toolName) {
                    commandIDs.insert(event.correlation?.actionID ?? call.callID)
                }
            case let .toolOutput(output):
                toolResultIDs.insert(output.callID)
            default:
                break
            }
        }
        let inputTokens = usageBySourceEvent.values.reduce(0) { $0 + $1.input }
        let outputTokens = usageBySourceEvent.values.reduce(0) { $0 + $1.output }
        let totalCost = usageBySourceEvent.values.reduce(0) { $0 + $1.cost }

        return AgentEventMetrics(
            eventCount: events.count, sessionCount: sessions.count,
            taskCount: tasks.count, turnCount: turns.count,
            llmRequestCount: requestKeys.count,
            llmResponseCount: byKind[.llmResponse, default: 0],
            toolCallCount: toolCallIDs.count, toolResultCount: toolResultIDs.count,
            fileActivityCount: byKind[.fileActivity, default: 0],
            commandExecutionCount: commandIDs.count,
            networkActivityCount: byKind[.networkActivity, default: 0],
            verificationCount: byKind[.verification, default: 0],
            findingCount: byKind[.finding, default: 0],
            inputTokens: inputTokens, outputTokens: outputTokens,
            totalCost: totalCost, eventsByKind: byKind)
    }

    private static func isCommandTool(_ name: String) -> Bool {
        let normalized = name.lowercased()
        return normalized.contains("shell") || normalized.contains("terminal") ||
            normalized.contains("command") || normalized.contains("exec") ||
            normalized == "bash" || normalized == "powershell"
    }
}
