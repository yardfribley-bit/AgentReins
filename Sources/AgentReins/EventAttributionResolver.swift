import Foundation

/// Conservatively joins fallback process/file observations to recent native agent turns.
/// It never emits `confirmed`: native IDs or hooks must supply that level of certainty.
@MainActor
final class EventAttributionResolver: ObservableObject {
    private struct Context {
        let sessionId: String
        let turnId: String
        let toolCallId: String?
        let toolName: String?
        let kind: String
        let op: String
        let command: String?
        let agent: String?
        let workspace: String?
        let timestamp: Date
    }

    private var contexts: [Context] = []
    private let window: TimeInterval

    init(window: TimeInterval = 45) {
        self.window = window
    }

    func labelNative(_ events: [GuardEvent]) -> [GuardEvent] {
        events.map { event in
            guard event.attributionConfidence == nil,
                  let sessionId = event.sessionId, let turnId = event.turnId else { return event }
            if event.source == "agentsight:workbuddy-local",
               event.kind == "model", event.op == "prompt" {
                return event.attributed(sessionId: sessionId, turnId: turnId,
                                        toolCallId: event.toolCallId, confidence: .confirmed,
                                        method: "native WorkBuddy prompt and turn IDs")
            }
            let source = event.source == "agentsight:codex-local-compat"
                ? "Codex rollout compatibility record" : "adapter session/turn correlation"
            return event.attributed(sessionId: sessionId, turnId: turnId,
                                    toolCallId: event.toolCallId, confidence: .inferred,
                                    method: source)
        }
    }

    func observe(_ events: [GuardEvent], now: Date = Date()) {
        for event in events {
            guard let sessionId = event.sessionId, let turnId = event.turnId else { continue }
            contexts.append(Context(sessionId: sessionId, turnId: turnId,
                                    toolCallId: event.toolCallId, toolName: event.toolName,
                                    kind: event.kind, op: event.op, command: event.command,
                                    agent: event.agent?.lowercased(),
                                    workspace: normalizedWorkspace(event.path), timestamp: event.ts))
        }
        contexts.removeAll { now.timeIntervalSince($0.timestamp) > max(window * 4, 180) }
        if contexts.count > 500 { contexts.removeFirst(contexts.count - 500) }
    }

    func resolve(_ event: GuardEvent) -> GuardEvent {
        if let sessionId = event.sessionId, let turnId = event.turnId {
            guard event.kind == "network", event.toolName == nil else { return event }
            let matching = contexts.filter {
                $0.sessionId == sessionId && $0.turnId == turnId &&
                abs(event.ts.timeIntervalSince($0.timestamp)) <= window &&
                agentMatches(event.agent, $0.agent)
            }
            guard let tool = uniqueToolContext(for: event, in: matching,
                                               sessionId: sessionId, turnId: turnId) else { return event }
            let previous = event.attributionMethod.map { $0 + " + " } ?? ""
            return event.attributed(sessionId: sessionId, turnId: turnId,
                                    toolCallId: tool.toolCallId, toolName: tool.toolName,
                                    remoteDomain: requestedDomain(in: tool.command),
                                    confidence: .inferred,
                                    method: previous + "single active tool call (late correlation)")
        }
        // A timestamp alone is not identity evidence. Require either a process-tree
        // agent attribution or a file path that can be checked against a workspace.
        guard event.agent != nil || event.path != "-" else { return event }
        let matching = contexts.filter { context in
            abs(event.ts.timeIntervalSince(context.timestamp)) <= window &&
            agentMatches(event.agent, context.agent) && workspaceMatches(event.path, context.workspace)
        }
        let candidates = Dictionary(grouping: matching) { "\($0.sessionId):\($0.turnId)" }
            .compactMap { $0.value.max(by: { $0.timestamp < $1.timestamp }) }
        // Parallel turns in the same agent/workspace are genuinely ambiguous
        // without a native PID or tool-call join key. Never choose one by recency.
        guard candidates.count == 1, let best = candidates.first else { return event }

        var reasons: [String] = ["bounded \(Int(window))s time window"]
        if event.agent != nil, best.agent != nil { reasons.insert("process-tree agent", at: 0) }
        if event.path != "-", best.workspace != nil { reasons.insert("workspace path", at: 0) }
        let tool = uniqueToolContext(for: event, in: matching,
                                     sessionId: best.sessionId, turnId: best.turnId)
        if tool != nil { reasons.append("single active tool call") }
        let resolvedToolCallId = event.kind == "network" ? tool?.toolCallId : best.toolCallId
        return event.attributed(sessionId: best.sessionId, turnId: best.turnId,
                                toolCallId: resolvedToolCallId, toolName: tool?.toolName,
                                remoteDomain: tool.flatMap { requestedDomain(in: $0.command) },
                                confidence: .inferred,
                                method: reasons.joined(separator: " + "))
    }

    /// A socket owner proves the process, not the logical tool. Attribute a
    /// network event to a tool only when exactly one tool call is present in a
    /// tighter time window for the already-resolved turn. Ambiguity stays empty.
    private func uniqueToolContext(for event: GuardEvent, in matching: [Context],
                                   sessionId: String, turnId: String) -> Context? {
        guard event.kind == "network" else { return nil }
        let toolWindow = min(window, 15)
        let tools = matching.filter {
            $0.sessionId == sessionId && $0.turnId == turnId &&
            $0.kind == "tool" && $0.op == "call" && $0.toolCallId != nil &&
            abs(event.ts.timeIntervalSince($0.timestamp)) <= toolWindow
        }
        let byCall = Dictionary(grouping: tools, by: { $0.toolCallId! })
        guard byCall.count == 1, let group = byCall.values.first else { return nil }
        return group.max(by: { $0.timestamp < $1.timestamp })
    }

    private func requestedDomain(in command: String?) -> String? {
        ExternalURLEvidence.firstDomain(in: command)
    }

    private func agentMatches(_ eventAgent: String?, _ contextAgent: String?) -> Bool {
        guard let eventAgent = eventAgent?.lowercased(), let contextAgent else { return true }
        return eventAgent == contextAgent || eventAgent.contains(contextAgent) || contextAgent.contains(eventAgent)
    }

    private func workspaceMatches(_ path: String, _ workspace: String?) -> Bool {
        guard path != "-" else { return true }
        guard let workspace else { return false }
        let observed = URL(fileURLWithPath: path).standardizedFileURL.path
        let root = URL(fileURLWithPath: workspace).standardizedFileURL.path
        return observed == root || observed.hasPrefix(root + "/")
    }

    private func normalizedWorkspace(_ path: String) -> String? {
        guard path != "-", path.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: path).standardizedFileURL.path
    }
}
