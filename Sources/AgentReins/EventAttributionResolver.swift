import Foundation

/// Conservatively joins fallback process/file observations to recent native agent turns.
/// It never emits `confirmed`: native IDs or hooks must supply that level of certainty.
@MainActor
final class EventAttributionResolver: ObservableObject {
    private struct Context {
        let sessionId: String
        let turnId: String
        let toolCallId: String?
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
                                    toolCallId: event.toolCallId, agent: event.agent?.lowercased(),
                                    workspace: normalizedWorkspace(event.path), timestamp: event.ts))
        }
        contexts.removeAll { now.timeIntervalSince($0.timestamp) > max(window * 4, 180) }
        if contexts.count > 500 { contexts.removeFirst(contexts.count - 500) }
    }

    func resolve(_ event: GuardEvent) -> GuardEvent {
        if event.sessionId != nil, event.turnId != nil { return event }
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
        return event.attributed(sessionId: best.sessionId, turnId: best.turnId,
                                toolCallId: best.toolCallId, confidence: .inferred,
                                method: reasons.joined(separator: " + "))
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
