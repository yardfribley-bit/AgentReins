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
        let userIntent: String?
        let agent: String?
        let workspace: String?
        let timestamp: Date
    }

    private var contexts: [Context] = []
    private var activeWorkBuddyPrompts: [String: Context] = [:]
    private var workBuddyReplies: [String: String] = [:]
    private var pendingWorkBuddyStops: [String: Set<String>] = [:]
    private var workBuddyFlows: [String: Context] = [:]
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
            if event.op == "hook_turn_stop", event.turnId == nil, let session = event.sessionId,
               let root = RealtimeDetailProjector.object(event.afterContent), let body = root["payload"] as? [String: Any],
               let final = body["last_assistant_message"] as? String {
                if final.count <= 16_000 { pendingWorkBuddyStops[session, default: []].insert(final) }
                let matches = workBuddyReplies.filter { $0.key.hasPrefix(session + "\u{0}") && $0.value == final }
                if matches.count == 1, let key = matches.first?.key { activeWorkBuddyPrompts.removeValue(forKey: key); workBuddyReplies.removeValue(forKey: key) }
            }
            guard let sessionId = event.sessionId, let turnId = event.turnId else { continue }
            let context = Context(sessionId: sessionId, turnId: turnId,
                                    toolCallId: event.toolCallId, toolName: event.toolName,
                                    kind: event.kind, op: event.op, command: event.command,
                                    userIntent: event.userIntent,
                                    agent: event.agent?.lowercased(),
                                    workspace: normalizedWorkspace(event.path), timestamp: event.ts)
            contexts.append(context)
            if context.agent == "workbuddy" {
                let key = sessionId + "\u{0}" + turnId
                if event.kind == "model", event.op == "prompt", event.source != "agentsight:workbuddy-network-body", event.userIntent?.isEmpty == false { activeWorkBuddyPrompts[key] = context }
                if event.kind == "model", event.op == "response", let text = event.modelResponse {
                    workBuddyReplies[key] = text
                    if pendingWorkBuddyStops[sessionId]?.contains(text) == true {
                        let matches = workBuddyReplies.filter { $0.key.hasPrefix(sessionId + "\u{0}") && $0.value == text }
                        if matches.count == 1 { activeWorkBuddyPrompts.removeValue(forKey: key); workBuddyReplies.removeValue(forKey: key); pendingWorkBuddyStops[sessionId]?.remove(text) }
                    }
                }
                if ["task_complete", "task_failed", "task_cancelled", "turn_completed", "hook_turn_stop"].contains(event.op) { activeWorkBuddyPrompts.removeValue(forKey: key); workBuddyReplies.removeValue(forKey: key) }
            }
        }
        contexts.removeAll { now.timeIntervalSince($0.timestamp) > max(window * 4, 180) }
        if contexts.count > 500 { contexts.removeFirst(contexts.count - 500) }
        if pendingWorkBuddyStops.count > 256 { pendingWorkBuddyStops.removeValue(forKey: pendingWorkBuddyStops.keys.sorted().first!) }
        for key in pendingWorkBuddyStops.keys where (pendingWorkBuddyStops[key]?.count ?? 0) > 8 { pendingWorkBuddyStops[key] = Set(pendingWorkBuddyStops[key]!.sorted().suffix(8)) }
        if activeWorkBuddyPrompts.count > 256 {
            for item in activeWorkBuddyPrompts.sorted(by: { $0.value.timestamp < $1.value.timestamp }).prefix(activeWorkBuddyPrompts.count - 256) {
                activeWorkBuddyPrompts.removeValue(forKey: item.key); workBuddyReplies.removeValue(forKey: item.key)
            }
        }
        if workBuddyFlows.count > 1024 {
            for item in workBuddyFlows.sorted(by: { $0.value.timestamp < $1.value.timestamp }).prefix(workBuddyFlows.count - 1024) { workBuddyFlows.removeValue(forKey: item.key) }
        }
    }

    /// Joins a captured WorkBuddy HTTPS body only when its user text identifies
    /// exactly one active native prompt for the full turn lifetime. Parallel or missing matches stay in a
    /// separate network evidence session instead of being guessed into a turn.
    func resolveWorkBuddyNetworkBody(_ event: GuardEvent) -> GuardEvent {
        guard event.source == "agentsight:workbuddy-network-body" else { return event }
        if event.op != "network_prompt", let trace = event.traceId, let match = workBuddyFlows[trace] {
            return event.attributed(sessionId: match.sessionId, turnId: match.turnId,
                toolCallId: event.toolCallId, confidence: .inferred, method: "same HTTPS flow as an already-attributed request")
        }
        guard let intent = normalizedIntent(event.userIntent), !intent.isEmpty else { return event }
        let matching = activeWorkBuddyPrompts.values.filter { context in
            guard context.timestamp <= event.ts.addingTimeInterval(1), let candidate = normalizedIntent(context.userIntent) else { return false }
            return candidate == intent || (candidate.count == 1_000 && intent.hasPrefix(candidate))
        }
        let turns = Dictionary(grouping: matching) { "\($0.sessionId):\($0.turnId)" }
        guard turns.count == 1, let match = turns.values.first?.first else { return event }
        if let trace = event.traceId { workBuddyFlows[trace] = match }
        return event.attributed(sessionId: match.sessionId, turnId: match.turnId,
            toolCallId: event.toolCallId, confidence: .inferred,
            method: "unique exact WorkBuddy user text in an active native turn; no 45s cutoff")
    }

    func resolve(_ event: GuardEvent) -> GuardEvent {
        // Observation arms identify processes, not tasks. Keep their raw samples
        // independent of whichever tool happens to be active in a time window.
        if event.ruleId == "process_observation" || event.ruleId == "workbuddy_hook_native" { return event }

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
                                    confidence: .inferred,
                                    method: previous + "single active tool call (late correlation)")
        }
        // A timestamp alone is not identity evidence. Require either a process-tree
        // agent attribution or a file path that can be checked against a workspace.
        guard event.agent != nil || event.path != "-" else { return event }
        let matching = contexts.filter { context in
            abs(event.ts.timeIntervalSince(context.timestamp)) <= window &&
            agentMatches(event.agent, context.agent) &&
            (workspaceMatches(event.path, context.workspace) || isAgentMemoryPath(event.path))
        }
        let candidates = Dictionary(grouping: matching) { "\($0.sessionId):\($0.turnId)" }
            .compactMap { $0.value.max(by: { $0.timestamp < $1.timestamp }) }
        // Parallel turns in the same agent/workspace are genuinely ambiguous
        // without a native PID or tool-call join key. Never choose one by recency.
        guard candidates.count == 1, let best = candidates.first else { return event }

        var reasons: [String] = ["bounded \(Int(window))s time window"]
        if event.agent != nil, best.agent != nil { reasons.insert("process-tree agent", at: 0) }
        if isAgentMemoryPath(event.path) { reasons.insert("known agent memory path", at: 0) }
        else if event.path != "-", best.workspace != nil { reasons.insert("workspace path", at: 0) }
        let tool = uniqueToolContext(for: event, in: matching,
                                     sessionId: best.sessionId, turnId: best.turnId)
        if tool != nil { reasons.append("single active tool call") }
        let resolvedToolCallId = event.kind == "network" ? tool?.toolCallId : best.toolCallId
        return event.attributed(sessionId: best.sessionId, turnId: best.turnId,
                                toolCallId: resolvedToolCallId, toolName: tool?.toolName,
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
        // Tool arguments describe intent. They must neither relabel a socket
        // nor associate an observed different destination with that URL tool.
        let destinationCompatible = tools.filter { tool in
            guard let observed = event.remoteDomain, let requested = requestedDomain(in: tool.command) else { return true }
            return observed.lowercased() == requested.lowercased()
        }
        let byCall = Dictionary(grouping: destinationCompatible, by: { $0.toolCallId! })
        if byCall.count > 1 {
            // When several tools start together, a single tool containing an
            // explicit URL is the only defensible candidate for a web socket.
            // Generic MCP and filesystem calls remain ambiguous.
            let networkTools = destinationCompatible.filter { requestedDomain(in: $0.command) != nil }
            let networkByCall = Dictionary(grouping: networkTools, by: { $0.toolCallId! })
            guard networkByCall.count == 1, let group = networkByCall.values.first else { return nil }
            return group.max(by: { $0.timestamp < $1.timestamp })
        }
        guard let group = byCall.values.first else { return nil }
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

    private func isAgentMemoryPath(_ path: String) -> Bool {
        let value = path.lowercased()
        return value.contains("/.workbuddy/memory/") ||
            (value.contains("/.workbuddy/") &&
                ["/memory.md", "/user.md", "/identity.md", "/soul.md"].contains(where: value.contains)) ||
            value.contains("/.kiro/knowledge/memory/") || value.contains("/.agent-memory/")
    }

    private func normalizedWorkspace(_ path: String) -> String? {
        guard path != "-", path.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: path).standardizedFileURL.path
    }

    private func normalizedIntent(_ value: String?) -> String? {
        value?.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: #"\s+"#, with: " ", options: .regularExpression)
    }
}
