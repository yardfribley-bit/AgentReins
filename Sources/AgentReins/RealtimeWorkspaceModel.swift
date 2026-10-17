import Foundation

/// Presentation-only projection. Never reads historical tasks or guesses cross-turn causality.
struct RealtimeWorkspacePayload: Encodable {
    var tasks: [RealtimeTask]
    var collected: [RealtimeCollectedRecord]
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
    var lazyTasks = false
    var collectedOrder: [String]? = nil
    var detailDelta: RealtimeWorkspaceTransport.DetailDelta? = nil
}
struct RealtimeCollectedRecord: Encodable {
    var networkBody: RealtimeNetworkBodyPreview? = nil
    var revision = UUID().uuidString
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
    var resource: RealtimeResourceDetail? = nil
}
struct RealtimeProcess: Equatable, Encodable {
    let id: String, pid: String, parent: String, agent: String, name: String
    var executable: String = ""
    var command: String = ""
    var active: Bool = true
    var depth: Int = 0
}
struct RealtimeHealth: Equatable, Encodable {
    let source: String, state: String
    let accepted: Int
    let detail: String?
}
struct RealtimeInputAttachment: Equatable, Encodable {
    let type: String
    let path: String?
    let source: String
    let eventIDs: [String]
}
struct RealtimeUserInput: Equatable, Encodable {
    let id: String
    let content: String?
    let timestamp: Date
    let source: String
    let eventIDs: [String]
    let basis: String
}
struct RealtimeTask: Equatable, Encodable, Identifiable {
    let id: String, agent: String, session: String, turn: String, title: String
    let startedAt: Date, lastActivity: Date
    var cards: [RealtimeCard]
    let model: String?
    var reportedComplete: Bool
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
    var inputAttachments: [RealtimeInputAttachment] = []
    var executionState: String = "observed"
    var completionEvidence: String = "unknown"
    var statusChangedAt: Date? = nil
    var nativeEndAt: Date? = nil
    var nativeTerminalEventID: String? = nil
    var nativeEndOp: String? = nil
    var nativeEndAction: String? = nil
    var nativeEndSource: String? = nil
    var nativeEndMessage: String? = nil
    var nativeEndMessageTruncated: Bool = false
    var stopReason: String? = nil
    var lastFailureCardID: String? = nil
    var unresolvedCallIDs: [String] = []
    var userInputs: [RealtimeUserInput] = []
    var latestUserInput: RealtimeUserInput? = nil
    var parentSession: String? = nil
    var subagentPath: String? = nil
    var projectionRevision = UUID().uuidString
    var detailsLoaded = true
    var searchText = ""
}
struct RealtimeCard: Equatable, Encodable, Identifiable {
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
    var networkBody: RealtimeNetworkBodyPreview? = nil
    var codeFindings: [CodeFinding] = []
}

enum RealtimeWorkspaceProjector {
    static func codeFindings(_ events: [GuardEvent]) -> [CodeFinding] {
        var seen = Set<String>()
        return events.flatMap { $0.codeFindings ?? [] }.filter { seen.insert($0.id).inserted }.map {
            CodeFinding(ruleId: $0.ruleId, title: $0.title, severity: $0.severity,
                        line: $0.line, evidence: $0.ruleId == "hardcoded-secret"
                        ? "[敏感值已隐藏，请在源文件核查并轮换可能泄露的凭据]"
                        : ProcessArgumentRedactor.redact($0.evidence))
        }
    }

    /// Retain both source IDs while displaying an unambiguous native/transport
    /// echo once. Repeated sends, different turns and ambiguous matches stay separate.
    static func userInputs(_ events: [GuardEvent]) -> [RealtimeUserInput] {
        let humans = events.filter { ["prompt", "hook_user_prompt"].contains($0.op) && ($0.userIntent != nil || $0.ruleId == "codex_model_prompt") }
            .sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
        func format(_ e: GuardEvent) -> String { RealtimeDetailProjector.object(e.command)?["input_record_kind"] as? String ?? "" }
        var paired = Set<UUID>(), pairs: [UUID: GuardEvent] = [:]
        for native in humans where format(native) == "native_user_message" {
            let matches = humans.filter { e in
                format(e) == "transport_user_message" && e.sessionId == native.sessionId && e.turnId == native.turnId && e.source == native.source &&
                e.userIntent == native.userIntent && (e.userIntent != nil || e.modelPrompt == native.modelPrompt) &&
                native.ts.timeIntervalSince(e.ts) >= 0 && native.ts.timeIntervalSince(e.ts) <= 1 && !paired.contains(e.id)
            }
            guard matches.count == 1, let transport = matches.first else { continue }
            let echoes = humans.filter { format($0) == "native_user_message" && $0.sessionId == transport.sessionId && $0.turnId == transport.turnId && $0.userIntent == transport.userIntent && $0.ts.timeIntervalSince(transport.ts) >= 0 && $0.ts.timeIntervalSince(transport.ts) <= 1 }
            guard echoes.count == 1 else { continue }
            paired.insert(transport.id); pairs[native.id] = transport
        }
        return humans.filter { !paired.contains($0.id) }.map { e in
            let echo = pairs[e.id]
            return RealtimeUserInput(id: e.id.uuidString, content: e.userIntent, timestamp: echo?.ts ?? e.ts,
                source: e.source ?? "unknown", eventIDs: [e.id.uuidString] + (echo.map { [$0.id.uuidString] } ?? []),
                basis: echo == nil ? "原始用户输入记录" : "同轮原生 UserMessage 与唯一即时、同文传输记录合并显示；两条原始证据保留")
        }.sorted { $0.timestamp < $1.timestamp }
    }
    /// Confirm explicit delivery and actual files independently of Agent Stop.
    /// File existence does not certify the business contents.
    static func assessingDelivery(_ tasks: [RealtimeTask], artifacts: [RealtimeArtifact]) -> [RealtimeTask] {
        tasks.map { task in
            guard task.lifecycleStatus == "stopped" else { return task }
            let deliveries = task.cards.filter { $0.title == "present_files" && $0.phase == "returned" }
            let paths = deliveries.flatMap { card -> [String] in
                guard let body = RealtimeDetailProjector.object(card.output), body["type"] as? String == "present_files_result" else { return [] }
                guard let rows = body["files"] as? [Any], !rows.isEmpty else { return [] }
                let paths = rows.compactMap { row -> String? in
                    let path = row as? String ?? (row as? [String: Any])?["path"] as? String
                    return path.flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0).standardizedFileURL.path : nil }
                }
                return paths.count == rows.count ? paths : [""]
            }
            guard !paths.isEmpty, paths.allSatisfy({ path in artifacts.contains { $0.taskID == task.id && $0.path == path && $0.exists } }) else { return task }
            var result = task
            result.lifecycleStatus = "completed"; result.reportedComplete = true
            result.completionEvidence = "verified_delivery"
            result.currentStep = "Agent 已结束；明确交付文件已存在，内容验证另行核对"
            result.statusBasis += " 同轮 present_files 明确交付且路径已实测存在；不代表内容已通过业务验收。"
            result.lifecycle = RealtimeTaskLifecycle(currentStageID: "artifact", phase: "completed", stages: task.lifecycle?.stages ?? [])
            return result
        }
    }
    static func canonicalAgent(_ value: String?) -> String? {
        guard let value = value?.lowercased() else { return nil }
        if value.contains("workbuddy") { return "WorkBuddy" }
        if value.contains("codex") { return "Codex" }
        if value.contains("cursor") { return "Cursor" }
        return nil
    }
    // Repair the presentation of an already-active live checkpoint captured by
    // the older role=user parser. Keep evidence bytes/IDs; do not read or mutate
    // history. Explicit user.* source metadata continues to identify human text.
    private static func normalizeCodexUserContext(_ event: GuardEvent) -> GuardEvent {
        guard (["agentsight:codex-local-compat", "agentsight:workbuddy-local"].contains(event.source ?? "") && event.op == "prompt") ||
            (event.source == "agentsight:workbuddy-network-body" && event.op == "network_prompt") else { return event }
        let body = event.modelPrompt ?? event.userIntent ?? ""
        let workBuddy = event.source == "agentsight:workbuddy-local"
        let network = event.op == "network_prompt"
        let kinds = RealtimeDetailProjector.object(event.command)?["content_item_kinds"] as? [String] ?? []
        let runtime = workBuddy ? WorkBuddySight.cleanUserIntent(body) == nil : event.model == "codex-auto-review" || CodexSight.isRuntimeUserContext(body, sourceKinds: kinds)
        var intent = network ? WorkBuddyNetworkEvidence.userIntent(in: RealtimeDetailProjector.object(body)) : runtime ? nil : event.userIntent
        let cleanedBody = workBuddy ? WorkBuddySight.cleanUserIntent(body) ?? "" : CodexSight.cleanUserIntent(body)
        // Older active image messages retained the app's <image> wrapper as
        // userIntent. Repair only that presentation; never invent image text.
        if !runtime, cleanedBody != body,
           event.userIntent == body || event.userIntent?.contains("<image") == true {
            intent = cleanedBody.isEmpty ? nil : cleanedBody
        }
        guard runtime || intent != event.userIntent else { return event }
        return GuardEvent(id: event.id, kind: runtime ? "context" : event.kind,
            ruleId: runtime ? (workBuddy ? "workbuddy_recovered_context" : "codex_runtime_user_context") : event.ruleId,
            path: event.path, command: event.command, agent: event.agent,
            op: runtime ? (workBuddy ? "recovered_context" : "runtime_user_context") : event.op,
            severity: event.severity, ts: event.ts, action: runtime ? "captured" : event.action, sessionId: event.sessionId,
            traceId: event.traceId, turnId: event.turnId, toolCallId: event.toolCallId, userIntent: intent,
            modelDecision: event.modelDecision, modelReasoning: event.modelReasoning, modelPrompt: event.modelPrompt,
            modelResponse: event.modelResponse, toolName: runtime ? (workBuddy ? "workbuddy.compacted_context" : "codex.runtime_context") : event.toolName, model: event.model,
            inputTokens: event.inputTokens, outputTokens: event.outputTokens, cachedTokens: event.cachedTokens,
            reasoningTokens: event.reasoningTokens, costUSD: event.costUSD, beforeContent: event.beforeContent,
            afterContent: event.afterContent, fileDiff: event.fileDiff, codeFindings: event.codeFindings,
            source: event.source, attributionConfidence: event.attributionConfidence,
            attributionMethod: event.attributionMethod, processId: event.processId,
            parentProcessId: event.parentProcessId, localAddress: event.localAddress, remoteHost: event.remoteHost,
            remotePort: event.remotePort, remoteDomain: event.remoteDomain, startedAt: event.startedAt,
            endedAt: event.endedAt, durationMS: event.durationMS, relatedPath: event.relatedPath)
    }
    static func normalizedEvents(_ events: [GuardEvent]) -> [GuardEvent] {
        let normalized = events.map(normalizeCodexUserContext).map { event -> GuardEvent in
            guard event.source == "lsof-network", event.kind == "network",
                  event.attributionMethod?.contains("single active tool call") == true,
                  let domain = event.remoteDomain, domain != event.remoteHost,
                  let session = event.sessionId, let turn = event.turnId else { return event }
            // Old correlation wrote a tool's requested domain over unrelated
            // sockets. Restore only an observed proxy-route host, or no domain.
            let actual = event.attributionMethod?.contains("client-port") == true
                ? event.remoteHost.flatMap { RealtimeDetailProjector.isIPAddress($0) ? nil : $0 } : nil
            return event.attributed(sessionId:session, turnId:turn, toolCallId:event.toolCallId,
                remoteDomain:actual, replaceRemoteDomain:true, confidence:event.attributionConfidence ?? .inferred,
                method:(event.attributionMethod ?? "") + "; requested URL is not the observed socket destination")
        }
        let humans = normalized.filter { $0.source == "agentsight:workbuddy-local" && $0.op == "prompt" && $0.userIntent != nil && $0.turnId != nil }
        var flowTargets: [String: (String, String)] = [:]
        for event in normalized where event.source == "agentsight:workbuddy-network-body" && event.op == "network_prompt" {
            guard let intent = event.userIntent, let trace = event.traceId else { continue }
            let matches = humans.filter { $0.userIntent == intent && $0.ts <= event.ts.addingTimeInterval(1) }
            let identities = Set(matches.map { ($0.sessionId ?? "") + "\u{0}" + ($0.turnId ?? "") })
            if identities.count == 1, let match = matches.first, let session = match.sessionId, let turn = match.turnId {
                flowTargets[trace] = (session, turn)
            }
        }
        return normalized.map { event in
            guard event.source == "agentsight:workbuddy-network-body", let trace = event.traceId,
                  let target = flowTargets[trace], event.sessionId != target.0 || event.turnId != target.1 else { return event }
            return event.attributed(sessionId: target.0, turnId: target.1, toolCallId: event.toolCallId,
                confidence: .inferred, method: "unique exact human input in the bounded live records; native turn and HTTPS flow retained")
        }
    }
    static func tasks(events: [GuardEvent], since: Date) -> [RealtimeTask] {
        let fresh = normalizedEvents(events.filter { $0.ts >= since && canonicalAgent($0.agent) != nil && $0.sessionId != nil })
        // Only native call identity can bridge a missing turn. Session-only evidence
        // remains in its own lane; never assign it to the latest task by time.
        func callKey(_ e: GuardEvent) -> String { "\(canonicalAgent(e.agent)!)\u{0}\(e.sessionId!)\u{0}\(e.toolCallId ?? "")" }
        let callTurns = Dictionary(grouping: fresh.filter { $0.toolCallId != nil && $0.turnId != nil }, by: callKey)
            .mapValues { Set($0.compactMap(\.turnId)) }
        func turn(_ e: GuardEvent) -> String {
            if let turn = e.turnId { return turn }
            if e.toolCallId != nil, let matches = callTurns[callKey(e)], matches.count == 1 { return matches.first! }
            // Hook input is authoritative human text but WorkBuddy omits the
            // turn ID. Join only a unique identical native input, not proximity.
            if e.source == "workbuddy-hook", e.op == "hook_user_prompt", let intent = e.userIntent, !intent.isEmpty {
                let matches = Set(fresh.filter { candidate in
                    candidate.source == "agentsight:workbuddy-local" && candidate.op == "prompt" &&
                    candidate.sessionId == e.sessionId && canonicalAgent(candidate.agent) == canonicalAgent(e.agent) &&
                    candidate.userIntent == intent && candidate.turnId != nil
                }.compactMap(\.turnId))
                if matches.count == 1 { return matches.first! }
            }
            // WorkBuddy Stop omits turn_id, but carries the exact final assistant
            // message. Bind only to one native turn in this same agent/session;
            // repeated content in multiple turns is deliberately left unlinked.
            if e.source == "workbuddy-hook", e.op == "hook_turn_stop",
               let record = RealtimeDetailProjector.object(e.afterContent),
               let payload = record["payload"] as? [String: Any],
               let final = payload["last_assistant_message"] as? String, !final.isEmpty {
                let matches = Set(fresh.filter { candidate in
                    candidate.source == "agentsight:workbuddy-local" && candidate.op == "response" &&
                    candidate.sessionId == e.sessionId && canonicalAgent(candidate.agent) == canonicalAgent(e.agent) &&
                    candidate.modelResponse == final && candidate.turnId != nil
                }.compactMap(\.turnId))
                if matches.count == 1 { return matches.first! }
            }
            return ""
        }
        let grouped = Dictionary(grouping: fresh) { "\(canonicalAgent($0.agent)!)\u{0}\($0.sessionId!)\u{0}\(turn($0))" }
        return grouped.map { key, values in
            let ordered = values.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
            let first = ordered[0]
            let subagent = ordered.first { $0.ruleId == "codex_subagent_identity" }
                .flatMap { RealtimeDetailProjector.object($0.command) }
            let subagentPath = subagent?["agent_path"] as? String
            let request = ordered.first { $0.op == "hook_user_prompt" && $0.userIntent?.isEmpty == false }
                ?? ordered.first { $0.op == "prompt" && $0.userIntent?.isEmpty == false }
                ?? ordered.first { $0.op == "network_prompt" && $0.userIntent?.isEmpty == false }
            let attachmentRecords = ordered.filter { $0.op == "attachment" && $0.ruleId == "codex_attachment" }
            let resources = attachmentRecords.flatMap { event -> [RealtimeInputAttachment] in
                let body = RealtimeDetailProjector.object(event.command)
                return (body?["resources"] as? [[String: String]] ?? []).map {
                    RealtimeInputAttachment(type: $0["type"] ?? "unknown", path: $0["path"], source: event.source ?? "unknown", eventIDs: [event.id.uuidString])
                }
            }
            let legacyResources = ordered.flatMap { event -> [RealtimeInputAttachment] in
                guard event.source == "agentsight:codex-local-compat", event.op == "prompt", let raw = event.modelPrompt else { return [] }
                let kinds = RealtimeDetailProjector.object(event.command)?["content_item_kinds"] as? [String] ?? []
                return CodexSight.appInputAttachments(raw, sourceKinds: kinds).map {
                    RealtimeInputAttachment(type: $0["type"] ?? "unknown", path: $0["path"], source: event.source ?? "unknown", eventIDs: [event.id.uuidString])
                }
            }
            var seenAttachments = Set<String>()
            let explicitAttachments = resources.isEmpty ? attachmentRecords.flatMap { event -> [RealtimeInputAttachment] in
                let body = RealtimeDetailProjector.object(event.command)
                return (body?["types"] as? [String] ?? []).map {
                    RealtimeInputAttachment(type: $0, path: nil, source: event.source ?? "unknown", eventIDs: [event.id.uuidString])
                }
            }.filter { seenAttachments.insert($0.type).inserted } : resources.filter { seenAttachments.insert($0.path ?? $0.type).inserted }
            var attachmentKeys = Set<String>()
            let attachments = (explicitAttachments + legacyResources).filter { attachmentKeys.insert($0.path ?? $0.type).inserted }
            let title = subagentPath.map { "子任务 · " + ($0.split(separator: "/").last.map(String.init) ?? $0) }
                ?? request?.userIntent ?? (!attachments.isEmpty ? "用户附件输入 · 未附带文字" : turn(first).isEmpty ? "会话活动 · 轮次尚未关联" : "当前轮次 · 用户需求未采集")
            let projectedCards = cards(ordered)
            let inputs = userInputs(ordered)
            let state = RealtimeLifecycleProjector.project(events: ordered, cards: projectedCards, hasRequest: request != nil || !attachments.isEmpty, hasTurn: !turn(first).isEmpty)
            return RealtimeTask(id: Data(key.utf8).base64EncodedString(), agent: canonicalAgent(first.agent)!, session: first.sessionId!, turn: turn(first),
                title: String(title.prefix(300)), startedAt: ordered.first!.ts, lastActivity: ordered.last!.ts,
                cards: projectedCards, model: ordered.compactMap(\.model).last,
                reportedComplete: state.status == "completed",
                isPrimaryTask: subagent == nil && !ordered.contains { $0.model == "codex-auto-review" || $0.toolName == "codex.internal_review_context" } && ordered.contains { ($0.op == "attachment" && $0.ruleId == "codex_attachment") || $0.kind == "model" || $0.op == "hook_user_prompt" || ($0.kind == "tool" && !turn($0).isEmpty) },
                originalRequest: request?.userIntent, requestSource: request?.source, requestEventID: request?.id.uuidString,
                lifecycleStatus: state.status, currentStep: state.currentStep, currentCardID: state.currentCardID, statusBasis: state.basis,
                coverage: state.coverage, lifecycle: state.lifecycle, inputAttachments: attachments,
                executionState: state.executionState, completionEvidence: state.completionEvidence,
                statusChangedAt: state.statusChangedAt, nativeEndAt: state.nativeEndAt, nativeTerminalEventID: state.nativeTerminalEventID,
                nativeEndOp: state.nativeEndOp, nativeEndAction: state.nativeEndAction, nativeEndSource: state.nativeEndSource,
                nativeEndMessage: state.nativeEndMessage, nativeEndMessageTruncated: state.nativeEndMessageTruncated,
                stopReason: state.stopReason, lastFailureCardID: state.lastFailureCardID, unresolvedCallIDs: state.unresolvedCallIDs,
                userInputs: inputs, latestUserInput: inputs.last,
                parentSession: subagent?["parent_session"] as? String, subagentPath: subagentPath,
                searchText: projectedCards.flatMap { [$0.title, $0.summary, $0.resource?.path, $0.resource?.url, $0.resource?.domain, $0.execution?.command.map { String($0.prefix(220)) }].compactMap { $0 } }.joined(separator: "\n"))
        }.sorted { $0.lastActivity > $1.lastActivity }
    }
    static func cards(_ records: [GuardEvent]) -> [RealtimeCard] {
        let normalized: [GuardEvent] = normalizedEvents(records)
        let ordered: [GuardEvent] = normalized.sorted { lhs, rhs in
            if lhs.ts == rhs.ts { return lhs.id.uuidString < rhs.id.uuidString }
            return lhs.ts < rhs.ts
        }
        var output: [RealtimeCard] = []
        // A call ID only pairs within the already isolated Agent/session/turn.
        let grouped = Dictionary(grouping: ordered.filter(isToolLifecycle)) { $0.toolCallId! }
        for (call, events) in grouped {
            let request = events.first { ["call", "hook_tool_start", "start", "started", "exec_start", "command_started"].contains($0.op) }
            let result = events.last { ["result", "hook_tool_end", "hook_tool_finish", "end", "completed", "command_completed"].contains($0.op) }
            let event = result ?? events.last!
            let rawInput = hookField(request, "tool_input") ?? request?.command ?? request?.modelPrompt ?? result?.command
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
                inputTruncated: RealtimeDetailProjector.truncated(rawInput), outputTruncated: RealtimeDetailProjector.truncated(visibleOutput), phase: phase,
                codeFindings: codeFindings(events)))
        }
        for event in ordered where !isToolLifecycle(event) {
            if ["prompt", "hook_user_prompt"].contains(event.op), event.userIntent != nil { continue }
            guard ["model", "file", "network", "cmd", "tool", "activity", "memory", "context", "task"].contains(event.kind) else { continue }
            let kind: String, title: String
            if ["prompt", "hook_user_prompt"].contains(event.op), event.userIntent?.isEmpty == false {
                kind = "user"; title = "我的需求"
            } else if event.kind == "context" {
                kind = event.op == "turn_context" ? "environment" : "context"
                title = event.toolName ?? "上下文材料"
            } else if event.kind == "task" || event.op.hasPrefix("task_") || event.op == "hook_turn_stop" {
                kind = "task"; title = "任务状态记录"
            } else if event.kind == "memory" {
                kind = "memory"; title = CollectionRecordPresentation(event, receivedAt: event.ts).title
            } else if event.kind == "activity" {
                kind = "process"; title = CollectionRecordPresentation(event, receivedAt: event.ts).title
            } else if event.kind == "model" {
                kind = "model"; title = ["prompt", "network_prompt"].contains(event.op) ? "Agent → 大模型" : event.op == "reasoning_summary" ? "模型返回的思考摘要" : "大模型 → Agent"
            } else if event.kind == "file" {
                kind = event.path.lowercased().hasSuffix("skill.md") ? "skill" : "files"
                title = "\(event.op) · \((event.path as NSString).lastPathComponent)"
            } else if event.kind == "network" {
                kind = "web"; title = "连接 · \(event.remoteDomain ?? event.remoteHost ?? "目标未知")"
            } else { kind = event.kind == "cmd" ? "command" : "tool"; title = event.toolName ?? event.op }
            let rawInput: String?
            let rawBody: String?
            if kind == "user" {
                rawInput = event.userIntent; rawBody = event.userIntent
            } else {
                let inputBody = event.modelPrompt ?? event.command ?? event.beforeContent
                rawInput = inputBody ?? (event.path == "-" ? nil : event.path)
                let responseBody = event.modelResponse ?? event.fileDiff ?? event.afterContent
                rawBody = responseBody ?? event.modelReasoning ?? event.command
            }
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
                inputTruncated: RealtimeDetailProjector.truncated(rawInput), outputTruncated: RealtimeDetailProjector.truncated(rawBody), phase: phase,
                networkBody: RealtimeNetworkBodyPreview(event: event), codeFindings: codeFindings([event])))
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
        for input in userInputs(ordered) where input.content != nil {
            let content = input.content ?? ""
            output.append(RealtimeCard(id: input.id, kind: "user", title: "用户输入", status: "returned", tag: "用户原话已记录", summary: String(content.prefix(220)), input: String(content.prefix(16000)), output: String(content.prefix(16000)), source: input.source, basis: input.basis, confidence: input.eventIDs.count > 1 ? "inferred" : "explicit", call: nil, pid: nil, timestamp: input.timestamp, eventIDs: input.eventIDs, detailType: "user", inputTruncated: RealtimeDetailProjector.truncated(content), outputTruncated: RealtimeDetailProjector.truncated(content)))
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
struct RealtimeIPLocation: Equatable, Encodable {
    let ip: String
    let location: String?
    let owner: String?
    let source: String
    let updatedAt: Date?
    let state: String
    let error: String?
}
