import Foundation
import CoreFoundation

/// Task state, step state and collector health are separate facts. This reducer
/// only consumes events already isolated by native Agent/session/turn identity.
struct RealtimeCoverage: Equatable, Encodable {
    let category: String, status: String, count: Int, detail: String
    let eventIDs: [String]
}
struct RealtimeLifecycleStage: Equatable, Encodable {
    let id: String, title: String, status: String, summary: String
    let eventIDs: [String], cardIDs: [String]
}
struct RealtimeTaskLifecycle: Equatable, Encodable {
    let currentStageID: String, phase: String
    let stages: [RealtimeLifecycleStage]
}
struct RealtimeOutputChunk: Equatable, Encodable {
    let channel: String, text: String, timestamp: Date, eventID: String
    let truncated: Bool
}
struct RealtimeExecutionDetail: Equatable, Encodable {
    let command: String?, cwd: String?, stdout: String?, stderr: String?, exitCode: Int?
    let processID: Int32?, executionID: String?, status: String
    let startAt: Date?, endAt: Date?, outputComplete: Bool, basis: String
    let chunks: [RealtimeOutputChunk]
    let commandTruncated: Bool, stdoutTruncated: Bool, stderrTruncated: Bool
}
struct RealtimeResourceDetail: Equatable, Encodable {
    let path: String?, url: String?, method: String?, statusCode: Int?, domain: String?
    let remoteIP: String?, remotePort: Int?, contentType: String?
    let before: String?, after: String?, diff: String?
    let addresses: [String], basis: String, ipScope: String?, location: String?
    let beforeTruncated: Bool, afterTruncated: Bool, diffTruncated: Bool
    var evidenceType: String? = nil
    var observedLocalAddress: String? = nil
    var observedRemoteHost: String? = nil
    var observedRemotePort: Int? = nil
    var socketState: String? = nil
    var processIdentity: String? = nil
    var proxySource: String? = nil
    var proxyObservedAt: Date? = nil
    var requestedURL: String? = nil
    var destinationBasis: String? = nil
}

struct RealtimeLifecycleProjection {
    let status: String, currentStep: String, currentCardID: String?, basis: String
    let coverage: [RealtimeCoverage], lifecycle: RealtimeTaskLifecycle
    let executionState: String, completionEvidence: String
    let statusChangedAt: Date?, nativeEndAt: Date?, nativeTerminalEventID: String?
    let nativeEndOp: String?, nativeEndAction: String?, nativeEndSource: String?
    let nativeEndMessage: String?, nativeEndMessageTruncated: Bool, stopReason: String?
    let lastFailureCardID: String?, unresolvedCallIDs: [String]
}

enum RealtimeLifecycleProjector {
    private static let stageNames = [("user", "需求"), ("environment", "材料"), ("context", "上下文"),
        ("model", "模型"), ("plan", "调度"), ("command", "执行"), ("mcp", "服务"),
        ("files", "文件"), ("network", "网络"), ("failure", "纠偏"), ("verify", "验证"), ("artifact", "交付")]
    static func project(events: [GuardEvent], cards: [RealtimeCard], hasRequest: Bool, hasTurn: Bool) -> RealtimeLifecycleProjection {
        let ordered = events.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
        // An explicit task terminal wins even if a late start has a later arrival
        // timestamp. A new native turn is a new task, not a reopen by a tool event.
        let terminal = ordered.last { terminalStatus($0, hasTurn: hasTurn) != nil }
        let active = cards.filter { ["running", "pending", "waiting"].contains($0.phase) }.last
        let confirmation = cards.last { $0.phase == "waiting" }
        let last = cards.last { !["process", "task"].contains($0.kind) } ?? cards.last
        let latestFailure = cards.last { $0.phase == "failed" }
        let lastCall = cards.last { $0.id.hasPrefix("call:") }
        let unresolvedCalls = cards.filter { $0.call != nil && ["running", "pending", "waiting"].contains($0.phase) }
        let endBody = terminal.flatMap { nativeEndPayload($0) }
        let endMessage = terminal.flatMap { event in
            (endBody?["last_assistant_message"] as? String) ?? event.modelResponse
        }
        let reason = endBody.flatMap { body in
            ["stop_reason", "reason", "failure_reason", "error"].compactMap { body[$0] as? String }.first
        }
        // A submitted call or PreToolUse without its result is not proof that
        // it is still running after Agent Stop. A native running executor ID
        // or an explicit background list can supply that distinct fact.
        let backgroundDenied = (endBody?["background_tasks"] as? [Any])?.isEmpty == true
        let backgroundListed = (endBody?["background_tasks"] as? [Any])?.isEmpty == false
        let background = cards.last { card in
            guard card.execution?.status == "running", card.execution?.executionID != nil else { return false }
            guard let terminal else { return true }
            return card.timestamp > terminal.ts || !backgroundDenied
        }
        let status: String, step: String, executionState: String, completionEvidence: String
        var basis: String
        let selected: RealtimeCard?
        if let terminal, let value = terminalStatus(terminal, hasTurn: hasTurn) {
            let fact = "原生轮次终态：\(terminal.op) / \(terminal.action)；记录 \(terminal.id.uuidString)。"
            if value == "failed" || value == "cancelled" {
                status = value; executionState = value; completionEvidence = "unknown"
                step = value == "failed" ? "原生任务已失败" : "原生任务已取消"
                basis = fact + (reason.map { " 原生原因：" + $0 } ?? " 未采到结构化终止原因；不推断超时、卡死或人为取消。")
                selected = cards.first { $0.eventIDs.contains(terminal.id.uuidString) } ?? latestFailure ?? last
            } else if value == "completed" {
                status = "completed"; executionState = "stopped"; completionEvidence = "native_goal_success"
                step = "原生目标成功证据已记录"
                basis = fact + " 来源提供显式目标验证/成功事实；普通模型答复或 Stop 不具备该语义。"
                selected = cards.first { $0.eventIDs.contains(terminal.id.uuidString) } ?? last
            } else if background != nil || backgroundListed {
                status = "running"; executionState = "background_running"; completionEvidence = "unknown"
                step = background.map { "Agent 已停止；后台执行尚未收到结束记录：" + $0.title } ?? "Agent 已停止；原生记录仍有后台任务"
                basis = fact + " 后台执行与 Agent 轮次分开核对；尚无目标达成证据。"
                selected = background ?? last
            } else {
                status = "stopped"; executionState = "stopped"; completionEvidence = "unknown"
                if let latestFailure, latestFailure.id == lastCall?.id {
                    let exit = latestFailure.execution?.exitCode.map { "（退出码 \($0)）" } ?? ""
                    step = "Agent 已停止；最近失败步骤：\(latestFailure.title)\(exit)"
                    selected = latestFailure
                } else if let last = lastCall ?? last, last.kind != "user" {
                    step = "Agent 已停止；最后记录：\(last.title)；目标达成未确认"
                    selected = last
                } else {
                    step = "Agent 已停止；目标达成未确认"; selected = cards.last
                }
                basis = fact + " 已停止不等于用户目标已完成。" + (reason.map { " 原生原因：" + $0 } ?? " 未采到结构化停止原因；查看最后答复与执行详情。")
                if !unresolvedCalls.isEmpty { basis += " \(unresolvedCalls.count) 个调用尚缺最终返回，不能据此继续宣称正在执行。" }
            }
        } else if !hasTurn, ordered.contains(where: { $0.op == "hook_turn_stop" }) {
            status = "observed"; executionState = "unknown"; completionEvidence = "unknown"; selected = last
            step = "会话记录到停止，轮次归属待确认"
            basis = "Stop缺少轮次身份，不能将会话中的其他调用继续显示为本任务进行中，也不能猜测它结束了哪条需求。"
        } else if let confirmation {
            status = "awaiting_confirmation"; executionState = "waiting"; completionEvidence = "unknown"
            step = "等待你确认：\(confirmation.title)"; basis = confirmation.basis; selected = confirmation
        } else if let active {
            status = "running"; executionState = "running"; completionEvidence = "unknown"; selected = active
            if active.kind == "model" { step = "等待模型返回" }
            else if active.phase == "pending" { step = "已记录工具计划：\(active.title)" }
            else if active.execution?.status == "requested" { step = "调用已提交，等待执行记录：\(active.title)" }
            else { step = "正在执行：\(active.title)" }
            basis = active.basis
        } else if let last {
            status = hasRequest || ordered.contains(where: { $0.kind == "model" || $0.kind == "tool" }) ? "running" : "observed"
            executionState = status; completionEvidence = "unknown"; selected = last
            step = last.phase == "failed" ? "步骤失败，等待 Agent 后续处理：\(last.title)" : last.kind == "model" ? "模型已返回，等待 Agent 后续步骤" : "已收到：\(last.title)；等待后续记录"
            basis = "最近步骤记录：\(last.eventIDs.joined(separator: ", "))；尚无原生任务结束记录。"
        } else {
            status = hasRequest ? "running" : "observed"; executionState = status; completionEvidence = "unknown"; selected = nil
            step = hasRequest ? "需求已收到，等待后续步骤" : "已采到会话活动，任务起点尚未采集"
            basis = hasRequest ? "已收到原始用户消息；尚无执行记录。" : "独立活动不能证明任务正在执行。"
        }
        let currentStage = status == "completed" ? "artifact" : ["failed", "cancelled"].contains(status) ? "failure" : confirmation != nil ? "failure" : selected.map(stageID) ?? (hasRequest ? "user" : "environment")
        let stages = stageNames.map { id, title -> RealtimeLifecycleStage in
            let relevant = cards.filter { stageID($0) == id }
            let latest = relevant.last
            var stageStatus = latest?.phase ?? "absent"
            if id == "failure" {
                let failures = cards.filter { ["failed", "waiting", "cancelled"].contains($0.phase) }
                if let record = failures.last { stageStatus = record.phase }
            }
            if currentStage == id, status == "completed" { stageStatus = "returned" }
            let associated = id == "failure" ? cards.filter { ["failed", "waiting", "cancelled"].contains($0.phase) } : relevant
            return RealtimeLifecycleStage(id: id, title: title, status: stageStatus,
                summary: latest?.summary ?? (id == "artifact" && status == "completed" ? "已收到结束记录；产物状态单独核对" : "尚无此环节的已关联记录"),
                eventIDs: associated.flatMap(\.eventIDs), cardIDs: associated.map(\.id))
        }
        func coverage(_ category: String, _ matching: [GuardEvent], complete: Bool = true, detail: String) -> RealtimeCoverage {
            RealtimeCoverage(category: category, status: matching.isEmpty ? "missing" : complete ? "captured" : "partial",
                count: matching.count, detail: detail, eventIDs: matching.map { $0.id.uuidString })
        }
        let textRequests = ordered.filter { ["prompt", "hook_user_prompt", "network_prompt"].contains($0.op) && $0.userIntent?.isEmpty == false }
        let attachmentRequests = ordered.filter { $0.op == "attachment" && $0.ruleId == "codex_attachment" }
        let request = textRequests + attachmentRequests
        let contexts = ordered.filter { $0.kind == "context" || $0.op == "network_prompt" }
        let model = ordered.filter { $0.kind == "model" && ["response", "network_response", "reasoning_summary"].contains($0.op) }
        let tool = ordered.filter { $0.toolCallId != nil && ($0.kind == "tool" || $0.op.hasPrefix("hook_tool")) }
        let outputs = ordered.filter { ["output", "stream", "tool_output", "command_output", "exec_command_output_delta"].contains($0.op) }
        let coverageItems = [
            coverage("user", request, detail: request.isEmpty ? "用户原始需求未采集；不以其他事件继承的 userIntent 补写" : textRequests.isEmpty ? "用户附件输入已采集；本次未附带文字需求" : "原始用户消息已记录"),
            coverage("context", contexts, complete: contexts.contains { $0.op == "network_prompt" && !$0.action.contains("partial") }, detail: "完整模型请求与本地上下文片段分别表达"),
            coverage("model", model, complete: !model.contains { $0.action.contains("partial") }, detail: "模型返回与原生任务结束分别核对"),
            coverage("tool", tool, detail: "模型指令、执行开始、输出和返回分别记录"),
            coverage("execution", outputs, detail: outputs.isEmpty ? "尚未采到命令中间输出；最终返回不计为实时输出" : "已收到原生执行输出增量"),
            coverage("files", ordered.filter { $0.kind == "file" }, detail: "只统计本任务已关联的文件观察"),
            coverage("network", ordered.filter { $0.kind == "network" || $0.remoteHost != nil || $0.remoteDomain != nil }, detail: "连接/IP 与资源 URL、正文是不同覆盖层"),
            coverage("result", terminal.map { [$0] } ?? [], detail: "原生任务结束；交付物存在性与验证另行核对")]
        return RealtimeLifecycleProjection(status: status, currentStep: step, currentCardID: selected?.id, basis: basis,
            coverage: coverageItems, lifecycle: RealtimeTaskLifecycle(currentStageID: currentStage, phase: status, stages: stages),
            executionState: executionState, completionEvidence: completionEvidence,
            statusChangedAt: terminal?.ts ?? selected?.timestamp ?? ordered.first?.ts,
            nativeEndAt: terminal?.endedAt ?? terminal?.ts, nativeTerminalEventID: terminal?.id.uuidString,
            nativeEndOp: terminal?.op, nativeEndAction: terminal?.action, nativeEndSource: terminal?.source,
            nativeEndMessage: RealtimeDetailProjector.preview(endMessage), nativeEndMessageTruncated: RealtimeDetailProjector.truncated(endMessage),
            stopReason: reason, lastFailureCardID: latestFailure?.id, unresolvedCallIDs: unresolvedCalls.compactMap(\.call))
    }
    private static func nativeEndPayload(_ event: GuardEvent) -> [String: Any]? {
        let root = RealtimeDetailProjector.object(event.afterContent) ?? RealtimeDetailProjector.object(event.command)
        return root?["payload"] as? [String: Any] ?? root
    }
    static func terminalStatus(_ event: GuardEvent, hasTurn: Bool) -> String? {
        let op = event.op.lowercased(), action = event.action.lowercased()
        let explicitTask = op.hasPrefix("task_") || op.hasPrefix("turn_") || event.ruleId.contains("task_complete") || event.ruleId.contains("task_failed") || event.ruleId.contains("task_cancel")
        if explicitTask {
            if ["failed", "failure", "error"].contains(action) || op.hasSuffix("failed") { return "failed" }
            if ["cancelled", "canceled", "aborted", "interrupted"].contains(action) || ["task_cancelled", "turn_aborted", "task_canceled"].contains(op) { return "cancelled" }
            // Native task_complete/turn_completed denote the Agent's turn end,
            // not a semantic verdict about the user's goal.
            if ["completed", "complete", "ended"].contains(action) || ["task_complete", "task_completed", "turn_completed"].contains(op) { return "stopped" }
        }
        if ["goal_verified", "task_verified", "task_success"].contains(op),
           ["verified", "success", "succeeded"].contains(action) { return "completed" }
        if event.kind == "model", op == "response", ["final_answer", "end_turn", "stop_sequence"].contains(action) { return "stopped" }
        // Hook Stop without a turn has no authority over any task in its session.
        if hasTurn, op == "hook_turn_stop" { return "stopped" }
        return nil
    }
    static func stageID(_ card: RealtimeCard) -> String {
        if card.title == "codex.attachment" { return "user" }
        if card.phase == "waiting" || card.phase == "cancelled" { return "failure" }
        switch card.kind {
        case "user": return "user"
        case "context": return "context"
        case "environment", "process", "memory": return "environment"
        case "plan", "decision": return "plan"
        case "command": return "command"
        case "mcp", "tool": return "mcp"
        case "files", "skill": return "files"
        case "web", "network": return "network"
        case "verify": return "verify"
        case "artifact": return "artifact"
        case "task": return "artifact"
        default: return "model"
        }
    }
}

/// Typed, bounded presentation of the original records. Parsing is structural:
/// strings containing "error" or filenames never invent success, failure or artifacts.
enum RealtimeDetailProjector {
    static let previewLimit = 16_000
    static func preview(_ value: String?) -> String? { value.map { String($0.prefix(previewLimit)) } }
    static func truncated(_ value: String?) -> Bool { (value?.count ?? 0) > previewLimit }
    static func object(_ value: String?) -> [String: Any]? {
        guard let value, value.utf8.count <= 1_000_000, let bytes = value.data(using: .utf8) else { return nil }
        if let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] { return object }
        // Existing WorkBuddy adapter represents calls as ToolName({arguments}).
        if let open = value.firstIndex(of: "("), value.last == ")" {
            return object(String(value[value.index(after: open)..<value.index(before: value.endIndex)]))
        }
        return nil
    }
    static func integer(_ value: Any?) -> Int? {
        if let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() { return number.intValue }
        if let string = value as? String { return Int(string) }
        return nil
    }
    static func text(_ value: Any?) -> String? {
        if let string = value as? String { return string }
        if let list = value as? [String], let bytes = try? JSONSerialization.data(withJSONObject: list, options: [.fragmentsAllowed]) { return String(decoding: bytes, as: UTF8.self) }
        return nil
    }
    static func resultObject(_ value: String?) -> [String: Any]? {
        guard let root = object(value) else { return nil }
        // Preserve outer protocol isError while exposing common result wrappers.
        if let result = root["result"] as? [String: Any] { return root.merging(result) { _, nested in nested } }
        return root
    }
    static func execution(request: GuardEvent?, result: GuardEvent?, events: [GuardEvent], input: String?, output: String?) -> RealtimeExecutionDetail {
        let args = object(input) ?? [:], body = resultObject(output) ?? [:]
        let commandValue = args["command"] ?? args["cmd"] ?? args["shell_command"]
        let rawCommand: String?
        if let argv = commandValue as? [String] {
            let shell = ["sh","bash","zsh","fish"].contains(((argv.first ?? "") as NSString).lastPathComponent)
            if shell, let flag = argv.firstIndex(where: { ["-c","-lc","-ic"].contains($0) }), argv.indices.contains(flag + 1) {
                rawCommand = argv[flag + 1]
            } else {
                rawCommand = argv.map { $0.contains(where: { $0.isWhitespace }) ? "'" + $0.replacingOccurrences(of:"'",with:"'\\''") + "'" : $0 }.joined(separator:" ")
            }
        } else { rawCommand = text(commandValue) ?? (object(input) == nil ? input : nil) }
        let command = rawCommand.flatMap { $0.isEmpty ? nil : $0 }
        let rawCWD = text(args["cwd"] ?? args["workdir"] ?? args["working_directory"]) ?? request.flatMap { $0.path == "-" || $0.path.isEmpty ? nil : $0.path }
        let cwd = rawCWD.flatMap { $0.hasPrefix("file://") ? URL(string:$0)?.path : $0 }
        let starts = events.filter { ["hook_tool_start", "start", "started", "exec_start", "command_started"].contains($0.op) }
        let streams = events.filter { ["output", "stream", "tool_output", "command_output", "exec_command_output_delta"].contains($0.op) }
        var stdout = text(body["stdout"]) ?? text(body["aggregated_output"] ?? body["formatted_output"]), stderr = text(body["stderr"])
        var exit = integer(body["exit_code"] ?? body["exitCode"] ?? body["returncode"])
        var session = text(body["execution_id"] ?? body["session_id"] ?? body["process_session_id"])
            ?? integer(body["execution_id"] ?? body["session_id"] ?? body["process_id"]).map(String.init)
        // Codex's native tool result has an explicit textual protocol envelope.
        if let output, body.isEmpty {
            if let range = output.range(of: #"(?m)^Process exited with code (-?\d+)\s*$"#, options: .regularExpression) {
                exit = Int(output[range].split(separator: " ").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
            }
            if let range = output.range(of: #"(?m)^Process running with session ID\s+[^\s]+"#, options: .regularExpression) {
                session = output[range].split(separator: " ").last.map(String.init)
            }
            if let range = output.range(of: "Final output:\n") { stdout = String(output[range.upperBound...]) }
            else if let range = output.range(of: "Output:\n") { stdout = String(output[range.upperBound...]) }
            else if result != nil { stdout = output }
        }
        // WorkBuddy's native Bash result has a distinct labelled envelope.
        // Parse only that executor protocol, never arbitrary output containing labels.
        if body.isEmpty, request?.toolName?.lowercased() == "bash", let output,
           output.hasPrefix("Command: "),
           let outStart = output.range(of: "\nStdout: "),
           let errStart = output.range(of: "\nStderr: ", range: outStart.upperBound..<output.endIndex),
           let exitStart = output.range(of: "\nExit Code: ", range: errStart.upperBound..<output.endIndex) {
            let rawOut = String(output[outStart.upperBound..<errStart.lowerBound])
            let rawErr = String(output[errStart.upperBound..<exitStart.lowerBound])
            stdout = rawOut == "(empty)" ? "" : rawOut
            stderr = rawErr == "(empty)" ? "" : rawErr
            exit = Int(output[exitStart.upperBound...].split(separator: "\n", maxSplits: 1).first.map(String.init) ?? "")
        }
        let chunks = streams.map { event -> RealtimeOutputChunk in
            let metadata = object(event.command) ?? [:]
            let channel = text(metadata["channel"]) ?? "output"
            let raw = event.modelResponse ?? event.afterContent ?? ""
            return RealtimeOutputChunk(channel: channel, text: preview(raw) ?? "", timestamp: event.ts, eventID: event.id.uuidString, truncated: truncated(raw))
        }
        if stdout == nil { stdout = chunks.filter { $0.channel == "stdout" || $0.channel == "output" }.map(\.text).joined().nilIfEmpty }
        if stderr == nil { stderr = chunks.filter { $0.channel == "stderr" }.map(\.text).joined().nilIfEmpty }
        if session == nil { session = streams.compactMap { text(object($0.command)?["execution_id"]) }.last }
        let event = result ?? events.last
        let action = event?.action.lowercased() ?? ""
        let complete = result != nil && (session == nil || exit != nil) && !action.contains("partial") && !["running", "streaming", "in_progress"].contains(text(body["status"]) ?? action)
        let status: String
        if ["approval_required", "awaiting_approval", "blocked"].contains(action) { status = "waiting" }
        else if ["cancelled", "canceled", "aborted"].contains(action) { status = "cancelled" }
        else if exit.map({ $0 != 0 }) == true { status = "failed" }
        else if let event, RealtimeWorkspaceProjector.isFailure(event, result: output) { status = "failed" }
        else if complete { status = "returned" }
        else if !starts.isEmpty || !streams.isEmpty || session != nil { status = "running" }
        else if ["planned", "queued"].contains(action) { status = "pending" }
        else { status = "requested" }
        return RealtimeExecutionDetail(command: preview(command), cwd: cwd, stdout: preview(stdout), stderr: preview(stderr), exitCode: exit,
            processID: event?.processId ?? integer(body["pid"]).flatMap(Int32.init(exactly:)), executionID: session,
            status: status, startAt: starts.first?.startedAt ?? starts.first?.ts, endAt: complete ? result?.endedAt ?? result?.ts : nil,
            outputComplete: complete, basis: starts.isEmpty ? "调用参数与原始输出；没有以模型指令代替执行开始" : "原生执行开始及同一调用 ID 的输出/返回",
            chunks: chunks, commandTruncated: truncated(command), stdoutTruncated: truncated(stdout), stderrTruncated: truncated(stderr))
    }
    static func resource(event: GuardEvent, input: String?, output: String?, kind: String) -> RealtimeResourceDetail? {
        let args = object(input) ?? [:], metadata = object(event.command) ?? [:], result = resultObject(output) ?? [:]
        guard ["files", "skill", "web", "network"].contains(kind) || event.remoteDomain != nil || event.remoteHost != nil || args["url"] != nil || args["uri"] != nil else { return nil }
        let rawURL = text(args["url"] ?? args["uri"] ?? result["url"] ?? metadata["url"])
        var url = rawURL.flatMap { URL(string: $0)?.scheme != nil ? $0 : nil }
        if url == nil, event.source?.contains("network-body") == true, let domain = event.remoteDomain, let path = text(metadata["requestPath"]) {
            url = "https://\(domain)\(path.hasPrefix("/") ? path : "/" + path)"
        }
        let path = text(args["file_path"] ?? args["path"] ?? args["filename"] ?? result["path"]) ?? (event.kind == "file" && event.path != "-" ? event.path : nil)
        let host = url.flatMap { URL(string: $0)?.host } ?? event.remoteDomain
        let ip = event.source == "tool-intent" ? nil : event.remoteHost.flatMap { isIPAddress($0) ? $0 : nil }
        var detail = RealtimeResourceDetail(path: path, url: url, method: text(args["method"] ?? metadata["method"]),
            statusCode: integer(result["status_code"] ?? result["status"] ?? metadata["responseStatus"]), domain: host,
            remoteIP: ip, remotePort: event.remotePort, contentType: text(result["content_type"] ?? metadata["contentType"]),
            before: preview(event.beforeContent), after: preview(event.kind == "file" ? event.afterContent : output), diff: preview(event.fileDiff),
            addresses: ip.map { [$0] } ?? [], basis: event.attributionMethod ?? "资源字段来自当前记录；未以 IP 反推访问路径", ipScope: ip.map(ipScope), location: nil,
            beforeTruncated: truncated(event.beforeContent), afterTruncated: truncated(event.kind == "file" ? event.afterContent : output), diffTruncated: truncated(event.fileDiff))
        let socket = metadata["socket"] as? [String:Any], proxy = metadata["proxy"] as? [String:Any]
        let legacyProxy = socket == nil && event.source == "lsof-network" && event.attributionMethod?.contains("client-port") == true
        detail.evidenceType = event.source == "tool-intent" ? "tool_intent" : socket != nil ? (proxy != nil ? "proxy_route" : "socket") : legacyProxy ? "proxy_route" : url != nil && detail.method != nil ? (event.kind == "tool" ? "tool_report" : "http") : event.source == "lsof-network" ? "socket" : nil
        detail.observedLocalAddress = text(socket?["localAddress"]) ?? event.localAddress
        detail.observedRemoteHost = text(socket?["remoteHost"]) ?? (event.source == "lsof-network" && !legacyProxy ? event.remoteHost : nil)
        detail.observedRemotePort = integer(socket?["remotePort"]) ?? (event.source == "lsof-network" && !legacyProxy ? event.remotePort : nil)
        detail.socketState = text(socket?["state"])
        detail.processIdentity = text(metadata["processIdentity"])
        detail.proxySource = text(proxy?["source"]) ?? (legacyProxy && event.attributionMethod?.contains("V2rayU") == true ? "V2rayU" : nil)
        detail.proxyObservedAt = (proxy?["observedAt"] as? Double).map(Date.init(timeIntervalSince1970:))
        detail.requestedURL = text(metadata["requestedURL"])
        detail.destinationBasis = text(metadata["destinationBasis"] ?? metadata["destinationStatus"])
        return detail
    }
    static func isIPAddress(_ value: String) -> Bool {
        if value.contains(":"), value.range(of: #"^[0-9a-fA-F:.]+$"#, options: .regularExpression) != nil { return true }
        let parts = value.split(separator: "."); return parts.count == 4 && parts.allSatisfy { Int($0).map { (0...255).contains($0) } == true }
    }
    static func ipScope(_ value: String) -> String {
        if value == "::1" || value.hasPrefix("127.") { return "loopback" }
        let parts = value.split(separator: ".").compactMap { Int($0) }
        if parts.count == 4 {
            if parts[0] == 10 || (parts[0] == 172 && (16...31).contains(parts[1])) || (parts[0] == 192 && parts[1] == 168) { return "private" }
            if parts[0] == 169 && parts[1] == 254 { return "link_local" }
            if parts[0] == 0 || parts[0] >= 224 || (parts[0] == 192 && parts[1] == 0 && parts[2] == 2) || (parts[0] == 198 && parts[1] == 51 && parts[2] == 100) || (parts[0] == 203 && parts[1] == 0 && parts[2] == 113) { return "reserved" }
        }
        if value.lowercased().hasPrefix("fc") || value.lowercased().hasPrefix("fd") { return "private" }
        if value.lowercased().hasPrefix("fe80:") { return "link_local" }
        if value.lowercased().hasPrefix("2001:db8:") { return "reserved" }
        return "public"
    }
}
private extension String { var nilIfEmpty: String? { isEmpty ? nil : self } }
