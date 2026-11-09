import Foundation

/// Read-only parse of Claude Code and Codex session logs, then a join onto host
/// effects the app already has. This module never writes evidence and never
/// keeps a raw log line: reasoning and arguments are capped excerpts.
public enum SessionVerification {
    public static let excerptLimit = 800
    public static let leadSeconds: TimeInterval = 2
    public static let tailSeconds: TimeInterval = 20
    public static let cardCap = 200

    public static func excerpt(_ text: String) -> (text: String, truncated: Bool) {
        let chars = Array(text)
        guard chars.count > excerptLimit else { return (text, false) }
        return (String(chars.prefix(excerptLimit)), true)
    }

    public static func load(claudeRoot: String, codexRoot: String, workbuddyRoots: [String] = [], maxFiles: Int = 32, maxBytes: Int = 512 * 1024) -> SessionLogSnapshot {
        let claude = readTree(root: claudeRoot, agent: "Claude Code", kind: .claude, maxFiles: maxFiles, maxBytes: maxBytes)
        let codex = readTree(root: codexRoot, agent: "Codex", kind: .codex, maxFiles: maxFiles, maxBytes: maxBytes)
        let buddies = workbuddyRoots.map { root in
            let agent = (root as NSString).lastPathComponent.lowercased().contains("codebuddy") || root.lowercased().contains("/.codebuddy") || root.contains("CodeBuddy")
                ? "CodeBuddy" : "WorkBuddy"
            return readTree(root: root, agent: agent, kind: .workbuddy, maxFiles: maxFiles, maxBytes: maxBytes)
        }
        var completions = claude.completions.merging(codex.completions) { _, new in new }
        for buddy in buddies { completions.merge(buddy.completions) { _, new in new } }
        let calls = (claude.calls + codex.calls + buddies.flatMap(\.calls))
            .sorted { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }
        return SessionLogSnapshot(calls: calls, completions: completions, sources: [claude.source, codex.source] + buddies.map(\.source))
    }

    public static func parseClaude(_ data: Data, sourcePath: String = "claude.jsonl") -> ParseBatch {
        parseLines(data, sourcePath: sourcePath, agent: "Claude Code", kind: .claude, sessionHint: sessionHint(sourcePath))
    }

    public static func parseCodex(_ data: Data, sourcePath: String = "codex.jsonl") -> ParseBatch {
        parseLines(data, sourcePath: sourcePath, agent: "Codex", kind: .codex, sessionHint: sessionHint(sourcePath))
    }

    public static func verify(
        calls: [ParsedToolCall],
        effects: [HostEffect],
        processes: [ProcessLink] = [],
        completions: [String: String] = [:],
        taskIDs: [String: String] = [:],
        fileChannel: Bool = false,
        networkChannel: Bool = false
    ) -> SessionVerificationDocument {
        let fileObservation = (fileChannel || effects.contains { $0.kind == "file" }) ? "present" : "absent"
        let networkObservation = (networkChannel || effects.contains { $0.kind == "network" }) ? "present" : "absent"
        let tree = Dictionary(processes.map { ($0.pid, $0.parentPid) }, uniquingKeysWith: { _, new in new })
        let ordered = calls.sorted { $0.timestamp == $1.timestamp ? $0.id < $1.id : $0.timestamp < $1.timestamp }
        var nextTime: [String: Date] = [:]
        var upcoming: [String: Date] = [:]
        for call in ordered.reversed() {
            nextTime[call.id] = upcoming[call.sessionId]
            upcoming[call.sessionId] = call.timestamp
        }
        var owner: [String: (callID: String, rank: Int, distance: TimeInterval, name: String)] = [:]
        for effect in effects {
            for call in ordered {
                guard let match = match(call: call, effect: effect, next: nextTime[call.id], tree: tree) else { continue }
                let distance = abs(effect.timestamp.timeIntervalSince(call.timestamp))
                if let existing = owner[effect.id] {
                    if match.rank < existing.rank { continue }
                    if match.rank == existing.rank && distance >= existing.distance { continue }
                }
                owner[effect.id] = (call.id, match.rank, distance, match.name)
            }
        }
        var happened: [String: [VerificationEffect]] = [:]
        var claimedEffects: Set<String> = []
        for effect in effects {
            guard let hit = owner[effect.id] else { continue }
            claimedEffects.insert(effect.id)
            happened[hit.callID, default: []].append(VerificationEffect(
                id: effect.id, kind: effect.kind, path: effect.path, diff: effect.diff,
                before: effect.before, after: effect.after, command: effect.command,
                remote: effect.remote, timestamp: effect.timestamp, join: hit.name,
                credential: effect.credential || effect.kind == "credential" || isCredential(effect.path) || isCredential(effect.command)
            ))
        }
        var cards: [ToolCallCard] = []
        for call in ordered {
            let effectsForCall = happened[call.id] ?? []
            let mismatches = mismatches(call: call, happened: effectsForCall, fileObservation: fileObservation)
            let note = cardNote(call: call, happened: effectsForCall, mismatches: mismatches, fileObservation: fileObservation)
            cards.append(ToolCallCard(
                id: call.id, callId: call.callId, sessionId: call.sessionId, agent: call.agent,
                timestamp: call.timestamp, pid: call.pid,
                status: mismatches.isEmpty ? "matched" : "mismatched",
                mismatches: mismatches, said: call.reasoning, saidTruncated: call.reasoningTruncated,
                toolName: call.toolName, arguments: call.arguments, argumentsTruncated: call.argumentsTruncated,
                happened: effectsForCall, note: note
            ))
        }
        let truncated = cards.count > cardCap
        if truncated { cards = Array(cards.suffix(cardCap)) }
        let unclaimed = effects.filter { $0.kind == "file" && !claimedEffects.contains($0.id) }.map { effect in
            UnclaimedChange(
                id: effect.id, path: effect.path ?? "路径未采到", diff: effect.diff, before: effect.before,
                after: effect.after, timestamp: effect.timestamp, sessionId: effect.sessionId,
                why: ordered.isEmpty ? "这段时间没有读到工具调用。" : "没有工具调用的时间窗和进程树能对上这条改动。",
                credential: effect.credential || isCredential(effect.path)
            )
        }.sorted { $0.timestamp > $1.timestamp }
        let checklists = checklist(allCalls: ordered, effects: effects, completions: completions, taskIDs: taskIDs)
        return SessionVerificationDocument(
            sources: [], fileObservation: fileObservation, networkObservation: networkObservation,
            cards: cards, unclaimed: unclaimed, checklists: checklists, truncated: truncated
        )
    }

    public static func isCredential(_ text: String?) -> Bool {
        guard let text, !text.isEmpty else { return false }
        return text.range(of: #"(\.ssh/|/\.aws/|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json|\.pem\b|secrets?\.)"#, options: .regularExpression) != nil
    }
}

public struct SessionLogSnapshot: Equatable, Sendable {
    public var calls: [ParsedToolCall]
    public var completions: [String: String]
    public var sources: [SessionLogSource]
    public init(calls: [ParsedToolCall], completions: [String: String], sources: [SessionLogSource]) {
        self.calls = calls
        self.completions = completions
        self.sources = sources
    }
}

public struct SessionLogSource: Codable, Equatable, Sendable {
    public var agent: String
    public var root: String
    public var state: String
    public var filesRead: Int
    public var filesSkipped: Int
    public var malformedLines: Int
    public var note: String
    public init(agent: String, root: String, state: String, filesRead: Int, filesSkipped: Int, malformedLines: Int, note: String) {
        self.agent = agent
        self.root = root
        self.state = state
        self.filesRead = filesRead
        self.filesSkipped = filesSkipped
        self.malformedLines = malformedLines
        self.note = note
    }
}

public struct ParseBatch: Equatable, Sendable {
    public var calls: [ParsedToolCall]
    public var completions: [String: String]
    public var malformed: Int
}

public struct ParsedToolCall: Codable, Equatable, Sendable {
    public var id: String
    public var callId: String
    public var sessionId: String
    public var agent: String
    public var sourcePath: String
    public var sourceOffset: Int
    public var timestamp: Date
    public var pid: Int32?
    public var reasoning: String
    public var reasoningTruncated: Bool
    public var toolName: String
    public var arguments: String
    public var argumentsTruncated: Bool
    public var claimedPaths: [String]
    public var claimsEdit: Bool
    public init(id: String, callId: String, sessionId: String, agent: String, sourcePath: String, sourceOffset: Int, timestamp: Date, pid: Int32?, reasoning: String, reasoningTruncated: Bool, toolName: String, arguments: String, argumentsTruncated: Bool, claimedPaths: [String], claimsEdit: Bool) {
        self.id = id
        self.callId = callId
        self.sessionId = sessionId
        self.agent = agent
        self.sourcePath = sourcePath
        self.sourceOffset = sourceOffset
        self.timestamp = timestamp
        self.pid = pid
        self.reasoning = reasoning
        self.reasoningTruncated = reasoningTruncated
        self.toolName = toolName
        self.arguments = arguments
        self.argumentsTruncated = argumentsTruncated
        self.claimedPaths = claimedPaths
        self.claimsEdit = claimsEdit
    }
}

public struct HostEffect: Codable, Equatable, Sendable {
    public var id: String
    public var kind: String
    public var timestamp: Date
    public var pid: Int32?
    public var path: String?
    public var diff: String?
    public var before: String?
    public var after: String?
    public var command: String?
    public var remote: String?
    public var sessionId: String?
    public var toolCallId: String?
    public var credential: Bool
    public var source: String
    public init(id: String, kind: String, timestamp: Date, pid: Int32? = nil, path: String? = nil, diff: String? = nil, before: String? = nil, after: String? = nil, command: String? = nil, remote: String? = nil, sessionId: String? = nil, toolCallId: String? = nil, credential: Bool = false, source: String) {
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self.pid = pid
        self.path = path
        self.diff = diff
        self.before = before
        self.after = after
        self.command = command
        self.remote = remote
        self.sessionId = sessionId
        self.toolCallId = toolCallId
        self.credential = credential
        self.source = source
    }
}

public struct ProcessLink: Codable, Equatable, Sendable {
    public var pid: Int32
    public var parentPid: Int32
    public init(pid: Int32, parentPid: Int32) {
        self.pid = pid
        self.parentPid = parentPid
    }
}

public struct VerificationMismatch: Codable, Equatable, Sendable {
    public var kind: String
    public var label: String
    public var detail: String
    public init(kind: String, label: String, detail: String) {
        self.kind = kind
        self.label = label
        self.detail = detail
    }
}

public struct VerificationEffect: Codable, Equatable, Sendable {
    public var id: String
    public var kind: String
    public var path: String?
    public var diff: String?
    public var before: String?
    public var after: String?
    public var command: String?
    public var remote: String?
    public var timestamp: Date
    public var join: String
    public var credential: Bool
    public init(id: String, kind: String, path: String? = nil, diff: String? = nil, before: String? = nil, after: String? = nil, command: String? = nil, remote: String? = nil, timestamp: Date, join: String, credential: Bool) {
        self.id = id
        self.kind = kind
        self.path = path
        self.diff = diff
        self.before = before
        self.after = after
        self.command = command
        self.remote = remote
        self.timestamp = timestamp
        self.join = join
        self.credential = credential
    }
}

public struct ToolCallCard: Codable, Equatable, Sendable {
    public var id: String
    public var callId: String
    public var sessionId: String
    public var agent: String
    public var timestamp: Date
    public var pid: Int32?
    public var status: String
    public var mismatches: [VerificationMismatch]
    public var said: String
    public var saidTruncated: Bool
    public var toolName: String
    public var arguments: String
    public var argumentsTruncated: Bool
    public var happened: [VerificationEffect]
    public var note: String
    public init(id: String, callId: String, sessionId: String, agent: String, timestamp: Date, pid: Int32?, status: String, mismatches: [VerificationMismatch], said: String, saidTruncated: Bool, toolName: String, arguments: String, argumentsTruncated: Bool, happened: [VerificationEffect], note: String) {
        self.id = id
        self.callId = callId
        self.sessionId = sessionId
        self.agent = agent
        self.timestamp = timestamp
        self.pid = pid
        self.status = status
        self.mismatches = mismatches
        self.said = said
        self.saidTruncated = saidTruncated
        self.toolName = toolName
        self.arguments = arguments
        self.argumentsTruncated = argumentsTruncated
        self.happened = happened
        self.note = note
    }
}

public struct UnclaimedChange: Codable, Equatable, Sendable {
    public var id: String
    public var path: String
    public var diff: String?
    public var before: String?
    public var after: String?
    public var timestamp: Date
    public var sessionId: String?
    public var why: String
    public var credential: Bool
}

public struct CompletionChecklist: Codable, Equatable, Sendable {
    public var sessionId: String
    public var agent: String
    public var taskId: String?
    public var doneText: String
    public var claimedFiles: Int
    public var claimedFrom: String
    public var actualFiles: Int
    public var egressCount: Int
    public var credentialsTouched: Bool
    public var claimedPaths: [String]
    public var actualPaths: [String]
}

public struct SessionVerificationDocument: Codable, Equatable, Sendable {
    public var sources: [SessionLogSource]
    public var fileObservation: String
    public var networkObservation: String
    public var cards: [ToolCallCard]
    public var unclaimed: [UnclaimedChange]
    public var checklists: [CompletionChecklist]
    public var truncated: Bool

    public init(sources: [SessionLogSource], fileObservation: String, networkObservation: String, cards: [ToolCallCard], unclaimed: [UnclaimedChange], checklists: [CompletionChecklist], truncated: Bool) {
        self.sources = sources
        self.fileObservation = fileObservation
        self.networkObservation = networkObservation
        self.cards = cards
        self.unclaimed = unclaimed
        self.checklists = checklists
        self.truncated = truncated
    }

    public var fingerprint: String {
        let source = sources.map { "\($0.agent):\($0.state):\($0.filesRead):\($0.malformedLines)" }.joined(separator: "|")
        let card = cards.map { "\($0.id):\($0.status):\($0.happened.count)" }.joined(separator: "|")
        let files = unclaimed.map(\.id).joined(separator: "|")
        let done = checklists.map { "\($0.sessionId):\($0.claimedFiles):\($0.actualFiles):\($0.egressCount):\($0.credentialsTouched)" }.joined(separator: "|")
        return [source, card, files, done].joined(separator: "\n")
    }
}

private enum LogKind { case claude, codex, workbuddy }

private struct TreeRead {
    var calls: [ParsedToolCall]
    var completions: [String: String]
    var source: SessionLogSource
}

private func readTree(root: String, agent: String, kind: LogKind, maxFiles: Int, maxBytes: Int) -> TreeRead {
    let expanded = (root as NSString).expandingTildeInPath
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir) else {
        return TreeRead(calls: [], completions: [:], source: SessionLogSource(agent: agent, root: root, state: "absent", filesRead: 0, filesSkipped: 0, malformedLines: 0, note: "目录不在：\(root)"))
    }
    guard isDir.boolValue else {
        return TreeRead(calls: [], completions: [:], source: SessionLogSource(agent: agent, root: root, state: "unreadable", filesRead: 0, filesSkipped: 0, malformedLines: 0, note: "路径不是目录：\(root)"))
    }
    guard let enumerator = FileManager.default.enumerator(at: URL(fileURLWithPath: expanded), includingPropertiesForKeys: [.contentModificationDateKey, .isSymbolicLinkKey, .isRegularFileKey], options: [.skipsPackageDescendants]) else {
        return TreeRead(calls: [], completions: [:], source: SessionLogSource(agent: agent, root: root, state: "unreadable", filesRead: 0, filesSkipped: 0, malformedLines: 0, note: "目录打不开：\(root)"))
    }
    var files: [(URL, Date)] = []
    var seen = 0
    var capped = false
    for case let url as URL in enumerator {
        seen += 1
        if seen > 5000 { capped = true; break }
        let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .isSymbolicLinkKey, .isRegularFileKey])
        if values?.isSymbolicLink == true { continue }
        guard url.pathExtension == "jsonl", values?.isRegularFile != false else { continue }
        files.append((url, values?.contentModificationDate ?? .distantPast))
    }
    files.sort { $0.1 > $1.1 }
    let chosen = Array(files.prefix(max(1, maxFiles)))
    let skipped = max(0, files.count - chosen.count) + (capped ? 1 : 0)
    var calls: [ParsedToolCall] = []
    var completions: [String: String] = [:]
    var malformed = 0
    for (url, _) in chosen {
        guard let data = readTail(url, maxBytes: maxBytes) else {
            malformed += 1
            continue
        }
        let batch = parseLines(data, sourcePath: url.path, agent: agent, kind: kind, sessionHint: sessionHint(url.path))
        calls.append(contentsOf: batch.calls)
        completions.merge(batch.completions) { _, new in new }
        malformed += batch.malformed
    }
    let note: String
    if chosen.isEmpty {
        note = capped ? "目录里文件很多，这次没有读到 jsonl。" : "目录在，里面没有 jsonl。"
    } else if skipped > 0 {
        note = "只读了最近 \(chosen.count) 个 jsonl，其余 \(skipped) 个这次没打开。全文仍在原来的日志里。"
    } else {
        note = "读了 \(chosen.count) 个 jsonl。卡片只留调用编号和摘录，不把日志抄进证据库。"
    }
    return TreeRead(calls: calls, completions: completions, source: SessionLogSource(agent: agent, root: root, state: "present", filesRead: chosen.count, filesSkipped: skipped, malformedLines: malformed, note: note))
}

private func readTail(_ url: URL, maxBytes: Int) -> Data? {
    guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
    defer { try? handle.close() }
    let size = (try? handle.seekToEnd()) ?? 0
    let budget = UInt64(max(1024, maxBytes))
    if size <= budget {
        try? handle.seek(toOffset: 0)
        return try? handle.readToEnd()
    }
    try? handle.seek(toOffset: size - budget)
    guard var data = try? handle.readToEnd() else { return nil }
    if let newline = data.firstIndex(of: 0x0A) {
        data = Data(data[data.index(after: newline)...])
    }
    return data
}

private func sessionHint(_ path: String) -> String {
    let filename = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
    if filename.count >= 36, UUID(uuidString: String(filename.suffix(36))) != nil {
        return String(filename.suffix(36))
    }
    return filename.isEmpty ? "session" : filename
}

private func parseLines(_ data: Data, sourcePath: String, agent: String, kind: LogKind, sessionHint: String) -> ParseBatch {
    var calls: [ParsedToolCall] = []
    var completions: [String: String] = [:]
    var malformed = 0
    var pending = ""
    var session = sessionHint
    var seen = Set<String>()
    var offset = 0
    var lockedCodex = kind == .codex && UUID(uuidString: sessionHint) != nil
    for raw in data.split(separator: 0x0A, omittingEmptySubsequences: false) {
        let lineStart = offset
        offset += raw.count + 1
        guard !raw.isEmpty else { continue }
        guard let row = try? JSONSerialization.jsonObject(with: Data(raw)) as? [String: Any] else {
            malformed += 1
            continue
        }
        let claudeShape = kind == .claude || (kind == .workbuddy && row["message"] != nil)
        if claudeShape {
            if let id = string(row["sessionId"]) ?? string(row["session_id"]) { session = id }
            let type = string(row["type"]) ?? ""
            let message = row["message"] as? [String: Any]
            let contents = contentItems(message?["content"])
            let toolResult = contents.contains { string($0["type"]) == "tool_result" }
            if type == "user", !toolResult {
                pending = ""
                continue
            }
            guard type == "assistant" || contents.contains(where: { string($0["type"]) == "tool_use" }) else { continue }
            guard let timestamp = VerifyTime.parse(row["timestamp"]) else {
                if contents.contains(where: { string($0["type"]) == "tool_use" }) { malformed += 1 }
                continue
            }
            let pid = int32(row["pid"])
            for item in contents {
                let itemType = string(item["type"]) ?? ""
                if itemType == "thinking" || itemType == "text" {
                    let piece = string(item["thinking"]) ?? string(item["text"]) ?? ""
                    if !piece.isEmpty { pending = pending.isEmpty ? piece : pending + "\n" + piece }
                } else if itemType == "tool_use" {
                    let callId = string(item["id"]) ?? "claude-\(lineStart)"
                    let name = string(item["name"]) ?? "unknown_tool"
                    let arguments = jsonText(item["input"])
                    calls.append(makeCall(id: unique(callId, &seen), callId: callId, session: session, agent: agent, sourcePath: sourcePath, offset: lineStart, timestamp: timestamp, pid: pid, reasoning: pending, toolName: name, arguments: arguments))
                    pending = ""
                }
            }
            if let done = donePhrase(pending) { completions[session] = done }
            if donePhrase(pending) != nil { pending = "" }
        } else if kind == .workbuddy {
            if let id = string(row["sessionId"]) ?? string(row["session_id"]) { session = id }
            let type = string(row["type"]) ?? ""
            if type == "reasoning" {
                if let text = textDeep(row["content"]) ?? textDeep(row["rawContent"]), !text.isEmpty {
                    pending = SessionVerification.excerpt(text).text
                }
                continue
            }
            if type == "message", string(row["role"]) == "user" {
                pending = ""
                continue
            }
            guard type == "function_call" else { continue }
            guard let timestamp = VerifyTime.parse(row["timestamp"]) else {
                malformed += 1
                continue
            }
            let callId = string(row["callId"]) ?? string(row["call_id"]) ?? "workbuddy-\(lineStart)"
            let name = string(row["name"]) ?? "unknown_tool"
            let arguments = jsonText(row["arguments"] ?? row["input"])
            let said = string(row["reasoning"]) ?? pending
            calls.append(makeCall(id: unique(callId, &seen), callId: callId, session: session, agent: agent, sourcePath: sourcePath, offset: lineStart, timestamp: timestamp, pid: int32(row["pid"]), reasoning: said, toolName: name, arguments: arguments))
            pending = ""
        } else {
            let type = string(row["type"]) ?? ""
            let payload = row["payload"] as? [String: Any] ?? [:]
            let payloadType = string(payload["type"]) ?? ""
            if type == "session_meta" {
                let recorded = string(payload["id"]) ?? string(payload["session_id"])
                if lockedCodex, let recorded, recorded != session { continue }
                if let recorded, !lockedCodex { session = recorded; lockedCodex = true }
                continue
            }
            guard let timestamp = VerifyTime.parse(row["timestamp"]) else {
                if payloadType == "function_call" || payloadType == "custom_tool_call" { malformed += 1 }
                continue
            }
            let pid = int32(row["pid"]) ?? int32(payload["pid"])
            if type == "event_msg", payloadType == "user_message" { pending = ""; continue }
            if type == "response_item", payloadType == "message", string(payload["role"]) == "user" { pending = ""; continue }
            if type == "response_item", payloadType == "reasoning" {
                if let summary = textDeep(payload["summary"]), !summary.isEmpty { pending = summary }
                continue
            }
            if type == "event_msg", payloadType == "task_complete" {
                let text = string(payload["last_agent_message"]) ?? string(payload["message"]) ?? "已完成"
                completions[session] = text
                continue
            }
            if type == "response_item", payloadType == "message", string(payload["role"]) == "assistant" {
                if let text = textDeep(payload["content"]), let done = donePhrase(text) { completions[session] = done }
                continue
            }
            guard type == "response_item", payloadType == "function_call" || payloadType == "custom_tool_call" else { continue }
            let callId = string(payload["call_id"]) ?? "codex-\(lineStart)"
            let name = string(payload["name"]) ?? "unknown_tool"
            let arguments = jsonText(payload["arguments"] ?? payload["input"])
            calls.append(makeCall(id: unique(callId, &seen), callId: callId, session: session, agent: agent, sourcePath: sourcePath, offset: lineStart, timestamp: timestamp, pid: pid, reasoning: pending, toolName: name, arguments: arguments))
            pending = ""
        }
    }
    return ParseBatch(calls: calls, completions: completions, malformed: malformed)
}

private func makeCall(id: String, callId: String, session: String, agent: String, sourcePath: String, offset: Int, timestamp: Date, pid: Int32?, reasoning: String, toolName: String, arguments: String) -> ParsedToolCall {
    let said = SessionVerification.excerpt(reasoning.trimmingCharacters(in: .whitespacesAndNewlines))
    let args = SessionVerification.excerpt(redact(arguments))
    let paths = claimedPaths(toolName: toolName, arguments: arguments)
    return ParsedToolCall(id: id, callId: callId, sessionId: session, agent: agent, sourcePath: sourcePath, sourceOffset: offset, timestamp: timestamp, pid: pid, reasoning: said.text, reasoningTruncated: said.truncated, toolName: toolName, arguments: args.text, argumentsTruncated: args.truncated, claimedPaths: paths, claimsEdit: claimsEdit(toolName: toolName, arguments: arguments))
}

private func unique(_ id: String, _ seen: inout Set<String>) -> String {
    if seen.insert(id).inserted { return id }
    var n = 2
    while !seen.insert("\(id)#\(n)").inserted { n += 1 }
    return "\(id)#\(n)"
}

private func contentItems(_ value: Any?) -> [[String: Any]] {
    if let items = value as? [[String: Any]] { return items }
    if let text = value as? String { return [["type": "text", "text": text]] }
    return []
}

private func string(_ value: Any?) -> String? {
    guard let text = value as? String else { return nil }
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : text
}

private func int32(_ value: Any?) -> Int32? {
    if let number = value as? Int { return Int32(number) }
    if let number = value as? Double { return Int32(number) }
    if let number = value as? NSNumber { return number.int32Value }
    return nil
}

private func jsonText(_ value: Any?) -> String {
    if let text = value as? String { return text }
    guard let value, JSONSerialization.isValidJSONObject(value), let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else {
        return ""
    }
    return String(data: data, encoding: .utf8) ?? ""
}

private func textDeep(_ value: Any?) -> String? {
    if let text = value as? String { return text }
    if let items = value as? [String] { return items.joined(separator: "\n") }
    if let items = value as? [[String: Any]] {
        let parts = items.compactMap { string($0["text"]) ?? string($0["summary_text"]) ?? textDeep($0["content"]) }
        return parts.isEmpty ? nil : parts.joined(separator: "\n")
    }
    if let object = value as? [String: Any] {
        return string(object["text"]) ?? string(object["summary_text"]) ?? textDeep(object["content"])
    }
    return nil
}

private func donePhrase(_ text: String) -> String? {
    guard text.range(of: #"(已完成|完成了|做完了|改好了|任务完成|all done|i(?:'ve| have) (?:finished|completed|done))"#, options: [.regularExpression, .caseInsensitive]) != nil else { return nil }
    return text
}

private let editTools: Set<String> = ["edit", "write", "multiedit", "notebookedit", "apply_patch", "str_replace", "str_replace_editor", "search_replace", "write_file", "edit_file", "create_file", "update_file"]

private func toolParts(_ name: String) -> [String] {
    name.lowercased().split { !$0.isLetter && !$0.isNumber }.map(String.init)
}

private func isEditTool(_ name: String) -> Bool {
    let parts = toolParts(name)
    if let last = parts.last, editTools.contains(last) { return true }
    if parts.count >= 2, editTools.contains(parts.suffix(2).joined(separator: "_")) { return true }
    return parts.contains("apply") && parts.contains("patch")
}

private func commandBody(_ arguments: String) -> String {
    guard let data = arguments.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return arguments }
    return string(object["command"]) ?? string(object["cmd"]) ?? arguments
}

private func claimsEdit(toolName: String, arguments: String) -> Bool {
    if isEditTool(toolName) { return true }
    let command = commandBody(arguments)
    let lower = command.lowercased()
    if lower.contains("sed -i") || lower.contains("apply_patch") || lower.range(of: #"\btee\s+"#, options: .regularExpression) != nil { return true }
    return command.range(of: #"(?:^|[^>&\d])>>?\s*[^\s|&;]+"#, options: .regularExpression) != nil
}

private func claimedPaths(toolName: String, arguments: String) -> [String] {
    var paths: [String] = []
    if let data = arguments.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) {
        collectPaths(object, into: &paths)
    }
    let command = commandBody(arguments)
    if let regex = try? NSRegularExpression(pattern: #"(?:^|[^>&\d])>>?\s*([^\s|&;]+)"#) {
        let range = NSRange(command.startIndex..., in: command)
        for match in regex.matches(in: command, range: range) {
            guard let span = Range(match.range(at: 1), in: command) else { continue }
            let path = String(command[span])
            if path == "/dev/null" || path.hasPrefix("&") { continue }
            paths.append(path)
        }
    }
    if isEditTool(toolName) == false && paths.count > 8 { paths = Array(paths.prefix(8)) }
    var seen = Set<String>()
    return paths.filter { seen.insert($0).inserted }
}

private func collectPaths(_ value: Any, into paths: inout [String]) {
    let keys: Set<String> = ["file_path", "filepath", "path", "target_file", "notebook_path", "file", "filename"]
    if let object = value as? [String: Any] {
        for (key, item) in object {
            if keys.contains(key.lowercased()), let text = item as? String, text.contains("/") || text.contains(".") {
                paths.append(text)
            } else {
                collectPaths(item, into: &paths)
            }
        }
    } else if let list = value as? [Any] {
        for item in list { collectPaths(item, into: &paths) }
    }
}

private func redact(_ text: String) -> String {
    guard let regex = try? NSRegularExpression(pattern: #"(?i)(password|token|secret|api_key|authorization)\s*[:=]\s*["']?[^"',\s}]+"#) else { return text }
    let range = NSRange(text.startIndex..., in: text)
    return regex.stringByReplacingMatches(in: text, range: range, withTemplate: "$1=[redacted]")
}

private enum VerifyTime {
    static func parse(_ value: Any?) -> Date? {
        if let number = value as? Double { return Date(timeIntervalSince1970: number > 10_000_000_000 ? number / 1000 : number) }
        if let number = value as? Int { return Date(timeIntervalSince1970: number > 10_000_000_000 ? Double(number) / 1000 : Double(number)) }
        guard let raw = value as? String else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: raw) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: raw)
    }
}

private func ancestors(of pid: Int32, tree: [Int32: Int32]) -> [Int32] {
    var out: [Int32] = []
    var seen = Set<Int32>()
    var current = tree[pid]
    while let parent = current, parent > 0, seen.insert(parent).inserted, out.count < 32 {
        out.append(parent)
        current = tree[parent]
    }
    return out
}

private func treeMatch(_ callPid: Int32, _ effectPid: Int32, _ tree: [Int32: Int32]) -> Bool {
    if callPid == effectPid { return true }
    if ancestors(of: effectPid, tree: tree).contains(callPid) { return true }
    if ancestors(of: callPid, tree: tree).contains(effectPid) { return true }
    return false
}

private func windowEnd(_ call: ParsedToolCall, next: Date?) -> Date {
    let cap = call.timestamp.addingTimeInterval(SessionVerification.tailSeconds)
    guard let next else { return cap }
    let untilNext = next.addingTimeInterval(1)
    return min(cap, max(call.timestamp.addingTimeInterval(0.5), untilNext))
}

private func pathHit(call: ParsedToolCall, effect: HostEffect) -> Bool {
    guard effect.kind == "file" || effect.kind == "credential", let path = effect.path, !path.isEmpty else { return false }
    if let session = effect.sessionId, session != call.sessionId { return false }
    guard call.claimedPaths.contains(where: { covers($0, path) }) else { return false }
    return abs(effect.timestamp.timeIntervalSince(call.timestamp)) <= 120
}

private func match(call: ParsedToolCall, effect: HostEffect, next: Date?, tree: [Int32: Int32]) -> (rank: Int, name: String)? {
    if let toolCallId = effect.toolCallId, toolCallId == call.callId || toolCallId == call.id {
        return (3, "call-id")
    }
    if pathHit(call: call, effect: effect) {
        return (2, "path")
    }
    let start = call.timestamp.addingTimeInterval(-SessionVerification.leadSeconds)
    let end = windowEnd(call, next: next)
    guard effect.timestamp >= start, effect.timestamp <= end else { return nil }
    if effect.sessionId != nil, effect.sessionId != call.sessionId { return nil }
    if let callPid = call.pid, let effectPid = effect.pid {
        return treeMatch(callPid, effectPid, tree) ? (2, "time-pid") : nil
    }
    return (1, "time-window")
}

private func hasFileChange(_ effect: VerificationEffect) -> Bool {
    if let diff = effect.diff, !diff.isEmpty { return true }
    if effect.before != nil || effect.after != nil { return true }
    return false
}

private func mentionsEgress(_ reasoning: String, remote: String?) -> Bool {
    var text = reasoning.lowercased()
    guard !text.isEmpty else { return false }
    if let remote {
        let host = remote.lowercased()
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .split(separator: "/").first.map(String.init) ?? ""
        if host.count >= 3, text.contains(host) { return true }
    }
    if let regex = try? NSRegularExpression(pattern: #"(?:不|不会|没有|没)[^。；\n]{0,24}(?:联网|外联|网络|访问|请求|下载|上传|curl|wget|fetch)"#) {
        let range = NSRange(text.startIndex..., in: text)
        text = regex.stringByReplacingMatches(in: text, range: range, withTemplate: "")
    }
    return text.range(of: #"网络|外联|联网|请求|下载|上传|curl|wget|fetch|https?://|访问"#, options: .regularExpression) != nil
}

private func mentionsCredential(_ reasoning: String, path: String?) -> Bool {
    var text = reasoning.lowercased()
    guard !text.isEmpty else { return false }
    if let path {
        let base = (path as NSString).lastPathComponent.lowercased()
        if base.count >= 3, text.contains(base) { return true }
    }
    if let regex = try? NSRegularExpression(pattern: #"(?:不|不会|没有|没)[^。；\n]{0,12}(?:密钥|凭证|凭据|密码|token|secret|\.env|ssh|私钥)"#) {
        let range = NSRange(text.startIndex..., in: text)
        text = regex.stringByReplacingMatches(in: text, range: range, withTemplate: "")
    }
    return text.range(of: #"密钥|凭证|凭据|密码|token|secret|credential|\.env|ssh|私钥|id_rsa|api_key"#, options: .regularExpression) != nil
}

private func covers(_ stated: String, _ actual: String) -> Bool {
    func norm(_ value: String) -> String {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("\""), text.hasSuffix("\""), text.count >= 2 { text = String(text.dropFirst().dropLast()) }
        while text.count > 1, text.hasSuffix("/") { text.removeLast() }
        return text.lowercased()
    }
    let statedPath = norm(stated)
    let actualPath = norm(actual)
    if statedPath.isEmpty || actualPath.isEmpty { return false }
    if statedPath == actualPath { return true }
    if actualPath.hasSuffix("/" + statedPath) || statedPath.hasSuffix("/" + actualPath) { return true }
    return false
}

private func mismatches(call: ParsedToolCall, happened: [VerificationEffect], fileObservation: String) -> [VerificationMismatch] {
    var out: [VerificationMismatch] = []
    let sawClaimedFile = happened.contains { effect in
        guard effect.kind == "file" || effect.kind == "credential" else { return false }
        if hasFileChange(effect) { return true }
        guard let path = effect.path else { return false }
        return call.claimedPaths.contains { covers($0, path) }
    }
    if call.claimsEdit, fileObservation == "present", !sawClaimedFile {
        let paths = call.claimedPaths.isEmpty ? call.toolName : call.claimedPaths.joined(separator: "、")
        out.append(VerificationMismatch(kind: "claimed_edit_without_diff", label: "说了没做", detail: "它调用 \(call.toolName) 要改 \(paths)，这个时间窗里没有文件 diff。"))
    }
    var unspoken: [String] = []
    for effect in happened where effect.kind == "network" {
        if !mentionsEgress(call.reasoning, remote: effect.remote) {
            unspoken.append(effect.remote ?? "外联")
        }
    }
    for effect in happened where effect.credential || effect.kind == "credential" || SessionVerification.isCredential(effect.path) || SessionVerification.isCredential(effect.command) {
        if !mentionsCredential(call.reasoning, path: effect.path ?? effect.command) {
            unspoken.append(effect.path ?? effect.command ?? "凭证")
        }
    }
    if !unspoken.isEmpty {
        var seen = Set<String>()
        let listed = unspoken.filter { seen.insert($0).inserted }.joined(separator: "、")
        out.append(VerificationMismatch(kind: "unmentioned_side_effect", label: "做了没说", detail: "主机记下 \(listed)，动手前的文字没提到这次外联或凭证读取。"))
    }
    if !call.claimedPaths.isEmpty {
        let extras = happened.filter { $0.kind == "file" || $0.kind == "credential" }.compactMap(\.path).filter { path in
            !call.claimedPaths.contains { covers($0, path) }
        }
        var seen = Set<String>()
        let unique = extras.filter { seen.insert($0).inserted }
        if !unique.isEmpty {
            out.append(VerificationMismatch(kind: "extra_paths", label: "做的比说的多", detail: "它点了 \(call.claimedPaths.joined(separator: "、"))，主机上还有 \(unique.joined(separator: "、"))。"))
        }
    }
    return out
}

private func cardNote(call: ParsedToolCall, happened: [VerificationEffect], mismatches: [VerificationMismatch], fileObservation: String) -> String {
    if !mismatches.isEmpty { return mismatches.map(\.detail).joined(separator: " ") }
    if happened.isEmpty {
        if call.claimsEdit, fileObservation != "present" {
            return "文件观测没接上，不能凭这次空窗说它没改。"
        }
        return "这个时间窗里没有对上的文件、进程、外联或凭证读取。"
    }
    let how = happened.map(\.join).contains("call-id") ? "调用编号" : (happened.map(\.join).contains("time-pid") ? "时间和进程树" : "时间窗")
    return "按\(how)对上。"
}

private func checklist(allCalls: [ParsedToolCall], effects: [HostEffect], completions: [String: String], taskIDs: [String: String]) -> [CompletionChecklist] {
    let sessions = Array(Set(allCalls.map(\.sessionId))).sorted()
    return sessions.compactMap { session -> CompletionChecklist? in
        guard let done = completions[session], !done.isEmpty else { return nil }
        let sessionCalls = allCalls.filter { $0.sessionId == session }
        guard let first = sessionCalls.map(\.timestamp).min(), let last = sessionCalls.map(\.timestamp).max() else { return nil }
        let start = first.addingTimeInterval(-SessionVerification.leadSeconds)
        let end = last.addingTimeInterval(SessionVerification.tailSeconds)
        let inWindow = effects.filter { effect in
            if let effectSession = effect.sessionId, effectSession != session { return false }
            return effect.timestamp >= start && effect.timestamp <= end
        }
        let claimed = Array(Set(sessionCalls.filter(\.claimsEdit).flatMap(\.claimedPaths))).sorted()
        let actual = Array(Set(inWindow.filter { $0.kind == "file" }.compactMap(\.path))).sorted()
        let egress = inWindow.filter { $0.kind == "network" }.count
        let credentials = inWindow.contains { $0.credential || $0.kind == "credential" || SessionVerification.isCredential($0.path) || SessionVerification.isCredential($0.command) }
        let explicit = explicitFileCount(done)
        return CompletionChecklist(
            sessionId: session, agent: sessionCalls.first?.agent ?? "", taskId: taskIDs[session],
            doneText: SessionVerification.excerpt(done).text,
            claimedFiles: explicit ?? claimed.count, claimedFrom: explicit == nil ? "tool-args" : "done-text",
            actualFiles: actual.count, egressCount: egress, credentialsTouched: credentials,
            claimedPaths: claimed, actualPaths: actual
        )
    }
}

private func explicitFileCount(_ text: String) -> Int? {
    guard let regex = try? NSRegularExpression(pattern: #"(\d+)\s*(?:个文件|个路径|files?)"#, options: .caseInsensitive) else { return nil }
    let range = NSRange(text.startIndex..., in: text)
    guard let match = regex.firstMatch(in: text, range: range), let span = Range(match.range(at: 1), in: text) else { return nil }
    return Int(text[span])
}
