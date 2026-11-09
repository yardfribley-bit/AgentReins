import AgentReinsCore
import AgentReinsVerify
import Foundation

enum SessionVerificationFeed {
    static func document(tasks: [RealtimeTask], collected: [RealtimeCollectedRecord], processes: [RealtimeProcess], logs: SessionLogSnapshot, fileWatching: Bool) -> SessionVerificationDocument {
        let effects = hostEffects(tasks: tasks, collected: collected)
        var taskIDs: [String: String] = [:]
        for task in tasks { taskIDs[task.session] = task.id }
        var document = SessionVerification.verify(
            calls: logs.calls, effects: effects, processes: processLinks(processes),
            completions: logs.completions, taskIDs: taskIDs,
            fileChannel: fileWatching, networkChannel: effects.contains { $0.kind == "network" })
        document.sources = logs.sources
        return document
    }

    static func hostEffects(tasks: [RealtimeTask], collected: [RealtimeCollectedRecord]) -> [HostEffect] {
        var effects: [HostEffect] = []
        for task in tasks {
            for card in task.cards {
                effects.append(contentsOf: effectsForCard(card, session: task.session))
            }
        }
        for row in collected {
            effects.append(contentsOf: effectsForCollected(row))
        }
        effects.append(contentsOf: hardGateEffects())
        if effects.count > 2000 { effects = Array(effects.suffix(2000)) }
        return effects
    }

    /// Blocked commands never create a transport row. The audit tail is one read.
    static func hardGateEffects() -> [HostEffect] {
        HardGateReceipts.enforcedDenies(from: HardGateReceipts.defaultURL(), limit: 40).compactMap { row in
            let credential = row.subject.hasPrefix("path:")
            let network = row.subject.hasPrefix("host:")
            guard credential || network else { return nil }
            let target = String(row.subject.dropFirst(5))
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            guard let timestamp = formatter.date(from: row.at) else { return nil }
            return HostEffect(
                id: "hardgate-\(row.at)-\(row.subject)", kind: credential ? "credential" : "network",
                timestamp: timestamp, pid: row.shellPid == 0 ? nil : row.shellPid,
                path: credential ? target : nil, command: row.command.isEmpty ? nil : row.command,
                remote: network ? target : nil,
                sessionId: row.session.isEmpty ? nil : row.session,
                credential: credential, source: "hardgate",
                exitCode: row.exitCode, durationMs: row.durationMs,
                parents: row.parentPid == 0 ? nil : String(row.parentPid),
                verdict: row.mechanism.isEmpty ? "shell-gate" : row.mechanism)
        }
    }

    static func processLinks(_ processes: [RealtimeProcess]) -> [ProcessLink] {
        processes.compactMap { process in
            guard let pid = Int32(process.pid), let parent = Int32(process.parent) else { return nil }
            return ProcessLink(pid: pid, parentPid: parent)
        }
    }

    private static func effectsForCard(_ card: RealtimeCard, session: String) -> [HostEffect] {
        var effects: [HostEffect] = []
        let pid = card.pid ?? card.execution?.processID
        let resource = card.resource
        if resource?.path?.isEmpty == false || resource?.diff?.isEmpty == false || resource?.before != nil || resource?.after != nil {
            effects.append(HostEffect(
                id: card.id + ":file", kind: "file", timestamp: card.timestamp, pid: pid,
                path: resource?.path, diff: resource?.diff, before: resource?.before, after: resource?.after,
                sessionId: session, toolCallId: card.call,
                credential: SessionVerification.isCredential(resource?.path), source: "task-card"))
        }
        let remote = resource?.domain ?? resource?.observedRemoteHost ?? resource?.remoteIP
        if card.kind == "network" || card.kind == "web" || remote != nil {
            effects.append(HostEffect(
                id: card.id + ":net", kind: "network", timestamp: card.timestamp, pid: pid,
                remote: remote, sessionId: session, toolCallId: card.call, source: "task-card"))
        }
        if let command = card.execution?.command, !command.isEmpty {
            effects.append(HostEffect(
                id: card.id + ":proc", kind: "process", timestamp: card.timestamp, pid: pid,
                command: command, sessionId: session, toolCallId: card.call,
                credential: SessionVerification.isCredential(command), source: "task-card"))
            if let host = firstHost(command) {
                effects.append(HostEffect(
                    id: card.id + ":egress", kind: "network", timestamp: card.timestamp, pid: pid,
                    command: command, remote: host, sessionId: session, toolCallId: card.call, source: "task-card"))
            }
        }
        return effects
    }

    private static func effectsForCollected(_ row: RealtimeCollectedRecord) -> [HostEffect] {
        let timestamp = row.timestamp ?? Date(timeIntervalSince1970: 0)
        guard row.timestamp != nil else { return [] }
        if row.kind == "file" {
            let path = row.resource?.path ?? pathFromDetails(row.details)
            return [HostEffect(
                id: row.id + ":file", kind: "file", timestamp: timestamp, pid: row.pid, path: path,
                after: row.preview.isEmpty ? nil : row.preview, sessionId: row.session, toolCallId: row.call,
                credential: SessionVerification.isCredential(path), source: "collected")]
        }
        if row.kind == "network" {
            let remote = row.resource?.domain ?? row.resource?.observedRemoteHost ?? row.resource?.remoteIP
            return [HostEffect(
                id: row.id + ":net", kind: "network", timestamp: timestamp, pid: row.pid,
                remote: remote, sessionId: row.session, toolCallId: row.call, source: "collected")]
        }
        return []
    }

    private static func pathFromDetails(_ details: String) -> String? {
        guard let range = details.range(of: "路径：") else { return nil }
        let rest = details[range.upperBound...]
        let line = rest.split(separator: "\n", maxSplits: 1).first.map(String.init) ?? ""
        return line.isEmpty ? nil : line
    }

    private static func firstHost(_ command: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: #"https?://([^/\s]+)"#, options: .caseInsensitive) else { return nil }
        let range = NSRange(command.startIndex..., in: command)
        guard let match = regex.firstMatch(in: command, range: range), let span = Range(match.range(at: 1), in: command) else { return nil }
        return String(command[span])
    }
}

final class SessionLogIndex {
    static let shared = SessionLogIndex()
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.agentreins.session-logs", qos: .utility)
    private var snapshot = SessionLogSnapshot(calls: [], completions: [:], sources: [])
    private var scanning = false
    private var scanned = false
    private var lastScan = Date.distantPast
    private var fingerprint = ""
    private var verdictFingerprint = ""

    static var scanEnabled: Bool {
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil { return false }
        return ProcessInfo.processInfo.environment["AGENTREINS_SESSION_LOG_SCAN"] != "0"
    }

    func current() -> SessionLogSnapshot {
        lock.lock(); defer { lock.unlock() }
        if !scanned {
            return SessionLogSnapshot(calls: [], completions: [:], sources: [
                SessionLogSource(agent: "Claude Code", root: "~/.claude/projects", state: Self.scanEnabled ? "pending" : "absent", filesRead: 0, filesSkipped: 0, malformedLines: 0, note: Self.scanEnabled ? "正在读本机 Claude Code 日志。" : "这次没有去读 ~/.claude/projects。"),
                SessionLogSource(agent: "Codex", root: "~/.codex/sessions", state: Self.scanEnabled ? "pending" : "absent", filesRead: 0, filesSkipped: 0, malformedLines: 0, note: Self.scanEnabled ? "正在读本机 Codex 日志。" : "这次没有去读 ~/.codex/sessions。"),
            ])
        }
        return snapshot
    }

    func persistVerdicts(_ document: SessionVerificationDocument, databaseURL: URL) {
        guard Self.scanEnabled else { return }
        let mark = document.fingerprint
        lock.lock()
        if mark == verdictFingerprint { lock.unlock(); return }
        verdictFingerprint = mark
        lock.unlock()
        queue.async {
            guard let index = try? SessionJoinIndex(url: SessionJoinIndex.url(beside: databaseURL)) else { return }
            try? index.saveVerdicts(document.cards)
        }
    }

    func kick(databaseURL: URL, onChange: @escaping () -> Void) {
        guard Self.scanEnabled else { return }
        lock.lock()
        let wait: TimeInterval = RuntimeBudget.shared.isThrottled ? 30 : 8
        if scanning || Date().timeIntervalSince(lastScan) < wait { lock.unlock(); return }
        scanning = true
        lock.unlock()
        queue.async { [weak self] in
            guard let self else { return }
            let home = NSHomeDirectory()
            let claude = ProcessInfo.processInfo.environment["AGENTREINS_CLAUDE_PROJECTS"] ?? (home as NSString).appendingPathComponent(".claude/projects")
            let codex = ProcessInfo.processInfo.environment["AGENTREINS_CODEX_SESSIONS"] ?? (home as NSString).appendingPathComponent(".codex/sessions")
            let loaded = SessionVerification.load(claudeRoot: claude, codexRoot: codex)
            if let index = try? SessionJoinIndex(url: SessionJoinIndex.url(beside: databaseURL)) {
                try? index.upsert(loaded.calls)
            }
            let next = loaded.sources.map { "\($0.agent):\($0.state):\($0.filesRead):\($0.malformedLines)" }.joined(separator: "|")
                + "|" + loaded.calls.map(\.id).joined(separator: ",")
            self.lock.lock()
            let changed = next != self.fingerprint || !self.scanned
            self.snapshot = loaded
            self.fingerprint = next
            self.scanned = true
            self.lastScan = Date()
            self.scanning = false
            self.lock.unlock()
            if changed { onChange() }
        }
    }
}
