import Foundation

/// Which AgentReinsMCP processes a loopback HTTP server may stop on startup.
/// The listener on this port stays. Stdio processes with a live parent stay.
/// Same-port `--http` processes that are not listening, and MCP processes
/// reparented to pid 1 after their client died, are orphans.
public enum MCPHTTPOrphans {
    public struct Proc: Equatable {
        public var pid: Int32
        public var ppid: Int32
        public var command: String

        public init(pid: Int32, ppid: Int32, command: String) {
            self.pid = pid
            self.ppid = ppid
            self.command = command
        }
    }

    /// `ps -ax -o pid=,ppid=,command=`
    public static func parsePS(_ text: String) -> [Proc] {
        var out: [Proc] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let raw = String(line).trimmingCharacters(in: .whitespaces)
            let parts = raw.split(maxSplits: 2, whereSeparator: \.isWhitespace).map(String.init)
            guard parts.count == 3, let pid = Int32(parts[0]), let ppid = Int32(parts[1]), pid > 0 else { continue }
            out.append(Proc(pid: pid, ppid: ppid, command: parts[2]))
        }
        return out
    }

    public static func isAgentReinsMCP(_ command: String) -> Bool {
        let token = command.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        return (token as NSString).lastPathComponent == "AgentReinsMCP"
    }

    public static func isHTTPServerCommand(_ command: String) -> Bool {
        guard isAgentReinsMCP(command) else { return false }
        return command.split(whereSeparator: \.isWhitespace).map(String.init).contains("--http")
    }

    public static func commandTargetsPort(_ command: String, port: Int) -> Bool {
        let parts = command.split(whereSeparator: \.isWhitespace).map(String.init)
        if let index = parts.firstIndex(of: "--port"), parts.indices.contains(index + 1), parts[index + 1] == String(port) {
            return true
        }
        return parts.contains("--port=\(port)")
    }

    /// PIDs in `lsof -nP -iTCP:port -sTCP:LISTEN` output. Empty output means nobody.
    public static func listenerPIDs(lsof text: String) -> Set<Int32> {
        var pids = Set<Int32>()
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard parts.count >= 2, let pid = Int32(parts[1]), pid > 0 else { continue }
            if line.contains("LISTEN") { pids.insert(pid) }
        }
        return pids
    }

    public static func orphanPIDs(_ procs: [Proc], selfPid: Int32, port: Int, listenerPIDs: Set<Int32>) -> [Int32] {
        procs.compactMap { proc in
            guard proc.pid != selfPid, !listenerPIDs.contains(proc.pid), isAgentReinsMCP(proc.command) else { return nil }
            if isHTTPServerCommand(proc.command) && commandTargetsPort(proc.command, port: port) { return proc.pid }
            // Stdio worker whose client is gone (reparented to launchd) and that never returned to read stdin.
            if proc.ppid == 1 && !isHTTPServerCommand(proc.command) { return proc.pid }
            return nil
        }
    }

    /// Old dev-tree binaries (`AgentSpec` / `AgentGuardApp`). The running pid is never included.
    public static func isLegacyBundle(_ command: String) -> Bool {
        let lower = command.lowercased()
        return lower.contains("/agentspec/") || lower.contains("/agentguardapp/")
    }

    /// Same-port orphans, abandoned stdio, and stale MCP processes launched from the old bundle.
    /// A legacy process that is the listener on this port is included so a new server can bind.
    /// A legacy listener on a different port is left alone. `selfPid` is never returned.
    public static func reapPIDs(_ procs: [Proc], selfPid: Int32, port: Int, listenerPIDs: Set<Int32>) -> [Int32] {
        var ids = Set(orphanPIDs(procs, selfPid: selfPid, port: port, listenerPIDs: listenerPIDs))
        for proc in procs {
            guard proc.pid != selfPid, isAgentReinsMCP(proc.command), isLegacyBundle(proc.command) else { continue }
            if listenerPIDs.contains(proc.pid) {
                if commandTargetsPort(proc.command, port: port) { ids.insert(proc.pid) }
                continue
            }
            if isHTTPServerCommand(proc.command) && !commandTargetsPort(proc.command, port: port) { continue }
            ids.insert(proc.pid)
        }
        return ids.sorted()
    }

    /// Launchd health check: the port is not accepting, and an `--http` process for
    /// this port has already been alive long enough that it is not still binding.
    /// When something is listening, nobody is killed.
    public static func healthVictims(_ procs: [Proc], port: Int, portListening: Bool, now: Date, startedAt: [Int32: Date], minimumAge: TimeInterval = 12) -> [Int32] {
        guard !portListening else { return [] }
        return procs.compactMap { proc in
            guard isHTTPServerCommand(proc.command), commandTargetsPort(proc.command, port: port) else { return nil }
            guard let start = startedAt[proc.pid], now.timeIntervalSince(start) >= minimumAge else { return nil }
            return proc.pid
        }
    }

    /// `launchctl kickstart -k` records SIGKILL as `last exit code = -9`
    /// (or "Killed: 9" / SIGKILL). That exit is expected. It is not a health failure.
    public static func isKickstartExit(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.contains("sigkill") || lower.contains("killed: 9") { return true }
        if let code = lastExitCode(text), code == -9 { return true }
        return false
    }

    /// True only for a recorded non-zero exit that is not the kickstart SIGKILL.
    /// Missing text and exit 0 are not errors. `-9` is not an error.
    public static func launchdExitIsHealthError(_ text: String) -> Bool {
        if isKickstartExit(text) { return false }
        guard let code = lastExitCode(text) else { return false }
        return code != 0
    }

    public static func lastExitCode(_ text: String) -> Int32? {
        guard let regex = try? NSRegularExpression(pattern: #"(?i)last exit code\s*=\s*(-?\d+)"#) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1,
              let codeRange = Range(match.range(at: 1), in: text),
              let code = Int32(text[codeRange]) else { return nil }
        return code
    }

    /// Lines the health agent may write. No victims means no line at all, so a
    /// kickstart that only left `last exit code = -9` is not reported as an error.
    /// A process that is still not listening is signaled, and that line does not
    /// call the earlier SIGKILL an error.
    public static func healthLogLines(victims: [Int32], port: Int, launchdText: String) -> [String] {
        guard !victims.isEmpty else { return [] }
        let detail = isKickstartExit(launchdText)
            ? "still not accepting after kickstart; signaled"
            : "alive but 127.0.0.1:\(port) is not accepting; signaled"
        return victims.map { "AgentReinsMCP health: pid \($0) \(detail)" }
    }

    /// After kickstart the replacement is allowed longer to bind before it is treated as a hang.
    public static func healthGrace(launchdText: String) -> TimeInterval {
        isKickstartExit(launchdText) ? 45 : 12
    }
}

/// Optional deadline for MCP reads. Nil keeps the full integrity walk used by parity tests.
public struct IntegrityReadBudget {
    public var deadline: Date
    public var maxFileBytes: Int

    public init(deadline: Date, maxFileBytes: Int = 32 * 1024 * 1024) {
        self.deadline = deadline
        self.maxFileBytes = max(64 * 1024, maxFileBytes)
    }

    public func expired() -> Bool { Date() >= deadline }

    public static func stopResult(_ reason: String) -> [String: Any] {
        [
            "ok": false,
            "status": "read_budget_exceeded",
            "statusText": reason,
            "confidence": "Unknown",
            "entriesChecked": 0,
            "scan": "stopped",
            "note": "证据没有被改写。这不是篡改结论。",
        ]
    }
}
