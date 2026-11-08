import Foundation

/// Which AgentReinsMCP processes a loopback HTTP server may stop on startup.
/// The listener on this port stays. Stdio processes with a live parent stay.
/// Same-port `--http` processes that are not listening, and MCP processes
/// reparented to pid 1 after their client died, are orphans.
/// Live evidence must not grow without a bound. These defaults are the product policy:
/// 14 days and 2 GiB. Infinite append is not acceptable.
public enum EvidenceRetentionDefaults {
    public static let maxAge: TimeInterval = 14 * 24 * 60 * 60
    public static let maxBytes: Int64 = 2 * 1024 * 1024 * 1024
    public static let batchRows = 200
    public static let maxBatchesPerPass = 4
}

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
