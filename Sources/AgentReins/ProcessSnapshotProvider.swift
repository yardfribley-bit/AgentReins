import Darwin
import Foundation

struct ProcessSnapshotRecord: Sendable, Equatable {
    let pid: String
    let ppid: String
    let command: String
    let agent: String?

    init(pid: String, ppid: String, command: String, agent: String? = nil) {
        self.pid = pid
        self.ppid = ppid
        self.command = command
        self.agent = agent
    }
}

enum ProcessArgumentRedactor {
    private static let patterns: [(NSRegularExpression, String)] = [
        (try! NSRegularExpression(pattern: #"(?i)(--?(?:token|api[-_]?key|secret|password)(?:=|\s+))[^\s]+"#), "$1[REDACTED]"),
        (try! NSRegularExpression(pattern: #"(?i)([\"']?Authorization[\"']?\s*[:=]\s*[\"']?Bearer\s+)[^\"',}\s]+"#), "$1[REDACTED]"),
        (try! NSRegularExpression(pattern: #"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}"#), "$1[REDACTED]")
    ]

    static func redact(_ command: String) -> String {
        patterns.reduce(command) { value, rule in
            rule.0.stringByReplacingMatches(in: value,
                                             range: NSRange(value.startIndex..., in: value),
                                             withTemplate: rule.1)
        }
    }
}

protocol ProcessSnapshotting: Sendable {
    var sourceID: String { get }
    func snapshot() -> [ProcessSnapshotRecord]
}

/// Entitlement-free macOS process inventory. libproc supplies durable PID/PPID
/// identity; KERN_PROCARGS2 is read only for agent process trees to limit cost
/// and avoid collecting unrelated users' command arguments.
final class DarwinLibprocSnapshotProvider: ProcessSnapshotting, @unchecked Sendable {
    let sourceID = "darwin-libproc"
    let agentMarkers: [String]
    private let stateLock = NSLock()
    private var knownRoots = Set<pid_t>()
    private var lastRootDiscovery = Date.distantPast
    private var cachedAgentRecords: [pid_t: ProcessSnapshotRecord] = [:]
    // New agent roots may appear at human timescale; their short-lived child
    // tools do not. Discover roots infrequently, then sample known subtrees at
    // high frequency so we catch one-second commands without rescanning the OS.
    private let rootDiscoveryInterval: TimeInterval = 30

    init(agentMarkers: [String]) {
        self.agentMarkers = agentMarkers.map { $0.lowercased() }
    }

    func snapshot() -> [ProcessSnapshotRecord] {
        stateLock.lock()
        let discoverRoots = Date().timeIntervalSince(lastRootDiscovery) >= rootDiscoveryInterval || knownRoots.isEmpty
        let rootsSnapshot = knownRoots
        stateLock.unlock()

        if !discoverRoots {
            return snapshotAgentTrees(roots: rootsSnapshot)
        }

        let capacity = max(Int(proc_listallpids(nil, 0)) * 2, 256)
        var pids = [pid_t](repeating: 0, count: capacity)
        let byteCount = Int32(pids.count * MemoryLayout<pid_t>.size)
        let found = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, byteCount) }
        guard found > 0 else { return [] }

        var records: [pid_t: (ppid: pid_t, executable: String)] = [:]
        for pid in pids.prefix(Int(found)) where pid > 0 {
            guard let identity = identity(pid: pid) else { continue }
            records[pid] = identity
        }

        var children: [pid_t: [pid_t]] = [:]
        for (pid, value) in records { children[value.ppid, default: []].append(pid) }
        let rootOwners = Dictionary(uniqueKeysWithValues: records.compactMap { pid, value in
            agentOwner(for: value.executable).map { (pid, $0) }
        })
        let roots = Array(rootOwners.keys)
        stateLock.lock()
        knownRoots = Set(roots)
        lastRootDiscovery = Date()
        stateLock.unlock()
        var agentTree = Set(roots)
        var owners = rootOwners
        var queue = rootOwners.map { (pid: $0.key, owner: $0.value) }
        while let current = queue.popLast() {
            let parent = current.pid
            for child in children[parent] ?? [] where agentTree.insert(child).inserted {
                owners[child] = current.owner
                queue.append((child, current.owner))
            }
        }

        // The all-PID map above is ephemeral and exists only to reconstruct
        // parent/child edges. Do not return unrelated machine processes to any
        // collector, store, or UI consumer.
        let result = agentTree.compactMap { pid -> ProcessSnapshotRecord? in
            guard let value = records[pid] else { return nil }
            let rawCommand = arguments(pid: pid) ?? value.executable
            return ProcessSnapshotRecord(pid: String(pid), ppid: String(value.ppid), command: rawCommand,
                agent: owners[pid])
        }
        stateLock.lock()
        cachedAgentRecords = Dictionary(uniqueKeysWithValues: result.compactMap {
            guard let pid = pid_t($0.pid) else { return nil }
            return (pid, $0)
        })
        stateLock.unlock()
        return result
    }

    func isAgentRootExecutable(_ executable: String) -> Bool {
        agentOwner(for: executable) != nil
    }

    private func agentOwner(for executable: String) -> String? {
        let path = executable.lowercased()
        if agentMarkers.contains("workbuddy"), path.contains("/applications/workbuddy.app/") { return "workbuddy" }
        if agentMarkers.contains("chatgpt"), path.contains("/applications/chatgpt.app/") { return "codex" }
        if agentMarkers.contains("cursor"), path.contains("/applications/cursor.app/") { return "cursor" }

        // Product names that commonly appear in user project paths need an
        // application-bundle identity above. Other adapters retain the generic
        // executable marker until they gain an explicit Runtime Profile.
        let bundleScoped = Set(["workbuddy", "chatgpt", "codex", "cursor"])
        return agentMarkers.filter { !bundleScoped.contains($0) }.first(where: path.contains)
    }

    /// Between low-frequency root discovery passes, enumerate only descendants
    /// of known AI agents. This is the hot path used to catch short-lived tools.
    private func snapshotAgentTrees(roots: Set<pid_t>) -> [ProcessSnapshotRecord] {
        stateLock.lock()
        let cache = cachedAgentRecords
        stateLock.unlock()
        var pending = roots.compactMap { root -> (pid_t, String)? in
            guard let owner = cache[root]?.agent else { return nil }
            return (root, owner)
        }
        var visited = Set<pid_t>()
        var result: [ProcessSnapshotRecord] = []
        while let current = pending.popLast() {
            let pid = current.0
            let owner = current.1
            guard visited.insert(pid).inserted else { continue }
            if let cached = cache[pid] {
                result.append(cached)
            } else if let value = identity(pid: pid) {
                result.append(ProcessSnapshotRecord(pid: String(pid), ppid: String(value.ppid),
                    command: arguments(pid: pid) ?? value.executable, agent: owner))
            } else {
                continue
            }
            pending.append(contentsOf: childPIDs(of: pid).map { ($0, owner) })
        }
        stateLock.lock()
        cachedAgentRecords = Dictionary(uniqueKeysWithValues: result.compactMap {
            guard let pid = pid_t($0.pid) else { return nil }
            return (pid, $0)
        })
        stateLock.unlock()
        return result
    }

    private func childPIDs(of parent: pid_t) -> [pid_t] {
        let requiredBytes = proc_listchildpids(parent, nil, 0)
        guard requiredBytes > 0 else { return [] }
        let count = max(Int(requiredBytes) / MemoryLayout<pid_t>.size, 1)
        var pids = [pid_t](repeating: 0, count: count + 8)
        let capacity = Int32(pids.count * MemoryLayout<pid_t>.size)
        let bytes = pids.withUnsafeMutableBytes {
            proc_listchildpids(parent, $0.baseAddress, capacity)
        }
        guard bytes > 0 else { return [] }
        return Array(pids.prefix(Int(bytes) / MemoryLayout<pid_t>.size).filter { $0 > 0 })
    }

    private func identity(pid: pid_t) -> (ppid: pid_t, executable: String)? {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let read = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, Int32(size))
        }
        guard read == size else { return nil }
        var buffer = [CChar](repeating: 0, count: 4_096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        let executable: String
        if length > 0 {
            executable = String(cString: buffer)
        } else {
            executable = withUnsafePointer(to: &info.pbi_comm) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
            }
        }
        guard !executable.isEmpty else { return nil }
        return (pid_t(info.pbi_ppid), executable)
    }

    private func arguments(pid: pid_t) -> String? {
        var mib = [CTL_KERN, KERN_PROCARGS2, Int32(pid)]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        size = min(size, 1_048_576)
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &bytes, &size, nil, 0) == 0 else { return nil }
        var argc: Int32 = 0
        withUnsafeMutableBytes(of: &argc) { target in
            bytes.withUnsafeBytes { source in target.copyBytes(from: source.prefix(MemoryLayout<Int32>.size)) }
        }
        guard argc > 0 else { return nil }
        let strings = bytes.dropFirst(MemoryLayout<Int32>.size).split(separator: 0).map {
            String(decoding: $0, as: UTF8.self)
        }
        guard strings.count > 1 else { return strings.first }
        // KERN_PROCARGS2 starts with executable path, followed by argc argv values,
        // then environment variables. Never cross the argc boundary.
        return strings.dropFirst().prefix(Int(argc)).joined(separator: " ")
    }
}

struct PsProcessSnapshotProvider: ProcessSnapshotting {
    let sourceID = "ps-fallback"

    func snapshot() -> [ProcessSnapshotRecord] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,ppid=,command="]
        let pipe = Pipe()
        process.standardOutput = pipe
        do { try process.run() } catch { return [] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return output.split(whereSeparator: \.isNewline).compactMap { line in
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 3 else { return nil }
            return ProcessSnapshotRecord(pid: String(parts[0]), ppid: String(parts[1]),
                                         command: parts[2...].joined(separator: " "))
        }
    }
}

struct ResilientProcessSnapshotProvider: ProcessSnapshotting {
    let sourceID = "libproc-with-ps-fallback"
    let primary: DarwinLibprocSnapshotProvider
    let fallback = PsProcessSnapshotProvider()

    init(agentMarkers: [String]) {
        primary = DarwinLibprocSnapshotProvider(agentMarkers: agentMarkers)
    }

    func snapshot() -> [ProcessSnapshotRecord] {
        let result = primary.snapshot()
        return result.isEmpty ? fallback.snapshot() : result
    }
}
