import Darwin
import Foundation

struct ProcessSnapshotRecord: Sendable, Equatable {
    let pid: String
    let ppid: String
    let command: String
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
struct DarwinLibprocSnapshotProvider: ProcessSnapshotting {
    let sourceID = "darwin-libproc"
    let agentMarkers: [String]

    init(agentMarkers: [String]) {
        self.agentMarkers = agentMarkers.map { $0.lowercased() }
    }

    func snapshot() -> [ProcessSnapshotRecord] {
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
        let roots = records.compactMap { pid, value in
            agentMarkers.contains(where: value.executable.lowercased().contains) ? pid : nil
        }
        var agentTree = Set(roots)
        var queue = roots
        while let parent = queue.popLast() {
            for child in children[parent] ?? [] where agentTree.insert(child).inserted {
                queue.append(child)
            }
        }

        return records.map { pid, value in
            let rawCommand = agentTree.contains(pid) ? (arguments(pid: pid) ?? value.executable) : value.executable
            return ProcessSnapshotRecord(pid: String(pid), ppid: String(value.ppid), command: rawCommand)
        }
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
