import Darwin
import Foundation

/// In-process process table. `proc_listpids` / `proc_pidinfo` / `sysctl(KERN_PROCARGS2)`.
/// Never spawns `/bin/ps`. A full `ps -ax` fills the stdout pipe and blocks in
/// `waitUntilExit` when the reader has not started yet.
public enum ProcessTable {
    public struct Row: Equatable, Sendable {
        public var pid: Int32
        public var ppid: Int32
        public var path: String
        public var startedAt: Date

        public init(pid: Int32, ppid: Int32, path: String, startedAt: Date) {
            self.pid = pid
            self.ppid = ppid
            self.path = path
            self.startedAt = startedAt
        }
    }

    public static func snapshot() -> [Row] {
        let bytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard bytes > 0 else { return [] }
        let slots = min(Int(bytes) / MemoryLayout<pid_t>.size + 32, 8192)
        var pids = [pid_t](repeating: 0, count: slots)
        let got = pids.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return 0 }
            return proc_listpids(UInt32(PROC_ALL_PIDS), 0, base, Int32(buffer.count * MemoryLayout<pid_t>.size))
        }
        guard got > 0 else { return [] }
        let count = min(Int(got) / MemoryLayout<pid_t>.size, pids.count)
        var rows: [Row] = []
        rows.reserveCapacity(min(count, 1024))
        let infoSize = Int32(MemoryLayout<proc_bsdinfo>.size)
        for pid in pids.prefix(count) where pid > 0 {
            var info = proc_bsdinfo()
            let read = withUnsafeMutablePointer(to: &info) {
                proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, infoSize)
            }
            guard read == infoSize else { continue }
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let n = proc_pidpath(pid, &buffer, UInt32(buffer.count))
            let path = n > 0 ? String(cString: buffer) : ""
            let started = Date(timeIntervalSince1970: TimeInterval(info.pbi_start_tvsec))
            rows.append(Row(pid: pid, ppid: Int32(bitPattern: info.pbi_ppid), path: path, startedAt: started))
        }
        return rows
    }

    /// Argument vector for one pid. Empty when the kernel refuses (other users).
    public static func commandLine(_ pid: Int32) -> String {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 4, size < 1_048_576 else { return "" }
        var data = [UInt8](repeating: 0, count: size)
        let rc = data.withUnsafeMutableBytes { raw -> Int32 in
            var length = raw.count
            return sysctl(&mib, u_int(mib.count), raw.baseAddress, &length, nil, 0)
        }
        guard rc == 0 else { return "" }
        guard data.count >= MemoryLayout<Int32>.size else { return "" }
        let argc = Int(data.withUnsafeBytes { $0.load(as: Int32.self) })
        var index = MemoryLayout<Int32>.size
        while index < data.count && data[index] == 0 { index += 1 }
        func next() -> String? {
            guard index < data.count else { return nil }
            if data[index] == 0 { return nil }
            let start = index
            while index < data.count && data[index] != 0 { index += 1 }
            let text = String(bytes: data[start..<index], encoding: .utf8) ?? ""
            if index < data.count { index += 1 }
            return text.isEmpty ? nil : text
        }
        var parts: [String] = []
        if let exec = next() { parts.append(exec) }
        while index < data.count && data[index] == 0 { index += 1 }
        var left = max(argc, 1)
        while left > 0, let arg = next() {
            parts.append(arg)
            left -= 1
            if parts.count > 64 { break }
        }
        if parts.count >= 2, parts[0] == parts[1] { parts.remove(at: 1) }
        return parts.joined(separator: " ")
    }

    /// Current working directory, when the kernel returns it. Empty otherwise.
    public static func workingDirectory(_ pid: Int32) -> String {
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        let read = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, $0, size)
        }
        guard read == size else { return "" }
        return withUnsafePointer(to: &info.pvi_cdir.vip_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
    }
}

/// Runs a child without the pipe-fill deadlock: stdout and stderr are drained
/// while the process is alive, and the child is killed when `timeout` elapses.
public enum BoundedProcess {
    public static func run(_ executable: String, arguments: [String], timeout: TimeInterval) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        let box = LockedBuffer()
        output.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if !chunk.isEmpty { box.append(chunk) }
        }
        errors.fileHandleForReading.readabilityHandler = { handle in
            _ = handle.availableData
        }
        do {
            try process.run()
        } catch {
            output.fileHandleForReading.readabilityHandler = nil
            errors.fileHandleForReading.readabilityHandler = nil
            return ""
        }
        let deadline = Date().addingTimeInterval(max(0.05, timeout))
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            kill(process.processIdentifier, SIGKILL)
            process.waitUntilExit()
        }
        output.fileHandleForReading.readabilityHandler = nil
        errors.fileHandleForReading.readabilityHandler = nil
        box.append(output.fileHandleForReading.readDataToEndOfFile())
        return box.string
    }
}

private final class LockedBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func append(_ chunk: Data) {
        lock.lock(); data.append(chunk); lock.unlock()
    }
    var string: String {
        lock.lock(); defer { lock.unlock() }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
