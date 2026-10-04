import Foundation
import Darwin

// A small, observation-only hook. It writes a spool record and always lets
// WorkBuddy continue. No database, network, UI, or model work in this process.
func callerAncestors() -> [[String: Any]] {
    var pid = getppid()
    var result: [[String: Any]] = []
    for _ in 0..<8 {
        guard pid > 1 else { break }
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let count = withUnsafeMutablePointer(to: &info) { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, Int32(size)) }
        guard Int(count) == size else { break }
        var path = [CChar](repeating: 0, count: 4096)
        let length = path.withUnsafeMutableBufferPointer { proc_pidpath(pid, $0.baseAddress, UInt32($0.count)) }
        let executable = length > 0 ? String(cString: path) : ""
        result.append(["pid": pid, "parent_pid": info.pbi_ppid,
                       "birth_identity": UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec),
                       "executable": executable])
        let parent = Int32(info.pbi_ppid)
        guard parent != pid else { break }
        pid = parent
    }
    return result
}

// Capture the issuer while it is still alive, before directory notification,
// database work, or a later process-tree poll. This remains a bounded snapshot.
func callerSnapshot(_ ancestors: [[String: Any]]) -> [String: Any]? {
    guard let caller = ancestors.first(where: { ($0["executable"] as? String ?? "").contains("/WorkBuddy.app/Contents/") }),
          let pid = caller["pid"] as? Int32, let birth = caller["birth_identity"] as? UInt64 else { return nil }
    let deadline = ProcessInfo.processInfo.systemUptime + 0.015
    var pending: [(Int32, Int32?)] = [(pid, nil)]
    var seen = Set<Int32>(), samples: [[String: Any]] = []
    var enumerationTruncated = false, unavailable = 0
    while let (current, expectedParent) = pending.popLast(), seen.count < 32, ProcessInfo.processInfo.systemUptime < deadline {
        guard current != getpid(), seen.insert(current).inserted else { continue }
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let read = withUnsafeMutablePointer(to: &info) { proc_pidinfo(current, PROC_PIDTBSDINFO, 0, $0, Int32(size)) }
        guard read == size, expectedParent == nil || info.pbi_ppid == UInt32(expectedParent!) else { unavailable += 1; continue }
        let identity = UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
        if current == pid && identity != birth { return nil }
        var task = proc_taskinfo()
        let taskSize = MemoryLayout<proc_taskinfo>.size
        let taskRead = withUnsafeMutablePointer(to: &task) { proc_pidinfo(current, PROC_PIDTASKINFO, 0, $0, Int32(taskSize)) }
        var path = [CChar](repeating: 0, count: 4096)
        let length = path.withUnsafeMutableBufferPointer { proc_pidpath(current, $0.baseAddress, UInt32($0.count)) }
        // Recheck birth identity after sampling to exclude reused PIDs.
        var final = proc_bsdinfo()
        let verified = withUnsafeMutablePointer(to: &final) { proc_pidinfo(current, PROC_PIDTBSDINFO, 0, $0, Int32(size)) }
        guard verified == size, final.pbi_start_tvsec == info.pbi_start_tvsec,
              final.pbi_start_tvusec == info.pbi_start_tvusec else { unavailable += 1; continue }
        var row: [String: Any] = ["pid": current, "parent_pid": info.pbi_ppid,
            "birth_identity": identity, "executable": length > 0 ? String(cString: path) : "",
            "observed_at_ms": Date().timeIntervalSince1970 * 1000,
            "resource_status": taskRead == taskSize ? "sampled" : "unavailable"]
        if taskRead == taskSize {
            row["resident_bytes"] = task.pti_resident_size
            row["cpu_time_nanoseconds"] = task.pti_total_user + task.pti_total_system
            row["thread_count"] = task.pti_threadnum
        }
        samples.append(row)
        var children = [Int32](repeating: 0, count: 32)
        let count = children.withUnsafeMutableBytes { proc_listchildpids(current, $0.baseAddress, Int32($0.count)) }
        if count >= 32 { enumerationTruncated = true }
        if count > 0 { pending.append(contentsOf: children.prefix(min(Int(count), 32)).filter { $0 > 1 }.map { ($0, current) }) }
    }
    return ["processes": samples, "truncated": !pending.isEmpty || enumerationTruncated, "unavailable_processes": unavailable,
        "coverage": "Hook-boundary resource snapshot of issuer branch; exited children, syscalls and network bodies not captured",
        "maximum_processes": 32, "budget_ms": 15]
}

let maximumBytes = 16_777_216
let arguments = CommandLine.arguments
let inbox: URL = {
    if let index = arguments.firstIndex(of: "--inbox"), arguments.indices.contains(index + 1) {
        return URL(fileURLWithPath: arguments[index + 1])
    }
    return FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/AgentGuard/hook-events/workbuddy")
}()
do {
    var input = Data()
    while input.count <= maximumBytes {
        guard let chunk = try FileHandle.standardInput.read(upToCount: min(65_536, maximumBytes + 1 - input.count)), !chunk.isEmpty else { break }
        input.append(chunk)
    }
    let parsed = input.count <= maximumBytes ? (try? JSONSerialization.jsonObject(with: input) as? [String: Any]) : nil
    let valid = parsed?["session_id"] as? String
    let payload: [String: Any] = valid?.isEmpty == false ? parsed! : ["session_id": "unattributed"]
    let name = valid?.isEmpty == false ? (payload["hook_event_name"] as? String ?? arguments.dropFirst().first ?? "unknown") : "CaptureGap"
    let ancestors = callerAncestors()
    var record: [String: Any] = ["schema_version": 1, "event_id": UUID().uuidString,
        "observed_at_ms": Date().timeIntervalSince1970 * 1000,
        "hook_event_name": name, "writer_pid": getpid(), "writer_parent_pid": getppid(),
        "payload": payload, "caller_ancestors": ancestors]
    if name == "CaptureGap" {
        record["capture_gap"] = ["reason": input.count > maximumBytes ? "payload_limit_exceeded" : "invalid_payload_or_session",
            "observed_input_bytes": input.count, "maximum_bytes": maximumBytes,
            "original_hook": arguments.dropFirst().first ?? "unknown", "payload_preserved": false]
    } else if let snapshot = callerSnapshot(ancestors) { record["caller_snapshot"] = snapshot }
    let manager = FileManager.default
    try manager.createDirectory(at: inbox, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let file = inbox.appendingPathComponent(UUID().uuidString + ".json")
    try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]).write(to: file, options: .atomic)
    try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
} catch {
    // Fail open. Hook spool failures must never block the user's task.
}
FileHandle.standardOutput.write(Data("{}\n".utf8))
