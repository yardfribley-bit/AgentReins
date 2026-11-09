import CryptoKit
import Foundation

/// Samples open vnodes on Cursor, Claude, Codex, and WorkBuddy process trees.
/// Does not read rules.json. Does not block or restore. Credential reads are
/// recorded in any directory. Writes are recorded when they are outside the
/// process working directory (or under /tmp when the working directory is unknown).
final class AgentTreeFileObserver {
    var onEvents: (([GuardEvent]) -> Void)?
    private let queue = DispatchQueue(label: "com.agentreins.file-layer", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var seen: [Int32: Set<String>] = [:]
    private var cursor = 0
    private let lock = NSLock()

    func start() {
        lock.lock()
        if timer != nil { lock.unlock(); return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 1, repeating: 1.5)
        source.setEventHandler { [weak self] in self?.sample() }
        source.resume()
        timer = source
        lock.unlock()
    }

    func stop() {
        lock.lock()
        timer?.cancel()
        timer = nil
        lock.unlock()
    }

    private func sample() {
        let rows = ProcessTable.snapshot()
        var owner: [Int32: String] = [:]
        for row in rows {
            if let agent = FileLayerCapture.agentOwner(path: row.path) {
                owner[row.pid] = agent
            }
        }
        var progressed = true
        var guardrails = 0
        while progressed && guardrails < 8 {
            progressed = false
            guardrails += 1
            for row in rows where owner[row.pid] == nil {
                if let parent = owner[row.ppid] {
                    owner[row.pid] = parent
                    progressed = true
                }
            }
        }
        let mine = rows.filter { owner[$0.pid] != nil && !rowIsSelf($0.path) }
        let slice: [ProcessTable.Row]
        if mine.count <= 48 {
            slice = mine
        } else {
            let start = cursor % mine.count
            cursor = (start + 48) % mine.count
            slice = (0..<48).map { mine[(start + $0) % mine.count] }
        }
        var events: [GuardEvent] = []
        let live = Set(mine.map(\.pid))
        seen = seen.filter { live.contains($0.key) }
        for row in slice {
            guard let agent = owner[row.pid] else { continue }
            let workspace = ProcessTable.workingDirectory(row.pid)
            let opens = LibprocOpenFiles.sample(pid: row.pid).map {
                FileLayerCapture.OpenFile(path: $0.path, writable: $0.writable)
            }
            let hits = FileLayerCapture.hits(opens: opens, workspace: workspace.isEmpty ? nil : workspace)
            var known = seen[row.pid] ?? []
            for hit in hits {
                let key = "\(hit.op)|\(hit.path)"
                guard known.insert(key).inserted else { continue }
                events.append(Self.event(hit: hit, agent: agent, pid: row.pid, ppid: row.ppid))
            }
            seen[row.pid] = known
        }
        guard !events.isEmpty else { return }
        let deliver = onEvents
        DispatchQueue.main.async { deliver?(events) }
    }

    private func rowIsSelf(_ path: String) -> Bool {
        let base = (path as NSString).lastPathComponent
        return base == "AgentReins" || base == "AgentReinsMCP"
    }

    private static func event(hit: FileLayerCapture.Hit, agent: String, pid: Int32, ppid: Int32) -> GuardEvent {
        let stamp = Int(Date().timeIntervalSince1970 / 3600)
        let id = stableUUID("\(agent)|\(pid)|\(hit.op)|\(hit.path)|\(stamp)")
        return GuardEvent(
            id: id, kind: "file", ruleId: hit.credential ? "credential_observe" : "agent_tree_write",
            path: hit.path, command: nil, agent: agent, op: hit.op,
            severity: hit.credential ? "high" : "info", ts: Date(), action: "observed",
            source: "libproc-vnode", attributionConfidence: .confirmed,
            attributionMethod: FileLayerCapture.mechanism + " " + FileLayerCapture.limits,
            processId: pid, parentProcessId: ppid)
    }

    private static func stableUUID(_ value: String) -> UUID {
        var bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x50
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

enum LibprocOpenFiles {
    struct File {
        var path: String
        var writable: Bool
    }

    static func sample(pid: Int32) -> [File] {
        let required = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard required > 0 else { return [] }
        let capacity = min(Int(required) / MemoryLayout<proc_fdinfo>.size + 8, 128)
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let bytes = descriptors.withUnsafeMutableBytes {
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
        }
        guard bytes > 0 else { return [] }
        var files: [File] = []
        let count = min(Int(bytes) / MemoryLayout<proc_fdinfo>.size, descriptors.count)
        for descriptor in descriptors.prefix(count) where descriptor.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
            var info = vnode_fdinfowithpath()
            let size = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
            let read = withUnsafeMutablePointer(to: &info) {
                proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDVNODEPATHINFO, $0, size)
            }
            guard read == size else { continue }
            let path = withUnsafePointer(to: &info.pvip.vip_path) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            guard !path.isEmpty else { continue }
            let access = info.pfi.fi_openflags & UInt32(O_ACCMODE)
            let writable = access == UInt32(O_WRONLY) || access == UInt32(O_RDWR)
            files.append(File(path: path, writable: writable))
            if files.count >= 64 { break }
        }
        return files
    }
}
