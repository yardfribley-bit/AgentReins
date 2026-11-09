import AgentReinsCore
import CryptoKit
import Darwin
import Foundation

/// Samples open vnodes on Cursor, Claude, Codex, and WorkBuddy process trees.
/// Does not read rules.json. Does not block or restore. Credential reads are
/// recorded in any directory. Writes are recorded when they are outside the
/// process working directory (or under /tmp when the working directory is unknown).
final class AgentTreeFileObserver {
    var onEvents: (([GuardEvent]) -> Void)?
    private let queue = DispatchQueue(label: "com.agentreins.file-layer", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var accessWatch: CredentialPathWatch?
    private var seen: [Int32: Set<String>] = [:]
    private var confirmedPaths = Set<String>()
    private var cursor = 0
    private var watchList: [String] = []
    private var accessStamps: [String: FileLayerCapture.AccessStamp] = [:]
    private var watchTick = 0
    private var sampleChanged = true
    private var cachedRows: [ProcessTable.Row] = []
    private var cachedRowsAt = Date.distantPast
    private var commandCache: [Int32: (at: Date, line: String)] = [:]
    private let lock = NSLock()

    func start() {
        lock.lock()
        if timer != nil { lock.unlock(); return }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 0.4, repeating: 0.4)
        source.setEventHandler { [weak self] in self?.sample() }
        source.resume()
        timer = source
        let watch = CredentialPathWatch(queue: queue)
        watch.onAccess = { [weak self] path in self?.noteAccess(path) }
        accessWatch = watch
        lock.unlock()
    }

    func stop() {
        lock.lock()
        timer?.cancel()
        timer = nil
        accessWatch?.stop()
        accessWatch = nil
        lock.unlock()
    }

    private func sample() {
        if !RuntimeBudget.shared.allowMainLoop(lane: "file-layer", base: 0.4, previousChanged: sampleChanged) {
            return
        }
        watchTick += 1
        let throttled = RuntimeBudget.shared.isThrottled
        let tableInterval = throttled ? 8.0 : (sampleChanged ? 1.2 : 3.0)
        if cachedRows.isEmpty || Date().timeIntervalSince(cachedRowsAt) >= tableInterval {
            cachedRows = ProcessTable.snapshot()
            cachedRowsAt = Date()
            MainProcessMeter.noteProcessTableScan()
        }
        let rows = cachedRows
        let owner = ownership(rows)
        let mine = rows.filter { owner[$0.pid] != nil && !rowIsSelf($0.path) }
        if watchList.isEmpty || watchTick == 1 || watchTick % 2 == 0 {
            watchList = watchPaths(agentRows: mine)
            accessWatch?.replace(paths: watchList)
            accessStamps = accessStamps.filter { watchList.contains($0.key) }
        }
        pollAccessTimes(paths: watchList)
        let slice = sampleSlice(mine)
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
                confirmedPaths.insert(hit.path)
                events.append(Self.event(hit: hit, agent: agent, pid: row.pid, ppid: row.ppid, grade: "confirmed", source: "libproc-vnode"))
            }
            seen[row.pid] = known
        }
        sampleChanged = !events.isEmpty
        guard !events.isEmpty else { return }
        let deliver = onEvents
        DispatchQueue.main.async { deliver?(events) }
    }

    /// Unseen processes are sampled first. A python that is still alive on this
    /// tick can be confirmed. One that has already exited is not in `mine`.
    private func sampleSlice(_ mine: [ProcessTable.Row]) -> [ProcessTable.Row] {
        if mine.count <= 48 { return mine }
        let unseen = mine.filter { seen[$0.pid] == nil }
        let rest = mine.filter { seen[$0.pid] != nil }
        let room = max(0, 48 - unseen.count)
        var picked: [ProcessTable.Row] = []
        if !rest.isEmpty && room > 0 {
            let start = cursor % rest.count
            picked = (0..<room).map { rest[(start + $0) % rest.count] }
            cursor = (start + room) % rest.count
        }
        return Array((unseen + picked).prefix(48))
    }

    /// Stat poll of the registered set. kqueue can miss a NOTE_ATTRIB; the stamp
    /// still moves when the kernel updates atime. No atime move means no event.
    private func pollAccessTimes(paths: [String]) {
        for path in paths {
            guard let current = Self.stamp(path) else { continue }
            let previous = accessStamps[path]
            accessStamps[path] = current
            guard let previous, FileLayerCapture.isAccessRead(previous: previous, current: current) else { continue }
            noteAccess(path, source: "credential-stat")
        }
    }

    private static func stamp(_ path: String) -> FileLayerCapture.AccessStamp? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        let access = TimeInterval(info.st_atimespec.tv_sec) + TimeInterval(info.st_atimespec.tv_nsec) / 1_000_000_000
        let modified = TimeInterval(info.st_mtimespec.tv_sec) + TimeInterval(info.st_mtimespec.tv_nsec) / 1_000_000_000
        return FileLayerCapture.AccessStamp(access: access, modified: modified)
    }

    /// `codebuddy` launched as a node script does not show up in `proc_pidpath`.
    /// Read argv for that process and its shell/python children, then let the
    /// parent chain carry the owner down to `python3`.
    private func ownership(_ rows: [ProcessTable.Row]) -> [Int32: String] {
        FileLayerCapture.agentTree(
            pids: rows.map(\.pid),
            parents: Dictionary(rows.map { ($0.pid, $0.ppid) }, uniquingKeysWith: { _, new in new }),
            paths: Dictionary(rows.map { ($0.pid, $0.path) }, uniquingKeysWith: { _, new in new }),
            commands: commandLines(rows))
    }

    private func commandLines(_ rows: [ProcessTable.Row]) -> [Int32: String] {
        let byPid = Dictionary(rows.map { ($0.pid, $0) }, uniquingKeysWith: { _, new in new })
        var commands: [Int32: String] = [:]
        for row in rows where !row.comm.isEmpty {
            commands[row.pid] = row.comm
        }
        var interesting: [Int32] = []
        let ranked = rows.filter { FileLayerCapture.shouldReadCommand(path: $0.path) }.sorted { lhs, rhs in
            let leftPython = FileLayerCapture.isPython(lhs.path)
            let rightPython = FileLayerCapture.isPython(rhs.path)
            if leftPython != rightPython { return leftPython && !rightPython }
            return lhs.pid > rhs.pid
        }
        var queued = Set<Int32>()
        for row in ranked {
            if interesting.count >= 12 { break }
            var pid = row.pid
            var hops = 0
            while pid > 1 && hops < 6 && interesting.count < 12 {
                if queued.insert(pid).inserted { interesting.append(pid) }
                guard let parent = byPid[pid] else { break }
                if FileLayerCapture.agentOwner(path: parent.path) != nil { break }
                pid = parent.pid
                hops += 1
            }
        }
        let now = Date()
        commandCache = commandCache.filter { now.timeIntervalSince($0.value.at) < 2 }
        for pid in interesting {
            if let cached = commandCache[pid] {
                commands[pid] = cached.line
                continue
            }
            let line = ProcessTable.commandLine(pid)
            guard !line.isEmpty else { continue }
            commandCache[pid] = (now, line)
            commands[pid] = line
        }
        return commands
    }

    private func rowIsSelf(_ path: String) -> Bool {
        let base = (path as NSString).lastPathComponent
        return base == "AgentReins" || base == "AgentReinsMCP"
    }

    /// kqueue saw the access time move. If a tracked agent still holds the
    /// descriptor, the read is confirmed. If the descriptor already closed, the
    /// same event is only possible (sampled).
    private func noteAccess(_ path: String, source: String = "credential-kqueue") {
        let rows = ProcessTable.snapshot()
        let owner = ownership(rows)
        let mine = rows.filter { owner[$0.pid] != nil && !rowIsSelf($0.path) }
        var holder: ProcessTable.Row?
        var holderAgent: String?
        for row in mine {
            let opens = LibprocOpenFiles.sample(pid: row.pid)
            if opens.contains(where: { Self.samePath($0.path, path) }) {
                holder = row
                holderAgent = owner[row.pid]
                break
            }
        }
        let grade = FileLayerCapture.readGrade(descriptorStillOpen: holder != nil)
        if grade == "possible", confirmedPaths.contains(path) { return }
        if grade == "confirmed" { confirmedPaths.insert(path) }
        let agents = Set(mine.compactMap { owner[$0.pid] })
        let agent = holderAgent ?? (agents.count == 1 ? agents.first : nil)
        let hit = FileLayerCapture.Hit(path: path, op: "read", credential: true)
        let event = Self.event(
            hit: hit, agent: agent, pid: holder?.pid ?? 0, ppid: holder?.ppid ?? 0,
            grade: grade, source: source)
        let deliver = onEvents
        DispatchQueue.main.async { deliver?([event]) }
    }

    private func watchPaths(agentRows: [ProcessTable.Row]) -> [String] {
        var names: [String: [String]] = [:]
        let home = NSHomeDirectory()
        let root = (home as NSString).expandingTildeInPath
        var workspaces: [String] = []
        var dirs = [
            (root as NSString).appendingPathComponent(".ssh"),
            (root as NSString).appendingPathComponent(".aws"),
            (root as NSString).appendingPathComponent(".config/gcloud"),
            (root as NSString).appendingPathComponent("Library/Keychains"),
            "/tmp", "/private/tmp",
        ]
        for row in agentRows {
            let cwd = ProcessTable.workingDirectory(row.pid)
            if cwd.hasPrefix("/") { workspaces.append(cwd); dirs.append(cwd) }
        }
        for dir in dirs {
            let key = (dir as NSString).standardizingPath
            names[key] = Self.oneLevelNames(dir)
        }
        var nested = 0
        let nestedRoots = (["/tmp", "/private/tmp"] + workspaces).map { ($0 as NSString).standardizingPath }
        for dir in nestedRoots where nested < 64 {
            for name in names[dir] ?? [] {
                if nested >= 64 { break }
                let base = (name as NSString).lastPathComponent
                guard base != ".", base != "..", !base.isEmpty else { continue }
                let child = (dir as NSString).appendingPathComponent(base)
                let url = URL(fileURLWithPath: child)
                let values = try? url.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
                if values?.isSymbolicLink == true { continue }
                guard values?.isDirectory == true else { continue }
                names[(child as NSString).standardizingPath] = Self.oneLevelNames(child)
                nested += 1
            }
        }
        return FileLayerCapture.watchFiles(home: home, workspaces: workspaces, directoryNames: names)
    }

    private static func oneLevelNames(_ dir: String) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
        return Array(names.prefix(2000))
    }

    private static func samePath(_ lhs: String, _ rhs: String) -> Bool {
        (lhs as NSString).standardizingPath == (rhs as NSString).standardizingPath
    }

    private static func event(hit: FileLayerCapture.Hit, agent: String?, pid: Int32, ppid: Int32, grade: String, source: String) -> GuardEvent {
        let stamp = Int(Date().timeIntervalSince1970 / 3600)
        let id = stableUUID("\(agent ?? "unknown")|\(pid)|\(hit.op)|\(hit.path)|\(grade)|\(stamp)")
        let method = grade == "confirmed"
            ? "confirmed. " + FileLayerCapture.limits
            : "possible (sampled). " + FileLayerCapture.limits
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let observedAt = formatter.string(from: Date())
        if hit.credential && hit.op == "read" {
            CredentialObservationLog.append(
                CredentialObservationLog.Row(
                    path: hit.path, grade: grade, agent: agent ?? "", at: observedAt,
                    source: source, blocked: false),
                to: CredentialObservationLog.defaultURL())
        }
        if hit.op == "modify" {
            FileObservationLog.append(
                FileObservationLog.Row(path: hit.path, at: observedAt, agent: agent ?? "", op: "modify"),
                to: FileObservationLog.defaultURL())
        }
        return GuardEvent(
            id: id, kind: "file", ruleId: hit.credential ? "credential_observe" : "agent_tree_write",
            path: hit.path, command: nil, agent: agent, op: hit.op,
            severity: hit.credential ? "high" : "info", ts: Date(), action: grade,
            source: source,
            attributionConfidence: grade == "confirmed" ? .confirmed : (agent == nil ? .unknown : .inferred),
            attributionMethod: method,
            processId: pid == 0 ? nil : pid, parentProcessId: ppid == 0 ? nil : ppid)
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
