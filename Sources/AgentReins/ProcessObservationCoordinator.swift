import Darwin
import Foundation

/// One logical observation arm per PID + birth time. Sampling is shared;
/// attaching an arm never launches a worker process for each target.
struct ProcessObservationSample: Codable, Equatable, Sendable {
    struct OpenFile: Codable, Equatable, Sendable {
        let descriptor: Int32
        let path: String
        let offset: Int64
        let size: Int64
    }
    let identity: String
    let pid: Int32
    let parentPID: Int32
    let executable: String
    let residentBytes: UInt64?
    let virtualBytes: UInt64?
    let cpuTimeNanoseconds: UInt64?
    let threadCount: Int32?
    let openFiles: [OpenFile]
    let resourceStatus: String
    let fileStatus: String
    let unreadableDescriptors: Int
    let truncated: Bool
}

protocol ProcessActivitySampling: Sendable {
    func sample(_ process: ProcessSnapshotRecord) -> ProcessObservationSample?
}

struct LibprocProcessActivitySampler: ProcessActivitySampling {
    func sample(_ process: ProcessSnapshotRecord) -> ProcessObservationSample? {
        guard let pid = Int32(process.pid), let birth = process.birthIdentity else { return nil }
        // Validate before and after reading: do not attach a reused PID to an old arm.
        guard Self.birthIdentity(pid) == birth else { return nil }
        var task = proc_taskinfo()
        let taskSize = MemoryLayout<proc_taskinfo>.size
        let taskRead = withUnsafeMutablePointer(to: &task) {
            proc_pidinfo(pid, PROC_PIDTASKINFO, 0, $0, Int32(taskSize))
        }
        let requiredBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        var files: [ProcessObservationSample.OpenFile] = []
        var unreadable = 0
        var truncated = false
        var fileStatus = "unavailable"
        if requiredBytes >= 0 {
            let requested = Int(requiredBytes) / MemoryLayout<proc_fdinfo>.size + 16
            let capacity = min(max(requested, 16), 4096)
            truncated = requested > capacity
            var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
            let bytes = descriptors.withUnsafeMutableBytes {
                proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
            }
            if bytes > 0 {
                fileStatus = "sampled_open_descriptors"
                let vnodeFDs = descriptors.prefix(Int(bytes) / MemoryLayout<proc_fdinfo>.size)
                    .filter { $0.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) }
                truncated = truncated || vnodeFDs.count > 256
                for descriptor in vnodeFDs.prefix(256) {
                    var info = vnode_fdinfowithpath()
                    let size = MemoryLayout<vnode_fdinfowithpath>.size
                    let read = withUnsafeMutablePointer(to: &info) {
                        proc_pidfdinfo(pid, descriptor.proc_fd, PROC_PIDFDVNODEPATHINFO, $0, Int32(size))
                    }
                    guard read == size else { unreadable += 1; continue }
                    let path = withUnsafePointer(to: &info.pvip.vip_path) {
                        $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) }
                    }
                    guard !path.isEmpty else { continue }
                    files.append(.init(descriptor: descriptor.proc_fd, path: path,
                        offset: info.pfi.fi_offset, size: info.pvip.vip_vi.vi_stat.vst_size))
                }
            } else if bytes == 0 { fileStatus = "empty_or_unavailable" }
        }
        guard Self.birthIdentity(pid) == birth else { return nil }
        let available = taskRead == taskSize
        return ProcessObservationSample(identity: "\(pid):\(birth)", pid: pid,
            parentPID: Int32(process.ppid) ?? 0, executable: process.executablePath ?? process.command,
            residentBytes: available ? task.pti_resident_size : nil,
            virtualBytes: available ? task.pti_virtual_size : nil,
            cpuTimeNanoseconds: available ? task.pti_total_user + task.pti_total_system : nil,
            threadCount: available ? task.pti_threadnum : nil,
            openFiles: files.sorted { $0.descriptor < $1.descriptor },
            resourceStatus: available ? "sampled" : "unavailable",
            fileStatus: fileStatus, unreadableDescriptors: unreadable, truncated: truncated)
    }

    static func birthIdentity(_ pid: Int32) -> UInt64? {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let read = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, Int32(size))
        }
        guard read == size else { return nil }
        return UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
    }
}

final class ProcessObservationCoordinator: @unchecked Sendable {
    private struct Arm {
        var process: ProcessSnapshotRecord
        var lastSample: ProcessObservationSample?
        var lastPublished: Date
    }
    private var arms: [String: Arm] = [:]
    private var ipcSockets: [String: [String]] = [:]
    private var sockets: [String: [String]] = [:]
    private var communicationSignatures: [String: Set<String>] = [:]
    private let hookArtifacts = WorkBuddyHookArtifactReader()
    private let sampler: any ProcessActivitySampling
    private let lock = NSLock()

    init(sampler: any ProcessActivitySampling = LibprocProcessActivitySampler()) { self.sampler = sampler }

    func collect(processes: [ProcessSnapshotRecord], now: Date = Date(), includeSamples: Bool = true, trigger: String? = nil) -> [GuardEvent] {
        lock.lock()
        defer { lock.unlock() }
        let live = Set(processes.map(Self.identity))
        var events: [GuardEvent] = []
        for key in Array(arms.keys) where !includeSamples && !live.contains(key) {
            if let arm = arms.removeValue(forKey: key) {
                sockets.removeValue(forKey: key)
                ipcSockets.removeValue(forKey: key)
                events.append(event(arm.process, operation: "process_watch_detached", now: now, sample: arm.lastSample))
                events += hookArtifacts.events(for: arm.process, now: now)
            }
        }
        for process in processes {
            let key = Self.identity(process)
            // Slow resource samples must never resurrect an arm removed by a newer lifecycle snapshot.
            if includeSamples && arms[key] == nil { continue }
            let isNew = arms[key] == nil
            var arm = arms[key] ?? Arm(process: process, lastSample: nil, lastPublished: .distantPast)
            if isNew { events.append(event(process, operation: "process_watch_attached", now: now, sample: nil)) }
            if arm.process.ppid != process.ppid || arm.process.executablePath != process.executablePath {
                events.append(event(process, operation: "process_identity_changed", now: now, sample: nil))
            }
            arm.process = process
            // Capture the first file/resource sample immediately on discovery.
            // Existing arms keep the slower cadence; no whole-tree resampling here.
            if !includeSamples && !isNew { arms[key] = arm; continue }
            if let sample = sampler.sample(process) {
                let previous = arm.lastSample
                let fileChanged = previous?.openFiles != sample.openFiles
                let memoryChanged = distance(previous?.residentBytes, sample.residentBytes) >= 4 * 1024 * 1024
                let cpuChanged = distance(previous?.cpuTimeNanoseconds, sample.cpuTimeNanoseconds) >= 100_000_000
                let coverageChanged = previous?.resourceStatus != sample.resourceStatus || previous?.fileStatus != sample.fileStatus || previous?.unreadableDescriptors != sample.unreadableDescriptors || previous?.truncated != sample.truncated
                if trigger != nil || isNew || fileChanged || memoryChanged || cpuChanged || coverageChanged  {
                    events.append(event(process, operation: "process_observation", now: now, sample: sample, trigger: trigger))
                    arm.lastSample = sample
                    arm.lastPublished = now
                }
            } else if trigger != nil || isNew || arm.lastPublished == .distantPast {
                events.append(event(process, operation: "process_observation_unavailable", now: now, sample: nil, trigger: trigger))
                arm.lastPublished = now
            }
            arms[key] = arm
        }
        return events
    }

    func reset() { lock.lock(); arms.removeAll(); sockets.removeAll(); ipcSockets.removeAll(); communicationSignatures.removeAll(); lock.unlock() }

    func observeSockets(processes: [ProcessSnapshotRecord], connections: [NetworkConnectionRecord], now: Date = Date(), trigger: String? = nil) -> [GuardEvent] {
        lock.lock()
        defer { lock.unlock() }
        var events: [GuardEvent] = []
        for process in processes {
            let key = Self.identity(process)
            guard arms[key] != nil else { continue }
            let owned = connections.filter { $0.pid == process.pid }
            let signatures = owned.map { "\($0.localAddress)->\($0.remoteHost):\($0.remotePort):\($0.state ?? "unknown")" }.sorted()
            guard trigger != nil || sockets[key] != signatures else { continue }
            let payload: [String: Any] = ["processIdentity": key, "state": "sampled_sockets", "trigger": trigger ?? "periodic",
                "absenceMeaning": "not_visible_in_sample; not proof of close",
                "connections": owned.map { ["local": $0.localAddress, "remoteHost": $0.remoteHost, "remotePort": $0.remotePort, "state": $0.state ?? "unknown", "isListener": $0.isListener] as [String: Any] }]
            let encoded = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) }
            events.append(GuardEvent(kind: "activity", ruleId: "process_observation", path: "-",
                command: nil, agent: process.agent, op: "process_socket_observation", severity: "info",
                ts: now, action: "observed", afterContent: encoded, source: "process-observation-lsof",
                attributionConfidence: .unknown, attributionMethod: "sampled socket owner; task unassigned",
                processId: Int32(process.pid), parentProcessId: Int32(process.ppid)))
            sockets[key] = signatures
        }
        events += communicationEvents(ProcessCommunicationEvidence.tcp(processes: processes.filter { arms[Self.identity($0)] != nil }, connections: connections), transport: "tcp", now: now, trigger: trigger)
        return events
    }

    func observeIPC(processes: [ProcessSnapshotRecord], records: [UnixSocketRecord], now: Date = Date(), trigger: String? = nil) -> [GuardEvent] {
        lock.lock()
        defer { lock.unlock() }
        var events: [GuardEvent] = []
        for process in processes {
            let key = Self.identity(process)
            guard arms[key] != nil else { continue }
            let owned = records.filter { $0.pid == process.pid }
            let signatures = owned.map { "\($0.descriptor):\($0.endpoint):\($0.processIdentity ?? "unknown"):\($0.socketHandle ?? 0):\($0.peerSocketHandle ?? 0)" }.sorted()
            guard trigger != nil || ipcSockets[key] != signatures else { continue }
            let payload: [String: Any] = ["processIdentity": key, "state": "sampled_unix_sockets", "trigger": trigger ?? "periodic",
                "coverage": "socket metadata and reciprocal peer ownership when available; IPC payload not collected",
                "truncated": owned.count > 256,
                "endpoints": owned.prefix(256).map { row -> [String: Any] in
                    var item: [String: Any] = ["descriptor": row.descriptor, "endpoint": row.endpoint]
                    if let identity = row.processIdentity { item["processIdentity"] = identity }
                    if let handle = row.socketHandle { item["socketHandle"] = String(handle, radix: 16) }
                    if let peer = row.peerSocketHandle { item["peerSocketHandle"] = String(peer, radix: 16) }
                    return item
                }]
            let json = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) }
            events.append(GuardEvent(kind: "activity", ruleId: "process_observation", path: "-",
                command: nil, agent: process.agent, op: "process_ipc_observation", severity: "info",
                ts: now, action: "observed", afterContent: json, source: "process-observation-lsof-unix",
                attributionConfidence: .unknown, attributionMethod: "Unix socket owner; task unassigned",
                processId: Int32(process.pid), parentProcessId: Int32(process.ppid)))
            ipcSockets[key] = signatures
        }
        events += communicationEvents(ProcessCommunicationEvidence.unix(processes: processes.filter { arms[Self.identity($0)] != nil }, records: records), transport: "unix", now: now, trigger: trigger)
        return events
    }

    private func communicationEvents(_ relations: [ProcessCommunicationRelation], transport: String, now: Date, trigger: String?) -> [GuardEvent] {
        let current = Set(relations.map(\.identity))
        let previous = communicationSignatures[transport] ?? []
        communicationSignatures[transport] = current
        return relations.filter { trigger != nil || !previous.contains($0.identity) }.map { relation in
            var payload: [String: Any] = ["schemaVersion": 1, "relation": "process_communication", "status": "observed",
                "firstProcessIdentity": relation.firstIdentity, "secondProcessIdentity": relation.secondIdentity,
                "transport": transport, "endpoints": relation.endpoints, "basis": relation.basis,
                "direction": "undetermined", "limitation": "connection metadata only; caller, payload and task not established; absence in later samples does not prove closure"]
            if let trigger { payload["trigger"] = trigger }
            let json = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])).flatMap { String(data: $0, encoding: .utf8) }
            let firstAgent = arms[relation.firstIdentity]?.process.agent
            let secondAgent = arms[relation.secondIdentity]?.process.agent
            let agent = firstAgent == secondAgent ? firstAgent : nil
            return GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil, agent: agent,
                op: "process_communication_observation", severity: "info", ts: now, action: "observed", afterContent: json,
                source: "process-communication-\(transport)", attributionConfidence: .confirmed,
                attributionMethod: "reciprocal socket ownership; task unassigned")
        }
    }

    static func identity(_ process: ProcessSnapshotRecord) -> String {
        "\(process.pid):\(process.birthIdentity.map(String.init) ?? "unknown")"
    }

    private func distance(_ a: UInt64?, _ b: UInt64?) -> UInt64 {
        guard let a, let b else { return 0 }
        return a > b ? a - b : b - a
    }

    private func event(_ process: ProcessSnapshotRecord, operation: String, now: Date,
                       sample: ProcessObservationSample?, trigger: String? = nil) -> GuardEvent {
        var data: [String: Any] = ["schemaVersion": 1, "processIdentity": Self.identity(process),
            "executable": process.executablePath ?? "", "command": process.command,
            "coverage": ["lifecycle": "sampled", "resources": "sampled_or_unavailable",
                "files": "open_descriptors_only", "network": "separate_socket_sampler",
                "memoryContent": "not_collected", "modelStream": "not_attached"]]
        if let trigger { data["trigger"] = trigger; data["timing"] = "sampled on receipt; not guaranteed before tool execution" }
        if let sample, let encoded = try? JSONEncoder().encode(sample),
           let object = try? JSONSerialization.jsonObject(with: encoded) { data["sample"] = object }
        let json = (try? JSONSerialization.data(withJSONObject: data, options: [.sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) }
        return GuardEvent(kind: "activity", ruleId: "process_observation", path: "-",
            command: nil, agent: process.agent, op: operation, severity: "info", ts: now,
            action: "observed", afterContent: json, source: "process-observation-libproc",
            attributionConfidence: .unknown, attributionMethod: "PID + birth identity; task unassigned",
            processId: Int32(process.pid), parentProcessId: Int32(process.ppid))
    }
}
