import Foundation

private final class AuditNoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // Evidence and enrollment credentials never follow redirects.
    }
}

private struct AuditHTTPFailure: LocalizedError {
    let status: Int
    let retryAfter: TimeInterval?
    var errorDescription: String? { "审计服务返回 HTTP \(status)" }
}

/// Main actor only schedules work. Queue IO, encoding and network live on the worker.
@MainActor
final class AuditUploadClient {
    struct Configuration: Codable, Sendable {
        let endpoint: URL
        let deviceID: String
        let token: String
        let enabledAt: Date
        let uploadEnabled: Bool
    }
    private let database: EvidenceDatabase
    private let worker: AuditUploadWorker
    private let enabledAt: Date
    private var timer: Timer?
    private var busy = false
    init?(database: EvidenceDatabase) {
        let directory = EventStore.defaultURL().deletingLastPathComponent().appendingPathComponent("CloudAudit", isDirectory: true)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: directory.appendingPathComponent("device.json")),
              let config = try? decoder.decode(Configuration.self, from: data), config.uploadEnabled,
              config.endpoint.scheme == "https", !config.token.isEmpty else { return nil }
        self.database = database
        enabledAt = config.enabledAt
        worker = AuditUploadWorker(config: config, directory: directory)
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.tick() }
        }
    }
    private func tick() async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        let database = self.database
        do {
            let claimed = try await Task.detached(priority: .background) {
                try database.claimAuditUploadJob()
            }.value
            guard let job = claimed else { return }
            let snapshot = job.snapshot
            guard AuditUploadScope(enabledAt: enabledAt).permits(
                taskStartedAt: snapshot.task.startedAt,
                observedUserRequest: !snapshot.conversation.userInputs.isEmpty),
                snapshot.sourceEvents.contains(where: { $0.kind == "model" && $0.op == "prompt" }) else {
                try await Task.detached(priority: .background) {
                    try database.completeAuditUploadJob(job, receiptID: "scope-skipped")
                }.value
                return
            }
            do {
                let receipt = try await worker.upload(snapshot, generation: Int(job.revision))
                try await Task.detached(priority: .background) {
                    try database.completeAuditUploadJob(job, receiptID: receipt)
                }.value
            } catch {
                try await Task.detached(priority: .background) {
                    try database.retryAuditUploadJob(job, message: error.localizedDescription,
                        retryAfter: (error as? AuditHTTPFailure)?.retryAfter)
                }.value
            }
        } catch {
            // The next timer tick retries durable state; no in-memory work is lost.
        }
    }
}

actor AuditUploadWorker {
    struct QoSPolicy: Sendable {
        /// Conservative default for an endpoint agent. Collection and local
        /// persistence must remain responsive even on a constrained uplink.
        let bytesPerSecond: Double = 1_048_576
        let maximumConnections = 1
    }
    struct Pending: Codable {
        let sessionID: String
        let turnID: String
        var generation: Int
        var notBefore: Date
        var retries: Int
        var followups: Int
        var prepared: AuditBlockProtocol.Prepared?
        var probeOffset: Int?
        var missing: [String]?
        var rejected: String?
        var key: String { "\(sessionID)\u{0}\(turnID)" }
    }
    struct State: Codable {
        var sequence = 0
        var pending: [String: Pending] = [:]
        var lastReceiptID: String?
        var lastReceivedAt: String?
        var lastError: String?
        var uploadedTasks = 0
    }
    private let config: AuditUploadClient.Configuration
    private let directory: URL
    private let session: URLSession
    private let qos = QoSPolicy()
    private var nextUploadSlot = Date.distantPast
    private var state = State()
    private var loaded = false
    private let encoder: JSONEncoder
    init(config: AuditUploadClient.Configuration, directory: URL, session: URLSession? = nil) {
        self.config = config; self.directory = directory
        let settings = URLSessionConfiguration.ephemeral
        settings.timeoutIntervalForRequest = 30; settings.timeoutIntervalForResource = 60
        settings.httpMaximumConnectionsPerHost = qos.maximumConnections
        settings.networkServiceType = .background
        settings.waitsForConnectivity = true
        self.session = session ?? URLSession(configuration: settings, delegate: AuditNoRedirect(), delegateQueue: nil)
        encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
    }
    private var blocks: URL { directory.appendingPathComponent("blocks", isDirectory: true) }
    private func load() throws {
        guard !loaded else { return }
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let current = directory.appendingPathComponent("queue-v2.json")
        let legacy = directory.appendingPathComponent("queue.json")
        if FileManager.default.fileExists(atPath: current.path) {
            state = try decoder.decode(State.self, from: Data(contentsOf: current))
        } else {
            if FileManager.default.fileExists(atPath: legacy.path) {
                state = try decoder.decode(State.self, from: Data(contentsOf: legacy))
            }
            let inflight = directory.appendingPathComponent("inflight.json")
            if FileManager.default.fileExists(atPath: inflight.path) {
                let packet = try JSONSerialization.jsonObject(with: Data(contentsOf: inflight)) as? [String: Any]
                guard let packet, let snapshot = packet["snapshot"] as? [String: Any],
                      let task = snapshot["task"] as? [String: Any], let s = task["sessionID"] as? String,
                      let t = task["turnID"] as? String else { throw CocoaError(.fileReadCorruptFile) }
                let key = "\(s)\u{0}\(t)"
                state.sequence = max(state.sequence, packet["sequence"] as? Int ?? 0)
                if state.pending[key] == nil {
                    state.pending[key] = Pending(sessionID: s, turnID: t, generation: packet["generation"] as? Int ?? 1,
                        notBefore: Date(), retries: 0, followups: 0)
                }
            }
            try persist()
        }
        loaded = true
    }
    private func persist() throws {
        let url = directory.appendingPathComponent("queue-v2.json")
        try encoder.encode(state).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    func observe(_ items: [TaskLiveProgress]) {
        do {
            try load()
            for item in items where AuditUploadScope(enabledAt: config.enabledAt).permits(taskStartedAt: item.startedAt, observedUserRequest: !item.modelRequests.isEmpty) {
                let key = "\(item.sessionID)\u{0}\(item.turnID)"
                if var old = state.pending[key] {
                    old.generation += 1; old.followups = 0; state.pending[key] = old
                } else {
                    state.pending[key] = Pending(sessionID: item.sessionID, turnID: item.turnID, generation: 1,
                        notBefore: Date().addingTimeInterval(3), retries: 0, followups: 0)
                }
            }
            try persist()
        } catch { state.lastError = "审计队列持久化失败：\(error.localizedDescription)" }
    }
    func next() -> Pending? {
        do {
            try load()
            return state.pending.values.filter { $0.rejected == nil && $0.notBefore <= Date() }.min { $0.notBefore < $1.notBefore }
        } catch { state.lastError = "审计队列读取失败：\(error.localizedDescription)"; return nil }
    }
    func prepare(_ job: Pending, snapshot: AgentTaskSnapshot) {
        do {
            guard AuditUploadScope(enabledAt: config.enabledAt).permits(taskStartedAt: snapshot.task.startedAt,
                observedUserRequest: !snapshot.conversation.userInputs.isEmpty),
                snapshot.sourceEvents.contains(where: { $0.kind == "model" && $0.op == "prompt" }) else {
                fail(job.key, message: "等待新任务请求证据，未上传历史数据"); return
            }
            state.sequence += 1; try persist()
            let prepared = try AuditBlockProtocol.prepare(snapshot, directory: blocks, sequence: state.sequence, generation: job.generation)
            guard var current = state.pending[job.key] else { return }
            current.prepared = prepared; current.probeOffset = 0; current.missing = []
            state.pending[job.key] = current; try persist()
        } catch { fail(job.key, message: "任务分块失败：\(error.localizedDescription)") }
    }
    private func request(_ fields: [String: Any]) async throws -> [String: Any] {
        var packet = fields; packet["protocol"] = 2; packet["deviceID"] = config.deviceID
        var request = URLRequest(url: config.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization")
        request.setValue(config.deviceID, forHTTPHeaderField: "X-AgentReins-Device")
        let data = try JSONSerialization.data(withJSONObject: packet)
        let (body, response) = try await session.upload(for: request, from: data)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let http = response as? HTTPURLResponse
            let delay = http?.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init)
            throw AuditHTTPFailure(status: http?.statusCode ?? 0, retryAfter: delay)
        }
        guard let result = try JSONSerialization.jsonObject(with: body) as? [String: Any] else { throw CocoaError(.fileReadCorruptFile) }
        return result
    }

    private func pace(payloadBytes: Int) async throws {
        let now = Date()
        if nextUploadSlot > now {
            try await Task.sleep(for: .seconds(nextUploadSlot.timeIntervalSince(now)))
        }
        let base = max(Date(), nextUploadSlot)
        nextUploadSlot = base.addingTimeInterval(Double(payloadBytes) / qos.bytesPerSecond)
    }

    /// Upload one durable outbox revision. SQLite owns scheduling/retry state;
    /// this actor only implements the content-addressed wire protocol.
    func upload(_ snapshot: AgentTaskSnapshot, generation: Int) async throws -> String {
        try load()
        // The task revision is the wire sequence. Retries after an unknown
        // network result must reuse it so the server returns the same receipt
        // instead of storing a second logical revision.
        let stableSequence = max(1, generation)
        let prepared = try AuditBlockProtocol.prepare(snapshot, directory: blocks,
                                                       sequence: stableSequence,
                                                       generation: generation)
        for offset in stride(from: 0, to: prepared.hashes.count, by: 512) {
            let hashes = Array(prepared.hashes[offset..<min(offset + 512, prepared.hashes.count)])
            let probe = try await request(["op": "probe", "hashes": hashes])
            guard let missing = probe["missing"] as? [String],
                  Set(missing).isSubset(of: Set(hashes)),
                  probe["serverStatus"] as? String == "accepting" else { throw CocoaError(.fileReadCorruptFile) }
            for digest in missing {
                let data = try Data(contentsOf: blocks.appendingPathComponent(digest))
                guard AuditBlockProtocol.hash(data) == digest else { throw CocoaError(.fileReadCorruptFile) }
                try await pace(payloadBytes: data.count)
                let ack = try await request(["op": "block", "hash": digest,
                                             "data": data.base64EncodedString()])
                guard ack["stored"] as? String == digest,
                      ack["serverStatus"] as? String == "block_persisted" else { throw CocoaError(.fileReadCorruptFile) }
            }
        }
        let identity = try JSONSerialization.jsonObject(with: encoder.encode(prepared.identity))
        let ack = try await request(["op": "commit", "root": prepared.root,
                                     "sequence": prepared.sequence, "identity": identity])
        guard ack["persisted"] as? Bool == true,
              ack["serverStatus"] as? String == "committed",
              let receipt = ack["receiptID"] as? String,
              ack["sequence"] as? Int == prepared.sequence else { throw CocoaError(.fileReadCorruptFile) }
        state.lastReceiptID = receipt
        state.lastReceivedAt = ack["receivedAt"] as? String
        state.lastError = nil
        state.uploadedTasks += 1
        try persist()
        return receipt
    }
    func sendSlice(_ key: String) async {
        guard let prepared = state.pending[key]?.prepared, state.pending[key]?.rejected == nil else { return }
        do {
            // Bounded work per task: a failing/large task cannot monopolize the queue.
            for _ in 0..<8 {
                guard let before = state.pending[key] else { return }
                if let digest = before.missing?.first {
                    let data = try Data(contentsOf: blocks.appendingPathComponent(digest))
                    guard AuditBlockProtocol.hash(data) == digest else { throw CocoaError(.fileReadCorruptFile) }
                    let ack = try await request(["op": "block", "hash": digest, "data": data.base64EncodedString()])
                    guard ack["stored"] as? String == digest else { throw CocoaError(.fileReadCorruptFile) }
                    state.pending[key]?.missing?.removeFirst()
                } else if (before.probeOffset ?? 0) < prepared.hashes.count {
                    let offset = before.probeOffset ?? 0, end = min(offset + 512, prepared.hashes.count)
                    let hashes = Array(prepared.hashes[offset..<end])
                    let ack = try await request(["op": "probe", "hashes": hashes])
                    guard let missing = ack["missing"] as? [String], Set(missing).isSubset(of: Set(hashes)) else { throw CocoaError(.fileReadCorruptFile) }
                    state.pending[key]?.probeOffset = end; state.pending[key]?.missing = missing
                } else {
                    let identity = try JSONSerialization.jsonObject(with: encoder.encode(prepared.identity))
                    let ack = try await request(["op": "commit", "root": prepared.root, "sequence": prepared.sequence, "identity": identity])
                    guard ack["persisted"] as? Bool == true, let receipt = ack["receiptID"] as? String,
                          ack["sequence"] as? Int == prepared.sequence else { throw CocoaError(.fileReadCorruptFile) }
                    state.lastReceiptID = receipt; state.lastReceivedAt = ack["receivedAt"] as? String
                    state.lastError = nil; state.uploadedTasks += 1
                    if var current = state.pending[key] {
                        current.prepared = nil; current.missing = nil; current.probeOffset = nil; current.retries = 0
                        if current.generation == prepared.generation { current.followups += 1 }
                        current.notBefore = Date().addingTimeInterval(current.generation == prepared.generation ? 30 : 3)
                        state.pending[key] = current.followups > 2 ? nil : current
                    }
                    try persist(); return
                }
                state.pending[key]?.notBefore = Date().addingTimeInterval(1)
                try persist()
            }
        } catch {
            let http = error as? AuditHTTPFailure
            if let status = http?.status, [400, 413, 422].contains(status) {
                state.pending[key]?.rejected = "服务端拒绝 HTTP \(status)，保留待处理证据"
            }
            if http?.status == 409 {
                state.pending[key]?.probeOffset = 0; state.pending[key]?.missing = []
            }
            fail(key, message: "分块上传失败：\(error.localizedDescription)")
        }
    }
    func fail(_ key: String, message: String) {
        if var current = state.pending[key] {
            current.retries += 1
            current.notBefore = Date().addingTimeInterval(min(300, pow(2, Double(min(8, current.retries))) * 5))
            state.pending[key] = current
        }
        state.lastError = message
        do { try persist() } catch { state.lastError = "审计队列无法持久化：\(error.localizedDescription)" }
    }
}
