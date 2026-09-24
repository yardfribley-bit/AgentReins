import Foundation

/// Explicit per-device enrollment, durable queue, one upload at a time.
/// No history scan. Tests/custom EventStores never instantiate this client.
@MainActor
final class AuditUploadClient {
    struct Configuration: Codable {
        let endpoint: URL
        let deviceID: String
        let token: String
        let enabledAt: Date
        let uploadEnabled: Bool
    }
    struct Pending: Codable {
        let sessionID: String
        let turnID: String
        var generation: Int
        var notBefore: Date
        var retries: Int
        var followups: Int
    }
    struct State: Codable {
        var sequence = 0
        var pending: [String: Pending] = [:]
        var lastReceiptID: String?
        var lastReceivedAt: String?
        var lastError: String?
        var uploadedTasks = 0
    }
    private let config: Configuration
    private let directory: URL
    private let encoder: JSONEncoder
    private var state: State
    private weak var store: EventStore?
    private var timer: Timer?
    private var busy = false
    private let session: URLSession

    init?(store: EventStore) {
        directory = EventStore.defaultURL().deletingLastPathComponent().appendingPathComponent("CloudAudit", isDirectory: true)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: directory.appendingPathComponent("device.json")),
              let config = try? decoder.decode(Configuration.self, from: data),
              config.uploadEnabled, config.endpoint.scheme == "https", !config.token.isEmpty else { return nil }
        self.config = config
        self.store = store
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        state = (try? Data(contentsOf: directory.appendingPathComponent("queue.json")))
            .flatMap { try? decoder.decode(State.self, from: $0) } ?? State()
        let settings = URLSessionConfiguration.ephemeral
        settings.timeoutIntervalForRequest = 45
        settings.timeoutIntervalForResource = 90
        settings.httpMaximumConnectionsPerHost = 1
        session = URLSession(configuration: settings)
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }

    func observe(_ evidence: [GuardEvent], progress: [String: TaskLiveProgress]) {
        let keys = Set(evidence.compactMap { event -> String? in
            guard let s = event.sessionId, let t = event.turnId else { return nil }
            return "\(s)\u{0}\(t)"
        })
        for key in keys {
            guard let item = progress[key],
                  AuditUploadScope(enabledAt: config.enabledAt).permits(taskStartedAt: item.startedAt, observedUserRequest: !item.modelRequests.isEmpty) else { continue }
            if var old = state.pending[key] {
                old.generation += 1
                old.followups = 0
                state.pending[key] = old
            } else {
                state.pending[key] = Pending(sessionID: item.sessionID, turnID: item.turnID,
                    generation: 1, notBefore: Date().addingTimeInterval(8), retries: 0, followups: 0)
            }
        }
        persist()
    }

    private func persist() {
        do {
            try encoder.encode(state).write(to: directory.appendingPathComponent("queue.json"), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: directory.appendingPathComponent("queue.json").path)
        } catch { state.lastError = "审计上传队列无法持久化：\(error.localizedDescription)" }
    }

    private func tick() {
        guard !busy, let store else { return }
        // A prepared packet survives process termination and is retried verbatim.
        let packetURL = directory.appendingPathComponent("inflight.json")
        if let packet = try? Data(contentsOf: packetURL) {
            busy = true
            send(packet)
            return
        }
        guard let (key, pending) = state.pending.filter({ $0.value.notBefore <= Date() })
            .min(by: { $0.value.notBefore < $1.value.notBefore }) else { return }
        busy = true
        store.loadTask(sessionID: pending.sessionID, turnID: pending.turnID) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure:
                self.fail(key, message: "任务证据尚未可读，稍后重试")
            case .success(let snapshot):
                guard AuditUploadScope(enabledAt: self.config.enabledAt).permits(
                    taskStartedAt: snapshot.task.startedAt, observedUserRequest: !snapshot.conversation.userInputs.isEmpty),
                    snapshot.sourceEvents.contains(where: { $0.kind == "model" && $0.op == "prompt" }) else {
                    self.state.pending.removeValue(forKey: key)
                    self.persist(); self.busy = false; return
                }
                self.state.sequence += 1
                self.persist()
                let sequence = self.state.sequence
                // Encoding large task bodies must not block the main UI.
                Task {
                    let config = self.config
                    let encoded = await Task.detached(priority: .utility) { () -> Data? in
                        let encoder = JSONEncoder()
                        encoder.dateEncodingStrategy = .iso8601
                        encoder.outputFormatting = [.sortedKeys]
                        return try? encoder.encode(Packet(deviceID: config.deviceID, identity: AuditDeviceIdentity.capture(), sequence: sequence,
                            queueKey: key, generation: pending.generation, snapshot: snapshot))
                    }.value
                    guard let encoded, encoded.count <= 64 * 1024 * 1024 else {
                        self.fail(key, message: "任务正文超过单次 64 MiB 限制或编码失败；未截断上传")
                        return
                    }
                    do {
                        try encoded.write(to: packetURL, options: .atomic)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: packetURL.path)
                        self.send(encoded)
                    } catch { self.fail(key, message: "待上传原文无法保存") }
                }
            }
        }
    }

    private struct Packet: Encodable {
        let deviceID: String
        let identity: AuditDeviceIdentity
        let sequence: Int
        let queueKey: String
        let generation: Int
        let snapshot: AgentTaskSnapshot
    }

    private func send(_ data: Data) {
        guard let packet = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let key = packet["queueKey"] as? String, let generation = packet["generation"] as? Int else {
            busy = false; state.lastError = "待上传原文损坏，请检查 inflight.json"; persist(); return
        }
        if let pending = state.pending[key], pending.notBefore > Date() { busy = false; return }
        var request = URLRequest(url: config.endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(config.token)", forHTTPHeaderField: "Authorization")
        request.setValue(config.deviceID, forHTTPHeaderField: "X-AgentReins-Device")
        Task {
            do {
                let (response, metadata) = try await session.upload(for: request, from: data)
                guard (metadata as? HTTPURLResponse)?.statusCode == 200,
                      let receipt = try JSONSerialization.jsonObject(with: response) as? [String: Any],
                      receipt["persisted"] as? Bool == true,
                      let id = receipt["receiptID"] as? String else {
                    self.fail(key, message: "上传未获入库回执，HTTP \((metadata as? HTTPURLResponse)?.statusCode ?? 0)")
                    return
                }
                state.lastReceiptID = id
                state.lastReceivedAt = receipt["receivedAt"] as? String
                state.lastError = nil
                state.uploadedTasks += 1
                if var current = state.pending[key] {
                    if current.generation == generation {
                        // Trace files may arrive after the last transcript event.
                        current.followups += 1
                        if current.followups > 2 { state.pending.removeValue(forKey: key) }
                        else { current.notBefore = Date().addingTimeInterval(30); state.pending[key] = current }
                    } else {
                        current.notBefore = Date().addingTimeInterval(10)
                        current.retries = 0; state.pending[key] = current
                    }
                }
                persist()
                try FileManager.default.removeItem(at: directory.appendingPathComponent("inflight.json"))
                busy = false
            } catch { fail(key, message: "上传网络或回执处理失败：\(error.localizedDescription)") }
        }
    }

    private func fail(_ key: String, message: String) {
        if var pending = state.pending[key] {
            pending.retries += 1
            pending.notBefore = Date().addingTimeInterval(min(300, pow(2, Double(min(8, pending.retries))) * 5))
            state.pending[key] = pending
        }
        state.lastError = message
        persist(); busy = false
    }
}
