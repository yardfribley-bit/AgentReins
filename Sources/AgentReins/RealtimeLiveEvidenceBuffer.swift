import CryptoKit
import Foundation

/// A working set for this live observation only. Cooling a record never removes
/// its identity or body; snapshots own the files until their readers finish.
struct RealtimeLiveEvidenceBuffer {
    final class Directory: @unchecked Sendable {
        let url: URL
        init() { url = FileManager.default.temporaryDirectory.appendingPathComponent("agentreins-live-" + UUID().uuidString) }
        deinit { try? FileManager.default.removeItem(at: url) }
    }
    final class Lease: @unchecked Sendable {
        let url: URL
        let directory: Directory
        init(url: URL, directory: Directory) { self.url = url; self.directory = directory }
        deinit { try? FileManager.default.removeItem(at: url) }
    }
    final class Record: Sendable {
        let id: UUID
        let revision: UUID
        let ts: Date
        let kind: String
        let op: String
        let call: String?
        let hasTaskIdentity: Bool
        let cost: Int
        let fingerprint: Int
        let agent: String?
        let session: String?
        let turn: String?
        let model: String?
        let toolName: String?
        let body: Body
        init(id: UUID, revision: UUID, ts: Date, kind: String, op: String, call: String?, hasTaskIdentity: Bool,
             cost: Int, fingerprint: Int, agent: String?, session: String?, turn: String?, model: String?, toolName: String?, body: Body) {
            self.id = id; self.revision = revision; self.ts = ts; self.kind = kind; self.op = op; self.call = call
            self.hasTaskIdentity = hasTaskIdentity; self.cost = cost; self.fingerprint = fingerprint
            self.agent = agent; self.session = session; self.turn = turn; self.model = model; self.toolName = toolName; self.body = body
        }
        enum Body: Sendable {
            case hot(GuardEvent)
            case cold(Lease, String, Int)
        }
        func read() throws -> GuardEvent {
            switch body {
            case .hot(let event): return event
            case let .cold(lease, hash, size):
                let data = try Data(contentsOf: lease.url)
                guard Self.hash(data) == hash else { throw CocoaError(.fileReadCorruptFile) }
                let decoded = try (data as NSData).decompressed(using: .lzfse) as Data
                guard decoded.count == size else { throw CocoaError(.fileReadCorruptFile) }
                let event = try JSONDecoder().decode(GuardEvent.self, from: decoded)
                guard event.id == id else { throw CocoaError(.fileReadCorruptFile) }
                return event
            }
        }
        private static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
        func cooled(in directory: Directory) throws -> Record {
            guard case .hot(let event) = body else { return self }
            let data = try JSONEncoder().encode(event)
            let compressed = try (data as NSData).compressed(using: .lzfse) as Data
            let manager = FileManager.default
            try manager.createDirectory(at: directory.url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            // Unique immutable revision, so updates cannot change an in-flight snapshot.
            let url = directory.url.appendingPathComponent(revision.uuidString + ".lzfse")
            try compressed.write(to: url, options: [.atomic])
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            return Record(id: id, revision: revision, ts: ts, kind: kind, op: op, call: call, hasTaskIdentity: hasTaskIdentity, cost: cost,
                          fingerprint: fingerprint, agent: agent, session: session, turn: turn, model: model, toolName: toolName,
                          body: .cold(Lease(url: url, directory: directory), Self.hash(compressed), data.count))
        }
    }
    struct Snapshot: Sendable {
        let records: [Record]
        func read() throws -> [GuardEvent] { try records.map { try $0.read() } }
    }
    private var records: [UUID: Record] = [:]
    private var hotRecords: [UUID: Record] = [:]
    private var recentIDs: [UUID] = []
    private var networkIDs: [UUID] = []
    private var exchangeIDs: [UUID] = []
    private var collectedIndexDirty = false
    private let directory = Directory()
    private(set) var hotBytes = 0
    private(set) var hotCount = 0
    var count: Int { records.count }
    private(set) var unattributedCount = 0
    func contains(_ id: UUID) -> Bool { records[id] != nil }
    func hasTaskAssociation(_ id: UUID) -> Bool { records[id]?.session != nil }
    func unchanged(_ event: GuardEvent) -> Bool {
        guard let record = records[event.id], record.fingerprint == event.hashValue else { return false }
        // Hot records can additionally compare exact values without disk I/O.
        if case .hot(let stored) = record.body { return stored == event }
        return true
    }
    func read(_ id: UUID) throws -> GuardEvent? { try records[id]?.read() }
    func snapshot() -> Snapshot { Snapshot(records: Array(records.values)) }
    /// Projection reads bodies. Network capture is a high-volume stream, so the
    /// live projection only rehydrates the bounded network windows plus task events.
    func liveProjectionSnapshot() -> Snapshot {
        let keep = Set(recentIDs + networkIDs + exchangeIDs)
        let networkOps: Set<String> = ["network_prompt", "network_response", "tool_service_request", "tool_service_response", "memory_recall", "memory_recall_response"]
        return Snapshot(records: records.values.filter { record in
            if keep.contains(record.id) { return true }
            if record.kind == "network" || networkOps.contains(record.op) { return false }
            return true
        })
    }
    private func newer(_ lhs: UUID, _ rhs: UUID) -> Bool {
        guard let left = records[lhs], let right = records[rhs] else { return false }
        return left.ts == right.ts ? lhs.uuidString < rhs.uuidString : left.ts > right.ts
    }
    private func recentIncluding(_ id: UUID, in ids: [UUID], limit: Int) -> [UUID] {
        if ids.count == limit, let last = ids.last, !newer(id, last) { return ids }
        return Array((ids + [id]).sorted(by: newer).prefix(limit))
    }
    mutating func latestCollected() -> Snapshot {
        if collectedIndexDirty {
            let ordered = records.keys.sorted(by: newer)
            recentIDs = Array(ordered.prefix(200))
            networkIDs = Array(ordered.filter { records[$0]?.kind == "network" }.prefix(100))
            exchangeIDs = Array(ordered.filter { ["network_prompt", "network_response", "tool_service_request", "tool_service_response"].contains(records[$0]?.op ?? "") }.prefix(50))
            collectedIndexDirty = false
        }
        let ids = Set(recentIDs + networkIDs + exchangeIDs).sorted(by: newer)
        return Snapshot(records: ids.compactMap { records[$0] })
    }
    mutating func insert(_ event: GuardEvent) {
        let isNew = records[event.id] == nil
        if let old = records[event.id], old.ts != event.ts || old.kind != event.kind || old.op != event.op { collectedIndexDirty = true }
        if let old = records[event.id] {
            if case .hot = old.body { hotBytes -= old.cost; hotCount -= 1 }
            if !old.hasTaskIdentity { unattributedCount -= 1 }
        }
        if event.sessionId == nil || event.turnId == nil { unattributedCount += 1 }
        let cost = [event.userIntent, event.modelPrompt, event.modelResponse, event.command, event.beforeContent,
                    event.afterContent, event.fileDiff, event.modelReasoning].compactMap { $0 }.reduce(512) { $0 + $1.utf8.count }
        records[event.id] = Record(id: event.id, revision: UUID(), ts: event.ts, kind: event.kind, op: event.op, call: event.toolCallId, hasTaskIdentity: event.sessionId != nil && event.turnId != nil, cost: cost, fingerprint: event.hashValue, agent: event.agent, session: event.sessionId, turn: event.turnId, model: event.model, toolName: event.toolName, body: .hot(event))
        hotRecords[event.id] = records[event.id]
        if isNew && !collectedIndexDirty {
            recentIDs = recentIncluding(event.id, in: recentIDs, limit: 200)
            if event.kind == "network" { networkIDs = recentIncluding(event.id, in: networkIDs, limit: 100) }
            if ["network_prompt", "network_response", "tool_service_request", "tool_service_response"].contains(event.op) { exchangeIDs = recentIncluding(event.id, in: exchangeIDs, limit: 50) }
        }
        hotBytes += cost; hotCount += 1
    }
    func coolingPlan(byteBudget: Int, countBudget: Int = 6000) -> (records: [Record], directory: Directory) {
        guard hotBytes > byteBudget || hotCount > countBudget else { return ([], directory) }
        var bytes = hotBytes, count = hotCount, selected: [Record] = []
        for record in hotRecords.values.sorted(by: { $0.ts < $1.ts }) {
            guard bytes > byteBudget || count > countBudget else { break }
            selected.append(record); bytes -= record.cost; count -= 1
        }
        return (selected, directory)
    }
    mutating func install(_ cooled: [Record]) {
        for record in cooled {
            guard let current = records[record.id], current.revision == record.revision,
                  case .hot = current.body, case .cold = record.body else { continue }
            records[record.id] = record; hotRecords.removeValue(forKey: record.id)
            hotBytes -= current.cost; hotCount -= 1
        }
    }
}
