import Foundation
import SwiftUI

/// Consumes complete WorkBuddy HTTPS request/response records produced by the
/// local audit proxy. The proxy is opt-in; this collector never changes the
/// system proxy or trust store.
@MainActor
final class WorkBuddyNetworkCapture: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var detail = "Waiting for the opt-in WorkBuddy audit proxy"
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var offset: UInt64 = 0
    private let queue = DispatchQueue(label: "com.agentspec.workbuddy-network", qos: .utility)
    private let database = try? EvidenceDatabase()

    private var captureURL: URL {
        if let path = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_NETWORK_JSONL"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/workbuddy-network.jsonl")
    }

    func start() {
        guard timer == nil else { return }
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func poll() {
        let url = captureURL
        let previous = offset
        let database = database
        queue.async { [weak self] in
            let result = Self.read(url: url, offset: previous)
            if let raw = result.raw { try? database?.appendRaw([raw]) }
            DispatchQueue.main.async {
                guard let self else { return }
                self.connected = result.fileExists
                self.detail = result.fileExists
                    ? (result.malformed == 0 ? "Complete WorkBuddy HTTPS body collector connected"
                                             : "WorkBuddy HTTPS collector found \(result.malformed) malformed records")
                    : "Waiting for the opt-in WorkBuddy audit proxy"
                self.offset = result.nextOffset
                if !result.events.isEmpty {
                    self.lastUpdate = Date()
                    self.onEvents?(result.events)
                }
                try? self.database?.updateHealth(CollectorHealthRecord(
                    source: "workbuddy-network-body",
                    state: !result.fileExists ? .failed : result.malformed > 0 ? .degraded : .healthy,
                    lastSuccess: result.fileExists ? Date() : nil, lagSeconds: nil,
                    accepted: result.events.count, malformed: result.malformed, dropped: 0,
                    detail: self.detail))
            }
        }
    }

    nonisolated static func read(url: URL, offset: UInt64)
        -> (events: [GuardEvent], nextOffset: UInt64, malformed: Int,
            fileExists: Bool, raw: RawEvidenceRecord?) {
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return ([], offset, 0, false, nil)
        }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? offset
        let start = min(offset, size)
        try? handle.seek(toOffset: start)
        let payload = handle.readDataToEndOfFile()
        guard !payload.isEmpty else { return ([], size, 0, true, nil) }
        let safeData: Data
        let nextOffset: UInt64
        if payload.last == 0x0A {
            safeData = payload
            nextOffset = size
        } else if let newline = payload.lastIndex(of: 0x0A) {
            safeData = Data(payload.prefix(through: newline))
            nextOffset = start + UInt64(newline + 1)
        } else {
            return ([], start, 0, true, nil)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var events: [GuardEvent] = [], malformed = 0
        for line in safeData.split(separator: 0x0A) {
            guard let record = try? decoder.decode(WorkBuddyNetworkCaptureRecord.self, from: Data(line)) else {
                malformed += 1
                continue
            }
            let projected = WorkBuddyNetworkEvidence.project(record)
            if projected.isEmpty { malformed += 1 } else { events += projected }
        }
        let raw = RawEvidenceRecord(source: "workbuddy-network-body", stream: url.path,
            offsetStart: Int64(start), offsetEnd: Int64(nextOffset), fingerprint: nil,
            observedAt: Date(), payload: safeData)
        return (events, nextOffset, malformed, true, raw)
    }
}
