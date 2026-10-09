import Foundation
import SwiftUI

/// Starts the bundled WorkBuddy audit proxy by default and consumes its complete
/// request/response records. It never changes the system proxy or trust store;
/// an already-running WorkBuddy process still needs a controlled restart to use it.
@MainActor
final class WorkBuddyNetworkCapture: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var proxyRunning = false
    @Published private(set) var lastUpdate: Date?
    @Published private(set) var detail = "Starting the WorkBuddy audit proxy"
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var proxy: Process?
    private var offset: UInt64 = 0
    private var acceptedEvents = 0
    private var pollInFlight = false
    private let queue = DispatchQueue(label: "com.agentspec.workbuddy-network", qos: .utility)
    private let database = try? EvidenceDatabase.shared()

    private var captureURL: URL {
        if let path = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_NETWORK_JSONL"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/workbuddy-network.jsonl")
    }

    func start(realtimeOnly: Bool = false) {
        guard timer == nil else { return }
        if realtimeOnly { offset = ((try? FileManager.default.attributesOfItem(atPath: captureURL.path)[.size]) as? NSNumber)?.uint64Value ?? 0 }
        startProxy()
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        if proxy?.isRunning == true { proxy?.terminate() }
        proxy = nil
        proxyRunning = false
    }

    private func startProxy() {
        guard proxy == nil else { return }
        guard let executable = Self.mitmdumpURL(),
              let addon = Bundle.main.url(forResource: "workbuddy_network_capture", withExtension: "py") else {
            detail = "WorkBuddy audit proxy unavailable: mitmdump or bundled addon was not found"
            return
        }
        let process = Process()
        process.executableURL = executable
        process.arguments = Self.proxyArguments(addon: addon)
        var environment = ProcessInfo.processInfo.environment
        environment["AGENTREINS_WORKBUDDY_NETWORK_JSONL"] = captureURL.path
        environment["AGENTREINS_CAPTURE_PARENT_PID"] = String(ProcessInfo.processInfo.processIdentifier)
        process.environment = environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] process in
            DispatchQueue.main.async {
                guard let self, self.proxy === process else { return }
                self.proxyRunning = false
                self.detail = "WorkBuddy audit proxy stopped with exit code \(process.terminationStatus)"
            }
        }
        do {
            try process.run()
            proxy = process
            proxyRunning = true
            detail = "Audit proxy ready on 127.0.0.1:\(Self.proxyPort); waiting for WorkBuddy traffic"
        } catch {
            detail = "WorkBuddy audit proxy failed to start: \(error.localizedDescription)"
        }
    }

    nonisolated static let proxyPort = 18_891

    nonisolated static func proxyArguments(addon: URL) -> [String] {
        ["--listen-host", "127.0.0.1", "--listen-port", String(proxyPort),
         "--set", "connection_strategy=lazy", "--scripts", addon.path]
    }

    nonisolated static func mitmdumpURL(fileManager: FileManager = .default) -> URL? {
        ["/opt/homebrew/bin/mitmdump", "/usr/local/bin/mitmdump", "/usr/bin/mitmdump"]
            .first(where: { fileManager.isExecutableFile(atPath: $0) })
            .map(URL.init(fileURLWithPath:))
    }

    private func poll() {
        guard !pollInFlight else { return }
        pollInFlight = true
        let url = captureURL
        let previous = offset
        let database = database
        queue.async { [weak self] in
            let result = Self.read(url: url, offset: previous)
            do {
                guard let database else { throw CocoaError(.fileWriteUnknown) }
                // Network events still need native session attribution on the main actor.
                // The offset is runtime-only and restarts at zero, so persisted raw data
                // remains replayable without preempting the corrected event identities.
                try database.appendRaw(result.raw.map { [$0] } ?? [])
            } catch {
                DispatchQueue.main.async { self?.pollInFlight = false }
                return // Do not advance the read offset before durable evidence.
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.pollInFlight = false
                let isFresh = self.lastUpdate.map { Date().timeIntervalSince($0) < 120 } ?? false
                self.connected = self.proxyRunning && isFresh
                if result.malformed > 0 {
                    self.detail = "WorkBuddy HTTPS collector found \(result.malformed) malformed records"
                } else if self.connected {
                    self.detail = "WorkBuddy HTTPS records received; completeness is verified per request"
                } else if self.proxyRunning {
                    self.detail = "Audit proxy is running on 18891; WorkBuddy must be launched with this proxy to capture HTTPS bodies"
                }
                self.offset = result.nextOffset
                if !result.events.isEmpty {
                    self.lastUpdate = result.events.map(\.ts).max()
                    self.onEvents?(result.events)
                }
                self.acceptedEvents += result.events.count
                self.database?.enqueueHealth(CollectorHealthRecord(
                    source: "workbuddy-network-body",
                    state: !self.proxyRunning ? .failed : result.malformed > 0 || !self.connected ? .degraded : .healthy,
                    lastSuccess: self.connected ? Date() : nil, lagSeconds: nil,
                    accepted: self.acceptedEvents, malformed: result.malformed, dropped: 0,
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
        // Do not load an entire historic capture file on startup. Allow a large
        // single record, but keep replay and memory bounded.
        var payload = (try? handle.read(upToCount: 8 * 1024 * 1024)) ?? Data()
        while !payload.isEmpty, !payload.contains(0x0A), payload.count < 64 * 1024 * 1024,
              start + UInt64(payload.count) < size {
            guard let more = try? handle.read(upToCount: 8 * 1024 * 1024), !more.isEmpty else { break }
            payload.append(more)
        }
        guard !payload.isEmpty else { return ([], size, 0, true, nil) }
        let safeData: Data
        let nextOffset: UInt64
        if payload.last == 0x0A {
            safeData = payload
            nextOffset = start + UInt64(payload.count)
        } else if let newline = payload.lastIndex(of: 0x0A) {
            safeData = Data(payload.prefix(through: newline))
            nextOffset = start + UInt64(newline + 1)
        } else {
            return ([], start, payload.count >= 64 * 1024 * 1024 ? 1 : 0, true, nil)
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
