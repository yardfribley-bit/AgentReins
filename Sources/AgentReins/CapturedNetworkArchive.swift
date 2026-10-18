import Foundation

/// AgentReins's own capture files. The 32 MB checkpoint restores the live task
/// working set; it is not this archive, and the network page does not use it.
enum CapturedNetworkArchive {
    static func commandRecords(
        liveRoot: URL = URL(fileURLWithPath: "/private/tmp/agentreins-transport-audit"),
        archiveRoot: URL = defaultArchiveRoot
    ) -> [[String: Any]] {
        let live = NativeTransportAudit.records(root: liveRoot)
        copyCommands(live, from: liveRoot, to: archiveRoot)
        return merged(live + NativeTransportAudit.records(root: archiveRoot))
    }

    /// Reads the capture file AgentReins already wrote, including lines from
    /// before this process started. The raw file stays on disk; only a bounded
    /// tail is decoded for the page.
    static func httpsRecords(
        jsonl: URL = defaultHTTPSLog,
        maximumTailBytes: Int = 64 * 1024 * 1024,
        limit: Int = 40
    ) -> [[String: Any]] {
        guard maximumTailBytes > 0, limit > 0,
              let handle = try? FileHandle(forReadingFrom: jsonl) else { return [] }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start: UInt64 = size > UInt64(maximumTailBytes) ? size - UInt64(maximumTailBytes) : 0
        try? handle.seek(toOffset: start)
        guard let data = try? handle.readToEnd(), !data.isEmpty else { return [] }
        let body: Data
        if start == 0 { body = data }
        else if let newline = data.firstIndex(of: 0x0A) { body = Data(data[data.index(after: newline)...]) }
        else { return [] }
        let decoder = WorkBuddyNetworkEvidence.captureDecoder()
        var flows: [String: [GuardEvent]] = [:]
        var order: [String] = []
        for line in body.split(separator: 0x0A).reversed() {
            guard let record = try? decoder.decode(WorkBuddyNetworkCaptureRecord.self, from: Data(line)),
                  WorkBuddyNetworkCapture.retainsLiveBody(record) else { continue }
            let events = WorkBuddyNetworkEvidence.project(record)
            guard let flow = events.first?.traceId, !flow.isEmpty else { continue }
            if flows[flow] == nil {
                guard order.count < limit else { continue }
                order.append(flow)
            }
            flows[flow, default: []].append(contentsOf: events)
        }
        return order.flatMap { flows[$0, default: []].compactMap(pageRecord) }
    }

    private static var defaultArchiveRoot: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/captures/commands")
    }
    private static var defaultHTTPSLog: URL {
        if let path = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_NETWORK_JSONL"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/workbuddy-network.jsonl")
    }

    private static func copyCommands(_ records: [[String: Any]], from liveRoot: URL, to archiveRoot: URL) {
        let live = liveRoot.resolvingSymlinksInPath().path + "/"
        try? FileManager.default.createDirectory(at: archiveRoot, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for record in records {
            guard let runID = record["runID"] as? String, !runID.isEmpty, !runID.contains("/") else { continue }
            let source = liveRoot.appendingPathComponent(runID).appendingPathComponent("transport.json")
            guard source.resolvingSymlinksInPath().path.hasPrefix(live) else { continue }
            let destination = archiveRoot.appendingPathComponent(runID).appendingPathComponent("transport.json")
            guard !FileManager.default.fileExists(atPath: destination.path) else { continue }
            try? FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? FileManager.default.copyItem(at: source, to: destination)
        }
    }

    private static func merged(_ records: [[String: Any]]) -> [[String: Any]] {
        var byID: [String: [String: Any]] = [:]
        for record in records {
            guard let runID = record["runID"] as? String else { continue }
            byID[runID] = record
        }
        return byID.values.sorted { ($0["startedAt"] as? String ?? "") > ($1["startedAt"] as? String ?? "") }.prefix(50).map { $0 }
    }

    private static func pageRecord(_ event: GuardEvent) -> [String: Any]? {
        guard let preview = RealtimeNetworkBodyPreview(event: event) else { return nil }
        var body: [String: Any] = [
            "flow": preview.flow,
            "requestTruncated": preview.requestTruncated,
            "responseTruncated": preview.responseTruncated,
            "responseRepresentation": preview.responseRepresentation
        ]
        if let request = preview.request { body["request"] = request }
        if let response = preview.response { body["response"] = response }
        if let bytes = preview.requestBytes { body["requestBytes"] = bytes }
        if let bytes = preview.responseBytes { body["responseBytes"] = bytes }
        if let complete = preview.requestComplete { body["requestComplete"] = complete }
        if let complete = preview.responseComplete { body["responseComplete"] = complete }
        if let status = preview.responseStatus { body["responseStatus"] = status }
        if let instructions = preview.toolInstructions { body["toolInstructions"] = instructions }
        if let reasoning = preview.reasoning { body["reasoning"] = reasoning }
        var row: [String: Any] = [
            "id": event.id.uuidString,
            "agent": "WorkBuddy",
            "source": event.source ?? "agentsight:workbuddy-network-body",
            "kind": event.kind,
            "op": event.op,
            "timestamp": iso8601.string(from: event.ts),
            "session": event.sessionId ?? "",
            "turn": event.turnId ?? "",
            "details": event.command ?? "",
            "networkBody": body
        ]
        if let call = event.toolCallId, !call.isEmpty { row["call"] = call }
        if let resource = RealtimeDetailProjector.resource(event: event, input: event.command, output: event.modelResponse, kind: "network") {
            var detail: [String: Any] = [:]
            if let domain = resource.domain { detail["domain"] = domain }
            if let url = resource.url { detail["url"] = url }
            if let method = resource.method { detail["method"] = method }
            if let ip = resource.remoteIP { detail["remoteIP"] = ip }
            if let port = resource.remotePort { detail["remotePort"] = port }
            if let evidence = resource.evidenceType { detail["evidenceType"] = evidence }
            row["resource"] = detail
        }
        return row
    }

    private static let iso8601: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
