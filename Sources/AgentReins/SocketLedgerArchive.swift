import Foundation

/// Read-only bridge from tools/socket-sampler's ledger to the 外网访问 page.
/// The sampler owns collection; this only decodes a bounded, metadata-only
/// subset (no payloads, no process arguments).
enum SocketLedgerArchive {
    static let fields = ["id", "agent", "pid", "ppid", "processName", "protocol", "localAddress",
        "remoteAddress", "remotePort", "state", "firstSeen", "lastSeen", "sampleCount", "scope",
        "viaProxy", "transportPeer", "realDestination", "destinationSource", "destinationEvidence",
        "destinationBasis", "forwardConfirmed", "evidence"]

    static var defaultURL: URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_SOCKET_LEDGER"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentGuard/socket-ledger.json")
    }

    static func pagePayload(url: URL = defaultURL, limit: Int = 300) -> [String: Any] {
        guard let data = try? Data(contentsOf: url),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return ["connections": [[String: Any]](), "coverage": ["state": "not_running"]]
        }
        var rows: [[String: Any]] = []
        for case let row as [String: Any] in (root["connections"] as? [Any] ?? []) {
            var out: [String: Any] = [:]
            for key in fields {
                if let value = row[key], !(value is NSNull) { out[key] = value }
            }
            rows.append(out)
        }
        rows.sort { (($0["lastSeen"] as? String) ?? "") > (($1["lastSeen"] as? String) ?? "") }
        var coverage = root["coverage"] as? [String: Any] ?? [:]
        let samples = root["samples"] as? [String: Any] ?? [:]
        coverage["state"] = "sampling"
        coverage["lastSampleAt"] = samples["lastAt"] ?? ""
        coverage["samples"] = samples["count"] ?? 0
        return ["connections": Array(rows.prefix(limit)), "coverage": coverage]
    }
}
