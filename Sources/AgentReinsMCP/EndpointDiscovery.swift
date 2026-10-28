import AgentReinsCore
import Darwin
import Foundation

/// Publishes the loopback MCP URL for other agents on this Mac.
/// Default path: ~/Library/Application Support/AgentGuard/mcp-endpoint.json (0600).
/// `AGENTREINS_MCP_ENDPOINT_FILE` overrides the path for tests so a live file is left alone.
enum EndpointDiscovery {
    static let defaultPort = 18977

    static var fileURL: URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_MCP_ENDPOINT_FILE"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return Paths.support.appendingPathComponent("mcp-endpoint.json")
    }

    static func write(state: String, port: Int, auth: String, detail: String? = nil) {
        let url = fileURL
        let parent = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                  attributes: [.posixPermissions: 0o700])
        var obj: [String: Any] = [
            "url": "http://127.0.0.1:\(port)/mcp",
            "port": port,
            "pid": Int(ProcessInfo.processInfo.processIdentifier),
            "version": MCPDispatcher.serverVersion,
            "state": state,
            "startedAt": Clock.iso(Date()),
            "auth": auth,
        ]
        if let detail, !detail.isEmpty {
            obj["detail"] = String(detail.prefix(2000))
        }
        let text = JSON.pretty(obj) + "\n"
        try? text.write(to: url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Removes the file only when it names this process, so a failing second instance
    /// cannot delete a healthy server's record and a crash leaves the last state in place.
    static func removeIfOwned() {
        guard let obj = JSON.objectAt(fileURL),
              intValue(obj["pid"]) == Int(ProcessInfo.processInfo.processIdentifier) else { return }
        try? FileManager.default.removeItem(at: fileURL)
    }

    /// Status for `get_coverage`. Missing file is `not_published`, not an error.
    static func snapshot() -> [String: Any] {
        guard var obj = JSON.objectAt(fileURL) else {
            return [
                "url": "http://127.0.0.1:\(defaultPort)/mcp",
                "port": defaultPort,
                "state": "not_published",
                "auth": "none",
                "processAlive": false,
            ]
        }
        if let pid = intValue(obj["pid"]) {
            obj["processAlive"] = PeerIdentity.processAlive(Int32(pid))
        } else {
            obj["processAlive"] = false
        }
        return obj
    }
}
