import Foundation

/// One MCP session. Stdio has a single session; HTTP has one per `Mcp-Session-Id`.
/// The actor name lives here so concurrent HTTP clients cannot overwrite each other.
final class MCPSession {
    let id: String
    var actorName: String
    var protocolVersion: String
    let transport: String

    init(id: String, transport: String) {
        self.id = id
        self.actorName = "unknown-client"
        self.protocolVersion = "2024-11-05"
        self.transport = transport
    }

    /// Audit actor. HTTP appends the kernel pid and executable basename; the whole string is capped at 200 characters.
    /// Schema of the audit line is unchanged (the actor field is still one string).
    func auditActor(peer: PeerIdentity?) -> String {
        guard transport == "http" else { return actorName }
        let pid = peer.map { String($0.pid) } ?? "?"
        let exe = peer?.exeBase ?? "unknown"
        let full = "\(actorName) via http pid=\(pid) exe=\(exe)"
        if full.count <= 200 { return full }
        return String(full.prefix(200))
    }
}

/// JSON-RPC dispatch shared by stdio and loopback HTTP. Tools, redaction and audit are not duplicated.
enum MCPDispatcher {
    static let serverName = "agentreins-supervisor"
    static let serverVersion = "0.2.0-swift"
    static let fallbackProtocol = "2024-11-05"
    static let supportedProtocols: Set<String> = ["2025-06-18", "2025-03-26", "2024-11-05"]

    static let tools: [[String: Any]] = [
        ["name": "list_agents", "description": "List observed agents. Read-only.",
         "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false]],
        ["name": "list_alerts", "description": "List risk alerts. Read-only.",
         "inputSchema": ["type": "object", "properties": [
            "agent": ["type": "string"], "since": ["type": "string"], "rule": ["type": "string"]
         ], "additionalProperties": false]],
        ["name": "get_execution", "description": "Get one execution; secrets redacted.",
         "inputSchema": ["type": "object", "properties": ["execution_id": ["type": "string"]],
                         "required": ["execution_id"], "additionalProperties": false]],
        ["name": "list_network", "description": "Outbound network: transport-audit commands plus per-process sampled TCP/UDP sockets (proxied or not). Read-only, redacted.",
         "inputSchema": ["type": "object", "properties": [
            "agent": ["type": "string"], "since": ["type": "string"]
         ], "additionalProperties": false]],
        ["name": "get_coverage", "description": "Rule coverage and integrity.",
         "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false]],
        ["name": "list_mcp_audit", "description": "HMAC-chained MCP read audit.",
         "inputSchema": ["type": "object", "properties": ["limit": ["type": "integer"]],
                         "additionalProperties": false]],
    ]

    /// Returns a JSON-RPC response object, or nil when `message` is a notification (no `id`).
    static func handle(_ msg: [String: Any], session: MCPSession, auditActor: String) -> [String: Any]? {
        let method = msg["method"] as? String
        let hasId = msg.keys.contains("id")
        let id = msg["id"]
        let params = msg["params"] as? [String: Any] ?? [:]

        if method == "initialize" {
            if let info = params["clientInfo"] as? [String: Any] {
                let name = (info["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let version = (info["version"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if !name.isEmpty {
                    session.actorName = version.isEmpty ? name : "\(name)/\(version)"
                }
            }
            let requested = params["protocolVersion"] as? String
            let negotiated: String
            if let requested {
                if !supportedProtocols.contains(requested) {
                    guard hasId else { return nil }
                    return rpcError(id ?? NSNull(), -32602, "unsupported protocol version: \(requested)")
                }
                negotiated = requested
            } else {
                negotiated = fallbackProtocol
            }
            session.protocolVersion = negotiated
            guard hasId else { return nil }
            return [
                "jsonrpc": "2.0",
                "id": id ?? NSNull(),
                "result": [
                    "protocolVersion": negotiated,
                    "capabilities": ["tools": ["listChanged": false]],
                    "serverInfo": ["name": serverName, "version": serverVersion],
                    "instructions": "Read-only AgentReins supervisor MCP (Swift, no system node/python).",
                ] as [String: Any],
            ]
        }

        if method == "notifications/initialized" || method == "initialized" || method?.hasPrefix("notifications/") == true {
            return nil
        }
        guard hasId else { return nil }

        if method == "ping" {
            return ["jsonrpc": "2.0", "id": id ?? NSNull(), "result": [:] as [String: Any]]
        }
        if method == "tools/list" {
            return ["jsonrpc": "2.0", "id": id ?? NSNull(), "result": ["tools": tools]]
        }
        if method == "tools/call" {
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            do {
                let result = try callTool(name, args, actor: auditActor)
                return [
                    "jsonrpc": "2.0", "id": id ?? NSNull(),
                    "result": [
                        "content": [["type": "text", "text": JSON.pretty(result)]],
                        "structuredContent": result,
                        "isError": false,
                    ] as [String: Any],
                ]
            } catch {
                return [
                    "jsonrpc": "2.0", "id": id ?? NSNull(),
                    "result": [
                        "content": [["type": "text", "text": "error: \(error.localizedDescription)"]],
                        "isError": true,
                    ] as [String: Any],
                ]
            }
        }
        return rpcError(id ?? NSNull(), -32601, "method not found: \(method ?? "")")
    }

    static func rpcError(_ id: Any?, _ code: Int, _ message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]]
    }

    static func callTool(_ name: String, _ args: [String: Any], actor: String) throws -> [String: Any] {
        let banned = ["write", "delete", "update", "set_", "save", "dismiss", "accept", "whitelist", "mute"]
        let lower = name.lowercased()
        if banned.contains(where: { lower.contains($0) }) {
            throw NSError(domain: "AgentReinsMCP", code: 1, userInfo: [NSLocalizedDescriptionKey: "write tools are not available"])
        }
        let allowed = Set(["list_agents", "list_alerts", "get_execution", "list_network", "get_coverage", "list_mcp_audit"])
        guard allowed.contains(name) else {
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: "unknown tool: \(name)"])
        }
        let integrity = Ctx.integrity()
        Ctx.appendAudit(integrity, actor: actor, tool: name, arguments: args)
        let records = Transport.load()
        switch name {
        case "list_agents":
            return Agents.list(records)
        case "list_alerts":
            return Alerts.list(records, agent: args["agent"] as? String, rule: args["rule"] as? String,
                               since: args["since"] as? String)
        case "get_execution":
            guard let eid = args["execution_id"] as? String else {
                throw NSError(domain: "AgentReinsMCP", code: 3, userInfo: [NSLocalizedDescriptionKey: "execution_id required"])
            }
            return Execution.get(eid, records)
        case "list_network":
            return NetworkTool.list(records, agent: args["agent"] as? String, since: args["since"] as? String, integrity: integrity)
        case "get_coverage":
            return Coverage.get(integrity)
        case "list_mcp_audit":
            let limit = (args["limit"] as? Int) ?? (args["limit"] as? NSNumber)?.intValue ?? 30
            return ["entries": Ctx.recent(integrity, limit: limit), "validation": integrity.validate(), "confidence": "Observed"]
        default:
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: name])
        }
    }
}
