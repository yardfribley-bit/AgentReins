import AgentReinsCore
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

    static let pageProperties: [String: Any] = [
        "limit": ["type": "integer", "minimum": 1, "maximum": ListPage.maxLimit] as [String: Any],
        "offset": ["type": "integer", "minimum": 0] as [String: Any],
        "cursor": ["type": "string"],
        "since": ["type": "string"],
        "until": ["type": "string"],
    ]

    static func schemaProps(_ extra: [String: Any] = [:]) -> [String: Any] {
        var props = pageProperties
        for (key, value) in extra { props[key] = value }
        return props
    }

    static let tools: [[String: Any]] = [
        ["name": "list_agents", "description": "List observed agents. Read-only. sessions and executionIds are capped; sessionCount and executionCount are the full totals.",
         "inputSchema": ["type": "object", "properties": schemaProps(), "additionalProperties": false]],
        ["name": "list_alerts", "description": "List risk alerts. Read-only.",
         "inputSchema": ["type": "object", "properties": schemaProps([
            "agent": ["type": "string"] as [String: Any],
            "rule": ["type": "string"] as [String: Any],
         ]), "additionalProperties": false]],
        ["name": "get_execution", "description": "Get one execution; secrets redacted.",
         "inputSchema": ["type": "object", "properties": ["execution_id": ["type": "string"]],
                         "required": ["execution_id"], "additionalProperties": false]],
        ["name": "list_network", "description": "Outbound network: transport-audit commands plus per-process sampled TCP/UDP sockets (proxied or not). Read-only, redacted.",
         "inputSchema": ["type": "object", "properties": schemaProps([
            "agent": ["type": "string"] as [String: Any],
         ]), "additionalProperties": false]],
        ["name": "get_coverage", "description": "Rule coverage and integrity.",
         "inputSchema": ["type": "object", "properties": [:], "additionalProperties": false]],
        ["name": "list_mcp_audit", "description": "HMAC-chained MCP read audit.",
         "inputSchema": ["type": "object", "properties": schemaProps(), "additionalProperties": false]],
    ]

    /// Returns a JSON-RPC response object, or nil when `message` is a notification (no `id`).
    /// `auditSync` is true for stdio (the next line may read the log). HTTP queues the write.
    static func handle(_ msg: [String: Any], session: MCPSession, auditActor: String,
                       auditSync: Bool = true, isCancelled: @escaping () -> Bool = { false }) -> [String: Any]? {
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
                let result = try callTool(name, args, actor: auditActor, auditSync: auditSync, isCancelled: isCancelled)
                if isCancelled() { return nil }
                return [
                    "jsonrpc": "2.0", "id": id ?? NSNull(),
                    "result": [
                        "content": [["type": "text", "text": JSON.pretty(result)]],
                        "structuredContent": result,
                        "isError": false,
                    ] as [String: Any],
                ]
            } catch {
                let message = error.localizedDescription
                return [
                    "jsonrpc": "2.0", "id": id ?? NSNull(),
                    "result": [
                        "content": [["type": "text", "text": "error: \(message)"]],
                        "structuredContent": ["error": message],
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

    static func callTool(_ name: String, _ args: [String: Any], actor: String, auditSync: Bool = true,
                         isCancelled: @escaping () -> Bool = { false }) throws -> [String: Any] {
        let banned = ["write", "delete", "update", "set_", "save", "dismiss", "accept", "whitelist", "mute"]
        let lower = name.lowercased()
        if banned.contains(where: { lower.contains($0) }) {
            throw NSError(domain: "AgentReinsMCP", code: 1, userInfo: [NSLocalizedDescriptionKey: "write tools are not available"])
        }
        let allowed = Set(["list_agents", "list_alerts", "get_execution", "list_network", "get_coverage", "list_mcp_audit"])
        guard allowed.contains(name) else {
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: "unknown tool: \(name)"])
        }
        applyToolDelay(isCancelled)
        if isCancelled() {
            throw NSError(domain: "AgentReinsMCP", code: 5, userInfo: [NSLocalizedDescriptionKey: "request cancelled"])
        }
        let integrity = Ctx.integrity()
        // 0.25s is enough for a healthy helper that was started at process launch, and short enough
        // that a Keychain prompt hang (15s) is reported as pending instead of blocking the read.
        let keyState = KeychainWarmup.shared.resolve(grace: 0.25)
        Ctx.appendAudit(actor: actor, tool: name, arguments: args, sync: auditSync && keyState != "pending")
        // A pending Keychain must not sit inside flush (the helper wait is up to 20s) and then
        // blow the 25s HTTP timeout. The page is the log as it already is.
        if name == "list_mcp_audit" && keyState != "pending" { Ctx.flushAudit() }
        let loaded = Transport.loadReporting()
        let records = loaded.records
        let page: (offset: Int, limit: Int?)
        if name.hasPrefix("list_") {
            page = try ListPage.parse(args: args, defaultLimit: name == "list_mcp_audit" ? 30 : nil)
        } else {
            page = (offset: 0, limit: nil)
        }
        switch name {
        case "list_agents":
            return stamp(Agents.list(records, since: str(args["since"]), until: str(args["until"]),
                                     limit: page.limit, offset: page.offset, transportTruncated: loaded.truncated), keyState)
        case "list_alerts":
            var result = Alerts.list(records, agent: str(args["agent"]), rule: str(args["rule"]),
                                     since: str(args["since"]), until: str(args["until"]),
                                     limit: page.limit, offset: page.offset)
            result["transportTruncated"] = loaded.truncated
            return result
        case "get_execution":
            guard let eid = str(args["execution_id"]) else {
                throw NSError(domain: "AgentReinsMCP", code: 3, userInfo: [NSLocalizedDescriptionKey: "execution_id required"])
            }
            return Execution.get(eid, records, transportTruncated: loaded.truncated)
        case "list_network":
            return NetworkTool.list(records, agent: str(args["agent"]), since: str(args["since"]), until: str(args["until"]),
                                    integrity: integrity, limit: page.limit, offset: page.offset,
                                    transportTruncated: loaded.truncated)
        case "get_coverage":
            if keyState == "pending" {
                return Coverage.get(integrity, validation: Coverage.pendingIntegrity())
            }
            return Coverage.get(integrity, validation: Ctx.cachedValidation(integrity))
        case "list_mcp_audit":
            let limit = page.limit ?? 30
            let paged = AuditPage.page(log: Paths.auditLog, seal: Paths.auditSeal,
                                       offset: page.offset, limit: limit,
                                       since: str(args["since"]), until: str(args["until"]))
            let validation: [String: Any] = keyState == "pending"
                ? Coverage.pendingIntegrity()
                : Ctx.cachedValidation(integrity)
            return stamp([
                "entries": paged.items,
                "validation": validation,
                "confidence": "Observed",
                "total": paged.total, "offset": page.offset, "limit": limit,
                "truncated": paged.truncated, "nextCursor": paged.nextCursor,
            ], keyState)
        default:
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: name])
        }
    }

    static func stamp(_ result: [String: Any], _ keyState: String) -> [String: Any] {
        var copy = result
        copy["keychainStatus"] = KeychainWarmup.reportedStatus(keyState)
        return copy
    }

    /// Test hook: `AGENTREINS_MCP_TOOL_DELAY_MS` sleeps in short slices so a timeout or a disconnect can stop it.
    /// Unset in production. Not a client-config switch.
    static func applyToolDelay(_ isCancelled: () -> Bool) {
        let ms = intValue(ProcessInfo.processInfo.environment["AGENTREINS_MCP_TOOL_DELAY_MS"]) ?? 0
        guard ms > 0 else { return }
        var left = ms
        while left > 0 {
            if isCancelled() { return }
            let slice = min(20, left)
            Thread.sleep(forTimeInterval: Double(slice) / 1000)
            left -= slice
        }
    }

    /// Newest `limit` audit rows, still oldest-first inside the page. Reads the tail of the jsonl,
    /// not the whole file. `total` prefers the seal count when the tail is only the recent end.
    static func pageRecent(_ items: [[String: Any]], offset: Int, limit: Int) -> ListPage.Window {
        let total = items.count
        let end = max(0, total - offset)
        let start = max(0, end - limit)
        let page = Array(items[start..<end])
        let truncated = start > 0
        return ListPage.Window(items: page, total: total, offset: offset, limit: limit,
                              truncated: truncated,
                              nextCursor: truncated ? ListPage.encodeCursor(offset + limit) : NSNull())
    }
}

/// Recent MCP audit rows from the tail of mcp-supervisor-audit.jsonl. A warm call with an unchanged
/// file does not touch the disk. Growth reads only the new bytes, capped so a 100MB log cannot
/// be pulled into one tools/call.
enum AuditPage {
    struct Result {
        var items: [[String: Any]]
        var total: Int
        var truncated: Bool
        var nextCursor: Any
    }

    private static let lock = NSLock()
    private static var sig: String?
    private static var entries: [[String: Any]] = []
    private static var parsedPath = ""
    private static var parsedSize: Int64 = 0
    private static let tailCap: Int64 = 2 * 1024 * 1024

    static func page(log: URL, seal: URL, offset: Int, limit: Int, since: String?, until: String?) -> Result {
        let loaded = load(log, need: offset + limit + 8, since: since)
        let sinceTs = Clock.parse(since)
        let untilTs = Clock.parse(until)
        let filtered = loaded.filter { entry in
            guard let ts = Clock.parse(entry["at"]) else { return true }
            if let sinceTs, ts < sinceTs { return false }
            if let untilTs, ts > untilTs { return false }
            return true
        }
        let window = MCPDispatcher.pageRecent(filtered, offset: offset, limit: limit)
        var total = window.total
        var truncated = window.truncated
        if since == nil && until == nil, let sealCount = sealEntryCount(seal), sealCount > total {
            total = sealCount
            truncated = offset + window.items.count < sealCount
        }
        let next: Any = truncated ? ListPage.encodeCursor(offset + limit) : NSNull()
        return Result(items: window.items, total: total, truncated: truncated, nextCursor: next)
    }

    private static func load(_ log: URL, need: Int, since: String?) -> [[String: Any]] {
        let attrs = try? FileManager.default.attributesOfItem(atPath: log.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? -1
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let key = "\(log.path)|\(size)|\(mtime)|\(since ?? "")"
        lock.lock()
        if sig == key {
            let copy = entries
            lock.unlock()
            return copy
        }
        let previousSize = parsedPath == log.path ? parsedSize : 0
        let previous = parsedPath == log.path ? entries : []
        lock.unlock()
        guard size > 0 else { return [] }
        let want = Int64(max(need, 30)) * 1024
        let cap: Int64 = since == nil ? tailCap : min(8 * 1024 * 1024, tailCap * 4)
        let budget = min(cap, max(Int64(65_536), want))
        let appending = since == nil && previousSize > 0 && size > previousSize && size - previousSize <= budget
        let start = appending ? previousSize : max(0, size - budget)
        guard let data = readBounded(log, start: start, maxBytes: Int(budget) + 65_536) else { return previous }
        var text = String(decoding: data, as: UTF8.self)
        if start > 0 && !appending, let nl = text.firstIndex(of: "\n") {
            text = String(text[text.index(after: nl)...])
        }
        var parsed = appending ? previous : []
        for line in text.split(whereSeparator: \.isNewline) {
            if let obj = JSON.object(String(line)) { parsed.append(obj) }
        }
        if parsed.count > 4000 { parsed = Array(parsed.suffix(4000)) }
        lock.lock()
        sig = key
        parsedPath = log.path
        parsedSize = size
        entries = parsed
        lock.unlock()
        return parsed
    }

    private static func sealEntryCount(_ seal: URL) -> Int? {
        guard let obj = JSON.objectAt(seal) else { return nil }
        return intValue(obj["count"])
    }

    private static func readBounded(_ path: URL, start: Int64, maxBytes: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: path) else { return nil }
        defer { try? handle.close() }
        do { try handle.seek(toOffset: UInt64(max(0, start))) } catch { return nil }
        guard handle.offsetInFile == UInt64(max(0, start)) else { return nil }
        return try? handle.read(upToCount: maxBytes)
    }
}
