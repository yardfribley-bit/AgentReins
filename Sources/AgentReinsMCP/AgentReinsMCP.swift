import AgentReinsCore
import CryptoKit
import Foundation
import JavaScriptCore
import Security

/// Packaged read-only supervisor MCP — no system node/python.
/// Stdio (default): Codex command = "…/AgentReins.app/Contents/MacOS/AgentReinsMCP"
/// Loopback HTTP: AgentReinsMCP --http [--port 18977]  →  http://127.0.0.1:18977/mcp
@main
enum AgentReinsMCP {
    static func main() {
        var http = false
        var port = EndpointDiscovery.defaultPort
        var portFromArg = false
        var envPortInvalid = false
        var requireToken = ProcessInfo.processInfo.environment["AGENTREINS_MCP_REQUIRE_TOKEN"] == "1"
        if let raw = ProcessInfo.processInfo.environment["AGENTREINS_MCP_PORT"], !raw.isEmpty {
            if let parsed = Int(raw) { port = parsed }
            else { envPortInvalid = true }
        }
        var index = 1
        let args = CommandLine.arguments
        while index < args.count {
            let arg = args[index]
            if arg == "--http" {
                http = true
            } else if arg == "--require-token" {
                requireToken = true
            } else if arg == "--port" {
                index += 1
                guard index < args.count, let parsed = Int(args[index]) else {
                    failArgs("missing value for --port")
                }
                port = parsed
                portFromArg = true
            } else if arg.hasPrefix("--port=") {
                guard let parsed = Int(arg.dropFirst("--port=".count)) else { failArgs("bad --port") }
                port = parsed
                portFromArg = true
            } else if arg == "--help" || arg == "-h" {
                FileHandle.standardError.write(Data("usage: AgentReinsMCP [--http] [--port 18977] [--require-token]\n".utf8))
                exit(0)
            } else {
                failArgs("unknown argument: \(arg)")
            }
            index += 1
        }
        // Overlap the Keychain helper with process startup. Tool calls do not wait out a 15s hang.
        KeychainWarmup.shared.start()
        if http {
            if envPortInvalid && !portFromArg { failArgs("invalid AGENTREINS_MCP_PORT") }
            guard (1...65535).contains(port) else { failArgs("port must be 1...65535") }
            HTTPTransport.run(port: port, requireToken: requireToken)
        }
        runStdio()
    }

    static func runStdio() {
        let session = MCPSession(id: "stdio", transport: "stdio")
        while let line = readLine(strippingNewline: true) {
            guard !line.isEmpty, let data = line.data(using: .utf8),
                  let msg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            if let reply = MCPDispatcher.handle(msg, session: session, auditActor: session.actorName) {
                print(JSON.string(reply))
                fflush(stdout)
            }
        }
    }

    static func failArgs(_ message: String) -> Never {
        FileHandle.standardError.write(Data("AgentReinsMCP: \(message)\n".utf8))
        exit(2)
    }
}

// MARK: - Paths

enum Paths {
    static var support: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentGuard")
    }
    static var transport: URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_TRANSPORT_ROOT"] {
            return URL(fileURLWithPath: env)
        }
        return support.appendingPathComponent("transport-audit")
    }
    static var auditLog: URL { support.appendingPathComponent("mcp-supervisor-audit.jsonl") }
    static var auditSeal: URL { support.appendingPathComponent("mcp-supervisor-audit.seal") }
    static var integrityDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReinsIntegrity")
    }
    static var workspaceJS: URL? {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_WORKSPACE_JS"] {
            return URL(fileURLWithPath: env)
        }
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let bundled = exe.deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Resources/RealtimeWorkspace")
        if FileManager.default.fileExists(atPath: bundled.appendingPathComponent("risk-alerts.js").path) {
            return bundled
        }
        return nil
    }
    static func ensureSupport() {
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? FileManager.default.createDirectory(at: transport, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
}

// MARK: - Transport (user dir only; never /private/tmp)

enum Transport {
    struct Load {
        var records: [[String: Any]]
        /// True when more than `limit` transport directories exist; only the newest `limit` are returned.
        var truncated: Bool
    }

    static func load(limit: Int = 80) -> [[String: Any]] { loadReporting(limit: limit).records }

    /// Names + root mtime. A warm list_agents returns this without re-reading transport.json files.
    private static let cacheLock = NSLock()
    private static var cacheKey: String?
    private static var cacheLoad: Load?

    static func loadReporting(limit: Int = 80) -> Load {
        let root = Paths.transport.resolvingSymlinksInPath()
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []).filter { !$0.hasPrefix(".") }
        let mtime = ((try? FileManager.default.attributesOfItem(atPath: root.path))?[.modificationDate] as? Date)?
            .timeIntervalSince1970 ?? 0
        let key = "\(root.path)|\(names.count)|\(mtime)|\(limit)"
        cacheLock.lock()
        if cacheKey == key, let cacheLoad {
            cacheLock.unlock()
            return cacheLoad
        }
        cacheLock.unlock()
        let fresh = loadReportingUncached(limit: limit)
        cacheLock.lock()
        cacheKey = key
        cacheLoad = fresh
        cacheLock.unlock()
        return fresh
    }

    static func loadReportingUncached(limit: Int = 80) -> Load {
        Paths.ensureSupport()
        let root = Paths.transport.resolvingSymlinksInPath()
        let path = root.path
        if path.hasPrefix("/private/tmp") || path.hasPrefix("/tmp/") { return Load(records: [], truncated: false) }
        guard let dirs = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return Load(records: [], truncated: false)
        }
        let sorted = dirs.map { $0.appendingPathComponent("transport.json") }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
            .sorted {
                let a = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let b = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return a > b
            }
        let truncated = sorted.count > limit
        let files = sorted.prefix(limit)
        var rows: [[String: Any]] = []
        for file in files {
            guard let data = try? Data(contentsOf: file),
                  let item = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let inv = item["invocation"] as? [String: Any],
                  inv["captureMode"] as? String == "agent-path" else { continue }
            if inv["testCapture"] as? Bool == true { continue }
            if let p = inv["provenance"] as? String, p == "test" || p == "seed" { continue }
            var row: [String: Any] = ["runID": file.deletingLastPathComponent().lastPathComponent]
            for key in ["agent", "tool", "args", "task", "call", "startedAt", "processStartAt", "pid", "exitCode", "gap", "auditBypass", "session", "parentPID", "parentName", "parentArgv", "parentStartAt", "launcherPID", "provenance", "testCapture", "codexThreadID", "sha256"] {
                row[key] = inv[key] ?? NSNull()
            }
            for key in ["connections", "blocks", "downloads"] { row[key] = item[key] as? [Any] ?? [] }
            if isNull(row["call"]) { row["call"] = row["runID"] }
            if let sa = item["securityAudit"] as? [String: Any], let host = sa["destinationHost"] { row["destinationHost"] = host }
            row["fileResult"] = item["fileResult"] ?? NSNull()
            if let sha = item["sha256"] as? String { row["sha256"] = sha }
            else if let fr = item["fileResult"] as? [String: Any], let sha = fr["sha256"] as? String { row["sha256"] = sha }
            row["securityAudit"] = item["securityAudit"] ?? NSNull()
            row["evidencePath"] = file.path
            rows.append(row)
        }
        return Load(records: rows, truncated: truncated)
    }
}

// MARK: - Alerts via JavaScriptCore (same JS as app)

enum Alerts {
    /// evidence.py list_alerts: rule normalised ('INB'), INB alerts carry the finding with a redacted context.
    static func list(_ records: [[String: Any]], agent: String?, rule: String?, since: String?, until: String? = nil,
                     limit: Int? = nil, offset: Int = 0) -> [String: Any] {
        let (alerts, engine, warning) = build(records)
        var byCall: [String: [String: Any]] = [:]
        for r in records {
            for k in [str(r["call"]), str(r["runID"])].compactMap({ $0 }) where byCall[k] == nil { byCall[k] = r }
        }
        let sinceTs = Clock.parse(since)
        let untilTs = Clock.parse(until)
        var out: [[String: Any]] = []
        for alert in alerts {
            var finding: Any = nn(alert["finding"])
            if Inb.isInb(alert["rule"]), isNull(alert["finding"]) {
                let record = byCall[str(alert["call"]) ?? str(alert["executionId"]) ?? ""]
                if let raw = Inb.findingFor(record) { finding = Inb.summary(raw, record) }
            }
            var item: [String: Any] = [
                "id": nn(alert["id"]), "rule": Inb.normalize(alert["rule"]), "title": nn(alert["title"]),
                "agent": nn(alert["agent"]), "session": nn(alert["session"]), "executionId": nn(alert["call"]),
                "confidence": nn(alert["confidence"]), "timestamp": nn(alert["timestamp"]), "sub": nn(alert["sub"]),
                "why": nn(alert["why"]), "finding": finding,
            ]
            if let f = finding as? [String: Any], f.keys.contains("matchContextRedacted") {
                item["matchContextRedacted"] = nn(f["matchContextRedacted"])
            }
            if let agent, agent != "all", str(item["agent"]) != agent { continue }
            if let rule, rule != "all", str(item["rule"]) != rule { continue }
            if let sinceTs, let ts = Clock.parse(item["timestamp"]), ts < sinceTs { continue }
            if let untilTs, let ts = Clock.parse(item["timestamp"]), ts > untilTs { continue }
            out.append(item)
        }
        let page = ListPage.slice(out, offset: offset, limit: limit)
        var result: [String: Any] = [
            "alerts": Redact.any(page.items),
            "confidence": out.isEmpty ? "Unknown" : "Observed",
            "engine": engine,
            "note": "告警由本机传输审计 + 与 App 相同的 risk-alerts.js（JavaScriptCore）推导；无数据即为空，不放样本。",
        ]
        for (k, v) in ListPage.meta(page) { result[k] = v }
        if let warning { result["warning"] = warning }
        return result
    }

    static func build(_ records: [[String: Any]]) -> (alerts: [[String: Any]], engine: String, warning: String?) {
        guard let root = Paths.workspaceJS else {
            return ([], "swift-fallback", "RealtimeWorkspace JS not packaged; alerts empty.")
        }
        let context = JSContext()!
        context.evaluateScript("var window = {};")
        for name in ["network-view.js", "risk-alerts.js"] {
            let url = root.appendingPathComponent(name)
            guard let src = try? String(contentsOf: url, encoding: .utf8) else {
                return ([], "swift-fallback", "missing \(name)")
            }
            context.evaluateScript(src)
        }
        let transports = records.map { r -> [String: Any] in
            [
                "captureMode": "agent-path",
                "agent": r["agent"] ?? NSNull(),
                "tool": r["tool"] ?? NSNull(),
                "startedAt": r["startedAt"] ?? NSNull(),
                "pid": r["pid"] ?? 0,
                "parentPID": r["parentPID"] ?? NSNull(),
                "launcherPID": r["launcherPID"] ?? NSNull(),
                "exitCode": r["exitCode"] ?? NSNull(),
                "runID": r["runID"] ?? NSNull(),
                "call": r["call"] ?? NSNull(),
                "session": r["session"] ?? NSNull(),
                "args": r["args"] ?? [],
                "connections": r["connections"] ?? [],
                "blocks": r["blocks"] ?? [],
                "downloads": r["downloads"] ?? [],
                "auditBypass": r["auditBypass"] ?? NSNull(),
                "securityAudit": r["securityAudit"] ?? NSNull(),
                "gap": r["gap"] ?? NSNull(),
                "provenance": r["provenance"] ?? NSNull(),
                "testCapture": r["testCapture"] ?? false,
            ]
        }
        let payload: [String: Any] = ["transports": transports, "tasks": [], "collected": [], "health": []]
        guard let payloadData = try? JSONSerialization.data(withJSONObject: payload),
              let payloadText = String(data: payloadData, encoding: .utf8) else {
            return ([], "swift-fallback", "payload encode failed")
        }
        let runner = """
        (function(raw){
          const input = JSON.parse(raw);
          window.AgentReinsNetwork.setLocalTransports(input.transports || []);
          const alerts = window.AgentReinsRisk.buildAlerts({tasks:[],collected:[],health:[]}).map(a => ({
            id:a.id, rule:a.rule, title:a.title, sub:a.sub, agent:a.agent, session:a.session,
            call:a.call, confidence:({obs:'Observed',cor:'Correlated',inf:'Inferred',unk:'Unknown'}[a.confidence]||a.confidence),
            timestamp:a.timestamp, why:a.why, executionId:a.call
          }));
          return JSON.stringify(alerts);
        })
        """
        guard let fn = context.evaluateScript(runner),
              let result = fn.call(withArguments: [payloadText])?.toString(),
              let data = result.data(using: .utf8),
              let alerts = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return ([], "swift-fallback", "JSC evaluation failed")
        }
        return (alerts, "swift-jsc-bridge", nil)
    }
}

enum Agents {
    static let executionIdCap = 40
    static let sessionCap = 40

    static func list(_ records: [[String: Any]], since: String? = nil, until: String? = nil,
                     limit: Int? = nil, offset: Int = 0, transportTruncated: Bool = false) -> [String: Any] {
        let sinceTs = Clock.parse(since)
        let untilTs = Clock.parse(until)
        var by: [String: [String: Any]] = [:]
        for r in records {
            // Same rule as list_alerts: a bound drops a row only when its timestamp parses out of range.
            if let sinceTs, let ts = Clock.parse(r["startedAt"]), ts < sinceTs { continue }
            if let untilTs, let ts = Clock.parse(r["startedAt"]), ts > untilTs { continue }
            let agent = (r["agent"] as? String) ?? "Unknown"
            var bucket = by[agent] ?? ["agent": agent, "sessions": Set<String>(), "executionIds": [String](), "tools": Set<String>()]
            if let s = r["session"] as? String { var set = bucket["sessions"] as! Set<String>; set.insert(s); bucket["sessions"] = set }
            if let c = r["call"] as? String { var ids = bucket["executionIds"] as! [String]; ids.append(c); bucket["executionIds"] = ids }
            if let t = r["tool"] as? String { var set = bucket["tools"] as! Set<String>; set.insert(t); bucket["tools"] = set }
            by[agent] = bucket
        }
        let sessionLimit = min(Self.sessionCap, limit ?? Self.sessionCap)
        let agents = by.keys.sorted().map { agent -> [String: Any] in
            let b = by[agent]!
            let sessions = Array(b["sessions"] as! Set<String>).sorted()
            let ids = b["executionIds"] as! [String]
            return [
                "agent": agent,
                "isCursor": agent == "Cursor",
                "sessions": Array(sessions.prefix(sessionLimit)),
                "sessionCount": sessions.count,
                "sessionsTruncated": sessions.count > sessionLimit,
                "executionIds": Array(ids.prefix(Self.executionIdCap)),
                "executionCount": ids.count,
                "executionIdsTruncated": ids.count > Self.executionIdCap,
                "tools": Array(b["tools"] as! Set<String>).sorted(),
                "confidence": ids.isEmpty ? "Unknown" : "Observed",
            ]
        }
        let page = ListPage.slice(agents, offset: offset, limit: limit)
        var result: [String: Any] = [
            "agents": page.items,
            "confidence": agents.isEmpty ? "Unknown" : "Observed",
            "note": "仅来自用户目录传输审计；不读 /private/tmp。",
            "transportTruncated": transportTruncated,
        ]
        for (k, v) in ListPage.meta(page) { result[k] = v }
        return result
    }
}

enum Execution {
    /// evidence.py get_execution: findings (INB with redacted context) and the same destination fields as list_network.
    static func get(_ id: String, _ records: [[String: Any]], transportTruncated: Bool = false) -> [String: Any] {
        guard let hit = records.first(where: { str($0["call"]) == id || str($0["runID"]) == id }) else {
            var note = "未找到该执行编号的传输审计记录。"
            if transportTruncated { note += "传输目录超过读取上限，只读了最近修改的记录。" }
            return ["executionId": id, "confidence": "Unknown", "note": note]
        }
        let downloads = ((hit["downloads"] as? [[String: Any]]) ?? []).map { d -> [String: Any] in
            ["path": nn(d["path"]), "sha256": nn(d["sha256"]), "bytes": nn(d["bytes"]), "state": nn(d["state"]),
             "confidence": isNull(d["sha256"]) ? "Unknown" : "Observed"]
        }
        let audit = hit["securityAudit"] as? [String: Any] ?? [:]
        let findings = (audit["findings"] as? [Any] ?? []).compactMap { $0 as? [String: Any] }.map { Inb.summary($0, hit) }
        func bytes(_ direction: String) -> Int {
            (hit["blocks"] as? [Any] ?? []).compactMap { $0 as? [String: Any] }
                .filter { str($0["direction"]) == direction }.reduce(0) { $0 + (intValue($1["observedBytes"]) ?? 0) }
        }
        var out: [String: Any] = [
            "executionId": nn(hit["call"] ?? hit["runID"]), "agent": nn(hit["agent"]), "session": nn(hit["session"]),
            "tool": nn(hit["tool"]), "commandArgs": hit["args"] as? [Any] ?? [], "startedAt": nn(hit["startedAt"]),
            "exitCode": nn(hit["exitCode"]), "auditBypass": (hit["auditBypass"] as? Bool) == true,
            "downloads": downloads, "securityFindings": findings,
            "requestBytes": bytes("send"), "responseBytes": bytes("receive"),
            "confidence": "Observed",
            "note": "正文预览已脱敏；S02 仅返回 finding 元数据。目的地字段与 list_network 同源（destination_fields）。",
        ]
        for (k, v) in Destination.fields(hit) { out[k] = v }
        return Redact.any(out) as! [String: Any]
    }
}

/// Tail of the audit-proxy route journal. The body archive is never read here.
enum ProxyJournal {
    static let lost = "via proxy · attribution lost"
    private static let lock = NSLock()
    private static var sig: String?
    private static var flows: [[String: Any]] = []
    private static var parsedPath = ""
    private static var parsedSize: Int64 = 0
    private static var byFlow: [String: [String: Any]] = [:]
    /// Never pull more than this off the route journal. The on-device file is over 100MB.
    private static let tailBytes: Int64 = 2 * 1024 * 1024

    static func url() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_ROUTE_JSONL"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentReins/workbuddy-network-routes.jsonl")
    }

    static func recent(limit: Int = 200) -> [[String: Any]] {
        let path = url()
        let attrs = try? FileManager.default.attributesOfItem(atPath: path.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? -1
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let key = "\(path.path)|\(size)|\(mtime)"
        lock.lock()
        if sig == key {
            let copy = flows
            lock.unlock()
            return copy
        }
        let previousSize = parsedPath == path.path ? parsedSize : 0
        let previous = parsedPath == path.path ? byFlow : [:]
        lock.unlock()
        let appending = previousSize > 0 && size > previousSize && size - previousSize <= tailBytes
        let start = appending ? previousSize : max(0, size - tailBytes)
        guard size > 0, let data = Self.readBounded(path, start: start, maxBytes: Int(tailBytes) + 65_536) else {
            return []
        }
        var text = String(decoding: data, as: UTF8.self)
        if start > 0 && !appending, let nl = text.firstIndex(of: "\n") {
            text = String(text[text.index(after: nl)...])
        }
        var by = appending ? previous : [:]
        for line in text.split(whereSeparator: \.isNewline) {
            guard let rec = JSON.object(String(line)), let flow = str(rec["flowID"]), !flow.isEmpty else { continue }
            let pid = intValue(rec["clientPid"])
            let state = str(rec["attributionState"]) ?? (pid == nil ? lost : nil)
            let lostRow = state == lost || pid == nil
            by[flow] = [
                "flowID": flow,
                "observedAt": nn(rec["observedAt"]),
                "agent": lostRow ? NSNull() : nn(rec["clientAgent"]),
                "pid": lostRow ? NSNull() : nn(rec["clientPid"]),
                "ppid": lostRow ? NSNull() : nn(rec["clientPpid"]),
                "processName": lostRow ? NSNull() : nn(rec["clientProcess"]),
                "processPath": lostRow ? NSNull() : nn(rec["clientPath"]),
                "processStartAt": lostRow ? NSNull() : nn(rec["clientStartAt"]),
                "parentChain": lostRow ? [Any]() : (rec["parentChain"] as? [Any] ?? []),
                "attributionState": nn(state),
                "attributionBasis": lostRow ? NSNull() : nn(rec["attributionBasis"]),
                "host": nn(rec["host"]),
                "path": nn(rec["path"]),
                "method": nn(rec["method"]),
                "clientAddress": nn(rec["clientAddress"]),
                "remoteHost": nn(rec["remoteHost"]),
                "remotePort": nn(rec["remotePort"]),
                "viaProxy": true,
                "realDestination": nn(rec["host"]),
                "destinationSource": lostRow ? "proxy_unattributed" : "proxy_attributed",
                "destinationEvidence": lostRow ? "Unknown" : "Observed",
                "captureStage": nn(rec["captureStage"]),
                "confidence": lostRow ? "Unknown" : "Observed",
            ]
        }
        let rows = Array(by.values.sorted { (str($0["observedAt"]) ?? "") > (str($1["observedAt"]) ?? "") }.prefix(limit))
        lock.lock()
        sig = key
        parsedPath = path.path
        parsedSize = size
        var kept: [String: [String: Any]] = [:]
        for row in rows {
            if let id = str(row["flowID"]) { kept[id] = row }
        }
        byFlow = kept
        flows = rows
        lock.unlock()
        return rows
    }

    /// Bytes from `start`, at most `maxBytes`. A failed seek returns nil instead of the front of a 100MB file.
    private static func readBounded(_ path: URL, start: Int64, maxBytes: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: path) else { return nil }
        defer { try? handle.close() }
        do { try handle.seek(toOffset: UInt64(start)) } catch { return nil }
        guard handle.offsetInFile == UInt64(start) else { return nil }
        return try? handle.read(upToCount: maxBytes)
    }
}

/// Renamed from `Network` so `import Network` (NWListener) does not clash with this tool.
enum NetworkTool {
    static func list(_ records: [[String: Any]], agent: String?, since: String?, until: String? = nil,
                     integrity: Integrity, limit: Int? = nil, offset: Int = 0,
                     transportTruncated: Bool = false) -> [String: Any] {
        let sinceTs = Clock.parse(since)
        let untilTs = Clock.parse(until)
        let rows = records.compactMap { r -> [String: Any]? in
            if let agent, agent != "all", str(r["agent"]) != agent { return nil }
            // `since` alone stays socket-only. Command rows are bounded once `until` is set.
            if let untilTs {
                if let sinceTs, let ts = Clock.parse(r["startedAt"]), ts < sinceTs { return nil }
                if let ts = Clock.parse(r["startedAt"]), ts > untilTs { return nil }
            }
            var row: [String: Any] = [
                "executionId": nn(r["call"] ?? r["runID"]), "agent": nn(r["agent"]), "tool": nn(r["tool"]),
                "auditBypass": (r["auditBypass"] as? Bool) == true, "startedAt": nn(r["startedAt"]),
                "exitCode": nn(r["exitCode"]),
            ]
            let dest = Destination.fields(r)
            for (k, v) in dest { row[k] = v }
            row["confidence"] = isNull(dest["destination"]) ? "Unknown" : "Observed"
            return row
        }
        let fetch = ListPage.socketFetchLimit(offset: offset, limit: limit)
        let sockets = SocketLedger.load(integrity, agent: agent, since: since, until: until, limit: fetch)
        let connections = sockets["connections"] as? [[String: Any]] ?? []
        let coverage = sockets["coverage"] as? [String: Any] ?? [:]
        let direct = connections.filter { ($0["viaProxy"] as? Bool) == false && str($0["scope"]) == "public" }.count
        let proxied = connections.filter { ($0["viaProxy"] as? Bool) == true }.count
        let networkPage = ListPage.slice(rows, offset: offset, limit: limit)
        let socketPage = ListPage.slice(connections, offset: offset, limit: limit, knownTotal: intValue(sockets["total"]))
        var result: [String: Any] = [
            "network": Redact.any(networkPage.items),
            "sockets": socketPage.items,
            "socketSummary": ["total": sockets["total"] ?? 0, "notViaProxyPublic": direct, "viaProxy": proxied,
                              "ledgerIntegrity": nn((coverage["integrity"] as? [String: Any])?["state"])] as [String: Any],
            "socketCoverage": coverage,
            "socketsPage": ListPage.meta(socketPage),
            "proxyFlows": ProxyJournal.recent(),
            "confidence": rows.isEmpty && connections.isEmpty ? "Unknown" : "Observed",
            "transportTruncated": transportTruncated,
            "note": "network = 经审计入口的命令；realDestination/destinationSource/transportPeer 与 get_execution 同源："
                + "proxy_observed / connection_observed = trace 里看到（Observed），argv_parsed = 只从命令参数推出（Inferred），"
                + "transport_peer_only = 只知道本机代理口（Unknown）。sockets = 按进程采样的 TCP/UDP 连接，与是否走代理无关；"
                + "会漏掉短于实测间隔（socketCoverage.missesShorterThanSeconds）的连接。",
        ]
        for (k, v) in ListPage.meta(networkPage) { result[k] = v }
        return result
    }
}

/// Read-only view of tools/socket-sampler output, verified with the same key and rules as the sampler.
enum SocketLedger {
    static var defaultURL: URL { Paths.support.appendingPathComponent("socket-ledger.json") }
    static var url: URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_SOCKET_LEDGER"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return defaultURL
    }

    private static let loadLock = NSLock()
    private static var loadKeySig: String?
    private static var loadCached: [String: Any]?

    static func load(_ integrity: Integrity, agent: String?, since: String?, until: String? = nil, limit: Int = 200) -> [String: Any] {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? -1
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let macAttrs = try? FileManager.default.attributesOfItem(atPath: url.path + ".mac")
        let macSize = (macAttrs?[.size] as? NSNumber)?.int64Value ?? -1
        let macMtime = (macAttrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let sig = "\(url.path)|\(size)|\(mtime)|\(macSize)|\(macMtime)|\(agent ?? "")|\(since ?? "")|\(until ?? "")|\(limit)|\(KeychainWarmup.shared.state)"
        loadLock.lock()
        if loadKeySig == sig, let loadCached {
            loadLock.unlock()
            return loadCached
        }
        loadLock.unlock()
        let seal = SocketLedgerCore.sealPath(ledger: url, defaultLedger: defaultURL, integrityDir: Paths.integrityDir)
        // Pending warmup: do not launch the helper on the tool thread (a cold Keychain is a 15s hang).
        let key: Data? = KeychainWarmup.shared.state == "pending" ? nil : (try? integrity.loadKey(create: false))
        let value = SocketLedgerCore.load(ledger: url, seal: seal, key: key, crypto: Ctx.crypto, agent: agent, since: since,
                                          until: until, limit: limit)
        loadLock.lock()
        loadKeySig = sig
        loadCached = value
        loadLock.unlock()
        return value
    }

    static func blindSpot(_ cov: [String: Any]) -> [String: Any] {
        guard str(cov["state"]) == "sampling" else {
            return ["topic": "未走代理流量", "confidence": "Unknown", "status": nn(cov["state"]),
                    "note": "socket-sampler 当前没有在采样（\(str(cov["state"]) ?? "?")）；不估算比例"]
        }
        func v(_ k: String) -> String { str(cov[k]) ?? "None" }
        let reference = str(cov["referenceShortConnectionSeconds"]) ?? "1.5"
        let intervalNote = str(cov["intervalNote"]).map { " " + $0 } ?? ""
        return [
            "topic": "未走代理流量",
            "confidence": str(cov["measurementConfidence"]) == "Observed" ? "Observed" : "Unknown",
            "status": "sampled",
            "note": "按进程采样 TCP/UDP 连接：有效间隔 p50 \(v("effectiveIntervalSeconds"))s / p95 \(v("effectiveIntervalSecondsP95"))s"
                + "（成功采样间隔，不是配置的 \(v("configuredIntervalSeconds"))s），短于 \(v("missesShorterThanSeconds"))s 的连接可能漏掉，"
                + "按 \(reference) 秒连接估算漏采率 \(v("estimatedMissRate"))"
                + "（最近一次 \(v("lastSampleAt"))；失败 \(v("failures")) 次）；系统解析器发出的 DNS 不可见。"
                + intervalNote,
        ]
    }

    static func sampling(_ cov: [String: Any]) -> [String: Any] {
        [
            "effectiveIntervalSeconds": nn(cov["effectiveIntervalSeconds"]),
            "effectiveIntervalSecondsP95": nn(cov["effectiveIntervalSecondsP95"]),
            "missesShorterThanSeconds": nn(cov["missesShorterThanSeconds"]),
            "estimatedMissRate": nn(cov["estimatedMissRate"]),
            "estimatedMissRateBasis": nn(cov["estimatedMissRateBasis"]),
            "referenceShortConnectionSeconds": nn(cov["referenceShortConnectionSeconds"]),
            "intervalNote": nn(cov["intervalNote"]),
            "measurementConfidence": nn(cov["measurementConfidence"]),
            "configuredIntervalSeconds": nn(cov["configuredIntervalSeconds"]),
            "state": nn(cov["state"]),
        ]
    }
}

let inProcessBlindSpot: [String: Any] = [
    "topic": "进程内工具（Read/Edit/Write/Glob）",
    "confidence": "Observed",
    "status": "outside_system_visibility",
    "note": "Read/Edit/Write/Glob 等不派生子进程、也不打开套接字的进程内工具，不在系统级采样和审计代理的可见范围内。这里没看到，不能当成没发生。Network Extension 不在本接口范围内。",
]

enum Coverage {
    static func get(_ integrity: Integrity, validation: [String: Any]? = nil) -> [String: Any] {
        let validation = validation ?? integrity.validate()
        let ledger = SocketLedger.load(integrity, agent: nil, since: nil, limit: 0)["coverage"] as? [String: Any] ?? [:]
        var result: [String: Any] = [
            "rules": [
                ["id": "S01", "status": "blind", "confidence": "Unknown", "note": "无 Endpoint Security 级文件读证据"],
                ["id": "S02", "status": "supported", "confidence": "Observed", "note": "content_audit credential-outbound"],
                ["id": "S03", "status": "supported", "confidence": "Correlated", "note": "同执行编号下载后执行"],
                ["id": "S04", "status": "supported", "confidence": "Observed", "note": "非白名单目的地"],
                ["id": "S06", "status": "blind", "confidence": "Unknown", "note": "未监看 agent 配置变更"],
                ["id": "S07", "status": "supported", "confidence": "Observed", "note": "仅认后端 auditBypass=true"],
            ],
            "blindSpots": [
                SocketLedger.blindSpot(ledger),
                inProcessBlindSpot,
                ["topic": "SSH 通道内正文", "confidence": "Unknown", "note": "只看到连到哪台主机"],
            ],
            "socketSampling": SocketLedger.sampling(ledger),
            "evidenceIntegrity": validation,
            "integritySummary": Integrity.summary(validation),
            "socketLedgerIntegrity": nn(ledger["integrity"]),
            "transportRoot": Paths.transport.path,
            "legacyPathPolicy": "never_read_/private/tmp",
            "runtime": "swift-mcp-no-system-node-python",
            "mcpEndpoint": EndpointDiscovery.snapshot(),
            "confidence": "Unknown",
        ]
        if let status = str(validation["keychainStatus"]) { result["keychainStatus"] = status }
        if let note = str(ledger["intervalNote"]) { result["intervalNote"] = note }
        return result
    }

    static func pendingIntegrity() -> [String: Any] {
        [
            "ok": false,
            "status": "pending",
            "statusText": "完整性密钥正在后台读取，这一次不阻塞等待钥匙串。",
            "confidence": "Unknown",
            "keychainStatus": "pending",
            "entriesChecked": 0,
            "tampered": [Any](),
            "deletedOrGap": [Any](),
            "currentTampered": ["count": 0, "reasons": [String: Any]()] as [String: Any],
            "legacyUnverifiable": ["count": 0, "from": NSNull(), "to": NSNull()] as [String: Any],
            "b6": ["sameUidCanForge": true, "reasons": ["钥匙串结果尚未返回，不把这次等待算成校验失败。"]] as [String: Any],
            "note": "pending 不是 key_unavailable，也不是篡改。助手返回后下一次读取会给出真实状态。",
        ]
    }
}

// MARK: - List paging (limit / offset / cursor). Omitted limit keeps the previous full result.

enum ListPage {
    struct Window {
        var items: [[String: Any]]
        var total: Int
        var offset: Int
        var limit: Int
        var truncated: Bool
        var nextCursor: Any
    }

    static let maxLimit = 500

    /// (`offset`, `limit`). `limit == nil` means "no extra cap" (historical full list, aside from each tool's own cap).
    static func parse(args: [String: Any], defaultLimit: Int?) throws -> (offset: Int, limit: Int?) {
        let offset: Int
        if let cursor = str(args["cursor"]), !cursor.isEmpty {
            guard let decoded = decodeCursor(cursor) else {
                throw NSError(domain: "AgentReinsMCP", code: 4, userInfo: [NSLocalizedDescriptionKey: "invalid cursor"])
            }
            offset = decoded
        } else {
            let raw = intValue(args["offset"]) ?? 0
            if raw < 0 {
                throw NSError(domain: "AgentReinsMCP", code: 4, userInfo: [NSLocalizedDescriptionKey: "invalid offset"])
            }
            offset = raw
        }
        if args["limit"] == nil || args["limit"] is NSNull {
            return (offset, defaultLimit)
        }
        guard var limit = intValue(args["limit"]) else {
            throw NSError(domain: "AgentReinsMCP", code: 4, userInfo: [NSLocalizedDescriptionKey: "invalid limit"])
        }
        if limit < 1 { limit = 1 }
        if limit > maxLimit { limit = maxLimit }
        return (offset, limit)
    }

    static func slice(_ items: [[String: Any]], offset: Int, limit: Int?, knownTotal: Int? = nil) -> Window {
        let sourceTotal = max(knownTotal ?? items.count, items.count)
        let start = min(max(0, offset), items.count)
        let page: [[String: Any]]
        let effective: Int
        if let limit {
            page = Array(items.dropFirst(start).prefix(limit))
            effective = limit
        } else {
            page = Array(items.dropFirst(start))
            effective = page.count
        }
        let consumed = offset + page.count
        let truncated = consumed < sourceTotal
        return Window(items: page, total: sourceTotal, offset: offset, limit: effective,
                      truncated: truncated, nextCursor: truncated ? encodeCursor(consumed) : NSNull())
    }

    static func meta(_ window: Window) -> [String: Any] {
        ["total": window.total, "offset": window.offset, "limit": window.limit,
         "truncated": window.truncated, "nextCursor": window.nextCursor]
    }

    /// Socket ledger historically returned at most 200 rows. Fetch enough for this page without
    /// dropping that default when the caller did not ask for a page.
    static func socketFetchLimit(offset: Int, limit: Int?) -> Int {
        let need = offset + (limit ?? 200)
        return min(5000, max(200, need))
    }

    static func encodeCursor(_ offset: Int) -> String {
        Data(String(offset).utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decodeCursor(_ cursor: String) -> Int? {
        var text = cursor.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - (text.count % 4)) % 4
        if pad > 0 { text += String(repeating: "=", count: pad) }
        guard let data = Data(base64Encoded: text), let raw = String(data: data, encoding: .utf8),
              let n = Int(raw), n >= 0 else { return nil }
        return n
    }
}

// MARK: - Keychain warmup (do not block a tool call on the 15s helper timeout)

/// Starts at process launch. `resolve` waits at most `grace` seconds; a helper that is still
/// running is `pending` (not a tamper result, and not a reason to mint a new key).
final class KeychainWarmup {
    static let shared = KeychainWarmup()
    private let lock = NSLock()
    private let queue = DispatchQueue(label: "com.agentreins.mcp.keychain-warm")
    private var started = false
    private var finished = false
    /// cold | pending | found | missing | error | no_helper | unavailable
    private(set) var state = "cold"

    func start() {
        lock.lock()
        if started {
            lock.unlock()
            return
        }
        started = true
        state = "pending"
        lock.unlock()
        queue.async {
            let (status, _) = Ctx.keychain.lookup(Integrity.accountHmac)
            self.lock.lock()
            self.finished = true
            switch status {
            case "found", "missing", "error", "no_helper": self.state = status
            default: self.state = "unavailable"
            }
            self.lock.unlock()
        }
    }

    /// Tool responses: ok (key readable), pending (helper still running), or key_unavailable.
    static func reportedStatus(_ state: String) -> String {
        switch state {
        case "found": return "ok"
        case "pending", "cold": return "pending"
        default: return "key_unavailable"
        }
    }

    func resolve(grace: TimeInterval) -> String {
        start()
        let deadline = Date().addingTimeInterval(max(0, grace))
        while Date() < deadline {
            lock.lock()
            let done = finished
            let current = state
            lock.unlock()
            if done { return current }
            Thread.sleep(forTimeInterval: 0.01)
        }
        lock.lock()
        let current = state
        lock.unlock()
        return current
    }
}

// MARK: - Process-wide Keychain cache and async audit writes

/// One helper launch per account per TTL, shared by every tools/call in this process.
/// `missing` is not cached: a key may be created on the next call. Failures (timeout, needs approval,
/// helper error) stay cached so a blocked Keychain costs one 15s wait, not one per tool call.
final class ProcessKeychainCache: KeychainStore {
    let inner: KeychainStore
    let foundTTL: TimeInterval
    let unavailableTTL: TimeInterval
    let now: () -> Date
    private let lock = NSLock()
    private struct Hit { var status: String; var data: Data?; var at: Date; var error: String? }
    private var cache: [String: Hit] = [:]
    private var storedError: String?

    init(_ inner: KeychainStore, foundTTL: TimeInterval = 300, unavailableTTL: TimeInterval = 300,
         now: @escaping () -> Date = { Date() }) {
        self.inner = inner
        self.foundTTL = foundTTL
        self.unavailableTTL = unavailableTTL
        self.now = now
    }

    func lookup(_ account: String) -> (String, Data?) {
        lock.lock()
        defer { lock.unlock() }
        let moment = now()
        if let hit = cache[account], hit.status != "missing" {
            let ttl = hit.status == "found" ? foundTTL : unavailableTTL
            if moment.timeIntervalSince(hit.at) < ttl {
                storedError = hit.error
                return (hit.status, hit.data)
            }
        }
        let value = inner.lookup(account)
        let error = inner.lastError
        storedError = error
        if value.0 == "missing" {
            cache[account] = nil
        } else {
            cache[account] = Hit(status: value.0, data: value.1, at: moment, error: error)
        }
        return value
    }

    func set(_ account: String, _ value: Data) -> Bool {
        let ok = inner.set(account, value)
        lock.lock()
        cache[account] = nil
        storedError = inner.lastError
        lock.unlock()
        return ok
    }

    var backend: String { inner.backend }
    var helperPath: String? { inner.helperPath }
    var lastError: String? {
        lock.lock()
        defer { lock.unlock() }
        return storedError ?? inner.lastError
    }
}

// MARK: - Per-call integrity context (CryptoKit + packaged Keychain helper)

enum Ctx {
    static let crypto = CryptoBox(
        hmacSHA256: { key, message in Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))) },
        sha256: { Data(SHA256.hash(data: $0)) },
        random: { count in
            var bytes = [UInt8](repeating: 0, count: count)
            let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
            precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
            return Data(bytes)
        })

    static let keychain = ProcessKeychainCache(HelperKeychain(helper: HelperKeychain.packaged()))
    private static let auditQueue = DispatchQueue(label: "com.agentreins.mcp.audit")
    private static let validationQueue = DispatchQueue(label: "com.agentreins.mcp.validation")
    private static var validationCache: (token: String, value: [String: Any])?

    static func integrity() -> Integrity {
        Paths.ensureSupport()
        return Integrity(auditDir: Paths.support, integrityDir: Paths.integrityDir, transport: Paths.transport,
                         keychain: keychain, crypto: crypto)
    }

    /// Without the Keychain key nothing is signed (never a throwaway file key); the read itself is still answered
    /// and get_coverage reports status key_unavailable.
    /// HTTP passes `sync: false` so the helper launch and the log write do not sit on the tool-call path.
    static func appendAudit(actor: String, tool: String, arguments: [String: Any], sync: Bool) {
        let argsCopy = arguments
        let work = {
            // The tool thread already returned when the helper was still pending. Wait here, not there.
            _ = KeychainWarmup.shared.resolve(grace: 20)
            let integrity = integrity()
            guard let key = try? integrity.loadKey() else { return }
            integrity.append(actor: actor, tool: tool, arguments: argsCopy, key: key)
        }
        if sync { auditQueue.sync(execute: work) } else { auditQueue.async(execute: work) }
    }

    static func flushAudit() { auditQueue.sync { } }

    /// Reuses the last `validate()` while the audit log, seals, evidence files and key fingerprint are unchanged.
    static func cachedValidation(_ integrity: Integrity) -> [String: Any] {
        validationQueue.sync {
            let token = validationToken(integrity)
            if let validationCache, validationCache.token == token { return validationCache.value }
            let value = integrity.validate()
            if validationToken(integrity) == token { validationCache = (token, value) }
            return value
        }
    }

    private static func validationToken(_ integrity: Integrity) -> String {
        let (status, data) = integrity.keychain.lookup(Integrity.accountHmac)
        let keyTag = data.map { String(crypto.shaHex(data: $0).prefix(16)) } ?? status
        var parts = ["key=\(keyTag)"]
        for url in [integrity.auditLog, integrity.auditSeal, integrity.sealMirror,
                    integrity.runInventory, integrity.runInventoryMac] {
            parts.append(statToken(url))
        }
        // Run-directory mtimes, one bulk listing. Not a stat-and-read of every transport.json.
        parts.append("dirs=" + integrity.transportDirectoryFingerprint())
        return parts.joined(separator: "|")
    }

    private static func statToken(_ url: URL) -> String {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? -1
        let mtime = (attrs?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        return "\(url.lastPathComponent):\(size):\(mtime)"
    }

    static func recent(_ integrity: Integrity, limit: Int) -> [[String: Any]] {
        Array(integrity.lines().suffix(max(0, limit))).compactMap { JSON.object($0) }
    }
}
