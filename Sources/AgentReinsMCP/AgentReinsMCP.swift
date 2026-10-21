import AgentReinsCore
import CryptoKit
import Foundation
import JavaScriptCore
import Security

/// Packaged read-only supervisor MCP — no system node/python.
/// Codex: command = "…/AgentReins.app/Contents/MacOS/AgentReinsMCP"
@main
enum AgentReinsMCP {
    static let protocolVersion = "2024-11-05"
    /// Real caller from initialize.clientInfo — never a hard-coded "Codex".
    static var actorName: String = "unknown-client"

    static func main() {
        let tools: [[String: Any]] = [
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

        while let line = readLine(strippingNewline: true) {
            guard !line.isEmpty, let data = line.data(using: .utf8),
                  let msg = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let method = msg["method"] as? String
            let id = msg["id"]
            let params = msg["params"] as? [String: Any] ?? [:]
            if method == "initialize" {
                if let info = params["clientInfo"] as? [String: Any] {
                    let name = (info["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                    let version = (info["version"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                    if !name.isEmpty {
                        actorName = version.isEmpty ? name : "\(name)/\(version)"
                    }
                }
                respond(id, [
                    "protocolVersion": params["protocolVersion"] as? String ?? protocolVersion,
                    "capabilities": ["tools": ["listChanged": false]],
                    "serverInfo": ["name": "agentreins-supervisor", "version": "0.2.0-swift"],
                    "instructions": "Read-only AgentReins supervisor MCP (Swift, no system node/python).",
                ])
                continue
            }
            if method == "notifications/initialized" || method == "initialized" { continue }
            if method == "ping" { respond(id, [:] as [String: Any]); continue }
            if method == "tools/list" { respond(id, ["tools": tools]); continue }
            if method == "tools/call" {
                let name = params["name"] as? String ?? ""
                let args = params["arguments"] as? [String: Any] ?? [:]
                do {
                    let result = try callTool(name, args)
                    let text = pretty(result)
                    respond(id, [
                        "content": [["type": "text", "text": text]],
                        "structuredContent": result,
                        "isError": false,
                    ])
                } catch {
                    respond(id, [
                        "content": [["type": "text", "text": "error: \(error.localizedDescription)"]],
                        "isError": true,
                    ])
                }
                continue
            }
            if id != nil { respondError(id, -32601, "method not found: \(method ?? "")") }
        }
    }

    static func callTool(_ name: String, _ args: [String: Any]) throws -> [String: Any] {
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
        Ctx.appendAudit(integrity, actor: actorName, tool: name, arguments: args)
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
            return Network.list(records, agent: args["agent"] as? String, since: args["since"] as? String, integrity: integrity)
        case "get_coverage":
            return Coverage.get(integrity)
        case "list_mcp_audit":
            let limit = (args["limit"] as? Int) ?? 30
            return ["entries": Ctx.recent(integrity, limit: limit), "validation": integrity.validate(), "confidence": "Observed"]
        default:
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: name])
        }
    }

    static func respond(_ id: Any?, _ result: Any) {
        guard id != nil else { return }
        let out: [String: Any] = ["jsonrpc": "2.0", "id": id as Any, "result": result]
        print(jsonString(out))
        fflush(stdout)
    }

    static func respondError(_ id: Any?, _ code: Int, _ message: String) {
        let out: [String: Any] = ["jsonrpc": "2.0", "id": id as Any, "error": ["code": code, "message": message]]
        print(jsonString(out))
        fflush(stdout)
    }

    static func pretty(_ value: Any) -> String { JSON.pretty(value) }

    static func jsonString(_ value: Any) -> String { JSON.string(value) }
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
    static func load(limit: Int = 80) -> [[String: Any]] {
        Paths.ensureSupport()
        let root = Paths.transport.resolvingSymlinksInPath()
        let path = root.path
        if path.hasPrefix("/private/tmp") || path.hasPrefix("/tmp/") { return [] }
        guard let dirs = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey]) else { return [] }
        let files = dirs.map { $0.appendingPathComponent("transport.json") }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
            .sorted {
                let a = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let b = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return a > b
            }
            .prefix(limit)
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
        return rows
    }
}

// MARK: - Alerts via JavaScriptCore (same JS as app)

enum Alerts {
    /// evidence.py list_alerts: rule normalised ('INB'), INB alerts carry the finding with a redacted context.
    static func list(_ records: [[String: Any]], agent: String?, rule: String?, since: String?) -> [String: Any] {
        let (alerts, engine, warning) = build(records)
        var byCall: [String: [String: Any]] = [:]
        for r in records {
            for k in [str(r["call"]), str(r["runID"])].compactMap({ $0 }) where byCall[k] == nil { byCall[k] = r }
        }
        let sinceTs = Clock.parse(since)
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
            out.append(item)
        }
        var result: [String: Any] = [
            "alerts": Redact.any(out),
            "confidence": out.isEmpty ? "Unknown" : "Observed",
            "engine": engine,
            "note": "告警由本机运输审计 + 与 App 相同的 risk-alerts.js（JavaScriptCore）推导；无数据即为空，不放样本。",
        ]
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
    static func list(_ records: [[String: Any]]) -> [String: Any] {
        var by: [String: [String: Any]] = [:]
        for r in records {
            let agent = (r["agent"] as? String) ?? "Unknown"
            var bucket = by[agent] ?? ["agent": agent, "sessions": Set<String>(), "executionIds": [String](), "tools": Set<String>()]
            if let s = r["session"] as? String { var set = bucket["sessions"] as! Set<String>; set.insert(s); bucket["sessions"] = set }
            if let c = r["call"] as? String { var ids = bucket["executionIds"] as! [String]; ids.append(c); bucket["executionIds"] = ids }
            if let t = r["tool"] as? String { var set = bucket["tools"] as! Set<String>; set.insert(t); bucket["tools"] = set }
            by[agent] = bucket
        }
        let agents = by.keys.sorted().map { agent -> [String: Any] in
            let b = by[agent]!
            return [
                "agent": agent,
                "isCursor": agent == "Cursor",
                "sessions": Array(b["sessions"] as! Set<String>).sorted(),
                "executionIds": Array((b["executionIds"] as! [String]).prefix(40)),
                "tools": Array(b["tools"] as! Set<String>).sorted(),
                "confidence": (b["executionIds"] as! [String]).isEmpty ? "Unknown" : "Observed",
            ]
        }
        return ["agents": agents, "confidence": agents.isEmpty ? "Unknown" : "Observed",
                "note": "仅来自用户目录运输审计；不读 /private/tmp。"]
    }
}

enum Execution {
    /// evidence.py get_execution: findings (INB with redacted context) and the same destination fields as list_network.
    static func get(_ id: String, _ records: [[String: Any]]) -> [String: Any] {
        guard let hit = records.first(where: { str($0["call"]) == id || str($0["runID"]) == id }) else {
            return ["executionId": id, "confidence": "Unknown", "note": "未找到该执行编号的运输审计记录。"]
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

enum Network {
    static func list(_ records: [[String: Any]], agent: String?, since: String?, integrity: Integrity) -> [String: Any] {
        let rows = records.compactMap { r -> [String: Any]? in
            if let agent, agent != "all", str(r["agent"]) != agent { return nil }
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
        let sockets = SocketLedger.load(integrity, agent: agent, since: since)
        let connections = sockets["connections"] as? [[String: Any]] ?? []
        let coverage = sockets["coverage"] as? [String: Any] ?? [:]
        let direct = connections.filter { ($0["viaProxy"] as? Bool) == false && str($0["scope"]) == "public" }.count
        let proxied = connections.filter { ($0["viaProxy"] as? Bool) == true }.count
        return [
            "network": Redact.any(rows),
            "sockets": connections,
            "socketSummary": ["total": sockets["total"] ?? 0, "notViaProxyPublic": direct, "viaProxy": proxied,
                              "ledgerIntegrity": nn((coverage["integrity"] as? [String: Any])?["state"])] as [String: Any],
            "socketCoverage": coverage,
            "confidence": rows.isEmpty && connections.isEmpty ? "Unknown" : "Observed",
            "note": "network = 经审计入口的命令；realDestination/destinationSource/transportPeer 与 get_execution 同源："
                + "proxy_observed / connection_observed = trace 里看到（Observed），argv_parsed = 只从命令参数推出（Inferred），"
                + "transport_peer_only = 只知道本机代理口（Unknown）。sockets = 按进程采样的 TCP/UDP 连接，与是否走代理无关；"
                + "会漏掉短于实测间隔（socketCoverage.missesShorterThanSeconds）的连接。",
        ]
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

    static func load(_ integrity: Integrity, agent: String?, since: String?, limit: Int = 200) -> [String: Any] {
        let seal = SocketLedgerCore.sealPath(ledger: url, defaultLedger: defaultURL, integrityDir: Paths.integrityDir)
        let key = try? integrity.loadKey(create: false)
        return SocketLedgerCore.load(ledger: url, seal: seal, key: key, crypto: Ctx.crypto, agent: agent, since: since,
                                     limit: limit)
    }

    static func blindSpot(_ cov: [String: Any]) -> [String: Any] {
        guard str(cov["state"]) == "sampling" else {
            return ["topic": "未走代理流量", "confidence": "Unknown", "status": nn(cov["state"]),
                    "note": "socket-sampler 当前没有在采样（\(str(cov["state"]) ?? "?")）；不估算比例"]
        }
        func v(_ k: String) -> String { str(cov[k]) ?? "None" }
        return [
            "topic": "未走代理流量",
            "confidence": str(cov["measurementConfidence"]) == "Observed" ? "Observed" : "Unknown",
            "status": "sampled",
            "note": "按进程采样 TCP/UDP 连接：实测周期 p50 \(v("observedCycleSecondsP50"))s / p95 \(v("observedCycleSecondsP95"))s，"
                + "最长首次发现延迟 \(v("maxFirstDetectionDelaySeconds"))s，短于 \(v("missesShorterThanSeconds"))s 的连接可能漏掉"
                + "（最近一次 \(v("lastSampleAt"))；失败 \(v("failures")) 次）；系统解析器发出的 DNS 不可见",
        ]
    }
}

enum Coverage {
    static func get(_ integrity: Integrity) -> [String: Any] {
        let validation = integrity.validate()
        let ledger = SocketLedger.load(integrity, agent: nil, since: nil, limit: 0)["coverage"] as? [String: Any] ?? [:]
        return [
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
                ["topic": "SSH 通道内正文", "confidence": "Unknown", "note": "只看到连到哪台主机"],
            ],
            "evidenceIntegrity": validation,
            "integritySummary": Integrity.summary(validation),
            "socketLedgerIntegrity": nn(ledger["integrity"]),
            "transportRoot": Paths.transport.path,
            "legacyPathPolicy": "never_read_/private/tmp",
            "runtime": "swift-mcp-no-system-node-python",
            "confidence": "Unknown",
        ]
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

    static func integrity() -> Integrity {
        Paths.ensureSupport()
        return Integrity(auditDir: Paths.support, integrityDir: Paths.integrityDir, transport: Paths.transport,
                         keychain: CachedKeychain(HelperKeychain(helper: HelperKeychain.packaged())), crypto: crypto)
    }

    /// Without the Keychain key nothing is signed (never a throwaway file key); the read itself is still answered
    /// and get_coverage reports status key_unavailable.
    static func appendAudit(_ integrity: Integrity, actor: String, tool: String, arguments: [String: Any]) {
        guard let key = try? integrity.loadKey() else { return }
        integrity.append(actor: actor, tool: tool, arguments: arguments, key: key)
    }

    static func recent(_ integrity: Integrity, limit: Int) -> [[String: Any]] {
        Array(integrity.lines().suffix(max(0, limit))).compactMap { JSON.object($0) }
    }
}
