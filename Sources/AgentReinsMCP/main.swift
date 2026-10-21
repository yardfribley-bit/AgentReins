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
        if ProcessInfo.processInfo.environment["AGENTREINS_REDACT_SELFTEST"] == "1" {
            Redact.selfTestAndExit()
        }
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
            ["name": "list_network", "description": "Outbound network summary.",
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
        Audit.append(actor: actorName, tool: name, arguments: args)
        let records = Transport.load()
        switch name {
        case "list_agents":
            return Agents.list(records)
        case "list_alerts":
            return Alerts.list(records, agent: args["agent"] as? String, rule: args["rule"] as? String)
        case "get_execution":
            guard let eid = args["execution_id"] as? String else {
                throw NSError(domain: "AgentReinsMCP", code: 3, userInfo: [NSLocalizedDescriptionKey: "execution_id required"])
            }
            return Execution.get(eid, records)
        case "list_network":
            return Network.list(records, agent: args["agent"] as? String)
        case "get_coverage":
            return Coverage.get()
        case "list_mcp_audit":
            let limit = (args["limit"] as? Int) ?? 30
            return ["entries": Audit.recent(limit: limit), "validation": Audit.validate(), "confidence": "Observed"]
        default:
            throw NSError(domain: "AgentReinsMCP", code: 2, userInfo: [NSLocalizedDescriptionKey: name])
        }
    }

    static func respond(_ id: Any?, _ result: Any) {
        guard id != nil else { return }
        var out: [String: Any] = ["jsonrpc": "2.0", "id": id as Any, "result": result]
        print(jsonString(out))
        fflush(stdout)
    }

    static func respondError(_ id: Any?, _ code: Int, _ message: String) {
        var out: [String: Any] = ["jsonrpc": "2.0", "id": id as Any, "error": ["code": code, "message": message]]
        print(jsonString(out))
        fflush(stdout)
    }

    static func pretty(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]),
              let s = String(data: data, encoding: .utf8) else { return "\(value)" }
        return s
    }

    static func jsonString(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
              let s = String(data: data, encoding: .utf8) else { return "{}" }
        return s
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
    static var hmacKey: URL { support.appendingPathComponent("mcp-supervisor-hmac.key") }
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

// MARK: - Redaction (shared vectors with tools/redact_secrets.py)

enum Redact {
    static func text(_ input: String) -> String {
        var out = input
        let patterns: [(String, String)] = [
            (#"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#, "[pem:REDACTED]"),
            (#"(?i)((?:https?|postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://)([^/\s]+)@"#, "$1[url_userinfo:REDACTED]@"),
            (#"(?i)(-uX?|--user|--username)(=)(\S+:\S+)"#, "$1$2[userpass:REDACTED]"),
            (#"(?i)(-u)([^\s:=/-][^:\s]*:[^\s]+)"#, "$1[userpass:REDACTED]"),
            (#"(?i)(-uX?|--user|--username)(\s+)(['\"])([^'\"]+:[^'\"]+)\3"#, "$1$2$3[userpass:REDACTED]$3"),
            (#"(?i)(-uX?|--user|--username)(\s+)(\S+:\S+)"#, "$1$2[userpass:REDACTED]"),

            (#"(?i)(\"(?:password|passwd|pwd|secret|client_secret|db_password)\"\s*:\s*\")([^\"\\]*(?:\\.[^\"\\]*)*)(\")"#, "$1[password:REDACTED]$3"),
            (#"(?i)((?:password|passwd|pwd|secret|client_secret|db_password)\s*[=:]\s*)(['\"])([^'\"]+)\2"#, "$1$2[password:REDACTED]$2"),
            (#"(?i)((?:export\s+)?(?:API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|TOKEN)\s*=\s*)([^\s'\"&,;]+)"#, "$1[token:REDACTED]"),
            (#"(?i)((?:export\s+)?(?:password|passwd|pwd|secret|client_secret|db_password|[_A-Z0-9]*(?:_PASS|_SECRET|_PASSWORD))\s*[=:]\s*)([^\s'\"&,;]+)"#, "$1[password:REDACTED]"),
            (#"(?i)(--password)(\s+|=)(\S+)"#, "$1$2[password:REDACTED]"),
            (#"(?i)(\b(?:mysql|mysqldump|sshpass|mariadb)\b(?:\s+\S+){0,6}\s+-p)(\s+)(?:'([^']*)'|\"([^\"]*)\"|(\S+))"#, "$1$2[password:REDACTED]"),
            (#"(?i)(\b(?:mysql|mysqldump|sshpass|mariadb)\b(?:\s+\S+){0,6}\s+-p)([^\s\-]+)"#, "$1[password:REDACTED]"),
            (#"(?i)((?:Cookie|Set-Cookie)\s*[:=]\s*)([^\r\n]+)"#, "$1[cookie:REDACTED]"),
            (#"(?i)((?:X-Api-Key|x-api-key)\s*[:=]\s*)(\S+)"#, "$1[api_key:REDACTED]"),
            (#"(?i)(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+)"#, "$1[basic:REDACTED]"),
            (#"(?i)(Bearer\s+)(\S+)"#, "$1[bearer:REDACTED]"),
            (#"\b(AKIA[0-9A-Z]{16})\b"#, "[aws_access_key:REDACTED]"),
            (#"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)(['\"])([A-Za-z0-9/+=]{20,})\2"#, "$1$2[aws_secret:REDACTED]$2"),
            (#"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"#, "$1[aws_secret:REDACTED]"),
            (#"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"#, "[credential:REDACTED]"),
        ]
        for (pattern, template) in patterns {
            if let re = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) {
                out = re.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: template)
            }
        }
        return out
    }

    static func any(_ value: Any) -> Any {
        if let s = value as? String { return text(s) }
        if let arr = value as? [Any] { return arr.map { any($0) } }
        if let dict = value as? [String: Any] {
            var out: [String: Any] = [:]
            for (k, v) in dict {
                let key = k.lowercased()
                if key.contains("password") || key.contains("secret") || key == "token"
                    || key == "authorization" || key == "cookie" || key == "x-api-key" || key == "pwd" {
                    if let list = v as? [Any] {
                        out[k] = list.map { $0 is String ? "[key:\(k):REDACTED]" : any($0) }
                    } else if v is String {
                        out[k] = "[key:\(k):REDACTED]"
                    } else {
                        out[k] = any(v)
                    }
                } else {
                    out[k] = any(v)
                }
            }
            return out
        }
        return value
    }

    /// Load tools/redact_vectors.json (or packaged copy) and exit 0/1.
    static func selfTestAndExit() -> Never {
        let candidates = [
            URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
                .deletingLastPathComponent().appendingPathComponent("Resources/agentreins-mcp/redact_vectors.json"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("tools/redact_vectors.json"),
        ]
        guard let url = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
              let data = try? Data(contentsOf: url),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            fputs("REDACT_VECTOR_FAIL missing vectors\n", stderr)
            exit(1)
        }
        var failures = 0
        for caseRow in rows {
            let name = caseRow["name"] as? String ?? "?"
            let kind = caseRow["kind"] as? String ?? "text"
            if kind == "text", let input = caseRow["input"] as? String {
                let out = text(input)
                for secret in (caseRow["must_absent"] as? [String] ?? []) where !secret.isEmpty && out.contains(secret) {
                    fputs("fail \(name): still present \(secret)\n", stderr); failures += 1
                }
                for keep in (caseRow["must_keep"] as? [String] ?? []) where !keep.isEmpty && !out.contains(keep) {
                    fputs("fail \(name): false positive removed \(keep)\n", stderr); failures += 1
                }
            } else if kind == "obj", let input = caseRow["input"] {
                let out = any(input)
                let blob = AgentReinsMCP.jsonString(out)
                for secret in (caseRow["must_absent"] as? [String] ?? []) where !secret.isEmpty && blob.contains(secret) {
                    fputs("fail \(name): obj still present \(secret)\n", stderr); failures += 1
                }
            }
        }
        if failures > 0 {
            fputs("REDACT_VECTOR_FAIL \(failures)\n", stderr)
            exit(1)
        }
        fputs("REDACT_VECTOR_OK \(rows.count)\n", stdout)
        exit(0)
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
    static func list(_ records: [[String: Any]], agent: String?, rule: String?) -> [String: Any] {
        let (alerts, engine, warning) = build(records)
        var out = alerts
        if let agent, agent != "all" {
            out = out.filter { ($0["agent"] as? String) == agent }
        }
        if let rule, rule != "all" {
            out = out.filter { ($0["rule"] as? String) == rule }
        }
        var result: [String: Any] = [
            "alerts": Redact.any(out) as Any,
            "confidence": out.isEmpty ? "Unknown" : "Observed",
            "engine": engine,
            "note": "告警由本机运输审计 + 与 App 相同的 risk-alerts.js（JavaScriptCore）推导。",
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
            timestamp:a.timestamp, why:a.why, evidence:a.evidence||null, executionId:a.call
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
    static func get(_ id: String, _ records: [[String: Any]]) -> [String: Any] {
        guard let hit = records.first(where: { ($0["call"] as? String) == id || ($0["runID"] as? String) == id }) else {
            return ["executionId": id, "confidence": "Unknown", "note": "未找到该执行编号的运输审计记录。"]
        }
        let downloads = ((hit["downloads"] as? [[String: Any]]) ?? []).compactMap { d -> [String: Any]? in
            guard d["path"] != nil else { return nil }
            return ["path": d["path"] as Any, "sha256": d["sha256"] as Any, "bytes": d["bytes"] as Any,
                    "confidence": d["sha256"] != nil ? "Observed" : "Unknown"]
        }
        return Redact.any([
            "executionId": hit["call"] ?? hit["runID"] as Any,
            "agent": hit["agent"] as Any,
            "session": hit["session"] as Any,
            "tool": hit["tool"] as Any,
            "commandArgs": hit["args"] as Any,
            "startedAt": hit["startedAt"] as Any,
            "exitCode": hit["exitCode"] as Any,
            "auditBypass": (hit["auditBypass"] as? Bool) == true,
            "downloads": downloads,
            "confidence": "Observed",
            "note": "正文已脱敏；不读 /private/tmp。",
        ]) as! [String: Any]
    }
}

enum Network {
    static func list(_ records: [[String: Any]], agent: String?) -> [String: Any] {
        let rows = records.compactMap { r -> [String: Any]? in
            if let agent, agent != "all", (r["agent"] as? String) != agent { return nil }
            return [
                "executionId": r["call"] ?? r["runID"] as Any,
                "agent": r["agent"] as Any,
                "tool": r["tool"] as Any,
                "auditBypass": (r["auditBypass"] as? Bool) == true,
                "startedAt": r["startedAt"] as Any,
                "confidence": "Observed",
            ]
        }
        return ["network": Redact.any(rows) as Any, "confidence": rows.isEmpty ? "Unknown" : "Observed"]
    }
}

enum Coverage {
    static func get() -> [String: Any] {
        ["rules": [
            ["id": "S01", "status": "blind", "confidence": "Unknown"],
            ["id": "S03", "status": "supported", "confidence": "Correlated"],
            ["id": "S07", "status": "supported", "confidence": "Observed"],
        ],
         "evidenceIntegrity": Audit.validate(),
         "transportRoot": Paths.transport.path,
         "legacyPathPolicy": "never_read_/private/tmp",
         "runtime": "swift-mcp-no-system-node-python",
         "confidence": "Observed"]
    }
}

// MARK: - HMAC audit + seal + evidence MAC

enum Audit {
    static func key() -> SymmetricKey {
        Paths.ensureSupport()
        let url = Paths.hmacKey
        if let data = try? Data(contentsOf: url), data.count >= 16 {
            return SymmetricKey(data: data)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let data = Data(bytes)
        try? data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return SymmetricKey(data: data)
    }

    static func macHex(_ message: String, key: SymmetricKey) -> String {
        let digest = HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: key)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static func sha256Hex(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func append(actor: String, tool: String, arguments: [String: Any]) {
        Paths.ensureSupport()
        let key = key()
        var prev = String(repeating: "0", count: 64)
        var count = 0
        if let text = try? String(contentsOf: Paths.auditLog, encoding: .utf8) {
            let lines = text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.isEmpty }
            count = lines.count
            if let last = lines.last, let obj = try? JSONSerialization.jsonObject(with: Data(last.utf8)) as? [String: Any],
               let h = obj["hash"] as? String { prev = h }
        }
        let argsDigest = String(sha256Hex(AgentReinsMCP.jsonString(arguments)).prefix(24))
        var body: [String: Any] = [
            "at": ISO8601DateFormatter().string(from: Date()),
            "actor": actor, "tool": tool, "argsDigest": argsDigest, "prevHash": prev,
        ]
        let bodyText = AgentReinsMCP.jsonString(body)
        body["mac"] = macHex(bodyText, key: key)
        body["hash"] = sha256Hex(AgentReinsMCP.jsonString(body) + prev)
        let line = AgentReinsMCP.jsonString(body) + "\n"
        if let handle = try? FileHandle(forWritingTo: Paths.auditLog) {
            defer { try? handle.close() }
            try? handle.seekToEnd()
            try? handle.write(contentsOf: Data(line.utf8))
        } else {
            try? line.write(to: Paths.auditLog, atomically: true, encoding: .utf8)
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: Paths.auditLog.path)
        var seal: [String: Any] = ["headHash": body["hash"] as Any, "count": count + 1, "schema": 1]
        seal["mac"] = macHex(AgentReinsMCP.jsonString(seal), key: key)
        try? AgentReinsMCP.jsonString(seal).write(to: Paths.auditSeal, atomically: true, encoding: .utf8)
        // Do not re-sign evidence on MCP read — collection-time signing only (B3).
    }

    static func recent(limit: Int) -> [[String: Any]] {
        guard let text = try? String(contentsOf: Paths.auditLog, encoding: .utf8) else { return [] }
        let lines = text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.isEmpty }.suffix(limit)
        return lines.compactMap { line in
            guard let data = line.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            return obj
        }
    }

    static func validate() -> [String: Any] {
        var result: [String: Any] = [
            "mode": "keyed-HMAC-SHA256 append-only + seal + evidence MAC",
            "ok": true, "entriesChecked": 0, "tampered": [[String: Any]](), "deletedOrGap": [[String: Any]](),
            "legacyPathPolicy": "never_read_/private/tmp", "confidence": "Observed",
        ]
        guard let text = try? String(contentsOf: Paths.auditLog, encoding: .utf8) else {
            result["note"] = "尚无审计日志"
            return result
        }
        let key = key()
        let lines = text.split(whereSeparator: \.isNewline).map(String.init).filter { !$0.isEmpty }
        var prev = String(repeating: "0", count: 64)
        var seenSigned = false
        var head = prev
        var tampered = [[String: Any]]()
        var gaps = [[String: Any]]()
        for (idx, line) in lines.enumerated() {
            guard let data = line.data(using: .utf8),
                  let entry = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                tampered.append(["index": idx, "reason": "invalid_json"]); continue
            }
            result["entriesChecked"] = (result["entriesChecked"] as? Int ?? 0) + 1
            if (entry["prevHash"] as? String) != prev {
                gaps.append(["index": idx, "reason": "prevHash_mismatch"])
            }
            var body: [String: Any] = [:]
            for k in ["at", "actor", "tool", "argsDigest", "prevHash"] {
                if let v = entry[k] { body[k] = v }
            }
            if entry["mac"] == nil {
                if seenSigned {
                    tampered.append(["index": idx, "reason": "missing_mac_after_signed_era"])
                }
            } else {
                seenSigned = true
                let expected = macHex(AgentReinsMCP.jsonString(body), key: key)
                if (entry["mac"] as? String) != expected {
                    tampered.append(["index": idx, "reason": "mac_mismatch"])
                }
            }
            prev = (entry["hash"] as? String) ?? prev
            head = prev
        }
        if let sealData = try? Data(contentsOf: Paths.auditSeal),
           let seal = try? JSONSerialization.jsonObject(with: sealData) as? [String: Any] {
            var sealBody: [String: Any] = [:]
            for k in ["headHash", "count", "schema"] { if let v = seal[k] { sealBody[k] = v } }
            if (seal["mac"] as? String) != macHex(AgentReinsMCP.jsonString(sealBody), key: key) {
                tampered.append(["reason": "seal_mac_mismatch"])
            } else if (seal["count"] as? Int) != (result["entriesChecked"] as? Int)
                        || (seal["headHash"] as? String) != head {
                gaps.append(["reason": "truncated_or_count_mismatch", "sealCount": seal["count"] as Any,
                             "actualCount": result["entriesChecked"] as Any])
            }
        }
        // Evidence file MACs
        if let dirs = try? FileManager.default.contentsOfDirectory(at: Paths.transport, includingPropertiesForKeys: nil) {
            let files = dirs.flatMap { dir in ["transport.json", "manifest.json"].map { dir.appendingPathComponent($0) } }
                .filter { FileManager.default.fileExists(atPath: $0.path) }
            let anyMac = files.contains { FileManager.default.fileExists(atPath: $0.appendingPathExtension("mac").path) }
            for file in files {
                let macFile = file.appendingPathExtension("mac")
                if !FileManager.default.fileExists(atPath: macFile.path) {
                    if anyMac { tampered.append(["path": file.path, "reason": "missing_mac_after_signed_era"]) }
                    continue
                }
                guard let data = try? Data(contentsOf: file),
                      let expectedRaw = try? String(contentsOf: macFile, encoding: .utf8) else { continue }
                let expected = expectedRaw.trimmingCharacters(in: .whitespacesAndNewlines)
                let actual = HMAC<SHA256>.authenticationCode(for: data, using: key).map { String(format: "%02x", $0) }.joined()
                if actual != expected {
                    tampered.append(["path": file.path, "reason": "evidence_mac_mismatch"])
                }
            }
        }
        result["tampered"] = tampered
        result["deletedOrGap"] = gaps
        result["ok"] = tampered.isEmpty && gaps.isEmpty
        return result
    }
}
