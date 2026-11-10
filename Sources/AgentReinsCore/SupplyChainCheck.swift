import Foundation

/// Looks at a fixed set of MCP configs and the top of skill/rule/plugin folders.
/// A new or changed entry becomes a card. Env values are never stored.
/// Decisions stay local. This type does not write agent config files.
public enum SupplyChainCheck {
    public enum Failure: Error, Equatable {
        case noteRequired
        case unknownEntry
    }

    private static let lock = NSLock()
    private static let headBytes = 256 * 1024
    private static let tailBytes = 64 * 1024
    private static let skillBytes = 16 * 1024
    private static let dirCap = 40
    private static let projectCap = 6
    private static let skipNames: Set<String> = [
        "node_modules", ".git", "cache", "__pycache__", "dist", ".venv", "venv",
        "skills-cursor", "sessions", "projects", "logs",
    ]
    private static let credParts = [
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY",
        "PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY", "SESSION",
    ]
    private static let authHeaders: Set<String> = [
        "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token",
    ]
    public static let disposition = "只展示。允许和拒绝记在本机。没有改写任何 agent 的 MCP 配置。拒绝只标出来并告警，没有拦住进程。"

    public static func storeURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_SUPPLY_STORE"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentReins", isDirectory: true)
            .appendingPathComponent("supply-chain.json")
    }

    public static func homeURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_SUPPLY_HOME"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    public static func projectURLs() -> [URL] {
        let env = ProcessInfo.processInfo.environment["AGENTREINS_SUPPLY_PROJECTS"] ?? ""
        let parts = env.split(whereSeparator: { $0 == ":" || $0 == "\n" }).map(String.init)
        return parts.filter { !$0.isEmpty }.prefix(projectCap).map { URL(fileURLWithPath: $0) }
    }

    public static func watchPaths(home: URL, projects: [URL]) -> [String] {
        var urls = [
            at(home, ".claude"),
            at(home, ".cursor"),
            at(home, ".codex"),
            at(home, ".agents"),
            at(home, ".workbuddy"),
            at(home, ".claude.json"),
            at(home, ".cursor/mcp.json"),
            at(home, ".codex/config.toml"),
            at(home, ".claude/mcp.json"),
            at(home, ".claude/skills"),
            at(home, ".cursor/skills"),
            at(home, ".codex/skills"),
        ]
        for project in projects.prefix(projectCap) {
            urls.append(at(project, ".cursor"))
            urls.append(at(project, ".claude"))
            urls.append(at(project, ".mcp.json"))
            urls.append(at(project, ".cursor/rules"))
            urls.append(at(project, ".cursor/mcp.json"))
        }
        var seen = Set<String>()
        var out: [String] = []
        for url in urls where exists(url) && seen.insert(url.path).inserted {
            out.append(url.path)
            if out.count >= 24 { break }
        }
        return out
    }

    // MARK: - store

    public static func load(store: URL) -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return loadUnlocked(store)
    }

    public static func observe(home: URL, store: URL, projects: [URL]? = nil, now: Date = Date()) -> [String: Any] {
        let current = scan(home: home, projects: projects)
        lock.lock()
        defer { lock.unlock() }
        let doc = loadUnlocked(store)
        let stamp = iso(now)
        let decisions = (doc["decisions"] as? [[String: Any]]) ?? []
        let alerts = (doc["alerts"] as? [[String: Any]]) ?? []
        if (doc["baselined"] as? Bool) != true {
            let stamped = current.map { stampSeen($0, previous: nil, now: stamp, fresh: false) }
            let next: [String: Any] = [
                "version": 1, "baselined": true, "scannedAt": stamp,
                "entries": stamped, "pending": [String](), "decisions": decisions, "alerts": alerts,
            ]
            writeUnlocked(next, store)
            return loadUnlocked(store)
        }
        let previous = Dictionary(uniqueKeysWithValues: ((doc["entries"] as? [[String: Any]]) ?? []).compactMap { entry -> (String, [String: Any])? in
            guard let id = entry["id"] as? String else { return nil }
            return (id, entry)
        })
        var pending: [String] = []
        var merged: [[String: Any]] = []
        for entry in current {
            let id = entry["id"] as? String ?? ""
            let old = previous[id]
            let same = old?["fingerprint"] as? String == entry["fingerprint"] as? String
            let stamped = stampSeen(entry, previous: old, now: stamp, fresh: !same)
            if !same && !closed(stamped, decisions) {
                pending.append(id)
            }
            merged.append(stamped)
        }
        let next: [String: Any] = [
            "version": 1, "baselined": true, "scannedAt": stamp,
            "entries": merged, "pending": pending, "decisions": decisions, "alerts": alerts,
        ]
        writeUnlocked(next, store)
        return loadUnlocked(store)
    }

    @discardableResult
    public static func approve(id: String, note: String, store: URL, now: Date = Date()) throws -> [String: Any] {
        let cleaned = note.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { throw Failure.noteRequired }
        return try decide(id: id, state: "approved", note: String(cleaned.prefix(500)), store: store, now: now, alert: false)
    }

    @discardableResult
    public static func reject(id: String, note: String, store: URL, now: Date = Date()) throws -> [String: Any] {
        let cleaned = note.trimmingCharacters(in: .whitespacesAndNewlines)
        let stored = cleaned.isEmpty ? "拒绝" : String(cleaned.prefix(500))
        return try decide(id: id, state: "rejected", note: stored, store: store, now: now, alert: true)
    }

    public static func toolPayload(store: URL, agent: String? = nil, limit: Int? = nil, offset: Int = 0) -> [String: Any] {
        let doc = load(store: store)
        let entries = (doc["entries"] as? [[String: Any]]) ?? []
        let pairs: [(String, [String: Any])] = entries.compactMap { entry in
            guard let id = entry["id"] as? String else { return nil }
            return (id, entry)
        }
        let byID = Dictionary(uniqueKeysWithValues: pairs)
        var pending = ((doc["pending"] as? [String]) ?? []).compactMap { byID[$0] }
        if let agent, agent != "all" {
            pending = pending.filter { ($0["agent"] as? String) == agent }
        }
        let start = max(0, offset)
        let page: [[String: Any]]
        if let limit {
            page = Array(pending.dropFirst(start).prefix(max(0, limit)))
        } else {
            page = Array(pending.dropFirst(start))
        }
        return [
            "schema": "agentreins.supply-chain.v1",
            "readOnly": true,
            "configEdited": false,
            "enforced": false,
            "blocked": false,
            "disposition": disposition,
            "scannedAt": doc["scannedAt"] as? String ?? "",
            "baselined": (doc["baselined"] as? Bool) == true,
            "pending": page,
            "decisions": (doc["decisions"] as? [[String: Any]]) ?? [],
            "alerts": (doc["alerts"] as? [[String: Any]]) ?? [],
            "total": pending.count,
            "offset": start,
            "limit": limit ?? NSNull(),
        ]
    }

    // MARK: - scan

    public static func scan(home: URL, projects: [URL]? = nil) -> [[String: Any]] {
        let chosen = Array((projects ?? discoverProjects(home)).prefix(projectCap))
        var used = Set<String>()
        var entries: [[String: Any]] = []
        let configs: [(URL, String)] = [
            (at(home, ".claude.json"), "Claude Code"),
            (at(home, ".claude/settings.json"), "Claude Code"),
            (at(home, ".claude/mcp.json"), "Claude Code"),
            (at(home, ".cursor/mcp.json"), "Cursor"),
            (at(home, ".codex/config.toml"), "Codex"),
            (at(home, ".workbuddy/mcp.json"), "WorkBuddy"),
            (at(home, ".codebuddy/mcp.json"), "WorkBuddy"),
        ]
        for (url, agent) in configs {
            entries.append(contentsOf: entriesFromMCP(url, agent: agent, home: home, used: &used))
        }
        let skills: [(URL, String, String)] = [
            (at(home, ".claude/skills"), "Claude Code", "skill"),
            (at(home, ".cursor/skills"), "Cursor", "skill"),
            (at(home, ".codex/skills"), "Codex", "skill"),
            (at(home, ".agents/skills"), "通用", "skill"),
            (at(home, ".workbuddy/skills"), "WorkBuddy", "skill"),
        ]
        for (url, agent, kind) in skills {
            entries.append(contentsOf: entriesFromDir(url, agent: agent, kind: kind, home: home, used: &used))
        }
        for (url, agent) in [(at(home, ".claude/plugins"), "Claude Code"), (at(home, ".cursor/plugins"), "Cursor")] {
            entries.append(contentsOf: entriesFromPlugins(url, agent: agent, home: home, used: &used))
        }
        for project in chosen {
            entries.append(contentsOf: entriesFromMCP(at(project, ".mcp.json"), agent: "Claude Code", home: home, used: &used))
            entries.append(contentsOf: entriesFromMCP(at(project, ".cursor/mcp.json"), agent: "Cursor", home: home, used: &used))
            entries.append(contentsOf: entriesFromMCP(at(project, ".codex/config.toml"), agent: "Codex", home: home, used: &used))
            entries.append(contentsOf: entriesFromDir(at(project, ".claude/skills"), agent: "Claude Code", kind: "skill", home: home, used: &used))
            entries.append(contentsOf: entriesFromDir(at(project, ".cursor/skills"), agent: "Cursor", kind: "skill", home: home, used: &used))
            entries.append(contentsOf: entriesFromDir(at(project, ".cursor/rules"), agent: "Cursor", kind: "rule", home: home, used: &used))
            entries.append(contentsOf: entriesFromDir(at(project, ".agents/skills"), agent: "通用", kind: "skill", home: home, used: &used))
            entries.append(contentsOf: entriesFromDir(at(project, ".codex/skills"), agent: "Codex", kind: "skill", home: home, used: &used))
        }
        var seen = Set<String>()
        return entries.filter { entry in
            guard let id = entry["id"] as? String else { return false }
            return seen.insert(id).inserted
        }
    }

    // MARK: - private store

    private static func emptyDoc() -> [String: Any] {
        ["version": 1, "baselined": false, "scannedAt": "", "entries": [[String: Any]](), "pending": [String](), "decisions": [[String: Any]](), "alerts": [[String: Any]]()]
    }

    private static func loadUnlocked(_ store: URL) -> [String: Any] {
        guard let data = try? Data(contentsOf: store),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return emptyDoc() }
        var doc = emptyDoc()
        for key in doc.keys {
            if let value = obj[key] { doc[key] = value }
        }
        return doc
    }

    private static func writeUnlocked(_ doc: [String: Any], _ store: URL) {
        try? FileManager.default.createDirectory(at: store.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard var data = try? JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys]) else { return }
        data.append(0x0A)
        try? data.write(to: store, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: store.path)
    }

    private static func stampSeen(_ entry: [String: Any], previous: [String: Any]?, now: String, fresh: Bool) -> [String: Any] {
        var copy = entry
        if fresh {
            copy["firstSeenAt"] = (previous?["firstSeenAt"] as? String) ?? now
            copy["changedAt"] = now
        } else if let previous {
            copy["firstSeenAt"] = (previous["firstSeenAt"] as? String) ?? now
            copy["changedAt"] = (previous["changedAt"] as? String) ?? now
        } else {
            copy["firstSeenAt"] = now
            copy["changedAt"] = now
        }
        return copy
    }

    private static func closed(_ entry: [String: Any], _ decisions: [[String: Any]]) -> Bool {
        let id = entry["id"] as? String ?? ""
        let fingerprint = entry["fingerprint"] as? String ?? ""
        return decisions.contains { decision in
            decision["id"] as? String == id
                && decision["fingerprint"] as? String == fingerprint
                && (decision["state"] as? String == "approved" || decision["state"] as? String == "rejected")
        }
    }

    private static func decide(id: String, state: String, note: String, store: URL, now: Date, alert: Bool) throws -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        var doc = loadUnlocked(store)
        let entries = (doc["entries"] as? [[String: Any]]) ?? []
        guard let entry = entries.first(where: { $0["id"] as? String == id }) else { throw Failure.unknownEntry }
        let stamp = iso(now)
        let decision: [String: Any] = [
            "id": id,
            "state": state,
            "note": note,
            "decidedAt": stamp,
            "fingerprint": entry["fingerprint"] as? String ?? "",
            "summary": entry["summary"] as? String ?? "",
            "blocked": false,
            "alerted": alert,
            "configEdited": false,
        ]
        var decisions = (doc["decisions"] as? [[String: Any]]) ?? []
        decisions.removeAll { $0["id"] as? String == id && $0["fingerprint"] as? String == decision["fingerprint"] as? String }
        decisions.insert(decision, at: 0)
        doc["decisions"] = decisions
        if alert {
            let kind = kindName(entry["kind"] as? String ?? "")
            let title = "拒绝了新加的\(kind)：\(entry["name"] as? String ?? id)"
            let flags = ((entry["flags"] as? [[String: Any]]) ?? []).compactMap { $0["id"] as? String }
            let row: [String: Any] = [
                "id": "supply-alert:" + id,
                "entryId": id,
                "agent": entry["agent"] as? String ?? "",
                "title": title,
                "summary": entry["summary"] as? String ?? "",
                "at": stamp,
                "blocked": false,
                "disposition": "已记下，未拦截",
                "flags": flags,
            ]
            var alerts = (doc["alerts"] as? [[String: Any]]) ?? []
            alerts.removeAll { $0["id"] as? String == row["id"] as? String }
            alerts.insert(row, at: 0)
            doc["alerts"] = alerts
        }
        doc["pending"] = ((doc["pending"] as? [String]) ?? []).filter { $0 != id }
        writeUnlocked(doc, store)
        return decision
    }

    private static func kindName(_ kind: String) -> String {
        switch kind {
        case "skill": return "技能"
        case "rule": return "规则"
        case "plugin": return "插件"
        default: return "MCP"
        }
    }

    // MARK: - files

    private static func entriesFromMCP(_ url: URL, agent: String, home: URL, used: inout Set<String>) -> [[String: Any]] {
        guard isFile(url) else { return [] }
        if url.pathExtension == "toml" || url.lastPathComponent == "config.toml" {
            return parseCodex(readCapped(url, headBytes)).compactMap { spec in
                entryFromSpec(agent: agent, name: spec["name"] as? String ?? "mcp", spec: spec, configPath: url.path, home: home, used: &used)
            }
        }
        var out: [[String: Any]] = []
        for servers in mcpMaps(readHeadTail(url)) {
            for (name, value) in Array(servers.prefix(40)) {
                guard let spec = value as? [String: Any] else { continue }
                if let built = entryFromSpec(agent: agent, name: name, spec: spec, configPath: url.path, home: home, used: &used) {
                    out.append(built)
                }
            }
        }
        return out
    }

    private static func entriesFromDir(_ url: URL, agent: String, kind: String, home: URL, used: inout Set<String>) -> [[String: Any]] {
        guard isDir(url) else { return [] }
        var out: [[String: Any]] = []
        for name in children(url) {
            let child = url.appendingPathComponent(name)
            if kind == "rule" {
                if isFile(child) && (name.hasSuffix(".md") || name.hasSuffix(".mdc")) {
                    let stem = (name as NSString).deletingPathExtension
                    out.append(entryFromText(agent: agent, kind: "rule", name: stem, text: readCapped(child, skillBytes), configPath: child.path, home: home, used: &used))
                } else if isDir(child) && isFile(child.appendingPathComponent("RULE.md")) {
                    let rule = child.appendingPathComponent("RULE.md")
                    out.append(entryFromText(agent: agent, kind: "rule", name: name, text: readCapped(rule, skillBytes), configPath: rule.path, home: home, used: &used))
                }
                continue
            }
            if isDir(child) && isFile(child.appendingPathComponent("SKILL.md")) {
                let skill = child.appendingPathComponent("SKILL.md")
                out.append(entryFromText(agent: agent, kind: "skill", name: name, text: readCapped(skill, skillBytes), configPath: skill.path, home: home, used: &used))
            } else if isFile(child) && name.hasSuffix(".md") {
                let stem = (name as NSString).deletingPathExtension
                out.append(entryFromText(agent: agent, kind: "skill", name: stem, text: readCapped(child, skillBytes), configPath: child.path, home: home, used: &used))
            }
        }
        return out
    }

    private static func entriesFromPlugins(_ url: URL, agent: String, home: URL, used: inout Set<String>) -> [[String: Any]] {
        guard isDir(url) else { return [] }
        var out: [[String: Any]] = []
        for name in children(url) {
            let child = url.appendingPathComponent(name)
            guard isDir(child) else { continue }
            for rel in ["plugin.json", ".claude-plugin/plugin.json"] {
                let manifest = at(child, rel)
                guard isFile(manifest) else { continue }
                let text = readCapped(manifest, 32 * 1024)
                if let data = text.data(using: .utf8),
                   let doc = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let servers = doc["mcpServers"] as? [String: Any] {
                    for (serverName, value) in Array(servers.prefix(20)) {
                        guard let spec = value as? [String: Any] else { continue }
                        if let built = entryFromSpec(agent: agent, name: serverName, spec: spec, configPath: manifest.path, home: home, used: &used) {
                            out.append(built)
                        }
                    }
                } else {
                    let label = (text.isEmpty ? name : frontName(text, fallback: name))
                    out.append(entryFromText(agent: agent, kind: "plugin", name: label, text: String(text.prefix(2000)), configPath: manifest.path, home: home, used: &used))
                }
                break
            }
            if isFile(child.appendingPathComponent("SKILL.md")) {
                let skill = child.appendingPathComponent("SKILL.md")
                out.append(entryFromText(agent: agent, kind: "skill", name: name, text: readCapped(skill, skillBytes), configPath: skill.path, home: home, used: &used))
            }
            out.append(contentsOf: entriesFromDir(child.appendingPathComponent("skills"), agent: agent, kind: "skill", home: home, used: &used))
        }
        return out
    }

    private static func discoverProjects(_ home: URL) -> [URL] {
        let root = at(home, ".claude/projects")
        guard isDir(root) else { return [] }
        let names = Array(children(root, limit: 80))
        var scored: [(Date, String)] = []
        for name in names {
            let url = root.appendingPathComponent(name)
            guard isDir(url), let date = (try? FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date) else { continue }
            scored.append((date, name))
        }
        scored.sort { $0.0 > $1.0 }
        var found: [URL] = []
        for (_, name) in scored where name.hasPrefix("-") {
            let decoded = "/" + name.dropFirst().replacingOccurrences(of: "-", with: "/")
            if decoded.split(separator: "/").count < 2 { continue }
            if isDir(URL(fileURLWithPath: decoded)) {
                found.append(URL(fileURLWithPath: decoded))
            }
            if found.count >= projectCap { break }
        }
        return found
    }

    private static func children(_ url: URL, limit: Int = 40) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: url.path)) ?? []
        return names.filter { name in
            !skipNames.contains(name) && !name.hasPrefix(".")
        }.prefix(limit).map { $0 }
    }

    // MARK: - cards

    private static func entryFromSpec(agent: String, name: String, spec: [String: Any], configPath: String, home: URL, used: inout Set<String>) -> [String: Any]? {
        if boolValue(spec["disabled"]) == true || boolValue(spec["enabled"]) == false { return nil }
        let command = redact(String((spec["command"] as? String ?? "").prefix(200)))
        let args = stringList(spec["args"]).map { redact(String($0.prefix(500))) }
        let rawURL = (spec["url"] as? String) ?? (spec["serverUrl"] as? String) ?? ""
        let safe = rawURL.isEmpty ? "" : safeURL(rawURL)
        let envRows = envList(spec)
        let headers = headerNames(spec)
        let bearer = spec["bearer_token_env_var"] as? String ?? ""
        let origin = classify(command: command, args: args, url: safe)
        let commandLine = ([command] + args).filter { !$0.isEmpty }.joined(separator: " ")
        let hosts = hostsIn([safe, commandLine].joined(separator: " "))
        let flags = buildFlags(commandLine: commandLine, unpinned: origin.unpinned, args: args, home: home.path, envRows: envRows, url: safe.isEmpty ? rawURL : safe, headers: headers, bearer: bearer)
        let summary = summaryLine(agent: agent, kindName: "MCP", name: name, origin: origin.text, commandLine: commandLine, envRows: envRows, hosts: hosts, flags: flags)
        let body: [String: Any] = [
            "args": args, "command": command, "env": envRows, "hosts": hosts,
            "kind": "mcp", "name": name, "originKind": origin.kind, "url": safe,
        ]
        return [
            "id": alloc(slug(agent, "mcp", name), configPath, &used),
            "agent": agent,
            "kind": "mcp",
            "name": String(name.prefix(120)),
            "configPath": configPath,
            "originKind": origin.kind,
            "origin": origin.text,
            "command": command,
            "args": args,
            "env": envRows,
            "hosts": hosts,
            "flags": flags,
            "summary": String(summary.prefix(800)),
            "fingerprint": fingerprint(body),
        ]
    }

    private static func entryFromText(agent: String, kind: String, name: String, text: String, configPath: String, home: URL, used: inout Set<String>) -> [String: Any] {
        let redacted = redact(text)
        let display = frontName(text, fallback: name)
        let hosts = hostsIn(redacted)
        var flags: [[String: String]] = []
        if matches(curlPipe, redacted) {
            flags.append(["id": "curl-pipe", "text": "说明里有 curl 或 wget 再管道给 shell"])
        }
        if matches(#"(?i)@latest\b"#, redacted) || matches(#"(?i)\bnpx\s+-y\s+[^\s@]+(\s|$)"#, redacted) {
            flags.append(["id": "unpinned", "text": "说明里用了没有钉死的包，装到的是当时的最新包"])
        }
        var creds: [String] = []
        for match in allMatches(#"\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY))\b"#, text) where !creds.contains(match) {
            creds.append(match)
        }
        if !creds.isEmpty {
            flags.append(["id": "credential-env", "text": "说明里点了凭据名字 \(creds.prefix(6).joined(separator: "、"))，值没有记下"])
        }
        let origin = "本机路径 \(configPath)"
        let summary = summaryLine(agent: agent, kindName: kindName(kind), name: display, origin: origin, commandLine: "", envRows: [], hosts: hosts, flags: flags)
        let body: [String: Any] = [
            "args": [String](), "command": "", "hosts": hosts, "kind": kind, "name": display,
            "originKind": "local", "path": configPath, "flags": flags.map { $0["id"] ?? "" },
        ]
        return [
            "id": alloc(slug(agent, kind, display), configPath, &used),
            "agent": agent, "kind": kind, "name": String(display.prefix(120)),
            "configPath": configPath, "originKind": "local", "origin": origin,
            "command": "", "args": [String](), "env": [[String: Any]](), "hosts": hosts,
            "flags": flags, "summary": String(summary.prefix(800)), "fingerprint": fingerprint(body),
        ]
    }

    private static func summaryLine(agent: String, kindName: String, name: String, origin: String, commandLine: String, envRows: [[String: Any]], hosts: [String], flags: [[String: String]]) -> String {
        let envText = envRows.isEmpty ? "没有" : envRows.compactMap { $0["name"] as? String }.joined(separator: "、")
        let hostText = hosts.isEmpty ? "看不出来" : hosts.joined(separator: "、")
        let flagText = flags.isEmpty ? "没有标红旗" : flags.compactMap { $0["text"] }.joined(separator: "；")
        let run = commandLine.isEmpty ? "没有单独的启动命令" : commandLine
        return "\(agent) 新加了\(kindName)「\(name)」。来源：\(origin)。会运行：\(run)。环境变量：\(envText)。会连：\(hostText)。\(flagText)"
    }

    private static func buildFlags(commandLine: String, unpinned: Bool, args: [String], home: String, envRows: [[String: Any]], url: String, headers: [String], bearer: String) -> [[String: String]] {
        var flags: [[String: String]] = []
        if matches(curlPipe, commandLine) {
            flags.append(["id": "curl-pipe", "text": "启动命令里有 curl 或 wget 再管道给 shell，装进去就会执行别人的脚本"])
        }
        if unpinned || matches(#"(?i)@latest\b"#, commandLine) {
            flags.append(["id": "unpinned", "text": "版本没有钉死，装到的是当时的最新包"])
        }
        let wide = broad(args, home: home)
        if !wide.isEmpty {
            let shown = wide.prefix(4).map { redact(String($0.prefix(80))) }.joined(separator: "、")
            flags.append(["id": "broad-fs", "text": "参数里有很宽的目录（\(shown)），等于把一大片文件交给它"])
        }
        let secretNames = envRows.compactMap { row -> String? in
            (row["credential"] as? Bool) == true ? row["name"] as? String : nil
        }
        if !secretNames.isEmpty {
            flags.append(["id": "credential-env", "text": "环境变量 \(secretNames.prefix(6).joined(separator: "、")) 的名字像凭据，值没有记下"])
        }
        if url.lowercased().hasPrefix("http://") && !isLoopback(hostOf(url)) {
            let authed = !bearer.isEmpty || headers.contains { authHeaders.contains($0.lowercased()) } || !secretNames.isEmpty
            if !authed {
                flags.append(["id": "remote-http-no-auth", "text": "远程地址是 http，而且没有看到鉴权"])
            }
        }
        return flags
    }

    private static let curlPipe = #"(?i)(\b(curl|wget)\b[^\n|]{0,300}\|\s*(sudo\s+)?(sh|bash|zsh)\b)|(\b(sh|bash|zsh)\b[^\n]{0,40}<\(\s*(curl|wget)\b)"#

    private static func classify(command: String, args: [String], url: String) -> (kind: String, text: String, unpinned: Bool) {
        if !url.isEmpty {
            return ("remote-url", "远程地址 \(url)", false)
        }
        for arg in args where arg.hasPrefix("git+") || arg.hasPrefix("git@") || (arg.hasSuffix(".git") && arg.contains("://")) {
            let shown = arg.contains("://") ? safeURL(arg) : redact(String(arg.prefix(180)))
            return ("git", "Git 地址 \(shown)", false)
        }
        let base = URL(fileURLWithPath: command).lastPathComponent.lowercased()
        if ["npx", "npm", "bunx", "pnpm", "yarn"].contains(base) {
            let spec = npmSpec(args)
            if !spec.isEmpty {
                let parts = splitPackage(spec)
                if pinned(parts.version) {
                    return ("npm", "npm 包 \(parts.name)，版本 \(parts.version ?? "")", false)
                }
                if let version = parts.version, ["latest", "next", "*"].contains(version.lowercased()) {
                    return ("npm", "npm 包 \(parts.name)，写了 \(version)", true)
                }
                return ("npm", "npm 包 \(parts.name)，没有钉版本", true)
            }
        }
        if ["uvx", "uv", "pipx", "pip", "python", "python3"].contains(base) {
            let spec = pypiSpec(args)
            if !spec.isEmpty && !spec.hasPrefix("-") {
                if spec.contains("==") {
                    let bits = spec.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    let name = bits.first.map(String.init) ?? spec
                    let version = spec.split(separator: "=").last.map(String.init) ?? ""
                    return ("pypi", "PyPI 包 \(name)，版本 \(version)", false)
                }
                let parts = splitPackage(spec)
                if pinned(parts.version) {
                    return ("pypi", "PyPI 包 \(parts.name)，版本 \(parts.version ?? "")", false)
                }
                return ("pypi", "PyPI 包 \(spec)，没有钉版本", true)
            }
        }
        if command.hasPrefix("/") || command.hasPrefix("./") || command.hasPrefix("~") {
            return ("local", "本机路径 \(redact(String(command.prefix(180))))", false)
        }
        if !command.isEmpty {
            return ("command", "看不出发布者，启动命令是 \(redact(String(command.prefix(80))))", false)
        }
        return ("unknown", "看不出从哪来", false)
    }

    private static func npmSpec(_ args: [String]) -> String {
        let skip: Set<String> = ["exec", "dlx", "x", "install", "i", "add", "run"]
        var index = 0
        while index < args.count {
            let arg = args[index]
            if (arg == "--package" || arg == "-p"), index + 1 < args.count { return args[index + 1] }
            if arg.hasPrefix("-") && !arg.hasPrefix("@-") { index += 1; continue }
            if skip.contains(arg) { index += 1; continue }
            return arg
        }
        return ""
    }

    private static func pypiSpec(_ args: [String]) -> String {
        var index = 0
        while index < args.count {
            let arg = args[index]
            if arg == "install" || arg == "-m" || arg == "run" || arg == "tool" || arg.hasPrefix("-") {
                index += 1
                continue
            }
            return arg
        }
        return ""
    }

    private static func splitPackage(_ spec: String) -> (name: String, version: String?) {
        if spec.hasPrefix("@") {
            if spec.filter({ $0 == "@" }).count >= 2 {
                let name = String(spec[..<spec.range(of: "@", options: .backwards)!.lowerBound])
                let version = String(spec[spec.index(after: spec.range(of: "@", options: .backwards)!.lowerBound)...])
                return (name, version)
            }
            return (spec, nil)
        }
        if let at = spec.range(of: "@", options: .backwards) {
            return (String(spec[..<at.lowerBound]), String(spec[at.upperBound...]))
        }
        return (spec, nil)
    }

    private static func pinned(_ version: String?) -> Bool {
        guard let version else { return false }
        let token = version.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if token.isEmpty || ["latest", "next", "*", "stable"].contains(token) { return false }
        return true
    }

    private static func broad(_ args: [String], home: String) -> [String] {
        let root = URL(fileURLWithPath: home).resolvingSymlinksInPath().path
        let exact: Set<String> = ["/", "/*", "~", "~/", "$HOME", "${HOME}", "/Users", "/home", "/private", "/Volumes", "/tmp", "/var", "/etc", root, root + "/"]
        var hits: [String] = []
        for arg in args {
            let raw = arg.trimmingCharacters(in: .whitespacesAndNewlines)
            if raw.isEmpty { continue }
            if exact.contains(raw) || exact.contains(String(raw.dropLast(raw.hasSuffix("/") ? 1 : 0))) || String(raw.dropLast(raw.hasSuffix("/") ? 1 : 0)) == root {
                hits.append(raw)
                continue
            }
            if raw.hasPrefix("~") {
                let expanded = NSString(string: raw).expandingTildeInPath
                if expanded == root || expanded == "/" || expanded == "/Users" || expanded == "/home" {
                    hits.append(raw)
                }
            }
        }
        return hits
    }

    private static func envList(_ spec: [String: Any]) -> [[String: Any]] {
        var rows: [[String: Any]] = []
        let env = spec["env"] as? [String: Any] ?? [:]
        for key in Array(env.keys).sorted().prefix(40) {
            let name = String(key.prefix(80))
            rows.append(["name": name, "credential": isCredential(name)])
        }
        if let bearer = spec["bearer_token_env_var"] as? String {
            let name = String(bearer.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80))
            if !name.isEmpty && !rows.contains(where: { $0["name"] as? String == name }) {
                rows.append(["name": name, "credential": isCredential(name)])
            }
        }
        return rows
    }

    private static func headerNames(_ spec: [String: Any]) -> [String] {
        let headers = spec["headers"] as? [String: Any] ?? [:]
        return Array(headers.keys).sorted().prefix(20).map { String($0.prefix(80)) }
    }

    private static func stringList(_ value: Any?) -> [String] {
        if let list = value as? [Any] {
            return list.compactMap { item -> String? in
                if item is [String: Any] || item is [Any] { return nil }
                return String(describing: item)
            }.prefix(32).map { $0 }
        }
        if let text = value as? String, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return [text]
        }
        return []
    }

    private static func isCredential(_ name: String) -> Bool {
        let parts = name.uppercased().split { !$0.isLetter && !$0.isNumber }.map(String.init)
        let blob = parts.joined(separator: "_")
        if credParts.contains(where: { blob.contains($0) }) { return true }
        return blob.hasSuffix("_KEY") || blob.hasSuffix("_AUTH")
    }

    private static func fingerprint(_ body: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "0" }
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in text.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 1_099_511_628_211
        }
        return String(format: "%016llx", hash)
    }

    private static func slug(_ agent: String, _ kind: String, _ name: String) -> String {
        let agentSlug: String
        switch agent {
        case "Claude Code": agentSlug = "claude"
        case "Cursor": agentSlug = "cursor"
        case "Codex": agentSlug = "codex"
        case "WorkBuddy": agentSlug = "workbuddy"
        case "通用": agentSlug = "agents"
        default: agentSlug = "local"
        }
        let cleaned = String(name.unicodeScalars.map { scalar -> Character in
            let ok = CharacterSet.alphanumerics.contains(scalar) || scalar == "." || scalar == "_" || scalar == "-"
            return ok ? Character(scalar) : "-"
        }.prefix(80)).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return "\(agentSlug):\(kind):\(cleaned.isEmpty ? "item" : cleaned)"
    }

    private static func alloc(_ base: String, _ path: String, _ used: inout Set<String>) -> String {
        if used.insert(base).inserted { return base }
        let extra = String(fingerprint(["path": path]).prefix(6))
        let minted = "\(base)-\(extra)"
        used.insert(minted)
        return minted
    }

    private static func frontName(_ text: String, fallback: String) -> String {
        guard text.hasPrefix("---") else { return fallback }
        let rest = text.dropFirst(3)
        let block: String
        if let end = rest.range(of: "\n---") {
            block = String(rest[..<end.lowerBound])
        } else {
            block = String(rest.prefix(400))
        }
        guard let range = block.range(of: #"(?m)^name:\s*['\"]?([^'"\n]+)"#, options: .regularExpression) else { return fallback }
        var value = String(block[range])
        if let colon = value.firstIndex(of: ":") {
            value = String(value[value.index(after: colon)...])
        }
        value = value.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        return value.isEmpty ? fallback : String(value.prefix(80))
    }

    // MARK: - text

    private static func redact(_ text: String) -> String {
        text.replacingOccurrences(
            of: #"(?i)(ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_\-]{12,}|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9\-]{8,}|bearer\s+[A-Za-z0-9._\-]{8,}|(token|password|secret|api[_-]?key)\s*=\s*\S+)"#,
            with: "[redacted]", options: .regularExpression)
    }

    private static func matches(_ pattern: String, _ text: String) -> Bool {
        text.range(of: pattern, options: .regularExpression) != nil
    }

    private static func allMatches(_ pattern: String, _ text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap { match in
            guard match.numberOfRanges > 1 else { return nil }
            let range = match.range(at: 1)
            guard range.location != NSNotFound else { return nil }
            return ns.substring(with: range)
        }
    }

    private static func hostsIn(_ text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: "https?://[^\\s\"'`<>]+", options: .caseInsensitive) else { return [] }
        let ns = text as NSString
        var found: [String] = []
        for match in regex.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let raw = ns.substring(with: match.range)
            let host = hostOf(raw)
            if !host.isEmpty && !found.contains(host) { found.append(host) }
            if found.count >= 8 { break }
        }
        return found
    }

    private static func hostOf(_ url: String) -> String {
        guard let parts = URLComponents(string: url.trimmingCharacters(in: .whitespacesAndNewlines)) else { return "" }
        return (parts.host ?? "").lowercased()
    }

    private static func safeURL(_ url: String) -> String {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parts = URLComponents(string: trimmed), let host = parts.host, let scheme = parts.scheme, !scheme.isEmpty else {
            return redact(String(trimmed.split(separator: "?", maxSplits: 1).first.map(String.init)?.prefix(300) ?? ""))
        }
        var port = ""
        if let number = parts.port { port = ":\(number)" }
        let path = parts.path
        return String("\(scheme)://\(host)\(port)\(path)".prefix(300))
    }

    private static func isLoopback(_ host: String) -> Bool {
        let value = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return value == "localhost" || value == "127.0.0.1" || value == "::1" || value.hasPrefix("127.")
    }

    private static func mcpMaps(_ text: String) -> [[String: Any]] {
        if let data = text.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let found = walkMCP(obj, depth: 0)
            if !found.isEmpty { return found }
        }
        var found: [[String: Any]] = []
        var search = text.startIndex
        let key = "\"mcpServers\""
        while search < text.endIndex, let range = text.range(of: key, range: search..<text.endIndex) {
            let rest = text[range.upperBound...]
            if let brace = rest.firstIndex(of: "{"), let (obj, next) = jsonObject(text, at: brace), let dict = obj as? [String: Any] {
                found.append(dict)
                search = next
            } else {
                search = range.upperBound
            }
        }
        return found
    }

    private static func walkMCP(_ obj: [String: Any], depth: Int) -> [[String: Any]] {
        if depth > 8 { return [] }
        var found: [[String: Any]] = []
        if let servers = obj["mcpServers"] as? [String: Any] { found.append(servers) }
        for (key, value) in obj where key != "mcpServers" {
            if let child = value as? [String: Any] {
                found.append(contentsOf: walkMCP(child, depth: depth + 1))
            }
        }
        return found
    }

    private static func jsonObject(_ text: String, at start: String.Index) -> (Any, String.Index)? {
        var index = start
        while index < text.endIndex, text[index].isWhitespace { index = text.index(after: index) }
        guard index < text.endIndex, text[index] == "{" else { return nil }
        let open = index
        var depth = 0
        var inString = false
        var escaped = false
        while index < text.endIndex {
            let ch = text[index]
            if inString {
                if escaped { escaped = false }
                else if ch == "\\" { escaped = true }
                else if ch == "\"" { inString = false }
            } else if ch == "\"" {
                inString = true
            } else if ch == "{" {
                depth += 1
            } else if ch == "}" {
                depth -= 1
                if depth == 0 {
                    let blob = String(text[open...index])
                    let next = text.index(after: index)
                    if let data = blob.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: data) {
                        return (obj, next)
                    }
                    return nil
                }
            }
            index = text.index(after: index)
        }
        return nil
    }

    private static func parseCodex(_ text: String) -> [[String: Any]] {
        var servers: [String: [String: Any]] = [:]
        var order: [String] = []
        var current: (name: String, section: String?)?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw.split(separator: "#", maxSplits: 1).first ?? "").trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let parts = line.dropFirst().dropLast().split(separator: ".").map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count >= 2 && parts[0] == "mcp_servers" && !parts[1].isEmpty {
                    let name = parts[1]
                    if servers[name] == nil { order.append(name); servers[name] = [:] }
                    let section = parts.count >= 3 ? parts[2] : nil
                    if section == "env" { current = (name, "env") }
                    else if section == "headers" || section == "http_headers" { current = (name, "headers") }
                    else { current = (name, nil) }
                } else {
                    current = nil
                }
                continue
            }
            guard let current, let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
            let rawValue = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            let value = tomlValue(rawValue)
            var spec = servers[current.name] ?? [:]
            if current.section == "env" {
                var env = spec["env"] as? [String: String] ?? [:]
                env[key] = ""
                spec["env"] = env
            } else if current.section == "headers" {
                var headers = spec["headers"] as? [String: String] ?? [:]
                headers[key] = ""
                spec["headers"] = headers
            } else if key == "env", let table = value as? [String: String] {
                spec["env"] = table
            } else if (key == "headers" || key == "http_headers"), let table = value as? [String: String] {
                spec["headers"] = table
            } else if key == "args", let list = value as? [String] {
                spec["args"] = list
            } else if ["command", "url", "bearer_token_env_var"].contains(key), let text = value as? String {
                spec[key] = text
            } else if key == "enabled" || key == "disabled", let flag = value as? Bool {
                spec[key] = flag
            }
            servers[current.name] = spec
        }
        return order.compactMap { name in
            guard var spec = servers[name] else { return nil }
            spec["name"] = name
            return spec
        }
    }

    private static func tomlValue(_ text: String) -> Any {
        let trimmed = text.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: ","))
        if trimmed.isEmpty { return "" }
        if trimmed.hasPrefix("\"") || trimmed.hasPrefix("'") {
            return tomlString(trimmed).value
        }
        if trimmed.hasPrefix("[") { return tomlArray(trimmed) }
        if trimmed.hasPrefix("{") {
            let pattern = #"([A-Za-z_][A-Za-z0-9_]*)\s*="#
            var table: [String: String] = [:]
            if let regex = try? NSRegularExpression(pattern: pattern) {
                let ns = trimmed as NSString
                for match in regex.matches(in: trimmed, range: NSRange(location: 0, length: ns.length)) where match.numberOfRanges > 1 {
                    table[ns.substring(with: match.range(at: 1))] = ""
                }
            }
            return table
        }
        if trimmed == "true" { return true }
        if trimmed == "false" { return false }
        return trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
    }

    private static func tomlString(_ text: String) -> (value: String, consumed: Int) {
        guard let quote = text.first else { return ("", 0) }
        var chars: [Character] = []
        var index = text.index(after: text.startIndex)
        var count = 1
        while index < text.endIndex {
            let ch = text[index]
            count += 1
            if ch == "\\" {
                let next = text.index(after: index)
                if next < text.endIndex {
                    chars.append(text[next])
                    index = text.index(after: next)
                    count += 1
                    continue
                }
            }
            if ch == quote { return (String(chars), count) }
            chars.append(ch)
            index = text.index(after: index)
        }
        return (String(chars), count)
    }

    private static func tomlArray(_ text: String) -> [String] {
        var out: [String] = []
        var index = text.index(after: text.startIndex)
        while index < text.endIndex {
            let ch = text[index]
            if ch == "\"" || ch == "'" {
                let slice = String(text[index...])
                let parsed = tomlString(slice)
                out.append(parsed.value)
                index = text.index(index, offsetBy: parsed.consumed, limitedBy: text.endIndex) ?? text.endIndex
                continue
            }
            index = text.index(after: index)
        }
        return out
    }

    private static func boolValue(_ value: Any?) -> Bool? {
        if let flag = value as? Bool { return flag }
        if let number = value as? NSNumber { return number.boolValue }
        return nil
    }

    private static func readCapped(_ url: URL, _ limit: Int) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: limit)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    private static func readHeadTail(_ url: URL) -> String {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
        defer { try? handle.close() }
        let head = (try? handle.read(upToCount: headBytes)) ?? Data()
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? head.count
        var tail = Data()
        if size > headBytes + 1024 {
            do {
                try handle.seek(toOffset: UInt64(max(0, size - tailBytes)))
                tail = (try? handle.read(upToCount: tailBytes)) ?? Data()
            } catch {
                tail = Data()
            }
        }
        let headText = String(decoding: head, as: UTF8.self)
        if tail.isEmpty { return headText }
        return headText + "\n" + String(decoding: tail, as: UTF8.self)
    }

    /// `appendingPathComponent` percent-encodes `/`, so multi-segment relatives go through here.
    private static func at(_ base: URL, _ relative: String) -> URL {
        relative.split(separator: "/").reduce(base) { url, part in
            url.appendingPathComponent(String(part))
        }
    }

    private static func exists(_ url: URL) -> Bool {
        FileManager.default.fileExists(atPath: url.path)
    }

    private static func isFile(_ url: URL) -> Bool {
        var dir: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &dir) && !dir.boolValue
    }

    private static func isDir(_ url: URL) -> Bool {
        var dir: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &dir) && dir.boolValue
    }

    private static func iso(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}
