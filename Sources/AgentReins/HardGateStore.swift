import CryptoKit
import Darwin
import Foundation

/// User decisions for the hard gate, and the keep-tier audit the enforcer appends.
///
/// Python (`hardgate_policy.py`) is what actually refuses a proxy flow or a PATH
/// exec. This store is the app side: approve writes an allowlist entry with a
/// reason, deny removes one, and both append a row. `actor == "agent"` is rejected.
/// There is no trim or truncate of `audit.jsonl`. Rows are tier `keep`.
enum HardGateStore {
    enum Failure: Error, Equatable {
        case agentWrite
        case reasonRequired
        case badSubject
    }

    struct Snapshot {
        var inbox: [[String: Any]]
        var receipts: [[String: Any]]
        var allowlist: [[String: Any]]
    }

    private static let zeroPrev = String(repeating: "0", count: 64)
    private static let stateLock = NSLock()
    private static var overrideRoot: URL?

    static func useRoot(_ url: URL?) {
        stateLock.lock()
        overrideRoot = url
        stateLock.unlock()
        if let url {
            try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        }
    }

    static var root: URL {
        stateLock.lock()
        let override = overrideRoot
        stateLock.unlock()
        if let override { return override }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentReins/hardgate", isDirectory: true)
    }

    static var auditURL: URL { root.appendingPathComponent("audit.jsonl") }
    static var allowlistURL: URL { root.appendingPathComponent("allowlist.json") }
    private static var lockURL: URL { root.appendingPathComponent("audit.lock") }

    static func approve(subject: String, kind: String, reason: String) throws {
        let cleaned = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { throw Failure.reasonRequired }
        guard valid(subject: subject, kind: kind) else { throw Failure.badSubject }
        try withFileLock {
            let row = try appendUnlocked(actor: "user", record: [
                "action": "allow", "kind": kind, "subject": subject, "reason": cleaned,
                "enforced": false, "inbox": false, "heartbeat": false,
            ])
            var entries = usableAllowlist().filter { ($0["subject"] as? String) != subject }
            entries.append([
                "actor": "user", "decidedAt": row["at"] as? String ?? "", "kind": kind,
                "reason": cleaned, "subject": subject,
            ])
            try writeAllowlist(entries, customized: true)
        }
    }

    static func deny(subject: String, kind: String, reason: String) throws {
        let cleaned = reason.trimmingCharacters(in: .whitespacesAndNewlines)
        let stored = cleaned.isEmpty ? "保持拒绝" : cleaned
        guard valid(subject: subject, kind: kind) else { throw Failure.badSubject }
        try withFileLock {
            _ = try appendUnlocked(actor: "user", record: [
                "action": "deny", "kind": kind, "subject": subject, "reason": stored,
                "enforced": false, "inbox": false, "heartbeat": false,
                "detail": "用户保持拒绝",
            ])
            let entries = usableAllowlist().filter { ($0["subject"] as? String) != subject }
            try writeAllowlist(entries, customized: true)
        }
    }

    /// Test and internal append. Refuses an agent writer and an enforcer allow.
    @discardableResult
    static func append(actor: String, record: [String: Any]) throws -> [String: Any] {
        try withFileLock { try appendUnlocked(actor: actor, record: record) }
    }

    static let defaultEgressHosts = [
        "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
        "registry.npmjs.org", "registry.yarnpkg.org", "registry.yarnpkg.com",
        "pypi.org", "files.pythonhosted.org",
        "crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
        "cdn.jsdelivr.net", "unpkg.com", "formulae.brew.sh", "ghcr.io",
        "docker.io", "registry-1.docker.io",
        "api.openai.com", "api.anthropic.com", "api2.cursor.sh",
        "cursor.com", "www.cursor.com", "chatgpt.com", "claude.ai", "openrouter.ai",
        "copilot.tencent.com",
    ]
    static let defaultAllowReason = "安装时写入的默认允许：包注册表或模型服务"

    /// Empty or missing rules.json on a fresh install or upgrade. A customized file stays put.
    @discardableResult
    static func seedRulesFile(at url: URL) -> Bool {
        if let data = try? Data(contentsOf: url),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if (obj["customized"] as? Bool) == true { return false }
            if let rules = obj["rules"] as? [Any], !rules.isEmpty { return false }
        }
        let rules: [[String: Any]] = [
            [
                "id": "default-deny-egress",
                "kind": "egress",
                "action": "block",
                "severity": "high",
                "message": "被监督的 Agent 访问允许名单之外的主机",
                "allowHosts": defaultEgressHosts,
                "naturalLanguage": "未列出的外联默认拒绝。允许名单是包注册表和模型服务。",
            ],
            [
                "id": "default-deny-credential-read",
                "kind": "credential-read",
                "action": "block",
                "severity": "high",
                "message": "被监督的 Agent 读取凭据路径",
                "naturalLanguage": "凭据路径默认拒绝，不在默认允许名单里。",
            ],
        ]
        let payload: [String: Any] = ["customized": false, "rules": rules, "version": 1]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) else { return false }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        do {
            try data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            return true
        } catch {
            return false
        }
    }

    @discardableResult
    static func seedDefaults() -> Bool {
        (try? withFileLock {
            let doc = readAllowlistDocument()
            if (doc?["customized"] as? Bool) == true { return false }
            let entries = doc?["entries"] as? [[String: Any]] ?? []
            if !entries.isEmpty { return false }
            let stamp = isoNow()
            let seeded: [[String: Any]] = defaultEgressHosts.map { host in
                [
                    "actor": "default", "decidedAt": stamp, "kind": "egress",
                    "reason": defaultAllowReason, "subject": "host:" + host,
                ]
            }
            try writeAllowlist(seeded, customized: false)
            return true
        }) ?? false
    }

    static func snapshot() -> Snapshot {
        _ = seedDefaults()
        let rows = loadRows()
        let allow = (try? readAllowlistEntries()) ?? []
        let usable = allow.filter(usableAllow)
        return Snapshot(
            inbox: openInbox(rows: rows, allowlist: usable),
            receipts: rows.suffix(400).map(receipt),
            allowlist: usable
        )
    }

    static func policyPayload() -> [String: Any] {
        let hosts = ((try? readAllowlistEntries()) ?? []).filter(usableAllow).compactMap { entry -> String? in
            guard (entry["kind"] as? String) == "egress", let subject = entry["subject"] as? String, subject.hasPrefix("host:") else { return nil }
            return String(subject.dropFirst(5))
        }
        return [
            "egress": "deny-unlisted",
            "credentialReads": "deny",
            "allowHosts": hosts,
        ]
    }

    static func verifyChain() -> Bool {
        verifyChain(Data(auditBytes()))
    }

    static func loadRows() -> [[String: Any]] {
        auditBytes().split(separator: 0x0A, omittingEmptySubsequences: true).compactMap { slice in
            (try? JSONSerialization.jsonObject(with: Data(slice))) as? [String: Any]
        }
    }

    // MARK: - chain

    static func previousHash(_ data: Data) -> String {
        let chunk = lastChunk(data)
        if chunk.isEmpty { return zeroPrev }
        var hashed = chunk
        if hashed.last != 0x0A { hashed.append(0x0A) }
        let digest = SHA256.hash(data: hashed)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static func verifyChain(_ data: Data) -> Bool {
        if data.isEmpty { return true }
        var prev = zeroPrev
        var start = data.startIndex
        var saw = false
        while start < data.endIndex {
            guard let newline = data[start...].firstIndex(of: 0x0A) else { return false }
            let chunk = data[start...newline]
            if chunk.allSatisfy({ $0 == 0x0A || $0 == 0x20 || $0 == 0x09 }) { return false }
            guard let obj = try? JSONSerialization.jsonObject(with: Data(chunk.dropLast())) as? [String: Any] else { return false }
            if (obj["prev"] as? String) != prev || (obj["tier"] as? String) != "keep" { return false }
            prev = SHA256.hash(data: Data(chunk)).map { String(format: "%02x", $0) }.joined()
            start = data.index(after: newline)
            saw = true
        }
        return saw
    }

    // MARK: - private

    private static func withFileLock<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let fd = Darwin.open(lockURL.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw Failure.agentWrite }
        defer { Darwin.close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw Failure.agentWrite }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    private static func appendUnlocked(actor: String, record: [String: Any]) throws -> [String: Any] {
        if actor == "agent" || (record["actor"] as? String) == "agent" {
            throw Failure.agentWrite
        }
        guard actor == "user" || actor == "enforcer" else { throw Failure.agentWrite }
        let action = record["action"] as? String ?? ""
        if action == "allow" && actor != "user" { throw Failure.agentWrite }
        guard action == "allow" || action == "deny" || action == "pass" else { throw Failure.badSubject }
        if let claimed = record["actor"] as? String, claimed != actor { throw Failure.agentWrite }
        let existing = auditBytes()
        var body: [String: Any] = [
            "v": 1,
            "at": (record["at"] as? String) ?? isoNow(),
            "action": action,
            "kind": record["kind"] as? String ?? "",
            "subject": record["subject"] as? String ?? "",
            "reason": String((record["reason"] as? String ?? "").prefix(500)),
            "actor": actor,
            "enforced": boolValue(record["enforced"]),
            "inbox": boolValue(record["inbox"]),
            "heartbeat": boolValue(record["heartbeat"]),
            "tier": "keep",
            "prev": previousHash(existing),
        ]
        if let mechanism = record["mechanism"] as? String, !mechanism.isEmpty {
            body["mechanism"] = mechanism
        } else {
            body["mechanism"] = NSNull()
        }
        if let detail = record["detail"] as? String, !detail.isEmpty {
            body["detail"] = String(detail.prefix(200))
        }
        let line = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        var output = line
        output.append(0x0A)
        let fd = Darwin.open(auditURL.path, O_CREAT | O_WRONLY | O_APPEND, 0o600)
        guard fd >= 0 else { throw Failure.agentWrite }
        let wrote = output.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return Darwin.write(fd, base, raw.count)
        }
        Darwin.close(fd)
        guard wrote == output.count else { throw Failure.agentWrite }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: auditURL.path)
        return body
    }

    private static func auditBytes() -> Data {
        (try? Data(contentsOf: auditURL)) ?? Data()
    }

    private static func lastChunk(_ data: Data) -> Data {
        if data.isEmpty { return Data() }
        if data.last == 0x0A {
            let body = data.dropLast()
            if let nl = body.lastIndex(of: 0x0A) {
                return data.subdata(in: (nl + 1)..<data.count)
            }
            return data
        }
        if let nl = data.lastIndex(of: 0x0A) {
            return data.subdata(in: (nl + 1)..<data.count)
        }
        return data
    }

    private static func writeAllowlist(_ entries: [[String: Any]], customized: Bool) throws {
        let payload: [String: Any] = ["customized": customized, "entries": entries, "version": 1]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: allowlistURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: allowlistURL.path)
    }

    private static func readAllowlistDocument() -> [String: Any]? {
        guard let data = try? Data(contentsOf: allowlistURL), !data.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private static func readAllowlistEntries() throws -> [[String: Any]] {
        guard let obj = readAllowlistDocument(),
              let entries = obj["entries"] as? [[String: Any]] else { return [] }
        return entries
    }

    private static func usableAllowlist() -> [[String: Any]] {
        (try? readAllowlistEntries())?.filter(usableAllow) ?? []
    }

    private static func usableAllow(_ entry: [String: Any]) -> Bool {
        let actor = entry["actor"] as? String
        guard actor == "user" || actor == "default" else { return false }
        let reason = (entry["reason"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !reason.isEmpty else { return false }
        return valid(subject: entry["subject"] as? String ?? "", kind: entry["kind"] as? String ?? "")
    }

    private static func valid(subject: String, kind: String) -> Bool {
        guard !subject.contains("\n"), !subject.contains("\r"), subject.count >= 6, subject.count <= 300 else { return false }
        if kind == "egress", subject.hasPrefix("host:"), subject.dropFirst(5).trimmingCharacters(in: .whitespaces).isEmpty == false {
            return !subject.contains(" ") && !subject.contains("/")
        }
        if kind == "credential-read", subject.hasPrefix("path:"), subject.count > 5 { return true }
        return false
    }

    static func openInbox(rows: [[String: Any]], allowlist: [[String: Any]]) -> [[String: Any]] {
        var closed = Set(allowlist.filter(usableAllow).compactMap { $0["subject"] as? String })
        for row in rows where (row["actor"] as? String) == "user" {
            let action = row["action"] as? String ?? ""
            if action == "allow" || action == "deny", let subject = row["subject"] as? String {
                closed.insert(subject)
            }
        }
        var picked: [[String: Any]] = []
        var seen = Set<String>()
        for row in rows {
            guard (row["tier"] as? String) == "keep" else { continue }
            guard boolValue(row["inbox"]), !boolValue(row["heartbeat"]) else { continue }
            guard (row["action"] as? String) == "deny" else { continue }
            guard let subject = row["subject"] as? String, !subject.isEmpty else { continue }
            if closed.contains(subject) || seen.contains(subject) { continue }
            seen.insert(subject)
            picked.append(row)
        }
        return picked
    }

    private static func receipt(_ row: [String: Any]) -> [String: Any] {
        var out: [String: Any] = [
            "subject": row["subject"] as? String ?? "",
            "action": row["action"] as? String ?? "",
            "enforced": boolValue(row["enforced"]),
            "at": row["at"] as? String ?? "",
            "inbox": boolValue(row["inbox"]),
            "heartbeat": boolValue(row["heartbeat"]),
            "tier": row["tier"] as? String ?? "",
            "kind": row["kind"] as? String ?? "",
            "actor": row["actor"] as? String ?? "",
        ]
        if let mechanism = row["mechanism"] as? String { out["mechanism"] = mechanism }
        if let detail = row["detail"] as? String { out["detail"] = detail }
        if let reason = row["reason"] as? String { out["reason"] = reason }
        return out
    }

    private static func boolValue(_ value: Any?) -> Bool {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        return false
    }

    private static func isoNow() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date())
    }
}
