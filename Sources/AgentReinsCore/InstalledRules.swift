import Foundation

/// Seeds the installed rules files. An empty rules array with `customized != true`
/// is filled on every launch. A file the user marked customized is left alone,
/// even when its rules array is empty.
public enum InstalledRules {
    public static let defaultEgressHosts = [
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

    public static func supportURLs(home: URL) -> [URL] {
        let library = home.appendingPathComponent("Library/Application Support", isDirectory: true)
        return [
            library.appendingPathComponent("AgentReins/rules.json"),
            library.appendingPathComponent("AgentGuard/rules.json"),
        ]
    }

    /// Returns the URLs that were written. Already-seeded and customized files are skipped.
    @discardableResult
    public static func seedSupportFiles(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [URL] {
        supportURLs(home: home).filter { seedFile(at: $0) }
    }

    @discardableResult
    public static func seedFile(at url: URL, allowHosts: [String] = InstalledRules.defaultEgressHosts) -> Bool {
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
                "allowHosts": allowHosts,
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
}
