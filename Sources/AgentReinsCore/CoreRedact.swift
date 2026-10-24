import Foundation

// MARK: - Redaction (shared vectors with tools/redact_secrets.py)

public enum Redact {
    public static func text(_ input: String) -> String {
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
            (#"(?i)((?:Cookie|Set-Cookie)\s*[:=]\s*)([^\r\n]*?)(?=(?:\s+https?://)|\s*$|\r|\n)"#, "$1[cookie:REDACTED]"),
            (#"(?i)\b((?:sessionid|jsessionid|phpsessid|mcp-session-id|session_id)=)([^;\s&]+)"#, "$1[session:REDACTED]"),
            (#"(?i)(\"(?:Mcp-Session-Id|X-Session-Id|Session-Id|session[_-]?id)\"\s*:\s*\")([^\"\\]*(?:\\.[^\"\\]*)*)(\")"#, "$1[session:REDACTED]$3"),
            (#"(?i)([?&](?:session[_-]?id|jsessionid|phpsessid|sid)=)([^&\s\"']+)"#, "$1[session:REDACTED]"),
            (#"(?i)(-b|--cookie)(=|\s+)(\S+)"#, "$1$2[cookie:REDACTED]"),
            (#"(?i)((?:Mcp-Session-Id|X-Session-Id|Session-Id|X-CSRF-Token|CSRF-Token|X-XSRF-Token)\s*[:=]\s*)(\S+)"#, "$1[session:REDACTED]"),
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

    public static func any(_ value: Any) -> Any {
        if let s = value as? String { return text(s) }
        if let arr = value as? [Any] { return arr.map { any($0) } }
        if let dict = value as? [String: Any] {
            var out: [String: Any] = [:]
            for (k, v) in dict {
                let key = k.lowercased()
                if key.contains("password") || key.contains("secret") || key == "token"
                    || key == "authorization" || key == "cookie" || key == "x-api-key" || key == "pwd"
                    || key == "mcp-session-id" || key == "session-id" || key == "session_id" || key == "jsessionid" {
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
}

extension Redact {
    /// tools/redact_vectors.json cases → (cases, failures). Used by the packaged self-test and the parity harness.
    public static func runVectors(_ rows: [[String: Any]], log: (String) -> Void) -> (Int, Int) {
        var failures = 0
        for caseRow in rows {
            let name = caseRow["name"] as? String ?? "?"
            let kind = caseRow["kind"] as? String ?? "text"
            if kind == "text", let input = caseRow["input"] as? String {
                let out = text(input)
                for secret in (caseRow["must_absent"] as? [String] ?? []) where !secret.isEmpty && out.contains(secret) {
                    log("fail \(name): secret still present"); failures += 1
                }
                for keep in (caseRow["must_keep"] as? [String] ?? []) where !keep.isEmpty && !out.contains(keep) {
                    log("fail \(name): false positive removed \(keep)"); failures += 1
                }
            } else if kind == "obj", let input = caseRow["input"] {
                let blob = JSON.string(any(input))
                for secret in (caseRow["must_absent"] as? [String] ?? []) where !secret.isEmpty && blob.contains(secret) {
                    log("fail \(name): obj secret still present"); failures += 1
                }
            }
        }
        return (rows.count, failures)
    }
}
