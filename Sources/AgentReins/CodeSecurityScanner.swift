import Foundation

struct CodeFinding: Codable, Hashable, Identifiable {
    var id: String { "\(ruleId):\(line):\(evidence)" }
    let ruleId: String
    let title: String
    let severity: String
    let line: Int
    let evidence: String
}

/// Fast, local screening for high-signal mistakes commonly introduced by generated code.
/// Findings are review prompts, not proof that a vulnerability is exploitable.
enum CodeSecurityScanner {
    private struct Rule {
        let id: String
        let title: String
        let severity: String
        let regex: NSRegularExpression
    }

    private static let sourceExtensions: Set<String> = [
        "c", "cc", "cpp", "cs", "go", "h", "hpp", "java", "js", "jsx", "kt", "kts",
        "m", "mm", "php", "py", "rb", "rs", "sh", "sql", "swift", "ts", "tsx", "yaml", "yml"
    ]

    private static let rules: [Rule] = [
        rule("hardcoded-secret", "Possible hard-coded secret", "critical",
             #"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{8,}["']"#),
        rule("shell-injection", "Untrusted data may reach a shell", "critical",
             #"(?i)(os\.system|subprocess\..*shell\s*=\s*true|child_process\.(exec|execSync)|Runtime\.getRuntime\(\)\.exec)"#),
        rule("dynamic-eval", "Dynamic code execution", "high",
             #"(?i)\b(eval|exec)\s*\("#),
        rule("sql-concatenation", "SQL query built with string interpolation", "high",
             #"(?i)(select|insert|update|delete).*(\+\s*\w+|\$\{|%s|\{\w+\})"#),
        rule("tls-verification-disabled", "TLS certificate verification disabled", "high",
             #"(?i)(verify\s*=\s*false|rejectUnauthorized\s*:\s*false|CERT_NONE)"#),
        rule("unsafe-deserialization", "Unsafe deserialization", "high",
             #"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\(|ObjectInputStream\s*\()"#),
        rule("permissive-cors", "Overly permissive CORS configuration", "medium",
             #"(?i)(allow_origins\s*=\s*\[?\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*)"#),
        rule("weak-hash", "Weak cryptographic hash", "medium",
             #"(?i)\b(md5|sha1)\s*\("#),
        rule("world-writable", "World-writable permission", "high",
             #"(?i)(chmod\s+(-R\s+)?777|permissions?\s*[:=]\s*["']?0777)"#)
    ]

    static func scan(path: String, before: String?, after: String?) -> [CodeFinding] {
        guard sourceExtensions.contains(URL(fileURLWithPath: path).pathExtension.lowercased()),
              let after, !after.isEmpty else { return [] }
        let oldLines = (before ?? "").components(separatedBy: .newlines)
        let newLines = after.components(separatedBy: .newlines)
        var findings: [CodeFinding] = []
        for (offset, line) in newLines.enumerated() {
            if offset < oldLines.count, oldLines[offset] == line { continue }
            let range = NSRange(line.startIndex..., in: line)
            for rule in rules where rule.regex.firstMatch(in: line, range: range) != nil {
                findings.append(CodeFinding(ruleId: rule.id, title: rule.title,
                    severity: rule.severity, line: offset + 1,
                    evidence: String(line.trimmingCharacters(in: .whitespaces).prefix(240))))
            }
        }
        return Array(findings.prefix(100))
    }

    private static func rule(_ id: String, _ title: String, _ severity: String, _ pattern: String) -> Rule {
        Rule(id: id, title: title, severity: severity,
             regex: try! NSRegularExpression(pattern: pattern))
    }
}
