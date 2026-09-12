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
        "html", "htm", "m", "mm", "php", "py", "rb", "rs", "sh", "sql", "swift", "ts", "tsx", "yaml", "yml"
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
             #"(?i)(chmod\s+(-R\s+)?777|permissions?\s*[:=]\s*["']?0777)"#),
        rule("remote-script", "Remote script executes inside generated UI", "medium",
             #"(?i)<script[^>]+src\s*=\s*["']https?://"#),
        rule("insecure-resource", "Generated UI loads an insecure HTTP resource", "high",
             #"(?i)(src|href)\s*=\s*["']http://"#),
        rule("dom-html-injection", "Dynamic HTML insertion may enable script injection", "high",
             #"(?i)(\.innerHTML\s*=|document\.write\s*\()"#),
        rule("unsafe-c-input", "Unbounded C input function", "critical",
             #"\bgets\s*\("#),
        rule("unsafe-c-copy", "Unbounded C string copy", "high",
             #"\b(strcpy|strcat)\s*\("#),
        rule("unsafe-c-format", "Unbounded C formatted output", "high",
             #"\bsprintf\s*\("#)
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

    /// Scan code carried inside a tool call even when it never becomes a file.
    /// WorkBuddy widgets and shell heredocs are important generated-code assets,
    /// not merely opaque tool arguments.
    static func scanGenerated(toolName: String?, arguments: String?) -> [CodeFinding] {
        guard let arguments, !arguments.isEmpty else { return [] }
        let name = toolName?.lowercased() ?? ""
        // Foundation's JSON reader recursively descends containers and can
        // overflow its stack on hostile or corrupted agent logs. Bound both
        // bytes and structural depth before handing untrusted evidence to it.
        let bounded = String(arguments.prefix(512_000))
        if arguments.utf8.count <= 512_000, hasSafeJSONShape(arguments),
           let data = arguments.data(using: .utf8),
           let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let filePath = (object["file_path"] as? String) ?? (object["path"] as? String)
            if let widget = object["widget_code"] as? String {
                return scan(path: "generated-widget.html", before: nil, after: widget)
            }
            if let command = object["command"] as? String {
                return scan(path: "generated-command.sh", before: nil, after: command)
            }
            for key in ["code", "content", "text"] {
                if let code = object[key] as? String {
                    let fallbackExtension = name.contains("html") || code.localizedCaseInsensitiveContains("<script")
                        ? "html" : "txt"
                    return scan(path: filePath ?? "generated.\(fallbackExtension)", before: nil, after: code)
                }
            }
        }
        if name.contains("bash") || name.contains("shell") {
            return scan(path: "generated-command.sh", before: nil, after: bounded)
        }
        return []
    }

    private static func hasSafeJSONShape(_ value: String, maximumDepth: Int = 64) -> Bool {
        var depth = 0
        var inString = false
        var escaped = false
        for scalar in value.unicodeScalars {
            if inString {
                if escaped { escaped = false }
                else if scalar == "\\" { escaped = true }
                else if scalar == "\"" { inString = false }
                continue
            }
            if scalar == "\"" { inString = true; continue }
            if scalar == "{" || scalar == "[" {
                depth += 1
                if depth > maximumDepth { return false }
            } else if scalar == "}" || scalar == "]" {
                depth -= 1
                if depth < 0 { return false }
            }
        }
        return !inString && depth == 0
    }

    private static func rule(_ id: String, _ title: String, _ severity: String, _ pattern: String) -> Rule {
        Rule(id: id, title: title, severity: severity,
             regex: try! NSRegularExpression(pattern: pattern))
    }
}
