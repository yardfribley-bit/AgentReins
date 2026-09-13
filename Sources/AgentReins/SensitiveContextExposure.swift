import Foundation

enum SensitiveExposureCategory: String, Codable, Sendable {
    case apiCredential = "API credential"
    case password = "Password"
    case privateKey = "Private key"
    case bankCard = "Bank card number"
    case nationalID = "National identity number"
    case email = "Email address"
}

struct SensitiveExposureFinding: Codable, Equatable, Sendable {
    let category: SensitiveExposureCategory
    let source: String
    let evidence: String
    let severity: String
}

enum SensitiveContextExposure {
    static func scan(events: [GuardEvent]) -> [SensitiveExposureFinding] {
        var inputs: [(String, String)] = events.compactMap {
            guard let prompt = $0.modelPrompt, !prompt.isEmpty else { return nil }
            return ("model context", prompt)
        }
        // A completed tool result can only be claimed as upstream exposure when
        // another model request was observed after it in the same turn.
        for event in events where event.kind == "tool" && event.op == "result" {
            guard let content = event.modelResponse, !content.isEmpty,
                  events.contains(where: { $0.inputTokens != nil && $0.ts > event.ts }) else { continue }
            inputs.append(("tool result · \(event.toolName ?? "unknown tool")", content))
        }
        return inputs.flatMap { source, text in patterns.flatMap { pattern in
            matches(pattern.regex, in: text).compactMap { match in
                guard pattern.validate(match) else { return nil }
                return SensitiveExposureFinding(category: pattern.category, source: source,
                    evidence: boundedEvidence(match), severity: pattern.severity)
            }
        }}
    }

    private struct Pattern {
        let category: SensitiveExposureCategory
        let regex: String
        let severity: String
        let validate: (String) -> Bool
    }

    private static let patterns: [Pattern] = [
        Pattern(category: .privateKey, regex: #"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#,
                severity: "critical", validate: { _ in true }),
        Pattern(category: .apiCredential,
                regex: #"(?:sk-[A-Za-z0-9_-]{16,}|(?:api[_ -]?key|access[_ -]?token|secret)[\s\"']*[:=][\s\"']*[A-Za-z0-9_./+\-=]{12,})"#,
                severity: "critical", validate: { _ in true }),
        Pattern(category: .password,
                regex: #"(?:password|passwd|pwd|密码)[\s\"']*[:=][\s\"']*[^\s\"']{6,}"#,
                severity: "high", validate: { _ in true }),
        Pattern(category: .nationalID, regex: #"(?<!\d)\d{17}[0-9Xx](?!\d)"#,
                severity: "high", validate: { _ in true }),
        Pattern(category: .bankCard, regex: #"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"#,
                severity: "high", validate: luhnValid),
        Pattern(category: .email, regex: #"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"#,
                severity: "medium", validate: { _ in true })
    ]

    private static func matches(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap {
            Range($0.range, in: text).map { String(text[$0]) }
        }
    }

    private static func luhnValid(_ value: String) -> Bool {
        let digits = value.compactMap(\.wholeNumberValue)
        guard (13...19).contains(digits.count) else { return false }
        return digits.reversed().enumerated().reduce(0) { sum, pair in
            var digit = pair.element
            if pair.offset % 2 == 1 { digit *= 2; if digit > 9 { digit -= 9 } }
            return sum + digit
        } % 10 == 0
    }

    private static func boundedEvidence(_ value: String) -> String {
        String(value.prefix(160))
    }
}
