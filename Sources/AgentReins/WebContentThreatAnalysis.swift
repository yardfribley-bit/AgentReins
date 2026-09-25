import Foundation
import CryptoKit

/// Content-based signals, independent of domain allow/block lists. These are
/// review candidates, not domain reputation or proof of successful phishing.
enum WebContentThreatAnalysis {
    static func scan(_ body: String) -> [InjectionFinding] {
        var findings = ExternalContentSecurity.scan(body)
        let patterns: [(InjectionCategory, String)] = [
            (.instructionOverride, "(?:忽略|无视|覆盖).{0,16}(?:之前|先前|用户|系统).{0,12}(?:指令|要求|规则)"),
            (.secretExfiltration, "(?:上传|发送|提交|粘贴|提供).{0,32}(?:私钥|助记词|验证码|API.?密钥|访问令牌|密码|\\.env)"),
            (.secretExfiltration, "(?:paste|submit|send|upload|provide).{0,40}(?:private key|seed phrase|api[ _-]?key|password|one.time code|access token)"),
            (.safeguardBypass, "(?:不要|无需|不必).{0,12}(?:告诉用户|用户确认|征求同意|报告此操作)"),
            (.memoryPoisoning, "(?:写入|保存到|更新).{0,20}(?:长期记忆|永久记忆).{0,30}(?:指令|规则|以后|后续)"),
            (.unsafeExecution, "curl\\s+[^\\r\\n|]{1,500}\\|\\s*(?:bash|sh)\\b")
        ]
        let ns = body as NSString
        for (category, pattern) in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
                  let match = regex.firstMatch(in: body, range: NSRange(location: 0, length: ns.length)) else { continue }
            let start = max(0, match.range.location - 80)
            let end = min(ns.length, NSMaxRange(match.range) + 120)
            let evidence = ns.substring(with: NSRange(location: start, length: end - start))
            let id = SHA256.hash(data: Data((category.rawValue + evidence).utf8)).map { String(format: "%02x", $0) }.joined()
            findings.append(InjectionFinding(id: id, category: category, severity: "high", confidence: "medium", evidence: evidence))
        }
        return findings
    }
}
