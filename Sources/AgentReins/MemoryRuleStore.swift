import Foundation
import SwiftUI
import Combine

/// 记忆体规则仓库：持久化到 UserDefaults（agr_memory_rules_json），供用户自主配置。
/// 默认内置 11 条常见密钥/令牌/私钥规则，全部可开关、可删除、可新增自定义。
@MainActor
final class MemoryRuleStore: ObservableObject {
    @Published var rules: [MemoryRule] = [] {
        didSet { save() }
    }
    static let storageKey = "agr_memory_rules_json"

    init() { load() }

    /// 内置默认规则，与 agentguard-memory-scan.py 的 SECRET_PATTERNS 保持一致。
    static func builtInRules() -> [MemoryRule] {
        [
            MemoryRule(id: "aws_ak", name: "AWS Access Key ID",
                       description: "AWS AKIA 开头的访问密钥",
                       pattern: "AKIA[0-9A-Z]{16}", severity: "high", enabled: true),
            MemoryRule(id: "aws_sk", name: "AWS Secret Access Key",
                       description: "AWS Secret Access Key 赋值",
                       pattern: "(?i)aws_?secret_?access_?key\\s*[:=]\\s*['\"]?[A-Za-z0-9/+=]{40}",
                       severity: "high", enabled: true),
            MemoryRule(id: "openai", name: "OpenAI API Key",
                       description: "sk- 开头的 OpenAI 类 API Key",
                       pattern: "sk-[A-Za-z0-9]{20,}", severity: "high", enabled: true),
            MemoryRule(id: "anthropic", name: "Anthropic API Key",
                       description: "sk-ant- 开头的 Anthropic API Key",
                       pattern: "sk-ant-[A-Za-z0-9_-]{20,}", severity: "high", enabled: true),
            MemoryRule(id: "github", name: "GitHub Token",
                       description: "ghp_/github_pat_ 等 GitHub Token",
                       pattern: "gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}",
                       severity: "high", enabled: true),
            MemoryRule(id: "google", name: "Google API Key",
                       description: "AIza 开头的 Google API Key",
                       pattern: "AIza[0-9A-Za-z_-]{35}", severity: "high", enabled: true),
            MemoryRule(id: "stripe", name: "Stripe Secret Key",
                       description: "sk_live_ 开头的 Stripe 生产密钥",
                       pattern: "sk_live_[0-9a-zA-Z]{16,}", severity: "high", enabled: true),
            MemoryRule(id: "slack", name: "Slack Token",
                       description: "xoxb/xoxa/xoxr 等 Slack Token",
                       pattern: "xox[baprs]-[0-9A-Za-z-]{10,}", severity: "high", enabled: true),
            MemoryRule(id: "privkey", name: "Private Key Block",
                       description: "BEGIN PRIVATE KEY 私钥块",
                       pattern: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                       severity: "critical", enabled: true),
            MemoryRule(id: "dbconn", name: "DB Connection String",
                       description: "带用户名密码的数据库连接串",
                       pattern: "(?i)(postgres|postgresql|mysql|mongodb(?:\\+srv)?|redis|amqp)://[^\\s:]+:[^\\s@]{3,}@",
                       severity: "high", enabled: true),
            MemoryRule(id: "generic_secret", name: "Generic Secret Assignment",
                       description: "通用 api_key/secret/token/password 赋值",
                       pattern: "(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-+/=!@#$%^&*()]{12,}['\"]",
                       severity: "medium", enabled: true),
        ]
    }

    func load() {
        guard let data = UserDefaults.standard.string(forKey: Self.storageKey)?.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([MemoryRule].self, from: data),
              !decoded.isEmpty else {
            rules = Self.builtInRules()
            return
        }
        rules = decoded
    }

    func save() {
        guard let data = try? JSONEncoder().encode(rules),
              let s = String(data: data, encoding: .utf8) else { return }
        UserDefaults.standard.set(s, forKey: Self.storageKey)
    }

    func add(_ r: MemoryRule) {
        rules.removeAll { $0.id == r.id }
        rules.append(r)
    }

    func remove(_ r: MemoryRule) {
        rules.removeAll { $0.id == r.id }
    }

    func toggle(_ r: MemoryRule) {
        if let idx = rules.firstIndex(where: { $0.id == r.id }) {
            rules[idx].enabled.toggle()
        }
    }

    func resetToDefaults() {
        rules = Self.builtInRules()
    }

    var enabledRules: [MemoryRule] { rules.filter { $0.enabled } }
}
