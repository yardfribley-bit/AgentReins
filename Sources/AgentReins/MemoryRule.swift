import Foundation

/// 记忆体敏感信息检测规则。
/// 用户可自由开关内置规则，也可新增自定义正则；通过 MemoryRuleStore 持久化到 AppStorage。
struct MemoryRule: Codable, Identifiable, Hashable {
    var id: String
    var name: String
    var description: String
    var pattern: String
    var severity: String   // critical | high | medium | info
    var enabled: Bool
}
