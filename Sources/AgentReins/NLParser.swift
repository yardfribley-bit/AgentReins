import Foundation

/// 完全离线的自然语言规则解析器。它不包含任何网络请求入口。
struct NLParser {
    static func parseLocal(_ text: String) -> Rule {
        let low = text.lowercased()
        var ops: [String] = []
        if text.contains("删除") || low.contains("delete") || low.range(of: #"\brm\b"#, options: .regularExpression) != nil { ops.append("delete") }
        if text.contains("修改") || text.contains("改动") || text.contains("写") || low.contains("modify") || low.contains("write") || low.contains("change") { ops.append("modify") }
        if text.contains("读取") || text.contains("读") || low.contains("read") || low.contains("cat") { ops.append("read") }
        if text.contains("移动") || low.contains("move") || low.contains("mv") { ops.append("move") }
        if text.contains("重命名") || low.contains("rename") { ops.append("rename") }
        if text.contains("执行") || low.contains("exec") { ops.append("execute") }
        if ops.isEmpty { ops = ["delete", "modify"] }

        let target = extractTarget(text)
        let projectRoot = ProcessInfo.processInfo.environment["AGENTGUARD_PROJECT_ROOT"]
            ?? (NSHomeDirectory() as NSString).appendingPathComponent("Projects")
        let watch: String
        if let target, target.hasPrefix("/") { watch = target }
        else if let target, target.hasPrefix("~") { watch = (target as NSString).expandingTildeInPath }
        else if let target, text.contains("项目") || low.contains("project") { watch = (projectRoot as NSString).appendingPathComponent(target) }
        else { watch = target ?? projectRoot }

        let labels = ["delete": "删除", "modify": "修改", "read": "读取", "move": "移动", "rename": "重命名", "execute": "执行"]
        let message = "阻止 Agent " + ops.map { labels[$0, default: $0] }.joined(separator: "、") + " " + watch
        let slug = (target ?? UUID().uuidString.prefix(8).description).lowercased()
            .replacingOccurrences(of: #"[^a-z0-9]"#, with: "_", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return Rule(id: "local_\(slug)", kind: "file", watch: [watch], ops: ops,
                    severity: ops.contains("delete") ? "critical" : "high", action: "protect",
                    restore: true, message: message, naturalLanguage: text)
    }

    private static func extractTarget(_ text: String) -> String? {
        let ns = text as NSString
        var paths: [String] = []
        var dotFiles: [String] = []
        if let regex = try? NSRegularExpression(pattern: #"(~?/?[\w./\-]+)"#) {
            for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                let token = ns.substring(with: match.range).trimmingCharacters(in: CharacterSet(charactersIn: ".,;"))
                if token.contains("/") || token.hasPrefix("~") { paths.append(token) }
                else if token.hasPrefix(".") { dotFiles.append(token) }
            }
        }
        if let regex = try? NSRegularExpression(pattern: #"(?<![\w./])([\w\-]+\.[A-Za-z0-9]+)"#),
           let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) {
            paths.append(ns.substring(with: match.range(at: 1)))
        }
        if let first = paths.first ?? dotFiles.first { return first }
        if let regex = try? NSRegularExpression(pattern: #"([\w.\-]+)\s*文件"#),
           let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) {
            return ns.substring(with: match.range(at: 1))
        }
        return nil
    }
}
