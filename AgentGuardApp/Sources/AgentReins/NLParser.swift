import Foundation

enum NLParseError: Error { case failed(String) }

/// 自然语言 → 规则 解析器。
/// 优先 LLM（用户自定义模型/供应商），失败/无 key 时回退本地关键词解析。
struct NLParser {

    static let systemPrompt = """
    你是一个安全规则解析器。把用户用自然语言描述的「编码智能体护栏规则」转成严格 JSON，
    不要任何解释，只输出 JSON（可以放在 ```json 代码块里，也可以直接输出）。
    字段：
      kind: "file" 或 "cmd"
      watch: [文件路径数组]（file 类用）
      pattern: "正则字符串"（cmd 类用，匹配命令行）
      ops: ["delete","modify","read","move","rename","execute"] 子集（file 类要保护的动作）
      severity: "critical" | "high" | "medium"
      action: "protect"（文件快照还原+告警）| "alert"（仅监测）| "block"（命令层拦截）
      message: 中文人类可读说明
    示例输入：agent 不允许 删除 修改 我项目中的 .env 文件
    示例输出：{"kind":"file","watch":[".env"],"ops":["delete","modify"],"severity":"critical","action":"protect","message":"编码智能体删除/修改 .env 文件"}
    """

    // MARK: - 本地回退解析

    static func parseLocal(_ text: String) -> Rule {
        let t = text
        let low = t.lowercased()
        var ops: [String] = []
        if t.contains("删除") || low.contains("delete") || low.range(of: #"\brm\b"#, options: .regularExpression) != nil {
            ops.append("delete")
        }
        if t.contains("修改") || t.contains("改动") || t.contains("写") ||
           low.contains("modify") || low.contains("write") || low.contains("change") {
            ops.append("modify")
        }
        if t.contains("读取") || t.contains("读") || low.contains("read") || low.contains("cat") {
            ops.append("read")
        }
        if t.contains("移动") || low.contains("move") || low.contains("mv") { ops.append("move") }
        if t.contains("重命名") || low.contains("rename") { ops.append("rename") }
        if t.contains("执行") || low.contains("exec") { ops.append("execute") }
        if ops.isEmpty { ops = ["delete", "modify"] }

        let fname = extractTarget(t)
        let isProject = t.contains("项目") || low.contains("project")
        let home = NSHomeDirectory()
        let projectRoot = ProcessInfo.processInfo.environment["AGENTGUARD_PROJECT_ROOT"]
            ?? (home as NSString).appendingPathComponent("Projects")

        let watch: String
        if let f = fname, f.hasPrefix("/") {
            watch = f
        } else if let f = fname, f.hasPrefix("~") {
            watch = (f as NSString).expandingTildeInPath
        } else if let f = fname, isProject {
            watch = (projectRoot as NSString).appendingPathComponent(f)
        } else if let f = fname {
            watch = f
        } else {
            watch = projectRoot
        }

        let severity = ops.contains("delete") ? "critical" : "high"
        let opCN = ["delete": "删除", "modify": "修改", "read": "读取",
                    "move": "移动", "rename": "重命名", "execute": "执行"]
        let msg = "编码智能体" + ops.map { opCN[$0, default: $0] }.joined(separator: "、") + " " + watch
        let rid = "nl_" + (fname ?? "project").lowercased()
            .replacingOccurrences(of: #"[^a-z0-9]"#, with: "_", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return Rule(id: rid, kind: "file", watch: [watch], ops: ops,
                    severity: severity, action: "protect", restore: true,
                    message: msg, naturalLanguage: text)
    }

    /// 提取目标文件/路径：显式路径 > 带名 file.ext > 裸点文件 >「X 文件」。
    private static func extractTarget(_ t: String) -> String? {
        let ns = t as NSString
        var pathCands: [String] = []
        var dotCands: [String] = []
        if let re = try? NSRegularExpression(pattern: #"(~?/?[\w./\-]+)"#) {
            for m in re.matches(in: t, range: NSRange(t.startIndex..., in: t)) {
                let tok = ns.substring(with: m.range).trimmingCharacters(in: CharacterSet(charactersIn: ".,;"))
                if tok.contains("/") || tok.hasPrefix("~") { pathCands.append(tok) }
                else if tok.hasPrefix(".") { dotCands.append(tok) }
            }
        }
        var namedCands: [String] = []
        if let re = try? NSRegularExpression(pattern: #"(?<![\w./])([\w\-]+\.[A-Za-z0-9]+)"#),
           let m = re.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) {
            namedCands.append(ns.substring(with: m.range(at: 1)))
        }
        if let re = try? NSRegularExpression(pattern: #"(\.[A-Za-z0-9_\-]+)"#),
           let m = re.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) {
            dotCands.append(ns.substring(with: m.range(at: 1)))
        }
        if let f = pathCands.first ?? namedCands.first ?? dotCands.first { return f }
        if let re = try? NSRegularExpression(pattern: #"([\w.\-]+)\s*文件"#),
           let m = re.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) {
            return ns.substring(with: m.range(at: 1))
        }
        return nil
    }

    // MARK: - LLM 解析（用户自定义模型/供应商）

    /// 用户可配置的模型连接。
    struct LLMConfig {
        var baseURL: String    // API base，如 https://openrouter.ai/api/v1 或 https://api.openai.com/v1
        var apiKey: String
        var model: String
    }

    static func parseLLM(_ text: String, config: LLMConfig) async throws -> Rule {
        var endpoint = config.baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while endpoint.hasSuffix("/") { endpoint.removeLast() }
        if !endpoint.lowercased().contains("/chat/completions") {
            endpoint += "/chat/completions"
        }
        guard let url = URL(string: endpoint) else { throw NLParseError.failed("Base URL 无法解析") }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(config.apiKey)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        // 仅 OpenRouter 需要这两个头；其他供应商忽略即可
        if endpoint.lowercased().contains("openrouter.ai") {
            req.setValue("https://agentreins.local", forHTTPHeaderField: "HTTP-Referer")
            req.setValue("AgentReins", forHTTPHeaderField: "X-Title")
        }
        let body: [String: Any] = [
            "model": config.model,
            "messages": [
                ["role": "system", "content": systemPrompt],
                ["role": "user", "content": text]
            ],
            "temperature": 0
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, resp) = try await URLSession.shared.data(for: req)
        if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            let bodyStr = String(data: data, encoding: .utf8) ?? ""
            throw NLParseError.failed("HTTP \(http.statusCode)：\(bodyStr.prefix(200))")
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let choices = json["choices"] as? [[String: Any]],
              let msg = choices.first?["message"] as? [String: Any],
              let content = msg["content"] as? String else {
            throw NLParseError.failed("响应中没有 content（可能不是 OpenAI 兼容接口）")
        }
        let ruleData = try extractJSONData(content)
        let rule = try decodeRule(from: ruleData, original: text)
        return rule
    }

    /// 从模型返回文本中稳健提取 JSON：兼容 ```json 代码块、前后多余文字。
    private static func extractJSONData(_ content: String) throws -> Data {
        var s = content
        // 1) 去 code fence
        if s.contains("```") {
            if let open = s.range(of: "```") {
                let after = s[open.upperBound...]
                // 去掉开头的语言标识，如 json\n
                var body = after
                if let close = after.range(of: "```") {
                    body = after[..<close.lowerBound]
                }
                s = String(body)
            }
        }
        // 2) 取第一个 { 到最后一个 }
        if let first = s.firstIndex(of: "{"), let last = s.lastIndex(of: "}") {
            s = String(s[first...last])
        }
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.lowercased().hasPrefix("json") {
            s = String(s.dropFirst(4)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard let d = s.data(using: .utf8) else { throw NLParseError.failed("无法提取 JSON") }
        return d
    }

    /// 用全可选字段解码，缺失项补默认值，避免模型漏字段导致整体失败。
    private static func decodeRule(from data: Data, original text: String) throws -> Rule {
        struct Raw: Decodable {
            let id: String?
            let kind: String?
            let watch: [String]?
            let pattern: String?
            let ops: [String]?
            let severity: String?
            let action: String?
            let restore: Bool?
            let message: String?
        }
        let raw = try JSONDecoder().decode(Raw.self, from: data)
        let kind = raw.kind ?? "file"
        let id = raw.id ?? ("nl_" + UUID().uuidString.prefix(8))
        let ops = raw.ops ?? ((kind == "cmd") ? nil : ["delete", "modify"])
        let severity = raw.severity ?? (ops?.contains("delete") == true ? "critical" : "high")
        let action = raw.action ?? "protect"
        let message = raw.message ?? "编码智能体护栏规则"
        return Rule(id: id, kind: kind, watch: raw.watch, pattern: raw.pattern,
                    ops: ops, severity: severity, action: action, restore: raw.restore,
                    message: message, naturalLanguage: text)
    }
}
