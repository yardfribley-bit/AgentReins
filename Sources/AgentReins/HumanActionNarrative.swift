import Foundation

/// Human-facing language derived only from observed tool evidence. This is
/// intentionally deterministic: an absent result is never described as success.
struct HumanActionNarrative: Sendable {
    let headline: String
    let explanation: String
    let outcome: String
    let command: String?
    let target: String?
    let duration: String?

    static func build(_ step: AgentTaskJourney.ToolStep) -> Self {
        let call = step.call
        let name = call.toolName.lowercased()
        let fields = argumentFields(call.arguments)
        let isCommandTool = name.contains("exec") || name.contains("bash") ||
            name.contains("shell") || name.contains("terminal")
        let rawArgument = call.arguments?.trimmingCharacters(in: .whitespacesAndNewlines)
        let command = first(fields, keys: ["command", "cmd", "script", "shell_command"])
            ?? (isCommandTool && rawArgument?.first != "{" ? rawArgument : nil)
        let target = first(fields, keys: ["path", "file_path", "filename", "url", "query"])
        let effectiveTarget = step.fileActivities.first?.path ?? target
        let purpose: String
        if name.contains("read") || name.contains("cat") {
            purpose = "读取文件"
        } else if name.contains("write") || name.contains("edit") || name.contains("patch") {
            purpose = "修改文件"
        } else if name.contains("search") {
            purpose = "搜索信息"
        } else if name.contains("fetch") || name.contains("browser") {
            purpose = "访问网页"
        } else if isCommandTool {
            purpose = commandPurpose(command)
        } else if name.contains("excel") || name.contains("spreadsheet") {
            purpose = "处理电子表格"
        } else if call.serverName != nil || name.hasPrefix("mcp__") {
            purpose = "调用 MCP 服务"
        } else {
            purpose = "调用 \(call.toolName)"
        }
        let headline = effectiveTarget.map { "\(purpose)：\(short($0, limit: 90))" }
            ?? command.map { "\(purpose)：\(short($0, limit: 90))" }
            ?? purpose
        let explanation: String
        if let command {
            explanation = "Agent 运行了命令“\(short(command, limit: 160))”。"
        } else if let effectiveTarget {
            explanation = "Agent 使用 \(call.toolName) 处理“\(short(effectiveTarget, limit: 160))”。"
        } else {
            explanation = "Agent 调用了 \(call.toolName)；参数中未提取到明确目标。"
        }
        let outcome: String
        switch call.state {
        case .completed:
            let resultPreview = step.result?.output.flatMap { output -> String? in
                let compact = output.replacingOccurrences(of: "\n", with: " ")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return compact.isEmpty ? nil : short(compact, limit: 130)
            }
            if let exit = call.exitCode, exit != 0 {
                outcome = "进程退出码 \(exit)" + resultPreview.map { "；工具返回：\($0)" }.orEmpty + "。"
            } else if let resultPreview {
                outcome = "工具已完成；返回内容：\(resultPreview)"
            } else {
                outcome = "工具记录为已完成；未采集到可展示的结果正文。"
            }
        case .failed: outcome = "工具执行失败。"
        case .denied: outcome = "工具调用被拒绝。"
        case .requested, .running: outcome = "工具仍在执行或尚未采集到结束事件。"
        }
        return Self(headline: headline, explanation: explanation, outcome: outcome,
                    command: command, target: effectiveTarget,
                    duration: step.durationMS.map { String(format: "%.1f 秒", $0 / 1_000) })
    }

    private static func argumentFields(_ arguments: String?) -> [String: Any] {
        guard let arguments, let data = arguments.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return object
    }

    private static func first(_ fields: [String: Any], keys: [String]) -> String? {
        for key in keys {
            if let value = fields[key] as? String, !value.isEmpty { return value }
        }
        return nil
    }

    private static func short(_ value: String, limit: Int) -> String {
        let line = value.replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return line.count > limit ? String(line.prefix(limit)) + "…" : line
    }

    private static func commandPurpose(_ command: String?) -> String {
        guard let command else { return "执行命令" }
        let value = command.lowercased()
        if ["g++ ", "clang++ ", "gcc ", "clang ", "cmake ", "make ", "swift build"].contains(where: value.contains) {
            return "编译程序"
        }
        if ["swift test", "pytest", "npm test", "pnpm test", "cargo test", "go test"].contains(where: value.contains) {
            return "运行测试"
        }
        if ["git status", "git diff", "git log"].contains(where: value.contains) {
            return "查看代码变更"
        }
        if ["rg ", "grep ", "find ", "ls "].contains(where: value.contains) {
            return "查找项目内容"
        }
        if value.hasPrefix("ssh ") || value.contains(" ssh ") || value.hasPrefix("scp ") {
            return "执行远程操作"
        }
        return "执行命令"
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
