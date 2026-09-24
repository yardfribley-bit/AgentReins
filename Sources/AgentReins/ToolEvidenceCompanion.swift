import AppKit
import SwiftUI

/// Explanations never replace evidence, execute captured code, or infer intent.
struct ToolEvidenceExplanation: Identifiable {
    let id: String
    let title: String
    let explanation: String
    let source: String
    let raw: String

    static func rows(for step: AgentTaskJourney.ToolStep) -> [Self] {
        var rows: [Self] = []
        if let arguments = step.call.arguments {
            // Bound interpretation cost; the original remains available in full.
            if arguments.utf8.count <= 256_000, let data = arguments.data(using: .utf8),
               let fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                for key in fields.keys.sorted() {
                    guard let value = fields[key], let encoded = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys]),
                          let raw = String(data: encoded, encoding: .utf8) else { continue }
                    if ["cmd", "command", "shell_command"].contains(key), let text = value as? String,
                       let parts = commandRows(text, prefix: "argument:\(key)") {
                        rows.append(contentsOf: parts)
                        continue
                    }
                    rows.append(Self(id: "argument:\(key)", title: title(key),
                        explanation: explain(key, value: value), source: "调用参数 / \(key) · JSON 值",
                        raw: raw))
                }
            } else {
                rows.append(Self(id: "arguments", title: "实际提交的调用内容",
                    explanation: "这里保留工具收到的原文。它可能是脚本或嵌套调用；尚未可靠拆解，不把整段代码当作一条终端命令，也不推测执行目的。",
                    source: "调用参数原文", raw: arguments))
            }
        } else {
            rows.append(Self(id: "arguments", title: "输入内容尚未采集", explanation: "不能根据工具名称补出它实际收到的参数。", source: "采集状态", raw: "调用参数未采集"))
        }
        rows.append(Self(id: "output", title: "工具实际返回了什么",
            explanation: step.result?.truncated == true
                ? "采集端标记结果已截断。右侧仅是已采集部分，不能当作完整输出。"
                : "这是工具返回的内容，不等于任务已通过验证。输出中的文字、数字及错误信息保留原样；未识别的字段不猜测含义。",
            source: "工具返回原文", raw: step.result?.output ?? "结果正文未采集"))
        let status: String
        switch step.call.state {
        case .completed: status = "工具记录为已完成；不代表用户任务已完成。"
        case .failed: status = "工具记录为执行失败，请结合返回内容查看原因。"
        case .denied: status = "调用被拒绝；不能视为操作已经执行。"
        case .requested, .running: status = "已观测到调用，尚不能确认执行结束。"
        }
        rows.append(Self(id: "execution", title: "状态与耗时怎样理解",
            explanation: status + " 耗时指这次工具调用的整体时间，不是每个内部操作的时间。退出码若来自多条命令，不能据此认定每条都成功。",
            source: "调用生命周期", raw: "state: \(step.call.state.rawValue)\nstarted_at: \(step.call.startedAt.map { $0.ISO8601Format() } ?? "未采集")\ncompleted_at: \(step.call.completedAt.map { $0.ISO8601Format() } ?? "未采集")\nduration_ms: \(step.durationMS.map { String($0) } ?? "未采集")\nexit_code: \(step.call.exitCode.map(String.init) ?? "未采集")"))
        for (index, file) in step.fileActivities.enumerated() {
            rows.append(Self(id: "file:\(index)", title: "关联文件记录",
                explanation: "这里保留关联文件的操作、路径和已采集变更。读取不等于修改；缺少变更正文时，不推测文件内容。",
                source: "文件证据", raw: "operation: \(file.operation.rawValue)\npath: \(file.path)\n\(file.patch ?? "变更正文未采集")"))
        }
        return rows
    }

    private static func title(_ key: String) -> String {
        switch key {
        case "file", "path", "file_path", "filename": return "涉及哪个文件或位置"
        case "sheet", "sheet_name": return "使用哪个工作表"
        case "range": return "选取哪一部分数据"
        case "cmd", "command", "shell_command": return "实际提交了什么命令"
        case "workdir", "cwd": return "从哪个目录执行"
        case "url": return "访问哪个地址"
        case "query", "pattern": return "搜索什么内容"
        case "content", "text", "new_text": return "提交了哪些文字"
        case "max_output_tokens": return "返回内容的长度限制"
        default: return "参数 \(key)"
        }
    }

    /// Only split simple literal command lists. Shell expansions, pipelines and
    /// nested programs remain intact rather than manufacturing an execution trace.
    static func commandRows(_ text: String, prefix: String) -> [Self]? {
        guard text.count < 32_000, !text.contains("$"), !text.contains("`"),
              !text.contains("\n"), !text.contains("\\") else { return nil }
        var quote: Character?
        var parts: [String] = []
        var part = ""
        for character in text {
            if let active = quote {
                part.append(character)
                if character == active { quote = nil }
            } else if character == "\"" || character == "'" {
                quote = character; part.append(character)
            } else if character == ";" {
                parts.append(part); part = ""
            } else if "|&<>(){}#".contains(character) { return nil }
            else { part.append(character) }
        }
        guard quote == nil else { return nil }
        parts.append(part)
        return parts.enumerated().compactMap { index, raw in
            let command = raw.trimmingCharacters(in: .whitespaces)
            guard !command.isEmpty else { return nil }
            var explanation = "这是调用中的第 \(index + 1) 个命令片段。分号连接的命令通常依次执行，不代表各项都已成功。"
            var title = "操作 \(index + 1) · 原始命令"
            if let regex = try? NSRegularExpression(pattern: #"^sed -n '([0-9]+),([0-9]+)p' (.+)$"#),
               let match = regex.firstMatch(in: command, range: NSRange(command.startIndex..., in: command)),
               let a = Range(match.range(at: 1), in: command), let b = Range(match.range(at: 2), in: command) {
                title = "操作 \(index + 1) · 读取指定行"
                explanation = "显示指定文件第 \(command[a])–\(command[b]) 行。这里的 -n 配合 p 只打印该范围，不修改文件。是否读取成功仍需核对输出。"
            } else if command.hasPrefix("rg -n ") {
                title = "操作 \(index + 1) · 查找文本"
                explanation = "rg 搜索指定文本模式；-n 让结果带上行号。模式中的竖线表示可匹配任意一个分支。搜索命中不是检查通过。"
            }
            return Self(id: "\(prefix):\(index)", title: title, explanation: explanation,
                source: "命令原文片段 \(index + 1) · 完整调用保留在下方", raw: raw)
        }
    }

    private static func explain(_ key: String, value: Any) -> String {
        switch key {
        case "file", "path", "file_path", "filename": return "这是调用中指定的文件或位置。路径本身不能证明文件已读取或修改，需要结合结果判断。"
        case "sheet", "sheet_name": return "这是表格内的工作表名称，不是整份文件的名称。"
        case "range":
            if let value = value as? String, let description = cellRange(value) { return description }
            return "这是工具收到的范围参数；未识别其格式，不推测覆盖哪些数据。"
        case "workdir", "cwd": return "命令在这个目录下执行；命令中的相对文件路径通常从这里查找。"
        case "cmd", "command", "shell_command": return "右侧是原始命令。分号通常连接依次执行的操作，&& 通常表示前一项成功才继续。引号内的符号可能只是文字；这里不自动拆分复杂脚本，也不推测意图。"
        case "url": return "这是调用指定的地址；是否实际访问成功，需要核对返回或网络证据。"
        case "query", "pattern": return "这是提交给工具的搜索条件，不代表已经找到匹配内容。"
        case "content", "text", "new_text": return "这是输入文本，保留原值；是否写入或发送成功，要看对应结果。"
        case "max_output_tokens": return "限制工具可返回的内容长度，不是本次模型实际消耗的 Token。"
        default: return "保留原始参数名和值。尚无可靠的字段解释，不能仅凭名称推测业务含义。"
        }
    }

    static func cellRange(_ value: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: "^([A-Z]{1,3})([1-9][0-9]{0,6}):([A-Z]{1,3})([1-9][0-9]{0,6})$"),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) else { return nil }
        let parts = (1...4).compactMap { Range(match.range(at: $0), in: value).map { String(value[$0]) } }
        guard parts.count == 4, let first = Int(parts[1]), let last = Int(parts[3]), last >= first else { return nil }
        func column(_ s: String) -> Int { s.utf8.reduce(0) { $0 * 26 + Int($1) - 64 } }
        let width = column(parts[2]) - column(parts[0]) + 1
        guard width > 0 else { return nil }
        return "从 \(parts[0]) 列第 \(first) 行到 \(parts[2]) 列第 \(last) 行，共 \(last - first + 1) 行、\(width) 列。不代表读取了整份表，也不能据此认定数据已经修改。"
    }
}

struct ToolEvidenceCompanion: View {
    let step: AgentTaskJourney.ToolStep
    let onInspect: () -> Void
    private let rows: [ToolEvidenceExplanation]
    @State private var selected: String?
    @State private var expanded = Set<String>()
    @State private var copyStatus = "点击说明，对照对应原文"

    init(step: AgentTaskJourney.ToolStep, onInspect: @escaping () -> Void = {}) {
        self.step = step
        self.onInspect = onInspect
        rows = ToolEvidenceExplanation.rows(for: step)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("工具记录 · 解释与原文").font(.headline)
            Text("\(step.call.toolName) · \(step.call.serverName.map { "MCP：\($0) · " } ?? "")\(step.durationMS.map { String(format: "%.1f 秒", $0 / 1000) } ?? "耗时未采集")")
                .font(.caption).foregroundStyle(TaskStoryStyle.muted)
            Text("说明基于已识别字段，不替代原始证据，也不代表 Agent 的意图。")
                .font(.caption).foregroundStyle(TaskStoryStyle.muted)
            ForEach(rows) { row in
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 18) {
                        explanation(row).frame(minWidth: 170, maxWidth: .infinity)
                        evidence(row).frame(minWidth: 220, maxWidth: .infinity)
                    }
                    VStack(alignment: .leading, spacing: 12) { explanation(row); evidence(row) }
                }
                Divider()
            }
            HStack {
                Text(copyStatus).font(.caption).foregroundStyle(TaskStoryStyle.muted)
                Spacer()
                Button("复制完整记录") { copy() }
            }
            DisclosureGroup("完整工具记录（保留调用结构）") {
                TextEditor(text: .constant(fullRecord)).font(.system(size: 12, design: .monospaced)).frame(height: 240)
            }
        }.padding(16).background(TaskStoryStyle.panel, in: RoundedRectangle(cornerRadius: 10))
    }

    private func explanation(_ row: ToolEvidenceExplanation) -> some View {
        Button { onInspect(); selected = row.id } label: {
            VStack(alignment: .leading, spacing: 7) {
                Text(row.title).font(.callout.bold())
                Text(row.explanation).font(.callout).foregroundStyle(TaskStoryStyle.text)
                Text(selected == row.id ? "对应原文已定位 →" : "定位对应原文 →")
                    .font(.caption).foregroundStyle(TaskStoryStyle.accent)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.buttonStyle(.plain)
    }

    private func evidence(_ row: ToolEvidenceExplanation) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(row.source).font(.caption).foregroundStyle(TaskStoryStyle.muted)
            Text(String(row.raw.prefix(expanded.contains(row.id) ? row.raw.count : 1600)))
                .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                .background(selected == row.id ? TaskStoryStyle.soft : TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 7))
                .overlay(alignment: .leading) { if selected == row.id { Rectangle().fill(TaskStoryStyle.accent).frame(width: 3) } }
            if row.raw.count > 1600 {
                Button(expanded.contains(row.id) ? "收起长内容" : "展开已采集全文（当前显示前 1600 字符）") {
                    onInspect()
                    if expanded.contains(row.id) { expanded.remove(row.id) } else { expanded.insert(row.id) }
                }.font(.caption)
            }
        }
    }

    private var fullRecord: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return (try? encoder.encode(step)).map { String(decoding: $0, as: UTF8.self) } ?? "记录编码失败"
    }

    private func copy() {
        onInspect()
        NSPasteboard.general.clearContents()
        copyStatus = NSPasteboard.general.setString(fullRecord, forType: .string) ? "完整记录已复制" : "复制失败，请从完整记录选择复制"
    }
}
