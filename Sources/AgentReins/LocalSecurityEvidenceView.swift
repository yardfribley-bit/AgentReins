import SwiftUI

struct LocalSecurityEvidenceView: View {
    let events: [GuardEvent]
    @State private var selectedID: UUID?

    private var selected: GuardEvent? { events.first { $0.id == selectedID } ?? events.first }

    var body: some View {
        HStack(alignment: .top, spacing: 24) {
            VStack(alignment: .leading, spacing: 14) {
                Text("这次任务里发生了什么").font(.headline)
                ForEach(events.sorted { $0.ts < $1.ts }, id: \.id) { event in
                    Button { selectedID = event.id } label: {
                        VStack(alignment: .leading, spacing: 5) {
                            Text(event.ts.formatted(date: .omitted, time: .standard)).font(.caption).foregroundStyle(.secondary)
                            Text(label(event)).fontWeight(.medium)
                            Text(event.toolName ?? event.op).font(.caption).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading).padding(12)
                            .background(selected?.id == event.id ? TaskStoryStyle.soft : TaskStoryStyle.panel,
                                        in: RoundedRectangle(cornerRadius: 7))
                    }.buttonStyle(.plain)
                }
                Text("只显示已关联的采集事实。时间相近不代表已证明数据流转关系。")
                    .font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 12) {
                Text("原始内容与来源").font(.headline)
                if let event = selected {
                    Text(event.path).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Text(event.modelPrompt ?? event.modelResponse ?? event.command ?? "此条事件没有记录正文，请查看完整 JSON。")
                        .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    if let destination = event.remoteDomain ?? event.remoteHost {
                        Text("外联目的地：\(destination) · \(event.remotePort.map(String.init) ?? "端口未采集")")
                        Text("位置与归属请查看上方接收地址；连接记录本身不能证明发送内容。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if let before = event.beforeContent { DisclosureGroup("修改前内容") { Text(before).textSelection(.enabled) } }
                    if let after = event.afterContent { DisclosureGroup("修改后内容") { Text(after).textSelection(.enabled) } }
                    if let diff = event.fileDiff { DisclosureGroup("修改差异") { Text(diff).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) } }
                    DisclosureGroup("完整 JSON 与采集标识") {
                        Text(json(event)).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    }
                } else {
                    Text("未找到对应原始证据，不能用 AI 文字代替。").foregroundStyle(.secondary)
                }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func label(_ event: GuardEvent) -> String {
        switch event.kind {
        case "model": return event.op == "prompt" ? "向模型发送内容" : "收到模型返回内容"
        case "tool": return "执行工具：\(event.toolName ?? "名称未采集")"
        case "memory": return "记录记忆相关活动"
        case "network": return "建立外联连接"
        case "file": return "访问文件"
        case "alert": return "检测到风险信号"
        default: return "采集到 \(event.kind) 活动"
        }
    }

    private func json(_ event: GuardEvent) -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return (try? encoder.encode(event)).map { String(decoding: $0, as: UTF8.self) } ?? "编码失败"
    }
}
