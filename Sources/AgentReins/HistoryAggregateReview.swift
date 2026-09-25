import SwiftUI

struct HistoryAggregateReview: View {
    let summary: TaskAggregates
    let question: String
    let open: (String, String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("匹配范围：\(summary.taskCount) 项已索引任务").font(.caption).foregroundStyle(.secondary)
            if case .memoryLineage = HistoryQueryIntent.classify(question) {
                Label(summary.taskCount == 0 ? "当前索引范围未找到匹配记录" : "记忆血缘 · 待核对写入证据", systemImage: "point.3.connected.trianglepath.dotted")
                    .foregroundStyle(.orange)
                Text(summary.taskCount == 0 ? "暂时无法回答何时写入。没有命中不等于从未写入，也不能据此认定记忆证据缺失。" : "下面的命中只能证明内容出现过，不能据此认定首次写入长期记忆的时间。")
                Text("判定写入时间需要记忆版本变化或写入操作的证据；证明它后来进入模型上下文是另一项核查。")
                    .font(.caption).foregroundStyle(.secondary)
            } else if case .repeatedTools = HistoryQueryIntent.classify(question) {
                Text("重复操作候选 · 数据库计算").font(.caption).foregroundStyle(TaskStoryStyle.accent)
                Text("相同工具与参数出现了多次，是否必要需要结合任务核查。")
                    .font(.title3.bold())
                ForEach(summary.repeatedTools.indices, id: \.self) { index in
                    let group = summary.repeatedTools[index]
                    HStack {
                        Text(group.value).lineLimit(2)
                        Spacer()
                        Text("\(group.occurrences) 次 · \(group.tasks) 项任务").monospacedDigit()
                    }.padding(.vertical, 8)
                    Divider()
                }
                if summary.repeatedTools.isEmpty { Text("当前匹配范围未发现相同工具与参数的重复记录。") }
                Text("参数相同不等于浪费；当前无法据此计算可节省的 Token。")
                    .font(.caption).foregroundStyle(.secondary)
            } else if case .tokenRanking = HistoryQueryIntent.classify(question), let first = summary.topTokenTasks.first {
                HStack {
                    Text("任务排名 · 数据库计算").foregroundStyle(TaskStoryStyle.accent)
                    Spacer()
                    Text("匹配 \(summary.taskCount) 项已索引任务").foregroundStyle(.secondary)
                }.font(.caption)
                Text("「\(first.title)」记录的 Token 消耗最多。")
                    .font(.system(size: 20, weight: .semibold))
                HStack(spacing: 30) {
                    number("总 Token", first.totalTokens)
                    number("输入 Token", first.inputTokens)
                    number("输出 Token", first.outputTokens)
                    Spacer()
                    Button("查看任务与依据") { open(first.sessionID, first.turnID) }
                        .buttonStyle(.borderedProminent).tint(TaskStoryStyle.accent)
                }
                DisclosureGroup("统计口径与覆盖范围") {
                    Text("按已记录输入＋输出 Token 排序，统计全部匹配的已索引任务，而非当前列表页。未采集的用量不补算；历史整理尚未完成时不能代表全部历史。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Divider()
                Text("任务 Token 排名 · 前 10 项").font(.headline)
                ForEach(Array(summary.topTokenTasks.enumerated()), id: \.element.id) { index, task in
                    Button { open(task.sessionID, task.turnID) } label: {
                        HStack(spacing: 14) {
                            Text(String(index + 1)).foregroundStyle(.secondary).frame(width: 24)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(task.title).fontWeight(.medium).lineLimit(2)
                                Text(task.agent).font(.caption).foregroundStyle(.secondary)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            VStack(alignment: .trailing, spacing: 5) {
                                Text("\(task.totalTokens.formatted()) Token").monospacedDigit()
                                ProgressView(value: Double(task.totalTokens), total: Double(max(first.totalTokens, 1)))
                                    .tint(TaskStoryStyle.accent).frame(width: 140)
                            }
                            Image(systemName: "chevron.right").foregroundStyle(.secondary)
                        }.padding(.vertical, 8).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                    Divider()
                }
            }
            if !summary.modelInputAddresses.isEmpty {
                DisclosureGroup("模型输入中的地址 · 不等于已确认泄露") {
                    ForEach(summary.modelInputAddresses.indices, id: \.self) { index in
                        let group = summary.modelInputAddresses[index]
                        Text("\(group.value) · \(group.occurrences) 条请求证据 · \(group.tasks) 项任务")
                            .font(.caption).textSelection(.enabled)
                    }
                }
            }
        }.storyPanel()
    }

    private func number(_ title: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value.formatted()).font(.system(size: 24, weight: .semibold)).monospacedDigit()
        }
    }
}
