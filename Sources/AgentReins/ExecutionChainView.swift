import SwiftUI

/// Uses the existing task projection and collectors. Playback highlights saved
/// evidence; it never creates execution events or changes collection state.
struct ExecutionChainView: View {
    let snapshot: AgentTaskSnapshot
    @State private var playing = false
    @State private var activeRound = 0
    private let clock = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("执行链路").font(.headline)
                Text("\(snapshot.journey.rounds.count) 次模型请求").foregroundStyle(.secondary)
                Spacer()
                Button(playing ? "暂停回放" : "回放已采集过程") {
                    if activeRound >= snapshot.journey.rounds.count { activeRound = 0 }
                    playing.toggle()
                }.disabled(snapshot.journey.rounds.isEmpty)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    evidence("用户需求", snapshot.conversation.userInputs.first ?? "未采集到用户输入")
                    ForEach(Array(snapshot.journey.rounds.enumerated()), id: \.element.requestEventID) { index, round in
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Circle().fill(index == activeRound && playing ? Color.blue : Color.secondary.opacity(0.3)).frame(width: 9, height: 9)
                                Text("模型请求 \(round.ordinal)").font(.headline)
                                Text(round.requestedAt.formatted(date: .omitted, time: .standard)).font(.caption)
                                Spacer()
                                Text(round.model ?? "模型标识未采集").font(.caption)
                            }
                            Text("来源：\(round.evidenceSource) · 请求完整性：\(round.completeness.rawValue) · \(round.bodyBytes) 字节")
                                .font(.caption).foregroundStyle(.secondary)
                            HStack(alignment: .top, spacing: 14) {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Agent → 大模型 · 本次上下文").font(.subheadline.bold())
                                    if round.requestSections.isEmpty { Text("上下文正文未采集") }
                                    ForEach(round.requestSections, id: \.id) { section in
                                        evidence(section.category, section.content)
                                    }
                                }.frame(maxWidth: .infinity, alignment: .leading)
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("大模型 → Agent · 返回与指示").font(.subheadline.bold())
                                    if let reasoning = round.response?.recordedReasoning, !reasoning.isEmpty {
                                        evidence("WorkBuddy 记录的推理 · reasoning", reasoning)
                                    }
                                    evidence("模型返回", round.response?.content ?? "响应尚未采集")
                                    Text("关联依据：\(round.responseCorrelation)").font(.caption).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading)
                            }
                            ForEach(round.toolSteps, id: \.call.callID) { step in
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("工具 · \(step.call.toolName) · \(step.call.state.rawValue)").font(.subheadline.bold())
                                    Text("调用标识：\(step.call.callID)").font(.caption.monospaced()).textSelection(.enabled)
                                    ForEach(snapshot.activities.networkFlows.filter { $0.sourceEvent.toolCallId == step.call.callID }) { flow in
                                        evidence("网络 · \(flow.destination):\(flow.port.map(String.init) ?? "未知端口")",
                                                 "进程：\(flow.sourceEvent.processId.map(String.init) ?? "未采集") · 证据等级：\(flow.grade.rawValue)\n\(flow.reason)")
                                    }
                                    ForEach(ToolEvidenceExplanation.rows(for: step)) { row in
                                        evidence(row.title, row.raw)
                                    }
                                }.padding(12).background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 6))
                            }
                            if index + 1 < snapshot.journey.rounds.count {
                                Label("后续模型请求 ↓ · 以保存的上下文核对工具结果是否带入", systemImage: "arrow.down")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .padding(16)
                        .background(TaskStoryStyle.panel, in: RoundedRectangle(cornerRadius: 8))
                        .overlay(RoundedRectangle(cornerRadius: 8).stroke(index == activeRound && playing ? Color.blue : TaskStoryStyle.border, lineWidth: index == activeRound && playing ? 2 : 1))
                        .animation(.easeInOut(duration: 0.35), value: activeRound)
                    }
                    VStack(alignment: .leading, spacing: 8) {
                        Text("模型回复与推理记录").font(.headline)
                        Text("按记录时间展示所有回复；未确认对应请求的回复也保留在这里。").font(.caption).foregroundStyle(.secondary)
                        ForEach(snapshot.modelResponses, id: \.eventID) { response in
                            VStack(alignment: .leading, spacing: 8) {
                                Text(response.receivedAt.formatted(date: .omitted, time: .standard)).font(.caption)
                                if let reasoning = response.recordedReasoning, !reasoning.isEmpty {
                                    evidence("WorkBuddy 记录的推理 · reasoning", reasoning)
                                } else { Text("此条回复未关联到推理记录").font(.caption).foregroundStyle(.secondary) }
                                evidence("模型回复", response.content)
                            }
                        }
                    }.padding(16)
                    VStack(alignment: .leading, spacing: 8) {
                        Text("任务资源证据").font(.headline)
                        Text("此处保留任务级记录；没有工具调用归属的记录不会被强行挂到某个工具下。").font(.caption).foregroundStyle(.secondary)
                        ForEach(snapshot.activities.networkFlows) { flow in
                            evidence("网络 · \(flow.destination):\(flow.port.map(String.init) ?? "未知端口")",
                                     "进程：\(flow.sourceEvent.processId.map(String.init) ?? "未采集") · 证据等级：\(flow.grade.rawValue)\n\(flow.reason)")
                        }
                        if snapshot.activities.networkFlows.isEmpty { Text("本任务未采集到网络流记录") }
                        ForEach(snapshot.journey.unassignedToolSteps, id: \.call.callID) { step in
                            evidence("轮次待确认 · \(step.call.toolName)", step.call.arguments ?? "参数未采集")
                        }
                    }.padding(16)
                }.padding(4)
            }
        }
        .onReceive(clock) { _ in
            guard playing else { return }
            if activeRound + 1 < snapshot.journey.rounds.count { activeRound += 1 }
            else { playing = false }
        }
    }

    private func evidence(_ title: String, _ content: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption.bold()).foregroundStyle(.secondary)
            ScrollView { Text(content).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                .frame(height: min(180, max(44, CGFloat(content.count / 65 + 1) * 17)))
        }.padding(10).background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 5))
    }
}
