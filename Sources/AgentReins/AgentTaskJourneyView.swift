import SwiftUI

struct AgentTaskJourneyView: View {
    let snapshot: AgentTaskSnapshot

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                Text("逐轮执行链路")
                    .font(.title3.bold())
                Text(summary)
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(snapshot.journey.rounds, id: \.ordinal) { round in
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("第 \(round.ordinal) 轮")
                                .font(.headline)
                            Text(round.model ?? round.response?.model ?? "模型未记录")
                                .font(.caption).foregroundStyle(.secondary)
                            Text(round.requestedAt, style: .time)
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            Spacer()
                            if let ms = round.requestToResponseMS {
                                Text(String(format: "响应 %.0f ms", ms))
                                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            }
                        }
                        Text("请求来源：\(round.evidenceSource) · \(round.captureMode.rawValue) · \(round.completeness.rawValue)")
                            .font(.caption).foregroundStyle(.secondary)
                        if let locator = snapshot.outboundRequests.first(where: { $0.eventID == round.requestEventID })?.sourceLocator {
                            Text("证据文件：\(locator)")
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        if !round.requestSections.isEmpty {
                            DisclosureGroup("请求内容拆解 · \(round.requestSections.count) 段") {
                                ForEach(round.requestSections, id: \.id) { section in
                                    DisclosureGroup("\(section.category) · \(section.byteCount) bytes") {
                                        evidenceText(section.content, height: 180)
                                    }
                                }
                            }
                        }
                        DisclosureGroup("Agent → 模型：请求正文（\(round.bodyBytes) bytes）") {
                            if let request = snapshot.outboundRequests.first(where: { $0.eventID == round.requestEventID }) {
                                evidenceText(request.body, height: 260)
                            }
                        }
                        if let response = round.response {
                            DisclosureGroup("模型 → Agent：响应 · \(round.responseCorrelation)") {
                                evidenceText(response.content, height: 180)
                                if let reasoning = response.recordedReasoning {
                                    Text("采集到的推理记录 / 摘要")
                                        .font(.caption.bold())
                                    evidenceText(reasoning, height: 140)
                                }
                            }
                        } else {
                            Text("未采集到可关联的模型响应")
                                .font(.caption).foregroundStyle(.orange)
                        }
                        ForEach(round.toolSteps, id: \.call.callID) { step in
                            toolDisclosure(step)
                        }
                    }
                    .padding(14)
                    .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
                }
                if !snapshot.journey.unassignedResponses.isEmpty ||
                    !snapshot.journey.unassignedToolSteps.isEmpty {
                    Text("未可靠关联到某一轮")
                        .font(.headline)
                    ForEach(snapshot.journey.unassignedResponses, id: \.eventID) { response in
                        DisclosureGroup("模型响应 · \(response.model ?? "未知模型")") {
                            evidenceText(response.content, height: 180)
                            if let reasoning = response.recordedReasoning {
                                Text("采集到的推理记录 / 摘要").font(.caption.bold())
                                evidenceText(reasoning, height: 140)
                            }
                        }
                    }
                    ForEach(snapshot.journey.unassignedToolSteps, id: \.call.callID) { step in
                        toolDisclosure(step)
                    }
                }
            }
            .padding(18)
        }
    }

    private func toolDisclosure(_ step: AgentTaskJourney.ToolStep) -> some View {
        DisclosureGroup("工具 · \(step.call.toolName) · \(step.call.state.rawValue)" +
            step.durationMS.map { String(format: " · %.0f ms", $0) }.orEmpty) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Call ID: \(step.call.callID)")
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                if let server = step.call.serverName {
                    Text("MCP 服务：\(server)").font(.caption)
                }
                if let arguments = step.call.arguments {
                    Text("调用参数 / 代码").font(.caption.bold())
                    evidenceText(arguments, height: 220)
                }
                if let output = step.result?.output {
                    Text(step.result?.truncated == true ? "执行结果（采集已截断）" : "执行结果")
                        .font(.caption.bold())
                    evidenceText(output, height: 180)
                }
                ForEach(Array(step.fileActivities.enumerated()), id: \.offset) { _, file in
                    Text("文件 \(file.operation.rawValue)：\(file.path)")
                        .font(.caption)
                    if let patch = file.patch { evidenceText(patch, height: 180) }
                }
            }
            .padding(.leading, 12)
        }
    }

    private func evidenceText(_ text: String, height: CGFloat) -> some View {
        TextEditor(text: .constant(text))
            .font(.system(size: 11, design: .monospaced))
            .frame(height: height)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.3)))
    }

    private var summary: String {
        let duration = snapshot.task.startedAt.flatMap { start in
            snapshot.task.endedAt.map { String(format: " · 任务耗时 %.1f 秒", max(0, $0.timeIntervalSince(start))) }
        } ?? ""
        return "\(snapshot.journey.rounds.count) 轮模型请求 · \(snapshot.activities.tools.count) 次工具调用\(duration)。按采集证据排列；时间关联不等于已证明因果关系。"
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
