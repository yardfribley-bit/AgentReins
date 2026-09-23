import SwiftUI

struct AgentTaskJourneyView: View {
    let snapshot: AgentTaskSnapshot
    @State private var selectedRound = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("逐轮执行链路").font(.title3.bold())
            Text(summary).font(.caption).foregroundStyle(.secondary)
            HStack(spacing: 16) {
                metric("模型请求", snapshot.metrics.llmRequestCount)
                metric("模型响应", snapshot.metrics.llmResponseCount)
                metric("工具完成 / 调用", "\(snapshot.metrics.toolResultCount) / \(snapshot.metrics.toolCallCount)")
                metric("已确认 Token", snapshot.metrics.inputTokens + snapshot.metrics.outputTokens)
                metric("文件活动", snapshot.activities.files.count)
            }
            HStack(alignment: .top, spacing: 14) {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 7) {
                        ForEach(snapshot.journey.rounds, id: \.ordinal) { round in
                            Button {
                                selectedRound = round.ordinal - 1
                            } label: {
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text("第 \(round.ordinal) 轮").font(.headline)
                                        Spacer()
                                        Text(round.requestedAt, style: .time)
                                            .font(.caption.monospacedDigit())
                                    }
                                    Text(round.response == nil ? "等待或缺少模型响应" :
                                            "模型响应 · \(round.toolSteps.count) 次工具调用")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Text(round.model ?? round.response?.model ?? "模型未记录")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(11)
                                .background(selectedRound == round.ordinal - 1
                                    ? Color.cyan.opacity(0.14) : Color.secondary.opacity(0.08),
                                    in: RoundedRectangle(cornerRadius: 9))
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("第 \(round.ordinal) 轮模型交互")
                        }
                        if snapshot.journey.rounds.isEmpty {
                            Text("没有采集到可展示的模型请求；查看原始 JSON 核对采集范围。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .padding(1)
                }
                .frame(width: 250)
                Divider()
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 13) {
                        if snapshot.journey.rounds.indices.contains(selectedRound) {
                            roundDetail(snapshot.journey.rounds[selectedRound])
                        }
                        if !snapshot.journey.unassignedResponses.isEmpty ||
                            !snapshot.journey.unassignedToolSteps.isEmpty {
                            unassignedEvidence
                        }
                        networkAndMemorySummary
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(2)
                }
            }
        }
        .padding(18)
    }

    private func metric(_ label: String, _ value: Int) -> some View {
        metric(label, value.formatted())
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.headline.monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private func roundDetail(_ round: AgentTaskJourney.Round) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("第 \(round.ordinal) 轮 · \(round.model ?? "模型未记录")").font(.headline)
                Spacer()
                if let ms = round.requestToResponseMS {
                    Text(String(format: "模型响应 %.0f ms", ms))
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
            Text("请求来源：\(round.evidenceSource) · \(round.captureMode.rawValue) · \(round.completeness.rawValue)")
                .font(.caption).foregroundStyle(.secondary)
            if let locator = snapshot.outboundRequests.first(where: { $0.eventID == round.requestEventID })?.sourceLocator {
                Text("证据文件：\(locator)").font(.caption.monospaced()).foregroundStyle(.secondary)
            }
            if !round.requestSections.isEmpty {
                DisclosureGroup("Agent → 模型：请求内容拆解 · \(round.requestSections.count) 段") {
                    ForEach(round.requestSections, id: \.id) { section in
                        DisclosureGroup("\(section.category) · \(section.byteCount) bytes") {
                            evidenceText(section.content, height: 180)
                        }
                    }
                }
            }
            DisclosureGroup("Agent → 模型：完整请求正文 · \(round.bodyBytes) bytes") {
                if let request = snapshot.outboundRequests.first(where: { $0.eventID == round.requestEventID }) {
                    evidenceText(request.body, height: 260)
                }
            }
            if let response = round.response {
                DisclosureGroup("模型 → Agent：响应 · \(round.responseCorrelation)") {
                    evidenceText(response.content, height: 180)
                    if let reasoning = response.recordedReasoning {
                        Text("采集到的推理记录 / 摘要").font(.caption.bold())
                        evidenceText(reasoning, height: 140)
                    } else {
                        Text("未采集到推理内容；不能据此判断模型没有推理。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("未采集到可关联的模型响应")
                    .font(.caption).foregroundStyle(.orange)
            }
            ForEach(round.toolSteps, id: \.call.callID) { step in toolDisclosure(step) }
            if round.toolSteps.isEmpty {
                Text("本轮没有可靠关联的工具调用")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var unassignedEvidence: some View {
        DisclosureGroup("未可靠关联到某一轮的证据") {
            ForEach(snapshot.journey.unassignedResponses, id: \.eventID) { response in
                DisclosureGroup("模型响应 · \(response.model ?? "未知模型")") {
                    evidenceText(response.content, height: 180)
                }
            }
            ForEach(snapshot.journey.unassignedToolSteps, id: \.call.callID) { step in
                toolDisclosure(step)
            }
        }
    }

    private var networkAndMemorySummary: some View {
        DisclosureGroup("任务关联的外联与记忆证据") {
            Text("外联 \(snapshot.activities.networkFlows.count) 条 · 记忆活动 \(snapshot.activities.memory.count) 条")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(Array(snapshot.activities.networkFlows.prefix(15).enumerated()), id: \.offset) { _, flow in
                Text("\(flow.category.rawValue) · \(flow.domain ?? flow.ip ?? "目标未采集"):\(flow.port.map(String.init) ?? "—") · \(flow.grade.rawValue)")
                    .font(.caption.monospaced()).textSelection(.enabled)
            }
            if snapshot.activities.networkFlows.count > 15 {
                Text("其余外联请查看完整任务 JSON")
                    .font(.caption).foregroundStyle(.secondary)
            }
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
