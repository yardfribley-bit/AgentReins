import SwiftUI

struct AgentTaskJourneyView: View {
    let snapshot: AgentTaskSnapshot
    enum Selection: Hashable {
        case intent, outcome, request(Int), response(Int), reasoning(Int), tool(Int, String), network(Int), unassigned
    }
    @State private var selection: Selection = .intent
    @State private var showingNetwork = false
    @State private var showingEvidence = false
    @State private var localFollowing = true
    private let externalFollowing: Binding<Bool>?
    private var following: Bool {
        get { externalFollowing?.wrappedValue ?? localFollowing }
        nonmutating set {
            if let externalFollowing { externalFollowing.wrappedValue = newValue }
            else { localFollowing = newValue }
        }
    }
    private let initialSelection: Selection?

    init(snapshot: AgentTaskSnapshot, initialSelection: Selection? = nil, following: Binding<Bool>? = nil) {
        self.snapshot = snapshot
        self.initialSelection = initialSelection
        self.externalFollowing = following
    }


    private var finalEvent: GuardEvent? {
        snapshot.sourceEvents.last {
            $0.kind == "model" && $0.op == "response" &&
            ["completed", "final_answer", "end_turn", "stop_sequence"].contains($0.action.lowercased())
        }
    }
    private var hasEnded: Bool {
        guard let finalEvent else { return false }
        return !snapshot.sourceEvents.contains {
            $0.ts > finalEvent.ts && (($0.kind == "tool" && $0.op == "call") || ($0.kind == "model" && $0.op == "prompt"))
        }
    }
    private var currentTitle: String {
        if hasEnded { return "Agent 已返回最终结果" }
        if let step = snapshot.journey.rounds.flatMap(\.toolSteps).last {
            return HumanActionNarrative.build(step).headline
        }
        return snapshot.modelResponses.isEmpty ? "请求已发出，等待模型返回内容" : "已收到模型回复"
    }

    var body: some View {
        ScrollViewReader { reader in
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    HStack {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(currentTitle).font(.system(size: 17, weight: .semibold)).foregroundStyle(TaskStoryStyle.accent)
                            Text(hasEnded ? "Agent 已报告完成；请结合交付内容和工具结果核对。" : "按已采集证据更新进展；未收到结果的动作不会标记完成。")
                                .font(.callout)
                        }
                        Spacer()
                        badge(hasEnded ? "已返回结果" : "跟踪中")
                    }.padding(20).background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 10))
                    HStack(spacing: 24) {
                        metric("已观测耗时", elapsed)
                        metric("当前动作", pendingAction)
                        metric("模型交互", snapshot.journey.rounds.isEmpty ? "未采集" : "\(snapshot.journey.rounds.count) 轮")
                        metric("已确认 Token", snapshot.metrics.inputTokens + snapshot.metrics.outputTokens > 0 ? (snapshot.metrics.inputTokens + snapshot.metrics.outputTokens).formatted() : "未采集")
                    }
                    HStack(alignment: .top, spacing: 18) {
                        LazyVStack(alignment: .leading, spacing: 16) {
                            HStack {
                                VStack(alignment: .leading, spacing: 5) {
                                    Text("思考与执行").font(.headline)
                                    Text("理解目标 → 提出方案 → 执行动作 → 根据结果继续判断")
                                        .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                                }
                                Spacer()
                                Button(following ? "跟随最新：开" : "跟随最新：暂停") {
                                    following.toggle()
                                    if following { showingEvidence = false; showingNetwork = false; reader.scrollTo("latest", anchor: .bottom) }
                                }
                            }
                            Divider()
                            storyStep(title: "明确交付目标", source: "用户原话") {
                                Text(snapshot.conversation.userInputs.first ?? "用户原话未采集").textSelection(.enabled)
                                if let first = snapshot.journey.rounds.first {
                                    evidenceButton("看它收到的上下文", .request(first.ordinal))
                                }
                            }
                            ForEach(snapshot.journey.rounds, id: \.requestEventID) { round in
                                roundStory(round)
                            }
                            if !snapshot.journey.unassignedResponses.isEmpty || !snapshot.journey.unassignedToolSteps.isEmpty {
                                storyStep(title: "其他已采集的响应与动作", source: "轮次归属待确认") {
                                    Text("这些证据属于本任务，但尚未可靠关联到某轮模型请求。")
                                    evidenceButton("查看未关联证据", .unassigned)
                                }
                            }
                            if snapshot.journey.rounds.isEmpty {
                                Text("模型请求尚未采集，不能还原模型交互过程。").foregroundStyle(TaskStoryStyle.muted)
                            }
                            if hasEnded { evidenceButton("查看最终回复与验证记录", .outcome) }
                            Color.clear.frame(height: 1).id("latest")
                            if showingEvidence {
                                VStack(alignment: .leading, spacing: 12) {
                                    HStack { Text("证据详情").font(.headline); Spacer(); Button("收起") { showingEvidence = false; showingNetwork = false } }
                                    if showingNetwork { networkEvidence } else { selectedDetail }
                                }.padding(15).background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 8)).id("evidence")
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading).storyPanel()
                        storySidebar.frame(width: 280).storyPanel()
                    }
                }.padding(.vertical, 4)
            }
            .onChange(of: selection) { _ in if showingEvidence { reader.scrollTo("evidence", anchor: .top) } }
            .onChange(of: showingEvidence) { visible in if visible { reader.scrollTo("evidence", anchor: .top) } }
            .onChange(of: snapshot.revision) { _ in if following { reader.scrollTo("latest", anchor: .bottom) } }
        }
        .onAppear { if let initialSelection { select(initialSelection) } }
    }

    private func select(_ target: Selection) {
        following = false
        showingNetwork = false
        selection = target
        showingEvidence = true
    }

    private func evidenceButton(_ title: String, _ target: Selection) -> some View {
        Button(title) { select(target) }.font(.caption).buttonStyle(.bordered)
    }

    private func badge(_ title: String) -> some View {
        Text(title).font(.caption).foregroundStyle(TaskStoryStyle.muted)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .overlay(RoundedRectangle(cornerRadius: 4).stroke(TaskStoryStyle.border))
    }

    private func storyStep<Content: View>(title: String, source: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(spacing: 0) {
                Circle().fill(TaskStoryStyle.accent).frame(width: 9, height: 9)
                Rectangle().fill(TaskStoryStyle.border).frame(width: 2)
            }.padding(.top, 6)
            VStack(alignment: .leading, spacing: 10) {
                Text(title).font(.system(size: 15, weight: .semibold))
                badge(source)
                content()
            }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 16)
        }.fixedSize(horizontal: false, vertical: true)
    }

    private func roundStory(_ round: AgentTaskJourney.Round) -> some View {
        storyStep(title: "第 \(round.ordinal) 轮 · \(round.response == nil ? "已发送上下文，等待模型响应" : "查看模型说明与后续动作")",
                  source: round.response == nil ? "请求证据" : "模型回复原文") {
            Text("\(round.model ?? "模型标识未采集") · \(round.requestedAt.formatted(date: .omitted, time: .standard))")
                .font(.caption).foregroundStyle(TaskStoryStyle.muted)
            if let response = round.response {
                Text(String(response.content.prefix(600))).lineLimit(6).textSelection(.enabled)
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(TaskStoryStyle.background, in: RoundedRectangle(cornerRadius: 7))
                if let reasoning = response.recordedReasoning, !reasoning.isEmpty {
                    badge("采集到的推理记录 / 摘要")
                    Text(String(reasoning.prefix(600))).lineLimit(5).textSelection(.enabled)
                }
            }
            HStack {
                evidenceButton("发送的上下文", .request(round.ordinal))
                evidenceButton("模型回复", .response(round.ordinal))
                evidenceButton("可见推理记录", .reasoning(round.ordinal))
            }
            ForEach(round.toolSteps, id: \.call.callID) { step in
                ToolEvidenceCompanion(step: step, onInspect: { following = false })
            }
            Text("按采集顺序展示；动作摘要由 AgentReins 整理，不代表模型思维原文。")
                .font(.caption).foregroundStyle(TaskStoryStyle.muted)
        }
    }

    private var pendingAction: String {
        let steps = snapshot.journey.rounds.flatMap(\.toolSteps) + snapshot.journey.unassignedToolSteps
        return steps.contains { $0.result == nil && $0.call.completedAt == nil } ? "结果待采集" : hasEnded ? "已返回结果" : "等待后续证据"
    }

    private var storySidebar: some View {
        VStack(alignment: .leading, spacing: 17) {
            Text("这次要交付什么").font(.headline)
            Text(snapshot.conversation.userInputs.first ?? "交付目标未采集").lineLimit(5)
            Text("以用户要求和实际验证记录核对完成情况。").font(.caption).foregroundStyle(TaskStoryStyle.muted)
            Divider()
            Text("已经产出了什么").font(.headline)
            if outputPaths.isEmpty {
                Text("文件产出尚无采集证据").foregroundStyle(TaskStoryStyle.muted)
            }
            ForEach(outputPaths, id: \.self) { path in
                Button {
                    if let round = snapshot.journey.rounds.first(where: { $0.toolSteps.contains { $0.fileActivities.contains { $0.path == path } } }),
                       let step = round.toolSteps.first(where: { $0.fileActivities.contains { $0.path == path } }) {
                        select(.tool(round.ordinal, step.call.callID))
                    } else { select(.outcome) }
                } label: { Label(URL(fileURLWithPath: path).lastPathComponent, systemImage: "doc.text").lineLimit(2) }
                .help(path)
            }
            Divider()
            Text("需要关注").font(.headline)
            Text(snapshot.metrics.findingCount > 0 ? "已采集 \(snapshot.metrics.findingCount) 条风险记录，请核对证据。" : "当前未采集到风险记录").font(.callout)
            ForEach(snapshot.analysis.codeFindings.prefix(3)) { finding in
                Text(finding.title).font(.caption).foregroundStyle(.orange)
            }
            Text("未发现记录不代表已经确认安全。").font(.caption).foregroundStyle(TaskStoryStyle.muted)
            Button("查看上下文与外联") { following = false; showingNetwork = true; showingEvidence = true }
            Divider()
            Text("思考记录覆盖").font(.headline)
            Text("模型回复：\(snapshot.modelResponses.isEmpty ? "未采集" : "已采集")")
            Text("独立推理记录：\(snapshot.modelResponses.contains { !($0.recordedReasoning ?? "").isEmpty } ? "已采集" : "未采集")")
            Text("不会补写隐藏思维；事件摘要与模型原话分开展示。").font(.caption).foregroundStyle(TaskStoryStyle.muted)
        }.font(.callout).frame(maxWidth: .infinity, alignment: .leading)
    }

    private var networkEvidence: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("上下文与外联").font(.headline)
            if let round = snapshot.journey.rounds.last { evidenceButton("查看最近一轮发送的上下文", .request(round.ordinal)) }
            if snapshot.activities.networkFlows.isEmpty { Text("未采集到外联记录；不代表没有发生外联。") }
            ForEach(snapshot.activities.networkFlows) { flow in
                Text("\(networkTitle(flow.category)) · \(flow.destination)").font(.callout.bold())
                Text(flow.reason).font(.caption).foregroundStyle(TaskStoryStyle.muted)
            }
        }
    }

    private var outputPaths: [String] {
        Array(Set(snapshot.activities.files.filter { $0.operation != .read }.map(\.path))).sorted()
    }


    private func networkTitle(_ category: NetworkTrafficCategory) -> String {
        switch category {
        case .model: return "模型服务"
        case .web: return "外部资源"
        case .remote: return "远程操作 / SSH"
        case .infrastructure: return "Agent 基础服务"
        case .unknown: return "归属待确认"
        }
    }


    @ViewBuilder private var selectedDetail: some View {
        switch selection {
        case .intent:
            Text("这次要完成什么").font(.headline)
            Text(snapshot.conversation.userInputs.first ?? "用户原话未采集")
                .textSelection(.enabled).padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(TaskStoryStyle.soft, in: RoundedRectangle(cornerRadius: 7))
            Text("工作位置").font(.subheadline.bold())
            Text(snapshot.task.projectID == "unassigned" ? "项目位置未采集" : snapshot.task.projectID)
                .font(.callout).textSelection(.enabled)
        case .outcome:
            Text("任务返回了什么").font(.headline)
            Text(finalEvent?.modelResponse ?? "最终回复正文未采集").textSelection(.enabled)
            Text("涉及的文件").font(.subheadline.bold()).padding(.top, 12)
            if snapshot.activities.files.isEmpty {
                Text("本任务没有采集到文件变更记录。").font(.callout).foregroundStyle(TaskStoryStyle.muted)
            }
            ForEach(Array(Set(snapshot.activities.files.map(\.path))).sorted(), id: \.self) { path in
                Text(path).font(.callout).textSelection(.enabled)
            }
            Text("验证依据").font(.subheadline.bold()).padding(.top, 12)
            Text(snapshot.journey.rounds.flatMap(\.toolSteps).isEmpty
                 ? "本任务未采集到可供验证的工具执行结果。"
                 : "以下是实际采集到的工具结果，可据此核对 Agent 的回复。")
                .font(.caption).foregroundStyle(TaskStoryStyle.muted)
            ForEach(snapshot.journey.rounds.flatMap(\.toolSteps), id: \.call.callID) { step in
                Text(HumanActionNarrative.build(step).headline).font(.callout.bold())
                Text(HumanActionNarrative.build(step).outcome).font(.callout)
            }
        case .request(let ordinal):
            if let round = snapshot.journey.rounds.first(where: { $0.ordinal == ordinal }) {
                requestDetail(round)
            }
        case .response(let ordinal):
            if let round = snapshot.journey.rounds.first(where: { $0.ordinal == ordinal }) {
                responseDetail(round)
            }
        case .reasoning(let ordinal):
            Text("第 \(ordinal) 轮 · 可见推理记录").font(.headline)
            if let reasoning = snapshot.journey.rounds.first(where: { $0.ordinal == ordinal })?.response?.recordedReasoning, !reasoning.isEmpty {
                Text("采集到的推理记录 / 摘要，不等于模型完整内部思考。").font(.caption).foregroundStyle(.secondary)
                evidenceText(reasoning, height: 280)
            } else {
                Text("本轮未采集到独立推理记录。可以查看模型回复和工具动作，但不能据此补写内部思考。")
            }
        case .tool(let ordinal, let callID):
            if let step = snapshot.journey.rounds.first(where: { $0.ordinal == ordinal })?
                .toolSteps.first(where: { $0.call.callID == callID }) {
                toolDisclosure(step)
            }
        case .network(let index):
            if snapshot.activities.networkFlows.indices.contains(index) {
                let flow = snapshot.activities.networkFlows[index]
                VStack(alignment: .leading, spacing: 10) {
                    Text("外联详情").font(.headline)
                    Text("目标：\(flow.domain ?? flow.ip ?? "未采集"):\(flow.port.map(String.init) ?? "—")")
                    Text("归类：\(flow.category.rawValue) · 证据等级：\(flow.grade.rawValue)")
                    Text(flow.reason).font(.caption).foregroundStyle(.secondary)
                    Text("此处展示连接元数据，不代表已读取加密流量正文。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        case .unassigned:
            unassignedEvidence
        }
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
        .padding(.vertical, 10)
    }

    private func requestDetail(_ round: AgentTaskJourney.Round) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("第 \(round.ordinal) 轮 · Agent 向模型发送了什么").font(.headline)
            Text(round.completeness == .complete
                 ? "已采集本轮请求正文。下面按内容来源查看。"
                 : "已采集到本轮部分上下文；尚不能确认覆盖了全部发送内容。")
                .font(.callout).foregroundStyle(.secondary)
            let memoryFiles = snapshot.analysis.memoryEvidence.contextSegments.filter {
                $0.requestEventID == round.requestEventID && $0.kind == .memoryFileContent
            }
            if !memoryFiles.isEmpty {
                Text("本轮上下文中包含的记忆文件").font(.headline)
                ForEach(memoryFiles) { segment in
                    Text(segment.sourcePaths.map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: "、"))
                        .font(.callout.bold()).textSelection(.enabled)
                    Text(preview(segment.content)).font(.callout).lineLimit(3)
                    DisclosureGroup("阅读记忆内容与依据") {
                        Text(segment.sourcePaths.joined(separator: "、")).font(.caption).textSelection(.enabled)
                        Text("在本轮采集的上下文中发现这段内容；是否完整发送取决于请求采集覆盖范围。")
                            .font(.caption).foregroundStyle(TaskStoryStyle.muted)
                        evidenceText(segment.content, height: 220)
                    }
                }
            }
            if round.requestSections.isEmpty {
                Text("这段内容尚未拆分，展开下方正文即可阅读。")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(round.requestSections, id: \.id) { section in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(sectionTitle(section.category)).font(.headline)
                        Text(section.category == "user_query"
                             ? "本轮附带的任务与上下文。用户原话：\(snapshot.conversation.userInputs.first ?? "未采集")"
                             : preview(section.content)).font(.callout)
                            .foregroundStyle(.secondary).lineLimit(4).textSelection(.enabled)
                        DisclosureGroup("阅读这段内容") {
                            evidenceText(section.content, height: 220)
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
                }
            }
            DisclosureGroup("查看已采集正文与来源") {
                if let request = snapshot.outboundRequests.first(where: { $0.eventID == round.requestEventID }) {
                    Text("来源：\(round.evidenceSource) · \(round.bodyBytes.formatted()) 字节")
                        .font(.caption).foregroundStyle(.secondary)
                    if let locator = request.sourceLocator {
                        Text(locator).font(.caption.monospaced()).textSelection(.enabled)
                    }
                    Text("段落可能包含嵌套内容，大小不能直接相加，也不等同于 Token 数。")
                        .font(.caption).foregroundStyle(.secondary)
                    evidenceText(request.body, height: 260)
                }
            }
        }
    }

    private func responseDetail(_ round: AgentTaskJourney.Round) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("第 \(round.ordinal) 轮 · 模型向 Agent 返回了什么").font(.headline)
            if let response = round.response {
                if let ms = round.requestToResponseMS {
                    Text(String(format: "请求至响应 %.0f ms", ms))
                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                Text(response.content).font(.callout).textSelection(.enabled)
                DisclosureGroup("查看响应来源与关联依据") {
                    Text("\(response.evidenceSource) · \(round.responseCorrelation)")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let reasoning = response.recordedReasoning {
                    Text("采集到的推理记录 / 摘要").font(.caption.bold())
                    evidenceText(reasoning, height: 180)
                } else {
                    Text("未采集到推理内容；不能据此判断模型没有推理。")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("未采集到可关联的模型响应。")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var unassignedEvidence: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("已采集的响应与动作").font(.headline)
            Text("以下内容属于这个任务，但尚不能可靠定位到某一轮模型请求。")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(snapshot.journey.unassignedResponses, id: \.eventID) { response in
                Text("模型返回的内容").font(.subheadline.bold())
                evidenceText(response.content, height: 220)
            }
            ForEach(snapshot.journey.unassignedToolSteps, id: \.call.callID) { step in
                toolDisclosure(step)
            }
        }
    }

    private func sectionTitle(_ category: String) -> String {
        switch category {
        case "user_query": return "任务与附带上下文"
        case "memory_context": return "记忆内容"
        case "memory_system": return "记忆使用规则"
        case "memory_and_skills_reminder": return "记忆与技能提示"
        case "identity_context", "product_identity": return "Agent 身份与职责"
        case "project_context": return "项目背景"
        case "tone_and_style": return "表达方式与风格要求"
        case "system-reminder", "message.system", "message.developer": return "系统指令与提醒"
        case "message.user": return "用户消息"
        case "message.assistant": return "已有的模型回复"
        case "message.tool": return "工具返回的结果"
        case "toolDefinitions": return "可调用的工具与用法"
        default: return "其他上下文"
        }
    }

    private func preview(_ content: String) -> String {
        let readable = String(content.prefix(4000))
            .replacingOccurrences(of: "\\n", with: "\n")
            .replacingOccurrences(of: "\\t", with: " ")
            .replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
        let lines = readable.components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty && !$0.hasPrefix("Path:") && !$0.hasPrefix("#") && $0 != "----" && $0 != "---" }
        return String(lines.joined(separator: " ").prefix(400))
    }

    private func toolDisclosure(_ step: AgentTaskJourney.ToolStep) -> some View {
        ToolEvidenceCompanion(step: step).id(step.call.callID)
    }

    private func evidenceText(_ text: String, height: CGFloat) -> some View {
        TextEditor(text: .constant(text))
            .font(.system(size: 11, design: .monospaced))
            .frame(height: height)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.3)))
    }


    private var elapsed: String {
        guard let start = snapshot.task.startedAt, let end = snapshot.task.endedAt else { return "未采集" }
        let seconds = max(0, Int(end.timeIntervalSince(start)))
        return seconds < 60 ? "\(seconds) 秒" : "\(seconds / 60) 分 \(seconds % 60) 秒"
    }
}

private extension Optional where Wrapped == String {
    var orEmpty: String { self ?? "" }
}
