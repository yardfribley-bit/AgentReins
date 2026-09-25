import SwiftUI

/// Presents the existing persisted rule/AI workflow without automatically approving proposals.
struct SecurityGovernanceView: View {
    enum Section: String, CaseIterable { case findings = "安全发现", analysis = "AI 主动检查", rules = "本机规则" }
    let section: Section
    @EnvironmentObject private var eventStore: EventStore
    @EnvironmentObject private var analyzer: SemanticAnalyzer
    @EnvironmentObject private var policies: AlertPolicyStore
    @State private var showingModel = false
    @State private var showingRules = false
    @State private var confirmingAnalysis = false
    @State private var candidateToApprove: AIRuleCandidate?
    @State private var loading = false
    @State private var analysisEvents: [GuardEvent] = []
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            if section == .analysis { analysisPanel }
            if section == .rules { rulesPanel }
        }
        .sheet(isPresented: $showingModel) { AnalysisModelSettingsView().environmentObject(analyzer) }
        .sheet(isPresented: $showingRules) { AlertPolicySettingsView().environmentObject(policies) }
        .confirmationDialog("将所选范围的证据发送给已配置的分析模型？", isPresented: $confirmingAnalysis) {
            Button("启用后台分析") {
                analyzer.setBackgroundEnabled(true)
                analyzer.startBackgroundWorker(evidenceURL: FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("AgentGuard/evidence.sqlite3"), policies: policies)
            }
        } message: {
            Text("启用后，后台逐项分析已解析的历史和新增任务，并将选取的证据发送至 \(analyzer.baseURL)。每次只分析一个任务，间隔至少 10 秒，可能产生模型费用。相同任务版本不重复分析；你可随时暂停。AI 不会自动启用规则。")
        }
        .confirmationDialog("批准这条规则入库？", isPresented: Binding(
            get: { candidateToApprove != nil }, set: { if !$0 { candidateToApprove = nil } })) {
            if let candidate = candidateToApprove {
                Button("批准入库 · 观察模式") { policies.approve(candidate); candidateToApprove = nil }
            }
        } message: {
            Text("\(candidateToApprove?.name ?? "")：批准后保存到本机规则库，先记录命中、不主动通知。可在规则管理中进一步启用。")
        }
    }

    private var analysisPanel: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                VStack(alignment: .leading, spacing: 6) {
                    Text("让 AI 检查本机任务，不只等待规则命中").font(.title3.bold())
                    Text("检查模型交互、工具、记忆和外联，发现已有规则没有覆盖的问题。")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                Button("配置分析模型") { showingModel = true }
                Button(analyzer.backgroundEnabled ? "暂停后台分析" : "启用后台分析") {
                    if analyzer.backgroundEnabled { analyzer.setBackgroundEnabled(false) }
                    else { confirmingAnalysis = true }
                }
                    .buttonStyle(.borderedProminent).tint(TaskStoryStyle.accent)
                    .disabled(!analyzer.configured && !analyzer.backgroundEnabled)
            }
            Text("范围：已保存且已关联到任务的事件文本，逐事件登记、分段检查并保存断点；每轮最多新增分析两段，再轮转其他任务。历史索引在后台补齐，未采集及尚未关联的数据不算已检查。模型：\(analyzer.configured ? analyzer.model : "未配置")。")
                .font(.caption).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("检查方式").font(.headline)
                    Text("启用后后台持续检查；无需保持本页面打开。")
                    Text("同一任务版本已分析则复用结果，版本变化后重新检查。")
                    Text("失败最多尝试 3 次，退避重试；已完成分段保留，不清空已有结果。")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .leading, spacing: 8) {
                    Text("数据会去哪里？").font(.headline)
                    Text("本机存储不等于本地推理。使用云端分析模型时，所选证据会发往配置的服务，开始前需要确认。")
                    Text("AI 建议不会自动新增或启用规则。")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if let error = error ?? analyzer.lastError { Text(error).foregroundStyle(.orange) }
            Text(analyzer.historyStage).font(.headline)
            Text("已完成 \(analyzer.historyCompleted) 项 · 待处理 \(analyzer.backgroundPending) 项 · 重试耗尽 \(analyzer.backgroundFailed) 项（已发现的任务范围）")
                .font(.caption).foregroundStyle(.secondary)
            if analyzer.analyzingHistory {
                Text(analyzer.backgroundCurrent).lineLimit(3)
                if let started = analyzer.historyStartedAt { HStack { Text("本项已用时"); Text(started, style: .timer) } }
            }
            if let draft = analyzer.historyDraft {
                ForEach(draft.findings) { finding in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("初步发现 · 尚在核查").foregroundStyle(.orange)
                        Text(finding.title).font(.headline)
                        Text(finding.summary)
                    }.storyPanel()
                }
            }
            if let analysis = analyzer.historicalAnalysis {
                Divider()
                Text("最近 20 项已保存任务的分析结果 · 其余结果仍保存在本机数据库")
                    .font(.caption).foregroundStyle(.secondary)
                Text("\(analysis.findings.count) 项发现 · \(analysis.rules.count) 条规则评估 · \(analysis.examinationPasses ?? 0) 轮复核")
                    .font(.headline)
                Text("AI 发现是待核查结论，不等于确认违规；既有报告的范围以报告证据为准。")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(analysis.findings) { finding in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(finding.title).font(.headline)
                        Text(finding.summary).textSelection(.enabled)
                        Text("建议核查：\(finding.recommendedAction)")
                        DisclosureGroup("复核依据与原始证据 · \(finding.evidenceEventIds.count) 条引用") {
                            Text("复核意见：\(finding.llmSelfExamine.verdict)")
                            Text(finding.llmSelfExamine.rationale)
                            Text("反证：\(finding.llmSelfExamine.counterEvidence)")
                            Text("误报风险：\(finding.llmSelfExamine.falsePositiveRisk)")
                            ForEach(finding.evidenceEventIds, id: \.self) { id in
                                if let event = analysisEvents.first(where: { $0.id.uuidString.caseInsensitiveCompare(id) == .orderedSame }) {
                                    Text(encoded(event)).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                } else {
                                    Text("证据 \(id) · 未加载原文").font(.caption).textSelection(.enabled)
                                }
                            }
                        }.font(.caption)
                    }.storyPanel()
                }
            } else {
                Text("尚无历史分析报告。AI 分析完成后，发现和待审批规则会保存在本机。")
                    .foregroundStyle(.secondary)
            }
        }.storyPanel()
    }

    private var rulesPanel: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("已有本机规则与 AI 提案").font(.title3.bold())
                Spacer()
                Button("管理规则与适用范围") { showingRules = true }
            }
            Text("已有 \(policies.policies.count) 条规则 · \(policies.aiCandidates.count) 条 AI 提案待处理。已有规则不会因界面改版而重置。")
                .foregroundStyle(.secondary)
            if !policies.aiCandidates.isEmpty {
                Text("待审批提案").font(.headline)
                ForEach(policies.aiCandidates) { candidate in
                    VStack(alignment: .leading, spacing: 10) {
                        Text(candidate.name).font(.headline)
                        Text(candidate.condition).textSelection(.enabled)
                        Text("\(candidate.historicalSampleCount.map { "已回测 \($0) 条证据，命中 \(candidate.historicalMatches) 次" } ?? "尚未记录历史回测范围") · \(candidate.detector == nil ? "无可执行检测器" : "有可执行检测器")")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("复核：\(candidate.rationale)").font(.caption)
                        Text("误报风险：\(candidate.falsePositiveRisk)").font(.caption)
                        HStack {
                            Button("不采纳") { policies.dismiss(candidate) }
                            Spacer()
                            Button("审批入库") { candidateToApprove = candidate }
                                .buttonStyle(.borderedProminent).tint(TaskStoryStyle.accent)
                                .disabled(candidate.detector == nil || candidate.verdict == "rejected" || !candidate.evidenceSufficient)
                        }
                        if candidate.detector == nil || candidate.verdict == "rejected" || !candidate.evidenceSufficient {
                            Text("暂不可入库：需具备可执行检测器、充分证据，且通过复核。")
                                .font(.caption).foregroundStyle(.orange)
                        }
                    }.storyPanel()
                }
            }
            ForEach(policies.policies) { policy in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(ruleTitle(policy)).font(.headline)
                        Text(policy.explanation).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text(policy.effectiveOrigin == "built_in" ? "内置规则" : policy.effectiveOrigin == "ai_proposed" ? "AI 提案 · 已批准" : "自定义规则")
                    Text(!policy.enabled ? "已停用" : policy.effectiveMode == "observe" ? "观察模式" : "已启用")
                        .foregroundStyle(TaskStoryStyle.accent)
                }.font(.caption).padding(.vertical, 10)
                Divider()
            }
        }.storyPanel()
    }

    private func encoded(_ event: GuardEvent) -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(event) else { return "无法编码证据" }
        return String(decoding: data, as: UTF8.self)
    }

    private func ruleTitle(_ policy: AlertPolicy) -> String {
        guard let original = AlertPolicy.defaults.first(where: { $0.id == policy.id }),
              original.name == policy.name else { return policy.name }
        switch policy.effectiveDetector {
        case .crossProjectSensitiveFileRead: return "读取项目外的敏感文件"
        case .crossProjectFileRead: return "读取当前项目范围外的文件"
        case .credentialInToolResult: return "工具返回内容中出现凭据"
        case .credentialInToolArguments: return "工具参数中包含密码、Token 或私钥"
        case .sensitiveDataInModelRequest: return "模型请求中包含敏感数据"
        case .crossApplicationSensitiveRead: return "读取其他应用的敏感数据"
        case nil: return policy.name
        }
    }

    private func analyze() {
        guard !loading, !analyzer.analyzingHistory, analyzer.canStartHistoricalAnalysis() else { return }
        loading = true; error = nil
        eventStore.loadRecentSecurityReview { result in
            switch result {
            case .failure(let failure): loading = false; error = failure.localizedDescription
            case .success(let events):
                guard !events.isEmpty else { loading = false; error = "当前范围内没有可分析的证据。"; return }
                analysisEvents = events
                let previous = analyzer.historicalAnalysis?.generatedAt
                Task {
                    await analyzer.analyzeHistory(events, policies: policies.policies)
                    if let analysis = analyzer.historicalAnalysis,
                       analysis.generatedAt != previous, analyzer.lastError == nil {
                        policies.ingestAIProposals(analysis, events: events)
                    }
                    loading = false
                }
            }
        }
    }
}
