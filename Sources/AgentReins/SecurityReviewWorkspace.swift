import SwiftUI

/// Bounded, on-demand review of persisted evidence. A detector hit is not an audit verdict.
struct SecurityReviewWorkspace: View {
    @EnvironmentObject private var eventStore: EventStore
    @EnvironmentObject private var analyzer: SemanticAnalyzer
    @EnvironmentObject private var policies: AlertPolicyStore
    @State private var incidents: [SecurityIncident] = []
    @State private var selected: UUID?
    @State private var loading = false
    @State private var error: String?
    @State private var evidenceCount = 0
    @State private var section: SecurityGovernanceView.Section = .findings
    @State private var sourceFilter = "全部"
    @State private var query = ""
    @State private var question: SafetyQuestion = .all
    @State private var selectedFinding: String?
    @State private var detailTab = "发生过程与原文"
    @State private var evidenceRows: [GuardEvent] = []
    @State private var evidenceLoading = false
    @State private var evidenceError: String?
    @AppStorage("agentreins.local-security-review-status.v1") private var statusData = Data()
    @AppStorage("agr_security_reported_domains") private var reportedDomains = ""

    private var reviewStatuses: [String: String] {
        (try? JSONDecoder().decode([String: String].self, from: statusData)) ?? [:]
    }

    private func mark(_ value: String, id: String) {
        var statuses = reviewStatuses
        statuses[id] = value
        if let data = try? JSONEncoder().encode(statuses) { statusData = data }
    }

    private var findings: [SecurityFindingItem] {
        let reports = [analyzer.historicalAnalysis, analyzer.behaviorAnalysis].compactMap { $0 }
        let combined = HistoricalSecurityAnalysis(findings: reports.flatMap(\.findings), rules: [], generatedAt: nil, model: nil, examinationPasses: nil)
        return SecurityFindingItem.merge(incidents: incidents, analysis: combined)
    }

    private var visibleFindings: [SecurityFindingItem] {
        findings.filter {
            (sourceFilter == "全部" || $0.agent == sourceFilter)
                && (query.isEmpty || "\($0.title) \($0.summary) \($0.task)".localizedCaseInsensitiveContains(query))
                && matchesQuestion($0)
        }
    }

    private func matchesQuestion(_ item: SecurityFindingItem) -> Bool {
        if question == .all { return true }
        if case .rule(let incident) = item { return question.matches(incident.events) }
        if case .ai(let finding, _) = item, finding.ruleId.hasPrefix("behavior:") {
            switch question {
            case .all: return true
            case .destination: return finding.ruleId == "behavior:external_content" || finding.ruleId == "behavior:proxy_configuration"
            case .command: return true
            case .changes: return finding.ruleId == "behavior:proxy_configuration"
            case .privacy: return false
            }
        }
        return false
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("我的 Agent，有哪些行为需要留意？").font(.system(size: 23, weight: .semibold))
                        Text("先看影响和处理建议，需要时核对每一条原始记录。")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("刷新证据", action: reload).disabled(loading)
                }
                Picker("安全工作区", selection: $section) {
                    ForEach(SecurityGovernanceView.Section.allCases, id: \.self) { section in
                        Text(section.rawValue).tag(section)
                    }
                }.pickerStyle(.segmented)
                if section != .findings {
                    SecurityGovernanceView(section: section)
                } else {
                HStack(spacing: 22) {
                    Text("\(findings.filter { reviewStatuses[$0.id] == nil }.count) 项需要查看").font(.headline)
                    Text("AI 发现 \(findings.filter(\.isAI).count) 项").foregroundStyle(.secondary)
                    Button("\(policies.aiCandidates.count) 条规则等待你审批") { section = .rules }
                    Spacer()
                }
                if loading { ProgressView("正在读取已存储的风险证据…") }
                Text(analyzer.behaviorCoverage).font(.caption).foregroundStyle(.secondary)
                if let failure = analyzer.behaviorError { Text(failure).foregroundStyle(.orange) }
                Text("自动检查已采集的网页内容，无需配置域名。可疑内容不等于攻击成功，需结合后续操作核查。")
                    .font(.caption).foregroundStyle(.secondary)
                DisclosureGroup("额外关注域名（可选，不影响自动检查）") {
                    TextField("输入域名，以空格或逗号分隔", text: $reportedDomains).textFieldStyle(.roundedBorder)
                    Text("保存后后台重新检查已解析任务。命中表示你标记的关注对象；是否钓鱼或诱导成功还需核对内容和后续行为。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.orange) }
                Picker("我关心的问题", selection: $question) {
                    ForEach(SafetyQuestion.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented)
                if question != .all {
                    Text("按已关联的事件类型筛选；尚未完成证据分类的 AI 发现请在“全部发现”查看。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    TextField("搜索任务、文件或目的地址", text: $query).textFieldStyle(.roundedBorder)
                    Picker("Agent", selection: $sourceFilter) {
                        ForEach(["全部"] + Array(Set(findings.map(\.agent))).sorted(), id: \.self) { Text($0).tag($0) }
                    }.frame(width: 220)
                }
                Text("按风险优先级展示。规则信号与 AI 发现分别标明来源，同一问题可能有多条发现；不将其相加当作独立违规数。")
                    .font(.caption).foregroundStyle(.secondary)
                LazyVStack(spacing: 12) {
                    ForEach(visibleFindings) { item in
                        HStack(alignment: .top, spacing: 18) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("\(item.agent) · \(item.task)").font(.caption).foregroundStyle(.secondary)
                                Text(item.title).font(.system(size: 16, weight: .semibold))
                                Text(item.summary)
                                Text("\(item.isAI ? "AI 发现" : "规则检测") · \(item.date.formatted(date: .abbreviated, time: .shortened)) · \(reviewStatuses[item.id] ?? "待查看")")
                                    .font(.caption).foregroundStyle(.secondary)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            Button(selectedFinding == item.id ? "正在查看" : "查看影响与处理建议") {
                                selectedFinding = item.id
                                detailTab = "发生过程与原文"
                                if case .rule(let incident) = item { selected = incident.id }
                                loadEvidence(item)
                            }
                        }
                        Divider()
                    }
                }.storyPanel()
                if let item = findings.first(where: { $0.id == selectedFinding }) {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            Text(item.title).font(.headline)
                            Spacer()
                            Button("收起") { selectedFinding = nil }
                        }
                        Picker("详情", selection: $detailTab) {
                            Text("发生过程与原文").tag("发生过程与原文")
                            Text("AI 发现依据").tag("AI 发现依据")
                        }.pickerStyle(.segmented)
                        SecurityDecisionView(summary: item.summary, recommendation: recommendation(item),
                            events: decisionEvents(item))
                        DisclosureGroup("核对发生过程、原始内容与完整证据") {
                        switch item {
                        case .rule(let incident):
                            if detailTab == "发生过程与原文" { LocalSecurityEvidenceView(events: incident.events) }
                            else { Text("本项为规则发现，尚未关联 AI 分析结果，不生成虚构判断。").foregroundStyle(.secondary) }
                        case .ai(let finding, let report):
                            if detailTab == "发生过程与原文" {
                                if evidenceLoading { ProgressView("按证据引用读取本机数据库…") }
                                if let evidenceError { Text(evidenceError).foregroundStyle(.orange) }
                                LocalSecurityEvidenceView(events: evidenceRows)
                                Text("引用 \(finding.evidenceEventIds.count) 条，找到 \(evidenceRows.count) 条；每次最多读取 200 条。")
                                    .font(.caption).foregroundStyle(.secondary)
                            } else { AIHistoricalFindingCard(finding: finding, report: report) }
                        }
                        }
                        Text("我需要做什么？").font(.headline)
                        Text("先核对内容、接收方和任务意图，再记录你的判断。标记不会删除证据或修改 Agent 配置。")
                        HStack {
                            ForEach(["需跟进", "符合我的预期", "判断有误"], id: \.self) { value in
                                Button(value) { mark(value, id: item.id) }
                            }
                        }
                        Text("本机记录：\(reviewStatuses[item.id] ?? "尚未标记")").font(.caption).foregroundStyle(.secondary)
                    }.storyPanel()
                }
                if visibleFindings.isEmpty && !loading && error == nil {
                    Text("当前来源与加载范围内没有安全发现。这不代表所有任务均已完成安全检查。")
                        .foregroundStyle(.secondary).padding(20)
                }
                Text("覆盖范围：最近最多 200 条已保存事件，当前读取 \(evidenceCount) 条并筛选风险信号。不是全库风险统计；按需展开原始数据，不扫描 Agent 原始文件。")
                    .font(.caption).foregroundStyle(.secondary)
                Button("加载更多历史行为发现") { analyzer.loadMoreBehaviorFindings() }
                Text("本地行为发现独立于 AI 保存并逐项更新；上方显示当前已读取的结果，任务解析与 AI 检查仍可能存在积压。")
                    .font(.caption).foregroundStyle(.secondary)
                }
            }.padding(24)
        }
        .task { reload() }
    }

    private func recommendation(_ item: SecurityFindingItem) -> String {
        switch item {
        case .rule(let incident): return SecurityIncidentPresentation.make(incident, chinese: true).recommendedAction
        case .ai(let finding, _): return finding.recommendedAction
        }
    }

    private func decisionEvents(_ item: SecurityFindingItem) -> [GuardEvent] {
        if case .rule(let incident) = item { return incident.events }
        return evidenceRows
    }

    private func counter(_ title: String, value: String, note: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).foregroundStyle(.secondary)
            Text(value).font(.system(size: 26, weight: .semibold))
            Text(note).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).storyPanel()
    }

    private func loadEvidence(_ item: SecurityFindingItem) {
        evidenceRows = []; evidenceError = nil; evidenceLoading = false
        guard case .ai(let finding, _) = item else { return }
        evidenceLoading = true
        eventStore.loadSecurityEvidence(ids: finding.evidenceEventIds) { result in
            guard selectedFinding == item.id else { return }
            evidenceLoading = false
            switch result {
            case .success(let events): evidenceRows = events
            case .failure(let error): evidenceError = error.localizedDescription
            }
        }
    }

    private func incidentCard(_ incident: SecurityIncident) -> some View {
        let presentation = SecurityIncidentPresentation.make(incident, chinese: true)
        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(incident.severity == "critical" || incident.severity == "high" ? "优先核查" : "待核查")
                    .font(.caption.bold()).foregroundStyle(.orange)
                Text("规则信号 · 尚未确认违规").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text(incident.ts.formatted(date: .abbreviated, time: .shortened)).font(.caption)
            }
            Text(presentation.title).font(.headline)
            Text("\(incident.agent ?? "Agent 归属未采集") · \(incident.events.count) 条关联证据")
                .font(.caption).foregroundStyle(.secondary)
            Text(presentation.whyItMatters).textSelection(.enabled)
            Button(selected == incident.id ? "收起证据" : "核查事实与原始证据") {
                selected = selected == incident.id ? nil : incident.id
            }.foregroundStyle(TaskStoryStyle.accent)
            if selected == incident.id {
                Divider()
                HStack(alignment: .top, spacing: 24) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("如何理解这条信号").font(.headline)
                        Text(presentation.recommendedAction)
                        Text("检测规则").font(.subheadline.bold())
                        Text(incident.ruleIDs.joined(separator: "\n")).font(.caption).textSelection(.enabled)
                        Text("是否违规、是否真正外泄，需要结合原始内容与企业授权范围确认。")
                            .font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 12) {
                        Text("原始证据").font(.headline)
                        ForEach(incident.events, id: \.id) { event in
                            DisclosureGroup("\(event.kind) · \(event.ts.formatted(date: .omitted, time: .standard))") {
                                Text(rawEvidence(event)).font(.system(size: 11, design: .monospaced))
                                    .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("人工处置记录尚未接入，暂不提供会丢失的“确认违规”操作。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.storyPanel()
    }

    private func rawEvidence(_ event: GuardEvent) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(event) else { return "证据编码失败" }
        return String(decoding: data, as: UTF8.self)
    }

    private func reload() {
        guard !loading else { return }
        loading = true; error = nil
        eventStore.loadRecentSecurityReview { result in
            loading = false
            switch result {
            case .success(let events):
                evidenceCount = events.count
                incidents = SecurityIncident.correlate(events.filter {
                    ["critical", "high", "medium"].contains($0.severity)
                        || $0.action == "block" || $0.kind == "alert"
                }).sorted {
                    let rank = ["critical": 4, "high": 3, "medium": 2, "info": 1]
                    let a = rank[$0.severity, default: 0], b = rank[$1.severity, default: 0]
                    return a == b ? $0.ts > $1.ts : a > b
                }
            case .failure(let failure): error = failure.localizedDescription
            }
        }
    }
}
