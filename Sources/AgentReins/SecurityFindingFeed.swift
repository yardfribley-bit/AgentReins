import SwiftUI

enum SecurityFindingItem: Identifiable {
    case rule(SecurityIncident)
    case ai(AIHistoricalFinding, HistoricalSecurityAnalysis)

    var id: String {
        switch self {
        case .rule(let incident): return "rule:\(incident.id)"
        case .ai(let finding, _): return "ai:\(finding.id)"
        }
    }
    var isAI: Bool { if case .ai(let finding, _) = self { return !finding.ruleId.hasPrefix("behavior:") }; return false }
    var title: String {
        switch self {
        case .rule(let incident): return SecurityIncidentPresentation.make(incident, chinese: true).title
        case .ai(let finding, _): return finding.title
        }
    }
    var summary: String {
        switch self {
        case .rule(let incident): return SecurityIncidentPresentation.make(incident, chinese: true).whyItMatters
        case .ai(let finding, _): return finding.summary
        }
    }
    var agent: String {
        switch self { case .rule(let incident): return incident.agent ?? "归属未采集"; case .ai(let finding, _): return finding.agentName ?? "归属待关联" }
    }
    var task: String {
        switch self {
        case .rule(let incident): return incident.primary.userIntent ?? "任务描述未采集"
        case .ai(let finding, _): return finding.taskTitle ?? "任务描述未采集 · 可查看关联证据"
        }
    }
    var severity: String {
        switch self { case .rule(let incident): return incident.severity; case .ai(let finding, _): return finding.severity }
    }
    var date: Date {
        switch self {
        case .rule(let incident): return incident.ts
        case .ai(let finding, let report): return (finding.observedAt ?? report.generatedAt).flatMap { ISO8601DateFormatter().date(from: $0) } ?? .distantPast
        }
    }

    static func merge(incidents: [SecurityIncident], analysis: HistoricalSecurityAnalysis?) -> [Self] {
        let rows = incidents.map(Self.rule) + (analysis.map { report in
            report.findings.map { Self.ai($0, report) }
        } ?? [])
        let rank = ["critical": 4, "high": 3, "medium": 2, "info": 1]
        return rows.sorted {
            let lhs = rank[$0.severity.lowercased(), default: 0], rhs = rank[$1.severity.lowercased(), default: 0]
            if lhs != rhs { return lhs > rhs }
            if $0.date != $1.date { return $0.date > $1.date }
            return $0.id < $1.id
        }
    }
}

struct AIHistoricalFindingCard: View {
    let finding: AIHistoricalFinding
    let report: HistoricalSecurityAnalysis

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(finding.ruleId.hasPrefix("behavior:") ? "本地行为检测" : "AI 分析发现").foregroundStyle(.purple)
                Text("待人工核查 · \(finding.severity)").foregroundStyle(.secondary)
                Spacer()
                Text(report.generatedAt ?? "分析时间未记录").foregroundStyle(.secondary)
            }.font(.caption)
            Text(finding.title).font(.headline)
            Text(finding.summary).textSelection(.enabled)
            Text("建议：\(finding.recommendedAction)")
            Text("分析模型：\(report.model ?? "未记录") · \(finding.evidenceEventIds.count) 条引用证据")
                .font(.caption).foregroundStyle(.secondary)
            DisclosureGroup("查看分析依据与证据引用") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("判定状态：\(finding.llmSelfExamine.verdict)（待用户核查）")
                    Text(finding.llmSelfExamine.rationale)
                    Text("反证：\(finding.llmSelfExamine.counterEvidence)")
                    Text("误报风险：\(finding.llmSelfExamine.falsePositiveRisk)")
                    Text("关联规则：\(finding.ruleId)")
                    Text(finding.evidenceEventIds.joined(separator: "\n"))
                        .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    Text("以上为报告保存的证据标识，不是原始证据正文。")
                        .foregroundStyle(.secondary)
                }.font(.caption).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
            }
        }.storyPanel()
    }
}
