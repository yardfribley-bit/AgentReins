import SwiftUI

/// First layer of the security experience: a decision surface rather than an
/// event counter. Detailed evidence remains in the incident and case views.
struct SecurityPostureSummaryView: View {
    let incidents: [SecurityIncident]
    let sessions: [AgentSessionSnapshot]
    let health: [CollectorHealthRecord]
    let evidenceCoverage: String
    let analysisConfigured: Bool
    let analysisModel: String
    let latestAIReview: HistoricalSecurityAnalysis?
    let chinese: Bool

    private var actionable: [SecurityIncident] {
        incidents.filter { ["critical", "high"].contains($0.severity.lowercased()) }
    }
    private var review: [SecurityIncident] {
        incidents.filter { $0.severity.lowercased() == "medium" }
    }
    private var confirmedExposureCount: Int {
        incidents.filter { incident in
            incident.ruleIDs.contains { rule in
                let value = rule.lowercased()
                return value.contains("confirmed_exfiltration") || value.contains("confirmed_data_leak")
            }
        }.count
    }
    private var unverifiedCompletions: Int {
        sessions.filter { session in
            guard session.turns.last?.finalResponse != nil else { return false }
            return !session.events.contains {
                $0.kind == "verification" && ["passed", "verified", "success"].contains($0.action.lowercased())
            }
        }.count
    }
    private var unhealthyCollectors: Int { health.filter { $0.state != .healthy }.count }

    var body: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack(alignment: .top, spacing: 14) {
                ZStack {
                    Circle().fill(postureColor.opacity(0.14)).frame(width: 48, height: 48)
                    Image(systemName: postureIcon).font(.system(size: 22, weight: .semibold)).foregroundStyle(postureColor)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(chinese ? "安全态势" : "SECURITY POSTURE")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(.cyan)
                    Text(headline).font(.system(size: 22, weight: .bold))
                    Text(subtitle).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Text(chinese ? "实时 · 本机" : "LIVE · LOCAL")
                    .font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(.secondary)
                    .padding(.horizontal, 8).padding(.vertical, 5)
                    .background(Color.secondary.opacity(0.10), in: Capsule())
            }

            HStack(spacing: 9) {
                metric(value: actionable.count, label: chinese ? "立即处理" : "ACT NOW", color: actionable.isEmpty ? .green : .red)
                metric(value: review.count, label: chinese ? "需要审查" : "REVIEW", color: review.isEmpty ? .green : .orange)
                metric(value: confirmedExposureCount, label: chinese ? "确认泄露" : "CONFIRMED LEAK", color: confirmedExposureCount == 0 ? .green : .red)
                metric(value: unverifiedCompletions, label: chinese ? "未独立验证" : "UNVERIFIED", color: unverifiedCompletions == 0 ? .green : .yellow)
                metricText(value: evidenceCoverage, label: chinese ? "证据覆盖" : "EVIDENCE", color: .cyan)
            }

            HStack(alignment: .center, spacing: 10) {
                Image(systemName: analysisConfigured ? "brain.head.profile.fill" : "brain.head.profile")
                    .foregroundStyle(analysisConfigured ? Color.purple : Color.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(chinese ? "AI 调查员" : "AI INVESTIGATOR")
                        .font(.system(size: 9, weight: .bold)).foregroundStyle(.tertiary)
                    Text(aiInvestigatorSummary)
                        .font(.system(size: 11, weight: .semibold)).foregroundStyle(.secondary)
                }
                Spacer()
                if let review = latestAIReview {
                    Text(chinese
                         ? "\(review.findings.count) 个历史发现 · \(review.examinationPasses ?? 0) 轮复核"
                         : "\(review.findings.count) findings · \(review.examinationPasses ?? 0) review passes")
                        .font(.system(size: 10, design: .monospaced)).foregroundStyle(.purple)
                }
            }
            .padding(.horizontal, 11).padding(.vertical, 9)
            .background(Color.purple.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))

            if unhealthyCollectors > 0 {
                Label(chinese
                      ? "\(unhealthyCollectors) 个采集器异常；部分结论可能存在盲区。"
                      : "\(unhealthyCollectors) collectors are degraded; some conclusions may have blind spots.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(.orange)
            }
        }
        .padding(16)
        .background(Color(red: 8/255, green: 27/255, blue: 45/255), in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(postureColor.opacity(0.45)))
    }

    private var headline: String {
        if !actionable.isEmpty {
            return chinese ? "\(actionable.count) 个问题需要立即处理" : "\(actionable.count) issue\(actionable.count == 1 ? "" : "s") need action"
        }
        if !review.isEmpty {
            return chinese ? "\(review.count) 个行为需要你确认" : "\(review.count) behavior\(review.count == 1 ? "" : "s") need review"
        }
        return chinese ? "当前没有需要处理的风险" : "No security action is needed now"
    }

    private var subtitle: String {
        if !actionable.isEmpty || !review.isEmpty {
            return chinese ? "按风险优先级处理；打开案件后再查看执行链和原始证据。" : "Work by risk priority. Open a case only when you need its execution chain and raw evidence."
        }
        return chinese ? "AgentReins 正在持续检查 Agent 的上下文、工具、文件、记忆与网络行为。" : "AgentReins continues to inspect agent context, tools, files, memory, and network activity."
    }

    private var postureColor: Color {
        if !actionable.isEmpty { return .red }
        if !review.isEmpty || unhealthyCollectors > 0 { return .orange }
        return .green
    }
    private var postureIcon: String {
        if !actionable.isEmpty { return "exclamationmark.shield.fill" }
        if !review.isEmpty || unhealthyCollectors > 0 { return "shield.lefthalf.filled" }
        return "checkmark.shield.fill"
    }

    private var aiInvestigatorSummary: String {
        guard analysisConfigured else {
            return chinese ? "未配置；当前仅由确定性规则判断" : "Not configured; deterministic rules only"
        }
        if latestAIReview != nil {
            return chinese
                ? "\(analysisModel) · 关联跨域证据并进行独立二次复核"
                : "\(analysisModel) · correlates evidence with independent self-review"
        }
        return chinese
            ? "\(analysisModel) 已就绪；尚未生成历史安全复核"
            : "\(analysisModel) is ready; no historical security review yet"
    }

    private func metric(value: Int, label: String, color: Color) -> some View {
        metricText(value: String(value), label: label, color: color)
    }

    private func metricText(value: String, label: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value).font(.system(size: 20, weight: .bold, design: .rounded)).foregroundStyle(color)
            Text(label).font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary).lineLimit(1)
        }
        .padding(.horizontal, 11).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}
