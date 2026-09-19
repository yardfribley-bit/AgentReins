import SwiftUI

/// Shared first-layer incident presentation for global and project workspaces.
/// Investigation details remain in ForensicCaseWorkspaceView.
struct SecurityIncidentCardView: View {
    enum Density { case standard, compact }

    let incident: SecurityIncident
    let chinese: Bool
    let density: Density
    let onOpen: () -> Void

    private var copy: SecurityIncidentPresentation {
        SecurityIncidentPresentation.make(incident, chinese: chinese)
    }
    private var assessment: SecurityIncidentAssessment {
        SecurityIncidentAssessment.make(incident, chinese: chinese)
    }

    var body: some View {
        Button(action: onOpen) {
            HStack(alignment: .top, spacing: density == .compact ? 8 : 12) {
                if density == .standard {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(severityColor).font(.system(size: 20)).frame(width: 26)
                } else {
                    Circle().fill(severityColor).frame(width: 8, height: 8).padding(.top, 5)
                }
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Text(copy.title).font(.system(size: density == .compact ? 13 : 15, weight: .bold)).lineLimit(2)
                        Spacer(minLength: 8)
                        if density == .standard { statusChip }
                        else { Text(incident.ts.formatted(date: .omitted, time: .shortened))
                            .font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary) }
                    }
                    if density == .standard {
                        securityStory
                        HStack(spacing: 7) {
                            Text("\(displayAgent) · \(incident.ts.formatted(date: .omitted, time: .shortened))")
                            Text("·")
                            Text(copy.confidence)
                            Spacer()
                            openLabel
                        }.font(.system(size: 11)).foregroundStyle(.tertiary)
                    } else {
                        HStack {
                            Text(chinese ? "处置建议" : "RESPONSE").font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
                            Text(assessment.disposition).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
                            Spacer()
                            openLabel
                        }
                    }
                }
            }
            .padding(density == .compact ? 11 : 15)
            .background(panel, in: RoundedRectangle(cornerRadius: density == .compact ? 9 : 10))
            .overlay(RoundedRectangle(cornerRadius: density == .compact ? 9 : 10)
                .stroke(severityColor.opacity(0.5)))
        }
        .buttonStyle(.plain)
    }

    private var securityStory: some View {
        VStack(alignment: .leading, spacing: 9) {
            storyRow(icon: "exclamationmark.circle", label: chinese ? "为什么重要" : "WHY IT MATTERS",
                     value: copy.whyItMatters, color: severityColor)
            evidenceBoundary
            storyRow(icon: "arrow.right.circle.fill", label: chinese ? "建议怎么做" : "WHAT TO DO NEXT",
                     value: copy.recommendedAction, color: .cyan)
        }
        .padding(11)
        .background(raised.opacity(0.72), in: RoundedRectangle(cornerRadius: 8))
    }

    private var evidenceBoundary: some View {
        let confirmed = assessment.fields.filter { $0.level == .confirmed }
        let inferred = assessment.fields.filter { $0.level == .inferred }
        let unknown = assessment.fields.filter { $0.level == .unknown }
        return VStack(alignment: .leading, spacing: 6) {
            if !confirmed.isEmpty {
                boundaryLine(color: .green, title: chinese ? "已确认" : "CONFIRMED",
                             value: confirmed.prefix(3).map { "\($0.label)：\($0.value)" }.joined(separator: " · "))
            }
            if !inferred.isEmpty {
                boundaryLine(color: .orange, title: chinese ? "关联推断" : "INFERRED",
                             value: inferred.prefix(2).map { "\($0.label)：\($0.value)" }.joined(separator: " · "))
            }
            if !unknown.isEmpty {
                boundaryLine(color: .gray, title: chinese ? "尚未确认" : "NOT PROVEN",
                             value: unknown.prefix(2).map { "\($0.label)：\($0.value)" }.joined(separator: " · "))
            }
        }
    }

    private func storyRow(icon: String, label: String, value: String, color: Color) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).foregroundStyle(color).frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.system(size: 9, weight: .bold)).foregroundStyle(.tertiary)
                Text(value).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func boundaryLine(color: Color, title: String, value: String) -> some View {
        HStack(alignment: .top, spacing: 7) {
            Circle().fill(color).frame(width: 7, height: 7).padding(.top, 4)
            Text(title).font(.system(size: 9, weight: .bold)).foregroundStyle(color).frame(width: 70, alignment: .leading)
            Text(value).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(3)
        }
    }

    private var statusChip: some View {
        Text(copy.status.uppercased()).font(.system(size: 9, weight: .bold)).foregroundStyle(severityColor)
            .padding(.horizontal, 7).padding(.vertical, 3).background(severityColor.opacity(0.12), in: Capsule())
    }
    private var openLabel: some View {
        HStack(spacing: 4) {
            Text(chinese ? "打开案件" : "Open case").font(.system(size: 10, weight: .semibold)).foregroundStyle(.cyan)
            Image(systemName: "chevron.right").foregroundStyle(.cyan)
        }
    }
    private var displayAgent: String {
        let raw = incident.agent ?? (chinese ? "未识别智能体" : "Unknown agent")
        return raw.prefix(1).uppercased() + raw.dropFirst()
    }
    private var severityColor: Color {
        switch incident.severity { case "critical": return .red; case "high": return .orange; case "medium": return .yellow; default: return .blue }
    }
    private var panel: Color { Color(red: 8/255, green: 27/255, blue: 45/255) }
    private var raised: Color { Color(red: 13/255, green: 36/255, blue: 59/255) }
}
