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
                    assessmentGrid
                    if density == .standard {
                        explanationRow
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

    private var assessmentGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible(), alignment: .topLeading),
                            GridItem(.flexible(), alignment: .topLeading)], spacing: 8) {
            ForEach(assessment.fields) { field in
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 5) {
                        Circle().fill(color(field.level)).frame(width: 6, height: 6)
                        Text(field.label.uppercased()).font(.system(size: 9, weight: .bold)).foregroundStyle(.tertiary)
                        Text(level(field.level)).font(.system(size: 8, weight: .semibold)).foregroundStyle(color(field.level))
                    }
                    Text(field.value).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).lineLimit(3)
                }
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(raised, in: RoundedRectangle(cornerRadius: 7))
            }
        }
    }

    private var explanationRow: some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: "checklist").foregroundStyle(.cyan).frame(width: 16)
            VStack(alignment: .leading, spacing: 2) {
                Text(chinese ? "处置建议" : "RESPONSE").font(.system(size: 9, weight: .bold)).foregroundStyle(.tertiary)
                Text(assessment.disposition).font(.system(size: 11)).foregroundStyle(.secondary)
            }
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
    private func color(_ level: SecurityIncidentAssessment.EvidenceLevel) -> Color {
        switch level { case .confirmed: return .green; case .inferred: return .orange; case .unknown: return .gray }
    }
    private func level(_ value: SecurityIncidentAssessment.EvidenceLevel) -> String {
        switch value {
        case .confirmed: return chinese ? "已确认" : "CONFIRMED"
        case .inferred: return chinese ? "关联推断" : "INFERRED"
        case .unknown: return chinese ? "未知" : "UNKNOWN"
        }
    }
    private var panel: Color { Color(red: 8/255, green: 27/255, blue: 45/255) }
    private var raised: Color { Color(red: 13/255, green: 36/255, blue: 59/255) }
}
