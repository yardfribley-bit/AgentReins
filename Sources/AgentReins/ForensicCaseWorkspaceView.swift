import SwiftUI

struct ForensicCaseWorkspaceView: View {
    let incident: SecurityIncident
    let events: [GuardEvent]
    let health: [CollectorHealthRecord]

    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var language: AppLanguageStore
    @State private var selectedEvidenceID: UUID?

    private var forensicCase: ForensicCase {
        ForensicCase.build(incident: incident, allEvents: events, health: health)
    }
    private var chinese: Bool { language.language == .simplifiedChinese }

    var body: some View {
        let item = forensicCase
        HStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header(item)
                    overview(item)
                    findings(item)
                    evidenceTimeline(item)
                }.padding(22)
            }
            .frame(minWidth: 700)
            Divider()
            evidenceInspector(item)
                .frame(width: 340)
        }
        .frame(minWidth: 1080, minHeight: 700)
        .background(Color(red: 4/255, green: 14/255, blue: 26/255))
        .preferredColorScheme(.dark)
    }

    private func header(_ item: ForensicCase) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(chinese ? "案件工作台" : "FORENSIC CASE WORKSPACE")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(.cyan)
                    Text(item.title).font(.system(size: 23, weight: .bold))
                    Text("AR-\(item.id.uuidString.prefix(8).uppercased()) · \(item.agent) · \(duration(item))")
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                }
                Spacer()
                Button(chinese ? "完成" : "Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            if let intent = item.intent {
                labelValue(chinese ? "用户原始需求" : "ORIGINAL USER INTENT", intent)
            }
        }
    }

    private func overview(_ item: ForensicCase) -> some View {
        HStack(alignment: .top, spacing: 12) {
            metric(chinese ? "已确认" : "Confirmed", "\(item.confirmedCount)", .green)
            metric(chinese ? "待验证" : "Open questions", "\(item.openQuestionCount)", .orange)
            metric(chinese ? "证据覆盖率" : "Evidence coverage", "\(item.coveragePercent)%", .cyan)
            metric(chinese ? "时间线证据" : "Timeline evidence", "\(item.timeline.count)", .blue)
        }
    }

    private func findings(_ item: ForensicCase) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionTitle(chinese ? "调查结论" : "INVESTIGATION FINDINGS",
                         chinese ? "事实、关联与未知项分开呈现" : "Facts, correlations, and unknowns remain separate")
            ForEach(item.findings) { finding in
                HStack(alignment: .top, spacing: 11) {
                    Image(systemName: icon(finding.confidence))
                        .foregroundStyle(color(finding.confidence)).frame(width: 20)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(finding.title).font(.system(size: 13, weight: .bold))
                            Spacer()
                            chip(label(finding.confidence), color: color(finding.confidence))
                        }
                        Text(finding.detail).font(.system(size: 12)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }.padding(12).background(panel, in: RoundedRectangle(cornerRadius: 9))
            }
        }
    }

    private func evidenceTimeline(_ item: ForensicCase) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionTitle(chinese ? "证据链" : "EVIDENCE CHAIN",
                         chinese ? "点击任一节点查看原始记录" : "Select any node to inspect the raw record")
            ForEach(item.timeline) { entry in
                Button { selectedEvidenceID = entry.id } label: {
                    HStack(alignment: .top, spacing: 10) {
                        VStack(spacing: 3) {
                            Circle().fill(color(entry.event)).frame(width: 9, height: 9)
                            Rectangle().fill(Color.cyan.opacity(0.25)).frame(width: 1, height: 32)
                        }.padding(.top, 4)
                        Text(entry.event.ts.formatted(date: .omitted, time: .standard))
                            .font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary).frame(width: 72, alignment: .leading)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(entry.relation).font(.system(size: 9, weight: .bold)).foregroundStyle(.cyan)
                            Text(entry.summary).font(.system(size: 12, weight: .medium)).lineLimit(3)
                            Text("\(entry.event.kind) · \(entry.event.op) · \(entry.event.source ?? "unknown source")")
                                .font(.system(size: 10)).foregroundStyle(.tertiary)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                    }.padding(10).background(selectedEvidenceID == entry.id ? Color.cyan.opacity(0.12) : panel,
                                              in: RoundedRectangle(cornerRadius: 8))
                }.buttonStyle(.plain)
            }
        }
    }

    private func evidenceInspector(_ item: ForensicCase) -> some View {
        let selected = item.timeline.first { $0.id == selectedEvidenceID } ?? item.timeline.first
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                sectionTitle(chinese ? "证据检查器" : "EVIDENCE INSPECTOR",
                             chinese ? "原始证据与采集盲区" : "Raw evidence and collection gaps")
                if let event = selected?.event {
                    inspectorField("EVENT ID", event.id.uuidString)
                    inspectorField("SESSION", event.sessionId ?? "Not captured")
                    inspectorField("TURN", event.turnId ?? "Not captured")
                    inspectorField("RULE", event.ruleId)
                    inspectorField("ATTRIBUTION", "\(event.attributionConfidence?.rawValue ?? "unknown") · \(event.attributionMethod ?? "No method")")
                    inspectorField("CONTENT", rawSummary(event))
                }
                Divider()
                Text(chinese ? "证据覆盖" : "EVIDENCE COVERAGE").font(.system(size: 11, weight: .bold)).foregroundStyle(.cyan)
                ForEach(item.coverage) { row in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: row.available ? "checkmark.circle.fill" : "questionmark.circle")
                            .foregroundStyle(row.available ? .green : .orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(row.capability).font(.system(size: 11, weight: .semibold))
                            Text(row.detail).font(.system(size: 10)).foregroundStyle(.secondary)
                        }
                    }
                }
                if !item.collectorWarnings.isEmpty {
                    Divider()
                    Text(chinese ? "采集器告警" : "COLLECTOR WARNINGS").font(.system(size: 11, weight: .bold)).foregroundStyle(.orange)
                    ForEach(item.collectorWarnings, id: \.self) { warning in
                        Text(warning).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
            }.padding(18)
        }.background(Color(red: 7/255, green: 23/255, blue: 38/255))
    }

    private var panel: Color { Color(red: 13/255, green: 36/255, blue: 59/255) }
    private func sectionTitle(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 11, weight: .bold)).foregroundStyle(.cyan)
            Text(subtitle).font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }
    private func metric(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(value).font(.system(size: 22, weight: .bold)).foregroundStyle(color)
            Text(title).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(panel, in: RoundedRectangle(cornerRadius: 9))
    }
    private func labelValue(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 9, weight: .bold)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 12)).textSelection(.enabled)
        }.padding(11).frame(maxWidth: .infinity, alignment: .leading).background(panel, in: RoundedRectangle(cornerRadius: 8))
    }
    private func chip(_ text: String, color: Color) -> some View {
        Text(text).font(.system(size: 9, weight: .bold)).foregroundStyle(color)
            .padding(.horizontal, 7).padding(.vertical, 3).background(color.opacity(0.12), in: Capsule())
    }
    private func inspectorField(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 9, weight: .bold)).foregroundStyle(.tertiary)
            Text(value).font(.system(size: 10, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
    private func duration(_ item: ForensicCase) -> String {
        let seconds = max(0, Int(item.endedAt.timeIntervalSince(item.startedAt)))
        return seconds < 60 ? "\(seconds)s" : "\(seconds / 60)m \(seconds % 60)s"
    }
    private func label(_ confidence: ForensicCase.Confidence) -> String {
        switch confidence {
        case .confirmed: return chinese ? "已确认" : "CONFIRMED"
        case .correlated: return chinese ? "已关联" : "CORRELATED"
        case .inferred: return chinese ? "推断" : "INFERRED"
        case .unverified: return chinese ? "未验证" : "UNVERIFIED"
        }
    }
    private func icon(_ confidence: ForensicCase.Confidence) -> String {
        switch confidence {
        case .confirmed: return "checkmark.shield.fill"
        case .correlated: return "link"
        case .inferred: return "waveform.path.ecg"
        case .unverified: return "questionmark.diamond"
        }
    }
    private func color(_ confidence: ForensicCase.Confidence) -> Color {
        switch confidence {
        case .confirmed: return .green
        case .correlated: return .cyan
        case .inferred: return .yellow
        case .unverified: return .orange
        }
    }
    private func color(_ event: GuardEvent) -> Color {
        switch event.kind {
        case "network": return .orange
        case "file": return .green
        case "tool": return .cyan
        case "model": return .purple
        default: return .gray
        }
    }
    private func rawSummary(_ event: GuardEvent) -> String {
        ProcessArgumentRedactor.redact(event.command ?? event.modelResponse ?? event.modelPrompt ?? event.path)
    }
}
