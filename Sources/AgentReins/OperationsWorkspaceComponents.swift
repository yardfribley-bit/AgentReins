import SwiftUI

struct GlobalSituationHeaderView: View {
    let eyebrow: String
    let headline: String
    let subtitle: String
    let projects: Int
    let activeTasks: Int
    let reviews: Int
    let evidenceCoverage: String
    let projectLabel: String
    let activeTaskLabel: String
    let reviewLabel: String
    let evidenceLabel: String

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 5) {
                Text(eyebrow).font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundStyle(.cyan)
                Text(headline).font(.system(size: 24, weight: .bold))
                Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
            }
            Spacer()
            metric(projectLabel, "\(projects)", .cyan)
            metric(activeTaskLabel, "\(activeTasks)", .blue)
            metric(reviewLabel, "\(reviews)", .orange)
            metric(evidenceLabel, evidenceCoverage, .green)
        }
        .padding(16).background(panel, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(border))
    }

    private func metric(_ label: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 20, weight: .bold, design: .rounded)).foregroundStyle(color)
        }.padding(.horizontal, 13).padding(.vertical, 9)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border.opacity(0.8)))
    }
    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let border = Color(red: 27/255, green: 66/255, blue: 96/255)
}

struct AgentLiveTaskHeaderView: View {
    let agentName: String
    let headline: String
    let active: Bool
    let pid: String?
    let model: String?
    let openTitle: String
    let onOpen: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 10) {
                    Circle().fill(active ? Color.green : Color.gray).frame(width: 9, height: 9)
                    Text(agentName).font(.system(size: 20, weight: .bold))
                    if active {
                        Text("Running").font(.system(size: 13, weight: .bold)).foregroundStyle(.green)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Color.green.opacity(0.12), in: Capsule())
                    }
                    if let pid { Text("PID \(pid)").font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary) }
                    if let model {
                        Text(model).font(.system(size: 11, weight: .semibold)).foregroundStyle(.blue)
                            .padding(.horizontal, 7).padding(.vertical, 3).background(Color.blue.opacity(0.12), in: Capsule())
                    }
                }
                Text(headline).font(.system(size: 14)).foregroundStyle(.secondary).lineLimit(2)
            }
            Spacer()
            if let onOpen { Button(openTitle, action: onOpen).buttonStyle(.bordered) }
        }
    }
}
