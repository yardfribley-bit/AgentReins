import SwiftUI

/// Retrospective review of everything captured after installation.
/// The live dashboard keeps only a bounded in-memory window; this view reads
/// the durable evidence database so any past session, command, or connection
/// can be audited later.
///
/// Visual language mirrors the main console's LIVE TASK journey panel:
/// dark surfaces, vertical timeline with severity-tinted nodes, card rows,
/// micro section labels, and monospaced evidence.
struct HistoryView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = HistoryViewModel()

    private let canvas = Color(red: 4/255, green: 14/255, blue: 26/255)
    private let panel = Color(red: 8/255, green: 27/255, blue: 45/255)
    private let raised = Color(red: 13/255, green: 36/255, blue: 59/255)
    private let border = Color(red: 27/255, green: 66/255, blue: 96/255)
    private let cyan = Color(red: 48/255, green: 211/255, blue: 229/255)
    private let green = Color(red: 57/255, green: 214/255, blue: 117/255)
    private let amber = Color(red: 255/255, green: 177/255, blue: 45/255)

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            filterBar
            statusLine
            timeline
        }
        .background(canvas)
        .preferredColorScheme(.dark)
        .environment(\.colorScheme, .dark)
        .frame(minWidth: 1080, minHeight: 700)
        .task { model.refresh() }
    }

    // MARK: - Chrome

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 20)).foregroundStyle(cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("HISTORY REVIEW").microLabel(cyan)
                Text("安装后所有已采集行为 · 数据来自本地证据库")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Done") { dismiss() }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(cyan)
                .padding(.horizontal, 14).padding(.vertical, 7)
                .background(cyan.opacity(0.12), in: Capsule())
        }
        .padding(.horizontal, 18).frame(height: 58)
        .background(panel)
        .overlay(Rectangle().fill(border).frame(height: 1), alignment: .bottom)
    }

    private var filterBar: some View {
        HStack(spacing: 10) {
            Picker("", selection: $model.window) {
                ForEach(HistoryWindow.allCases) { window in
                    Text(window.label).tag(window)
                }
            }
            .pickerStyle(.segmented).frame(width: 470)
            .onChange(of: model.window) { _ in model.refresh() }

            Picker("", selection: $model.sourceFilter) {
                Text("全部来源").tag("All")
                ForEach(model.sources, id: \.source) { source in
                    Text("\(source.source) (\(source.count))").tag(source.source)
                }
            }
            .font(.system(size: 10)).frame(width: 250)
            .onChange(of: model.sourceFilter) { _ in model.refresh() }

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                TextField("关键词（命令 / 域名 / 路径）", text: $model.keyword)
                    .textFieldStyle(.plain)
                    .font(.system(size: 11, design: .monospaced))
                    .onSubmit { model.refresh() }
                if !model.keyword.isEmpty {
                    Button { model.keyword = ""; model.refresh() } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 10)).foregroundStyle(.secondary)
                    }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10).frame(height: 30)
            .background(raised, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(border))

            Button { model.refresh() } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 11)).foregroundStyle(cyan)
            }.buttonStyle(.plain)
        }
        .padding(.horizontal, 18).padding(.vertical, 12)
        .background(panel.opacity(0.6))
        .overlay(Rectangle().fill(border.opacity(0.5)).frame(height: 1), alignment: .bottom)
    }

    private var statusLine: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(model.loading ? amber : green)
                .frame(width: 7, height: 7)
            Text(model.loading ? "QUERYING…" : "\(model.totalCount) RECORDS · SHOWING \(model.rows.count)")
                .microLabel(model.loading ? amber : green)
            Spacer()
            if model.rows.count < model.totalCount {
                Button("LOAD MORE ↓") { model.loadMore() }
                    .buttonStyle(.plain)
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(cyan)
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background(cyan.opacity(0.12), in: Capsule())
                    .disabled(model.loading)
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 8)
    }

    // MARK: - Timeline

    private var timeline: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                if model.rows.isEmpty && !model.loading {
                    VStack(spacing: 10) {
                        Image(systemName: "clock.arrow.circlepath")
                            .font(.system(size: 34)).foregroundStyle(border)
                        Text("该筛选条件下没有记录")
                            .font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
                        Text("放宽时间范围或清空关键词后重试")
                            .font(.system(size: 10)).foregroundStyle(.tertiary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.top, 120)
                } else {
                    ForEach(Array(model.rows.enumerated()), id: \.element.id) { index, event in
                        HistoryTimelineRow(event: event,
                                           palette: HistoryPalette(canvas: canvas, panel: panel,
                                               raised: raised, border: border, cyan: cyan,
                                               green: green, amber: amber),
                                           isLast: index == model.rows.count - 1)
                    }
                    Color.clear.frame(height: 24)
                }
            }
            .padding(.horizontal, 18)
        }
    }
}

// MARK: - Local text helpers (main console's `micro` is fileprivate)

private extension Text {
    func microLabel(_ color: Color) -> Text {
        font(.system(size: 9, weight: .bold)).tracking(0.8).foregroundColor(color)
    }
}

// MARK: - Timeline row

private struct HistoryPalette {
    let canvas: Color
    let panel: Color
    let raised: Color
    let border: Color
    let cyan: Color
    let green: Color
    let amber: Color
}

private struct HistoryTimelineRow: View {
    let event: GuardEvent
    let palette: HistoryPalette
    let isLast: Bool

    @State private var expanded = false
    @State private var prettyPayload: String?

    private var nodeColor: Color {
        switch event.severity {
        case "critical": return .red
        case "high": return palette.amber
        case "medium": return palette.cyan
        default: return Color.gray
        }
    }

    private var headline: String {
        switch event.kind {
        case "network":
            let host = event.remoteDomain ?? event.remoteHost ?? "?"
            let port = event.remotePort.map { ":\($0)" } ?? ""
            return "Connection → \(host)\(port)"
        case "tool": return "\(event.toolName ?? "tool") · \(event.op)"
        case "file": return "\(event.op) \(event.path)"
        case "cmd": return event.command ?? event.ruleId
        case "memory": return "Memory access · \(event.ruleId)"
        case "model": return event.op == "prompt" ? "Model request sent" : "Model response received"
        default: return event.ruleId
        }
    }

    private var detail: String {
        var parts: [String] = []
        if let agent = event.agent { parts.append(agent.capitalized) }
        if let session = event.sessionId { parts.append("session " + session.prefix(8)) }
        if let turn = event.turnId { parts.append("turn " + turn.prefix(8)) }
        if let command = event.command, event.kind != "cmd" { parts.append(command) }
        return parts.joined(separator: "  ·  ")
    }

    private var timeText: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MM-dd HH:mm:ss"
        return formatter.string(from: event.ts)
    }

    var body: some View {
        Button { expanded.toggle(); loadPayload() } label: {
            HStack(alignment: .top, spacing: 10) {
                VStack(spacing: 0) {
                    Circle()
                        .fill(nodeColor.opacity(event.severity == "info" ? 0.6 : 1))
                        .frame(width: event.severity == "high" || event.severity == "critical" ? 11 : 9,
                               height: event.severity == "high" || event.severity == "critical" ? 11 : 9)
                        .shadow(color: event.severity == "high" || event.severity == "critical"
                                ? nodeColor.opacity(0.8) : .clear, radius: 5)
                        .padding(.top, 8)
                    if !isLast {
                        Rectangle().fill(palette.border).frame(width: 1).frame(maxHeight: .infinity)
                    }
                }
                .frame(width: 10)

                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8) {
                        Text(event.kind.uppercased())
                            .font(.system(size: 6.5, weight: .bold))
                            .foregroundStyle(nodeColor)
                            .padding(.horizontal, 6).padding(.vertical, 3)
                            .background(nodeColor.opacity(0.12), in: Capsule())
                        Text(headline)
                            .font(.system(size: 11.5, weight: .semibold, design: event.kind == "cmd" ? .monospaced : .default))
                            .lineLimit(1)
                        Spacer()
                        Text(event.severity.uppercased())
                            .font(.system(size: 6.5, weight: .bold)).foregroundStyle(nodeColor)
                        Text(timeText)
                            .font(.system(size: 8, design: .monospaced)).foregroundStyle(.secondary)
                        Image(systemName: expanded ? "chevron.down" : "chevron.right")
                            .font(.system(size: 8)).foregroundStyle(.secondary)
                    }
                    Text(detail)
                        .font(.system(size: 9.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    if expanded {
                        VStack(alignment: .leading, spacing: 6) {
                            evidenceField("SESSION", event.sessionId)
                            evidenceField("TURN", event.turnId)
                            evidenceField("RULE", event.ruleId)
                            evidenceField("COMMAND", event.command)
                            evidenceField("PATH", event.path)
                            evidenceField("USER INTENT", event.userIntent)
                            evidenceField("ATTRIBUTION", event.attributionMethod)
                            if let prettyPayload {
                                Text(prettyPayload)
                                    .font(.system(size: 8.5, design: .monospaced))
                                    .foregroundStyle(.primary.opacity(0.85))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(8)
                                    .background(palette.canvas, in: RoundedRectangle(cornerRadius: 6))
                                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(palette.border))
                            }
                        }
                        .padding(.top, 4)
                    }
                }
                .padding(10)
                .background(expanded ? nodeColor.opacity(0.1) : palette.raised,
                            in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(expanded ? nodeColor : palette.border))
            }
            .padding(.bottom, 6)
        }
        .buttonStyle(.plain)
    }

    private func evidenceField(_ title: String, _ value: String?) -> some View {
        guard let value, !value.isEmpty, value != "-" else { return AnyView(EmptyView()) }
        return AnyView(HStack(alignment: .top, spacing: 8) {
            Text(title)
                .font(.system(size: 7, weight: .bold))
                .tracking(0.6)
                .foregroundStyle(palette.cyan.opacity(0.8))
                .frame(width: 88, alignment: .trailing)
            Text(value)
                .font(.system(size: 9.5, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(4)
                .frame(maxWidth: .infinity, alignment: .leading)
        })
    }

    private func loadPayload() {
        guard prettyPayload == nil, let data = try? JSONEncoder().encode(event) else { return }
        if let object = try? JSONSerialization.jsonObject(with: data),
           let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
           let text = String(data: pretty, encoding: .utf8) {
            prettyPayload = text
        }
    }
}

// MARK: - Filters & model

enum HistoryWindow: String, CaseIterable, Identifiable {
    case hour1, hour6, day, week, month, all

    var id: String { rawValue }

    var label: String {
        switch self {
        case .hour1: return "1H"
        case .hour6: return "6H"
        case .day: return "24H"
        case .week: return "7D"
        case .month: return "30D"
        case .all: return "ALL"
        }
    }

    var seconds: TimeInterval? {
        switch self {
        case .hour1: return 3600
        case .hour6: return 6 * 3600
        case .day: return 24 * 3600
        case .week: return 7 * 24 * 3600
        case .month: return 30 * 24 * 3600
        case .all: return nil
        }
    }
}

@MainActor
final class HistoryViewModel: ObservableObject {
    @Published var rows: [GuardEvent] = []
    @Published var sources: [(source: String, count: Int)] = []
    @Published var totalCount = 0
    @Published var window: HistoryWindow = .day
    @Published var sourceFilter = "All"
    @Published var keyword = ""
    @Published var loading = false

    private var database: EvidenceDatabase?
    private var offset = 0
    private let pageSize = 300

    private var since: TimeInterval? {
        window.seconds.map { Date().timeIntervalSince1970 - $0 }
    }

    init() {
        database = try? EvidenceDatabase()
        reloadSources()
    }

    func refresh() {
        offset = 0
        loadPage(reset: true)
    }

    func loadMore() {
        offset += pageSize
        loadPage(reset: false)
    }

    private func reloadSources() {
        guard let database else { return }
        sources = (try? database.historySources())?.map { $0 } ?? []
    }

    private func loadPage(reset: Bool) {
        guard let database else { return }
        loading = true
        let since = self.since, source = sourceFilter == "All" ? nil : sourceFilter
        let keyword = self.keyword.isEmpty ? nil : self.keyword
        let currentOffset = reset ? 0 : offset
        Task.detached(priority: .userInitiated) { [weak self] in
            let rows = (try? database.history(since: since, source: source, keyword: keyword,
                                              limit: self?.pageSize ?? 300, offset: currentOffset)) ?? []
            let count = (try? database.historyCount(since: since, source: source, keyword: keyword)) ?? 0
            await MainActor.run { [weak self] in
                guard let self else { return }
                if reset { self.rows = rows } else { self.rows += rows }
                self.totalCount = count
                self.loading = false
            }
        }
    }
}
