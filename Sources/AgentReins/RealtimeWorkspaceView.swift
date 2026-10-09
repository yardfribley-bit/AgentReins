import SwiftUI
import WebKit

/// Uses the approved prototype's local layout. No network access or script message bridge.
struct RealtimeWorkspaceView: NSViewRepresentable {
    let payload: RealtimeWorkspacePayload
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        view.setValue(false, forKey: "drawsBackground")
        context.coordinator.latest = payload
        if let directory = (Bundle.main.resourceURL?.appendingPathComponent("RealtimeWorkspace")).flatMap({ FileManager.default.fileExists(atPath: $0.path) ? $0 : nil }) ?? Bundle.module.url(forResource: "Resources", withExtension: nil)?.appendingPathComponent("RealtimeWorkspace"),
           FileManager.default.fileExists(atPath: directory.appendingPathComponent("index.html").path) {
            view.loadFileURL(directory.appendingPathComponent("index.html"), allowingReadAccessTo: directory)
        } else { view.loadHTMLString("<body style='background:#0c1014;color:#e7ecec'>实时界面资源缺失，请重新构建安装包。</body>", baseURL: nil) }
        return view
    }
    func updateNSView(_ view: WKWebView, context: Context) {
        context.coordinator.latest = payload
        context.coordinator.publish(view)
    }
    final class Coordinator: NSObject, WKNavigationDelegate {
        var latest: RealtimeWorkspacePayload?
        var ready = false
        private var sending = false
        private var dirty = false
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { ready = true; publish(webView) }
        func publish(_ webView: WKWebView) {
            guard ready else { return }
            guard !sending else { dirty = true; return }
            guard let latest else { return }
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            guard let bytes = try? encoder.encode(latest), let json = String(data: bytes, encoding: .utf8) else { return }
            sending = true
            // Structured arguments prevent evidence strings from becoming executable JavaScript.
            Task { @MainActor [weak self, weak webView] in
                guard let self, let webView else { return }
                do { _ = try await webView.callAsyncJavaScript("window.agentreinsReceive(JSON.parse(payload))", arguments: ["payload": json], in: nil, contentWorld: .page) }
                catch { NSLog("Realtime workspace delivery failed: %@", String(describing: error)) }
                self.sending = false
                if self.dirty { self.dirty = false; self.publish(webView) }
            }
        }
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            decisionHandler(action.request.url?.isFileURL == true ? .allow : .cancel)
        }
    }
}

@MainActor
final class RealtimeWorkspaceState: ObservableObject {
    @Published private(set) var revision = 0
    private var evidence: [UUID: GuardEvent] = [:]
    private var sizes: [UUID: Int] = [:]
    private var retainedBytes = 0
    private var registry = CollectionProcessRegistry()
    func updateProcesses(_ processes: [ProcessSnapshotRecord]) { registry.update(processes, now: Date()); revision += 1 }
    private let byteBudget: Int
    init(byteBudget: Int = 32 * 1024 * 1024) { self.byteBudget = byteBudget }
    private(set) var truncated = false
    let since = Date()
    func ingest(_ events: [GuardEvent]) {
        for event in events where event.ts >= since {
            let size = [event.modelPrompt, event.modelResponse, event.command, event.beforeContent, event.afterContent, event.fileDiff, event.modelReasoning].compactMap { $0 }.reduce(512) { $0 + $1.utf8.count }
            retainedBytes += size - (sizes[event.id] ?? 0)
            sizes[event.id] = size; evidence[event.id] = event
        }
        if evidence.count > 6000 || retainedBytes > byteBudget {
            for event in evidence.values.sorted(by: { $0.ts < $1.ts }) {
                guard evidence.count > 6000 || retainedBytes > byteBudget else { break }
                retainedBytes -= sizes.removeValue(forKey: event.id) ?? 0
                evidence.removeValue(forKey: event.id); truncated = true
            }
        }
        revision += 1
    }
    func payload(processes: [ProcessSnapshotRecord], health: [CollectorHealthRecord], observing: Bool, error: String?) -> RealtimeWorkspacePayload {
        RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: Array(evidence.values), since: since),
            collected: evidence.values.sorted { $0.ts > $1.ts }.prefix(200).map { event in
                let display = CollectionRecordPresentation(event, receivedAt: event.ts)
                return RealtimeCollectedRecord(id: event.id.uuidString, agent: RealtimeWorkspaceProjector.canonicalAgent(event.agent) ?? "归属未确认", source: event.source ?? "来源未知",
                    kind: event.kind, op: event.op, summary: display.summary, preview: String(display.preview.prefix(16000)),
                    hasTaskIdentity: event.sessionId != nil && event.turnId != nil,
                    title: display.title, category: display.category, details: (display.details + ["路径：\(event.path)", "会话：\(event.sessionId ?? "未关联")", "轮次：\(event.turnId ?? "未关联")"]).joined(separator: "\n"), pid: event.processId,
                    session: event.sessionId, turn: event.turnId, call: event.toolCallId, timestamp: event.ts)
            }, unattributedCount: evidence.values.filter { $0.sessionId == nil || $0.turnId == nil }.count,
            processes: registry.ordered.map { row in
                let process = row.node.process
                return RealtimeProcess(id: row.node.id, pid: process.pid, parent: process.ppid,
                    agent: "WorkBuddy", name: row.node.role.title,
                    executable: process.executablePath ?? "未采集", command: ProcessArgumentRedactor.redact(process.command), active: row.node.active, depth: row.depth)
            } + processes.compactMap { process in
                guard let agent = RealtimeWorkspaceProjector.canonicalAgent(process.agent), agent != "WorkBuddy" || registry.nodes.isEmpty else { return nil }
                return RealtimeProcess(id: ProcessObservationCoordinator.identity(process), pid: process.pid, parent: process.ppid,
                    agent: agent, name: CollectionProcessNode(process: process, firstSeen: since, lastSeen: Date(), active: true).role.title,
                    executable: process.executablePath ?? "未采集", command: ProcessArgumentRedactor.redact(process.command))
            }, health: health.map { RealtimeHealth(source: $0.source, state: $0.state.rawValue, accepted: $0.accepted, detail: $0.detail) },
            observing: observing, persistenceError: error, publishedAt: Date(), truncated: truncated, collectedCount: evidence.count)
    }
}
