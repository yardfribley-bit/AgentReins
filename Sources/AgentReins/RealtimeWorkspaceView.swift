import SwiftUI
import WebKit

/// Local evidence UI. A small native bridge only accepts known task/artifact IDs.
struct RealtimeWorkspaceView: NSViewRepresentable {
    let payload: RealtimeWorkspacePayload
    var onMarkRead: ((String) -> Void)? = nil
    var onRefreshArtifacts: (() -> Void)? = nil
    var onResolveIP: ((String) -> Void)? = nil
    func makeCoordinator() -> Coordinator { Coordinator() }
    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.add(context.coordinator, name: "agentreins")
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        view.setValue(false, forKey: "drawsBackground")
        context.coordinator.onMarkRead = onMarkRead
        context.coordinator.onRefreshArtifacts = onRefreshArtifacts
        context.coordinator.onResolveIP = onResolveIP
        context.coordinator.latest = payload
        if let directory = (Bundle.main.resourceURL?.appendingPathComponent("RealtimeWorkspace")).flatMap({ FileManager.default.fileExists(atPath: $0.path) ? $0 : nil }) ?? Bundle.module.url(forResource: "Resources", withExtension: nil)?.appendingPathComponent("RealtimeWorkspace"),
           FileManager.default.fileExists(atPath: directory.appendingPathComponent("index.html").path) {
            view.loadFileURL(directory.appendingPathComponent("index.html"), allowingReadAccessTo: directory)
        } else { view.loadHTMLString("<body style='background:#0c1014;color:#e7ecec'>实时界面资源缺失，请重新构建安装包。</body>", baseURL: nil) }
        return view
    }
    func updateNSView(_ view: WKWebView, context: Context) {
        context.coordinator.onMarkRead = onMarkRead
        context.coordinator.onRefreshArtifacts = onRefreshArtifacts
        context.coordinator.onResolveIP = onResolveIP
        context.coordinator.latest = payload
        context.coordinator.publish(view)
    }
    static func dismantleNSView(_ view: WKWebView, coordinator: Coordinator) {
        view.configuration.userContentController.removeScriptMessageHandler(forName: "agentreins")
    }
    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        var onMarkRead: ((String) -> Void)?
        var onRefreshArtifacts: (() -> Void)?
        var onResolveIP: ((String) -> Void)?
        func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
            guard message.frameInfo.isMainFrame, message.frameInfo.request.url?.isFileURL == true,
                  let body = message.body as? [String: Any], let action = body["action"] as? String, let latest else { return }
            if action == "refreshArtifacts" { onRefreshArtifacts?(); return }
            guard let taskID = body["taskID"] as? String, latest.tasks.contains(where: { $0.id == taskID }) else { return }
            if action == "markRead" { onMarkRead?(taskID) }
            else if action == "resolveIP", let ip = body["ip"] as? String,
                    IPGeolocationStore.isPublicIPAddress(ip),
                    latest.tasks.first(where: { $0.id == taskID })?.cards.contains(where: { $0.resource?.remoteIP == ip || $0.resource?.addresses.contains(ip) == true }) == true {
                onResolveIP?(ip)
            }
            else if action == "openArtifact", let id = body["artifactID"] as? String,
                    let artifact = latest.artifacts.first(where: { $0.id == id && $0.taskID == taskID }) {
                let opened = RealtimeArtifactProjector.open(artifact)
                Task { @MainActor in
                    _ = try? await message.webView?.callAsyncJavaScript("window.agentreinsHostResult && window.agentreinsHostResult(result)", arguments: ["result": ["action": action, "artifactID": id, "success": opened, "message": opened ? "已交给系统打开" : "文件不存在或不支持安全打开"]], in: nil, contentWorld: .page)
                }
            }
        }
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
    private let contextQueue = DispatchQueue(label: "com.agentreins.context-presentation", qos: .utility)
    private var parsedContexts: [UUID: RealtimeContextExchange] = [:]
    private var parsingContexts = Set<UUID>()
    private var contextInputs: [UUID: String] = [:]
    private var registry = CollectionProcessRegistry()
    func updateProcesses(_ processes: [ProcessSnapshotRecord]) { registry.update(processes, now: Date()); revision += 1 }
    private let byteBudget: Int
    init(byteBudget: Int = 32 * 1024 * 1024, checkpointURL: URL? = nil) {
        self.byteBudget = byteBudget; self.checkpointURL = checkpointURL
        terminationObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.flushCheckpoint() }
        }
        if let checkpointURL {
            do {
                if let checkpoint = try RealtimeActiveCheckpoint.load(checkpointURL) {
                    for event in checkpoint.events {
                        evidence[event.id] = event; restoredIDs.insert(event.id)
                        let size = Self.eventSize(event); sizes[event.id] = size; retainedBytes += size
                    }
                    readTaskIDs = Set(checkpoint.readTaskIDs)
                    since = min(since, checkpoint.events.map(\.ts).min() ?? since)
                    if !checkpoint.events.isEmpty {
                        continuityNotice = "已恢复本机已采活跃任务；\(checkpoint.savedAt.formatted()) 至本次启动之间的来源缺口需核对"
                    }
                }
            } catch { continuityNotice = "活跃任务检查点无法恢复：\(error.localizedDescription)" }
        }
    }
    private static func eventSize(_ event: GuardEvent) -> Int {
        [event.userIntent, event.modelPrompt, event.modelResponse, event.command, event.beforeContent, event.afterContent, event.fileDiff, event.modelReasoning].compactMap { $0 }.reduce(512) { $0 + $1.utf8.count }
    }
    private var terminationObserver: NSObjectProtocol?
    private(set) var truncated = false
    private let runtimeStartedAt = Date()
    private(set) var since = Date()
    private var restoredIDs = Set<UUID>()
    private var readTaskIDs = Set<String>()
    private var artifacts: [RealtimeArtifact] = []
    private var artifactCandidates: [RealtimeArtifactProjector.Candidate] = []
    private let artifactQueue = DispatchQueue(label: "com.agentreins.artifacts", qos: .utility)
    private var artifactGeneration = 0
    private let checkpointURL: URL?
    private let checkpointQueue = DispatchQueue(label: "com.agentreins.active-checkpoint", qos: .utility)
    private var checkpointWork: DispatchWorkItem?
    private var checkpointGeneration = 0
    private var continuityNotice: String?
    static func checkpointLocation() -> URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/AgentGuard/realtime-active-v1.json")
    }
    func markRead(_ taskID: String) {
        guard RealtimeWorkspaceProjector.tasks(events: Array(evidence.values), since: since).contains(where: { $0.id == taskID }) else { return }
        readTaskIDs.insert(taskID); revision += 1; scheduleCheckpoint()
    }
    func refreshArtifacts() {
        artifactGeneration += 1
        let generation = artifactGeneration, candidates = artifactCandidates
        artifactQueue.async { [weak self] in
            let values = RealtimeArtifactProjector.probe(candidates)
            DispatchQueue.main.async {
                guard let self, self.artifactGeneration == generation else { return }
                self.artifacts = values; self.revision += 1
            }
        }
    }
    private func scheduleArtifacts() {
        let values = Array(evidence.values)
        let tasks = RealtimeWorkspaceProjector.tasks(events: values, since: since)
        let candidates = RealtimeArtifactProjector.candidates(events: values, tasks: tasks)
        guard candidates != artifactCandidates else { return }
        artifactCandidates = candidates; refreshArtifacts()
    }
    func flushCheckpoint() {
        guard let checkpointURL else { return }
        checkpointWork?.cancel(); checkpointWork = nil
        checkpointQueue.sync {} // Finish any previous atomic save before the shutdown snapshot.
        let values = Array(evidence.values)
        let tasks = RealtimeWorkspaceProjector.tasks(events: values, since: since)
        let active = tasks.filter { !["completed", "failed", "cancelled"].contains($0.lifecycleStatus) }
        let keys = Set(active.map { $0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn })
        let linked = Set(active.flatMap { $0.cards.flatMap(\.eventIDs) + [$0.requestEventID].compactMap { $0 } })
        let events = values.filter { e in
            guard let agent = RealtimeWorkspaceProjector.canonicalAgent(e.agent), let session = e.sessionId else { return false }
            return linked.contains(e.id.uuidString) || keys.contains(agent + "\u{0}" + session + "\u{0}" + (e.turnId ?? ""))
        }
        do { try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: events, readTaskIDs: Array(readTaskIDs)).save(checkpointURL) }
        catch { continuityNotice = "退出时活跃任务保存失败：\(error.localizedDescription)" }
    }
    private func scheduleCheckpoint() {
        guard let checkpointURL else { return }
        checkpointGeneration += 1
        guard checkpointWork == nil else { return }
        let generation = checkpointGeneration
        let values = Array(evidence.values)
        let tasks = RealtimeWorkspaceProjector.tasks(events: values, since: since)
        let activeTasks = tasks.filter { !["completed", "failed", "cancelled"].contains($0.lifecycleStatus) }
        let activeKeys = Set(activeTasks.map { $0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn })
        let linkedIDs = Set(activeTasks.flatMap { $0.cards.flatMap(\.eventIDs) + [$0.requestEventID].compactMap { $0 } })
        let active = values.filter { e in
            guard let agent = RealtimeWorkspaceProjector.canonicalAgent(e.agent), let session = e.sessionId else { return false }
            return linkedIDs.contains(e.id.uuidString) || activeKeys.contains(agent + "\u{0}" + session + "\u{0}" + (e.turnId ?? ""))
        }
        let checkpoint = RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: active, readTaskIDs: Array(readTaskIDs))
        let work = DispatchWorkItem { [weak self] in
            defer {
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.checkpointWork = nil
                    if self.checkpointGeneration != generation { self.scheduleCheckpoint() }
                }
            }
            do { try checkpoint.save(checkpointURL) }
            catch {
                DispatchQueue.main.async {
                    self?.continuityNotice = "活跃任务检查点保存失败：\(error.localizedDescription)；重启连续性未保证"
                    self?.revision += 1
                }
            }
        }
        checkpointWork = work
        checkpointQueue.asyncAfter(deadline: .now() + .milliseconds(800), execute: work)
    }
    func ingest(_ events: [GuardEvent]) {
        var changed = false
        for event in events where event.ts >= runtimeStartedAt || restoredIDs.contains(event.id) {
            if let old = evidence[event.id], old.ts == event.ts, old.action == event.action, old.userIntent == event.userIntent,
               old.modelResponse == event.modelResponse, old.modelPrompt == event.modelPrompt, old.command == event.command,
               old.afterContent == event.afterContent, old.fileDiff == event.fileDiff, old.beforeContent == event.beforeContent,
               old.agent == event.agent, old.sessionId == event.sessionId, old.turnId == event.turnId, old.traceId == event.traceId,
               old.toolName == event.toolName, old.source == event.source, old.path == event.path,
               old.attributionMethod == event.attributionMethod, old.attributionConfidence == event.attributionConfidence,
               old.processId == event.processId, old.remoteHost == event.remoteHost, old.remoteDomain == event.remoteDomain,
               old.remotePort == event.remotePort, old.modelDecision == event.modelDecision, old.modelReasoning == event.modelReasoning,
               old.endedAt == event.endedAt, old.startedAt == event.startedAt, old.inputTokens == event.inputTokens, old.outputTokens == event.outputTokens { continue }
            changed = true
            let size = Self.eventSize(event)
            retainedBytes += size - (sizes[event.id] ?? 0)
            sizes[event.id] = size; evidence[event.id] = event
        }
        // Preserve small original-request records and currently active call
        // boundaries ahead of bulky model/output previews under pressure.
        if evidence.count > 6000 || retainedBytes > byteBudget {
            let protected = Set(evidence.values.filter { ["prompt", "hook_user_prompt", "call", "hook_tool_start", "result", "hook_tool_end", "task_complete", "task_completed", "task_failed", "turn_completed", "task_cancelled", "hook_turn_stop"].contains($0.op) && Self.eventSize($0) <= byteBudget / 2 }.map(\.id))
            for event in evidence.values.sorted(by: { a, b in
                if protected.contains(a.id) != protected.contains(b.id) { return !protected.contains(a.id) }
                return a.ts < b.ts
            }) {
                guard evidence.count > 6000 || retainedBytes > byteBudget else { break }
                retainedBytes -= sizes.removeValue(forKey: event.id) ?? 0
                evidence.removeValue(forKey: event.id); truncated = true
            }
        }
        parsedContexts = parsedContexts.filter { evidence[$0.key] != nil }
        contextInputs = contextInputs.filter { evidence[$0.key] != nil }
        for event in evidence.values where event.kind == "model" && ["prompt", "network_prompt"].contains(event.op) {
            guard let body = event.modelPrompt, contextInputs[event.id] != body, !parsingContexts.contains(event.id) else { continue }
            parsingContexts.insert(event.id)
            contextQueue.async { [weak self] in
                let parsed = RealtimeContextProjector.parse(event)
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.parsingContexts.remove(event.id)
                    guard self.evidence[event.id] != nil else { return }
                    self.contextInputs[event.id] = body
                    self.parsedContexts[event.id] = parsed
                    self.revision += 1
                }
            }
        }
        if changed { scheduleArtifacts(); scheduleCheckpoint() }
        revision += 1
    }
    func payload(processes: [ProcessSnapshotRecord], health: [CollectorHealthRecord], observing: Bool, error: String?, geolocation: IPGeolocationStore? = nil) -> RealtimeWorkspacePayload {
        var value = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.tasks(events: Array(evidence.values), since: since),
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
            observing: observing, persistenceError: error, publishedAt: Date(), truncated: truncated, collectedCount: evidence.count, contexts: RealtimeContextProjector.assemble(Array(parsedContexts.values), events: Array(evidence.values)))
        if let geolocation {
            let addresses = Set(value.tasks.flatMap { $0.cards.flatMap { card in ([card.resource?.remoteIP].compactMap { $0 } + (card.resource?.addresses ?? [])) } }.filter(IPGeolocationStore.isPublicIPAddress))
            value.ipGeolocations = addresses.sorted().map { ip in
                let record = geolocation.records[ip]
                return RealtimeIPLocation(ip: ip, location: record?.locationLabel, owner: record?.ownerLabel, source: "ipwho.is", updatedAt: record?.fetchedAt,
                    state: record != nil ? "ready" : geolocation.pending.contains(ip) ? "loading" : geolocation.failures[ip] != nil ? "failed" : "unqueried", error: geolocation.failures[ip])
            }
        }
        value.artifacts = artifacts; value.readTaskIDs = Array(readTaskIDs); value.continuityNotice = continuityNotice
        return value
    }
}
