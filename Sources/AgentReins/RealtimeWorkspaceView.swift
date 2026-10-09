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
        private let encodingQueue = DispatchQueue(label: "com.agentreins.live-encoding", qos: .utility)
        // Explicit development preview only. The browser consumes this same
        // native projection; it must not keep displaying a fixed test snapshot.
        private let previewPayloadURL: URL? = {
            let arguments = ProcessInfo.processInfo.arguments
            guard let flag = arguments.firstIndex(of: "--realtime-preview-payload"), arguments.indices.contains(flag + 1),
                  arguments[flag + 1].hasPrefix("/") else { return nil }
            return URL(fileURLWithPath: arguments[flag + 1])
        }()
        func publish(_ webView: WKWebView) {
            guard ready else { return }
            guard !sending else { dirty = true; return }
            guard let latest else { return }
            sending = true
            let previewURL = previewPayloadURL
            encodingQueue.async { [weak self, weak webView] in
                let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
                let data = try? encoder.encode(latest)
                if let previewURL, let data {
                    do {
                        try FileManager.default.createDirectory(at: previewURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                        try data.write(to: previewURL, options: [.atomic])
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: previewURL.path)
                    } catch { NSLog("Realtime preview export failed: %@", String(describing: error)) }
                }
                let json = data.flatMap { String(data: $0, encoding: .utf8) }
                DispatchQueue.main.async {
                    guard let self, let webView else { return }
                    Task { @MainActor in
                        if let json {
                            // Structured arguments prevent evidence from becoming code.
                            do { _ = try await webView.callAsyncJavaScript("window.agentreinsReceive(JSON.parse(payload))", arguments: ["payload": json], in: nil, contentWorld: .page) }
                            catch { NSLog("Realtime workspace delivery failed: %@", String(describing: error)) }
                        }
                        self.sending = false
                        if self.dirty {
                            self.dirty = false
                            DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(250)) { [weak self, weak webView] in
                                if let webView { self?.publish(webView) }
                            }
                        }
                    }
                }
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
    private var lastProcessSnapshot: [ProcessSnapshotRecord]?
    private let backgroundProjection: Bool
    private let projectionQueue = DispatchQueue(label: "com.agentreins.live-presentation", qos: .userInitiated)
    private var projectionInFlight = false
    private var projectionGeneration = 0
    private var tasksDirty = true, contextsDirty = true
    private var cachedTasks: [RealtimeTask] = []
    private var cachedContexts: [RealtimeContextExchange] = []
    private var collectedDirty = true
    private var cachedCollected: [RealtimeCollectedRecord] = []
    private var collectedByID: [UUID: RealtimeCollectedRecord] = [:]
    private var projectedProcessInput: [ProcessSnapshotRecord]?
    private var cachedProcesses: [RealtimeProcess] = []
    private(set) var taskProjectionBuilds = 0
    private(set) var contextProjectionBuilds = 0
    private func projectedTasks(force: Bool = false) -> [RealtimeTask] {
        if backgroundProjection && !force { scheduleLiveProjection(); return cachedTasks }
        if tasksDirty {
            cachedTasks = RealtimeWorkspaceProjector.tasks(events: Array(evidence.values), since: since)
            tasksDirty = false; taskProjectionBuilds += 1
        }
        return cachedTasks
    }
    private func projectedContexts() -> [RealtimeContextExchange] {
        if backgroundProjection { scheduleLiveProjection(); return cachedContexts }
        if contextsDirty {
            cachedContexts = RealtimeContextProjector.assemble(Array(parsedContexts.values), events: Array(evidence.values))
            contextsDirty = false; contextProjectionBuilds += 1
        }
        return cachedContexts
    }
    func updateProcesses(_ processes: [ProcessSnapshotRecord]) {
        guard lastProcessSnapshot != processes else { return }
        lastProcessSnapshot = processes; registry.update(processes, now: Date()); projectedProcessInput = nil; revision += 1
    }
    private let byteBudget: Int
    init(byteBudget: Int = 32 * 1024 * 1024, checkpointURL: URL? = nil, backgroundProjection: Bool = false) {
        self.backgroundProjection = backgroundProjection
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
        guard projectedTasks().contains(where: { $0.id == taskID }) else { return }
        readTaskIDs.insert(taskID); revision += 1; scheduleCheckpoint()
    }
    func refreshArtifacts() {
        artifactGeneration += 1
        let generation = artifactGeneration, candidates = artifactCandidates
        artifactQueue.async { [weak self] in
            let values = RealtimeArtifactProjector.probe(candidates)
            DispatchQueue.main.async {
                guard let self, self.artifactGeneration == generation else { return }
                if self.artifacts != values { self.artifacts = values; self.revision += 1 }
            }
        }
    }
    private func scheduleArtifacts() {
        if backgroundProjection { scheduleLiveProjection(); return }
        let values = Array(evidence.values)
        let tasks = projectedTasks()
        let candidates = RealtimeArtifactProjector.candidates(events: values, tasks: tasks)
        guard candidates != artifactCandidates else { return }
        artifactCandidates = candidates; refreshArtifacts()
    }
    func flushCheckpoint() {
        guard let checkpointURL else { return }
        checkpointWork?.cancel(); checkpointWork = nil
        checkpointQueue.sync {} // Finish any previous atomic save before the shutdown snapshot.
        let values = Array(evidence.values)
        let tasks = projectedTasks(force: true)
        let active = tasks.filter { retainForRestart($0) }
        let keys = Set(active.map { $0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn })
        let networkIDs = Set(values.filter { $0.kind == "network" }.sorted { $0.ts > $1.ts }.prefix(100).map { $0.id.uuidString })
        let linked = Set(active.flatMap { $0.cards.flatMap(\.eventIDs) + [$0.requestEventID, $0.nativeTerminalEventID].compactMap { $0 } }).union(networkIDs)
        let events = values.filter { e in
            if linked.contains(e.id.uuidString) { return true }
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
        let tasks = projectedTasks()
        let activeTasks = tasks.filter { retainForRestart($0) }
        let activeKeys = Set(activeTasks.map { $0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn })
        let networkIDs = Set(values.filter { $0.kind == "network" }.sorted { $0.ts > $1.ts }.prefix(100).map { $0.id.uuidString })
        let linkedIDs = Set(activeTasks.flatMap { $0.cards.flatMap(\.eventIDs) + [$0.requestEventID, $0.nativeTerminalEventID].compactMap { $0 } }).union(networkIDs)
        let active = values.filter { e in
            if linkedIDs.contains(e.id.uuidString) { return true }
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
            // Startup EventStore replay can contain the old database projection
            // of this same source ID. It must not overwrite a newer repaired
            // live checkpoint. Fresh source observations still update normally.
            if restoredIDs.contains(event.id), event.ts < runtimeStartedAt, evidence[event.id] != nil { continue }
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
            collectedByID.removeValue(forKey: event.id)
            let size = Self.eventSize(event)
            retainedBytes += size - (sizes[event.id] ?? 0)
            sizes[event.id] = size; evidence[event.id] = event
        }
        // Preserve small original-request records and currently active call
        // boundaries ahead of bulky model/output previews under pressure.
        if evidence.count > 6000 || retainedBytes > byteBudget {
            func internalReview(_ e: GuardEvent) -> Bool { e.model == "codex-auto-review" || e.toolName == "codex.internal_review_context" }
            let finalMessages = Set(evidence.values.filter { $0.op == "hook_turn_stop" }.compactMap { e -> String? in
                guard let final = (RealtimeDetailProjector.object(e.afterContent)?["payload"] as? [String: Any])?["last_assistant_message"] as? String else { return nil }
                return (e.sessionId ?? "") + "\u{0}" + final
            })
            let protected = Set(evidence.values.filter { e in
                !internalReview(e) && Self.eventSize(e) <= byteBudget / 2 &&
                (e.kind == "network" || ["prompt", "hook_user_prompt", "call", "hook_tool_start", "result", "hook_tool_end", "task_complete", "task_completed", "task_failed", "turn_completed", "task_cancelled", "hook_turn_stop"].contains(e.op) ||
                 (e.op == "response" && e.modelResponse.map { finalMessages.contains((e.sessionId ?? "") + "\u{0}" + $0) } == true))
            }.map(\.id))
            for event in evidence.values.sorted(by: { a, b in
                if internalReview(a) != internalReview(b) { return internalReview(a) }
                if protected.contains(a.id) != protected.contains(b.id) { return !protected.contains(a.id) }
                return a.ts < b.ts
            }) {
                guard evidence.count > 6000 || retainedBytes > byteBudget else { break }
                retainedBytes -= sizes.removeValue(forKey: event.id) ?? 0
                evidence.removeValue(forKey: event.id); truncated = true
            }
        }
        if changed { tasksDirty = true; contextsDirty = true; collectedDirty = true; projectionGeneration += 1 }
        parsedContexts = parsedContexts.filter { evidence[$0.key] != nil }
        contextInputs = contextInputs.filter { evidence[$0.key] != nil }
        for event in evidence.values where event.kind == "model" && event.model != "codex-auto-review" && ["prompt", "network_prompt"].contains(event.op) {
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
                    self.contextsDirty = true; self.projectionGeneration += 1
                    self.scheduleLiveProjection()
                    self.revision += 1
                }
            }
        }
        if changed { scheduleArtifacts(); scheduleCheckpoint(); revision += 1 }
    }
    private func retainForRestart(_ task: RealtimeTask) -> Bool {
        // Internal approval reviews are not unread user tasks. Their original
        // collector evidence remains in the evidence store and current live view.
        guard task.model != "codex-auto-review", !task.cards.contains(where: { $0.title == "codex.internal_review_context" }) else { return false }
        return !["completed", "failed", "cancelled", "stopped"].contains(task.lifecycleStatus) || !readTaskIDs.contains(task.id)
    }
    private func scheduleLiveProjection() {
        guard backgroundProjection, (tasksDirty || contextsDirty), !projectionInFlight else { return }
        projectionInFlight = true
        let generation = projectionGeneration, values = Array(evidence.values), since = since
        let contexts = Array(parsedContexts.values)
        projectionQueue.async { [weak self] in
            let tasks = RealtimeWorkspaceProjector.tasks(events: values, since: since)
            let exchanges = RealtimeContextProjector.assemble(contexts, events: values)
            let candidates = RealtimeArtifactProjector.candidates(events: values, tasks: tasks)
            DispatchQueue.main.async {
                guard let self else { return }
                self.projectionInFlight = false
                // Publish coherent snapshots in worker order, then catch up with
                // newer input. Never starve the UI while evidence keeps arriving.
                self.cachedTasks = tasks; self.cachedContexts = exchanges
                self.taskProjectionBuilds += 1; self.contextProjectionBuilds += 1
                if generation == self.projectionGeneration { self.tasksDirty = false; self.contextsDirty = false }
                if self.artifactCandidates != candidates { self.artifactCandidates = candidates; self.refreshArtifacts() }
                self.revision += 1; self.scheduleCheckpoint(); self.scheduleLiveProjection()
            }
        }
    }
    private func projectedCollected() -> [RealtimeCollectedRecord] {
        guard collectedDirty else { return cachedCollected }
        let ordered = evidence.values.sorted { $0.ts > $1.ts }
        var seen = Set<UUID>()
        let visible = (Array(ordered.prefix(200)) + Array(ordered.filter { $0.kind == "network" }.prefix(100)))
            .filter { seen.insert($0.id).inserted }.sorted { $0.ts > $1.ts }
        cachedCollected = visible.map { event in
                if let cached = collectedByID[event.id] { return cached }
            let display = CollectionRecordPresentation(event, receivedAt: event.ts)
                let row = RealtimeCollectedRecord(id: event.id.uuidString, agent: RealtimeWorkspaceProjector.canonicalAgent(event.agent) ?? "归属未确认", source: event.source ?? "来源未知",
                    kind: event.kind, op: event.op, summary: display.summary, preview: String(display.preview.prefix(16000)),
                    hasTaskIdentity: event.sessionId != nil && event.turnId != nil,
                    title: display.title, category: display.category, details: (display.details + ["路径：\(event.path)", "会话：\(event.sessionId ?? "未关联")", "轮次：\(event.turnId ?? "未关联")"]).joined(separator: "\n"), pid: event.processId,
                    session: event.sessionId, turn: event.turnId, call: event.toolCallId, timestamp: event.ts,
                    resource: event.kind == "network" ? RealtimeDetailProjector.resource(event:event,input:event.command,output:event.modelResponse,kind:"network") : nil)
                collectedByID[event.id] = row; return row
            }
        let kept = Set(cachedCollected.map(\.id))
        collectedByID = collectedByID.filter { kept.contains($0.key.uuidString) }
        collectedDirty = false
        return cachedCollected
    }
    private func projectedProcesses(_ processes: [ProcessSnapshotRecord]) -> [RealtimeProcess] {
        guard projectedProcessInput != processes else { return cachedProcesses }
        cachedProcesses = registry.ordered.map { row in
                let process = row.node.process
                return RealtimeProcess(id: row.node.id, pid: process.pid, parent: process.ppid,
                    agent: "WorkBuddy", name: row.node.role.title,
                    executable: process.executablePath ?? "未采集", command: ProcessArgumentRedactor.redact(process.command), active: row.node.active, depth: row.depth)
            } + processes.compactMap { process in
                guard let agent = RealtimeWorkspaceProjector.canonicalAgent(process.agent), agent != "WorkBuddy" || registry.nodes.isEmpty else { return nil }
                return RealtimeProcess(id: ProcessObservationCoordinator.identity(process), pid: process.pid, parent: process.ppid,
                    agent: agent, name: CollectionProcessNode(process: process, firstSeen: since, lastSeen: Date(), active: true).role.title,
                    executable: process.executablePath ?? "未采集", command: ProcessArgumentRedactor.redact(process.command))
            }
        projectedProcessInput = processes
        return cachedProcesses
    }
    func payload(processes: [ProcessSnapshotRecord], health: [CollectorHealthRecord], observing: Bool, error: String?, geolocation: IPGeolocationStore? = nil) -> RealtimeWorkspacePayload {
        var value = RealtimeWorkspacePayload(tasks: RealtimeWorkspaceProjector.assessingDelivery(projectedTasks(), artifacts: artifacts),
            collected: projectedCollected(), unattributedCount: evidence.values.filter { $0.sessionId == nil || $0.turnId == nil }.count,
            processes: projectedProcesses(processes), health: health.map { RealtimeHealth(source: $0.source, state: $0.state.rawValue, accepted: $0.accepted, detail: $0.detail) },
            observing: observing, persistenceError: error, publishedAt: Date(), truncated: truncated, collectedCount: evidence.count, contexts: projectedContexts())
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
