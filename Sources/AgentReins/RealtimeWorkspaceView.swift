import CryptoKit
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
            if action == "refreshCollected" {
                detailRequestGeneration += 1; deliveredCollected = [:]
                if let view = message.webView { publish(view) }; return
            }
            if action == "refreshArtifacts" { onRefreshArtifacts?(); return }
            guard let taskID = body["taskID"] as? String, latest.tasks.contains(where: { $0.id == taskID }) else { return }
            if action == "selectTask" { detailRequestGeneration += 1; deliveredTaskRevision = nil; deliveredDetail = nil; selectedTaskID = taskID; if let view = message.webView { publish(view) }; return }
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
        private var detailRequestGeneration = 0
        private var deliveredCollected: [String: String] = [:]
        private var deliveredDetail: RealtimeWorkspaceTransport.TaskDetail?
        private var deliveredPublication: RealtimeWorkspaceTransport.PublicationKey?
        private var deliveredGeneration = -1
        private var deliveredTaskRevision: String?
        private var selectedTaskID: String?
        var latest: RealtimeWorkspacePayload?
        var ready = false
        private var sending = false
        private var dirty = false
        private var publishScheduled = false
        private var lastPublish = Date.distantPast
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { ready = true; detailRequestGeneration += 1; deliveredCollected = [:]; deliveredTaskRevision = nil; deliveredDetail = nil; publish(webView) }
        private let encodingQueue = DispatchQueue(label: "com.agentreins.live-encoding", qos: .utility)
        // Explicit development preview only. The browser consumes this same
        // native projection; it must not keep displaying a fixed test snapshot.
        private let previewPayloadURL: URL? = {
            let arguments = ProcessInfo.processInfo.arguments
            guard let flag = arguments.firstIndex(of: "--realtime-preview-payload"), arguments.indices.contains(flag + 1),
                  arguments[flag + 1].hasPrefix("/") else { return nil }
            return URL(fileURLWithPath: arguments[flag + 1])
        }()
        // Accessed only on encodingQueue. Old task bodies are exported once per
        // source revision, so localhost detail reads never scan the evidence DB.
        private var exportedTasks: [String: String] = [:]
        func publish(_ webView: WKWebView) {
            guard ready else { return }
            let delay = 1 - Date().timeIntervalSince(lastPublish)
            if delay > 0 {
                guard !publishScheduled else { return }
                publishScheduled = true
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self, weak webView] in
                    guard let self, let webView else { return }
                    self.publishScheduled = false; self.publish(webView)
                }
                return
            }
            guard !sending else { dirty = true; return }
            guard let latest else { return }
            let publication = RealtimeWorkspaceTransport.publicationKey(latest)
            guard publication != deliveredPublication || detailRequestGeneration != deliveredGeneration else { return }
            sending = true; lastPublish = Date()
            let previewURL = previewPayloadURL, selectedID = selectedTaskID
            let chosenID = RealtimeWorkspaceTransport.selectedID(latest, requested: selectedID)
            let chosen = latest.tasks.first { $0.id == chosenID }
            let signature = chosen.map { $0.id + "\u{0}" + $0.projectionRevision }
            let knownDetail = deliveredDetail
            let nextDetail = chosen.map { RealtimeWorkspaceTransport.TaskDetail(task: $0, contexts: RealtimeWorkspaceTransport.contexts(latest, task: $0)) }
            let knownCollected = deliveredCollected
            let collectedVersions = Dictionary(latest.collected.map { ($0.id, $0.revision) }, uniquingKeysWith: { _, new in new })
            let requestGeneration = detailRequestGeneration
            let reuseDetails = signature != nil && signature == deliveredTaskRevision
            encodingQueue.async { [weak self, weak webView] in
                let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
                let transport = RealtimeWorkspaceTransport.project(latest, selectedTaskID: selectedID, omitSelectedDetails: reuseDetails, knownCollected: knownCollected, knownDetail: knownDetail)
                let data = try? encoder.encode(transport)
                if let previewURL, let data {
                    do {
                        try FileManager.default.createDirectory(at: previewURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                        let directory = previewURL.deletingLastPathComponent().appendingPathComponent("tasks")
                        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                        for task in latest.tasks {
                            // Task revision already includes parsed-context invalidation.
                            // Do not serialize every old context just to discover it is unchanged.
                            let signature = task.projectionRevision
                            guard self?.exportedTasks[task.id] != signature else { continue }
                            let name = SHA256.hash(data: Data(task.id.utf8)).map { String(format: "%02x", $0) }.joined() + ".json"
                            let file = directory.appendingPathComponent(name)
                            let contexts = RealtimeWorkspaceTransport.contexts(latest, task: task)
                            let detail = RealtimeWorkspaceTransport.TaskDetail(task: task, contexts: contexts)
                            try encoder.encode(detail).write(to: file, options: [.atomic])
                            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                            self?.exportedTasks[task.id] = signature
                        }
                        let previewData = (reuseDetails || knownDetail != nil || !knownCollected.isEmpty) ? try encoder.encode(RealtimeWorkspaceTransport.project(latest, selectedTaskID: selectedID)) : data
                        try previewData.write(to: previewURL, options: [.atomic])
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: previewURL.path)
                    } catch { NSLog("Realtime preview export failed: %@", String(describing: error)) }
                }
                let json = data.flatMap { String(data: $0, encoding: .utf8) }
                DispatchQueue.main.async {
                    guard let self, let webView else { return }
                    Task { @MainActor in
                        if let json {
                            // Structured arguments prevent evidence from becoming code.
                            do { _ = try await webView.callAsyncJavaScript("window.agentreinsReceive(JSON.parse(payload))", arguments: ["payload": json], in: nil, contentWorld: .page); if self.detailRequestGeneration == requestGeneration { self.deliveredPublication = publication; self.deliveredGeneration = requestGeneration; self.deliveredTaskRevision = signature; self.deliveredDetail = nextDetail; self.deliveredCollected = collectedVersions } }
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
    private var evidence = RealtimeLiveEvidenceBuffer()
    private let coolingQueue = DispatchQueue(label: "com.agentreins.live-evidence-cache", qos: .utility)
    private var coolingInFlight = false
    private var evidenceError: String?
    private var checkpointError: String?
    private var pendingContextEvents: [UUID: GuardEvent] = [:]
    private func allEvidence() -> [GuardEvent] {
        do { return try evidence.snapshot().read() }
        catch { evidenceError = "实时证据读取失败：\(error.localizedDescription)"; return [] }
    }
    private func scheduleCooling() {
        guard !coolingInFlight else { return }
        let plan = evidence.coolingPlan(byteBudget: byteBudget)
        guard !plan.records.isEmpty else { return }
        coolingInFlight = true
        coolingQueue.async { [weak self] in
            do {
                let cooled = try plan.records.map { try $0.cooled(in: plan.directory) }
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.evidence.install(cooled); self.coolingInFlight = false
                    if self.evidenceError != nil { self.evidenceError = nil; self.revision += 1 }; self.scheduleCooling()
                }
            } catch {
                DispatchQueue.main.async {
                    guard let self else { return }
                    // Keep the original in RAM on write failure; never drop it.
                    self.coolingInFlight = false
                    self.evidenceError = "实时证据转存失败，原文仍保留在内存：\(error.localizedDescription)"
                    self.revision += 1
                }
            }
        }
    }
    private let contextQueue = DispatchQueue(label: "com.agentreins.context-presentation", qos: .utility)
    private var parsedContexts: [UUID: RealtimeContextExchange] = [:]
    private var parsingContexts = Set<UUID>()
    private var contextInputs: [UUID: Int] = [:]
    private var registry = CollectionProcessRegistry()
    private var lastProcessSnapshot: [ProcessSnapshotRecord]?
    private let backgroundProjection: Bool
    private let projectionQueue = DispatchQueue(label: "com.agentreins.live-presentation", qos: .userInitiated)
    private let projectionCache = RealtimeProjectionCache()
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
            cachedTasks = RealtimeWorkspaceProjector.tasks(events: allEvidence(), since: since)
            tasksDirty = false; taskProjectionBuilds += 1
        }
        return cachedTasks
    }
    private func projectedContexts() -> [RealtimeContextExchange] {
        if backgroundProjection { scheduleLiveProjection(); return cachedContexts }
        if contextsDirty {
            cachedContexts = RealtimeContextProjector.assemble(Array(parsedContexts.values), events: allEvidence())
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
        self.checkpointWriter = checkpointURL.map { RealtimeActiveCheckpoint.Writer(url: $0, useDatabase: backgroundProjection) }
        terminationObserver = NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.flushCheckpoint() }
        }
        if let checkpointURL {
            do {
                if let checkpoint = try RealtimeActiveCheckpoint.load(checkpointURL) {
                    for event in checkpoint.events {
                        evidence.insert(event); restoredIDs.insert(event.id)
                        if event.kind == "model", event.model != "codex-auto-review", event.modelPrompt != nil, ["prompt", "network_prompt"].contains(event.op) { pendingContextEvents[event.id] = event }
                    }
                    readTaskIDs = Set(checkpoint.readTaskIDs)
                    truncated = checkpoint.coverageTruncated
                    since = min(since, checkpoint.events.map(\.ts).min() ?? since)
                    if !checkpoint.events.isEmpty {
                        continuityNotice = "已恢复本机已采活跃任务；\(checkpoint.savedAt.formatted()) 至本次启动之间的来源缺口需核对"
                    }
                }
            } catch {
                continuityNotice = "活跃任务检查点无法恢复：\(error.localizedDescription)"
                if FileManager.default.fileExists(atPath: RealtimeCheckpointDatabase.location(for: checkpointURL).path) {
                    checkpointWriter = nil
                    checkpointError = "实时恢复数据库读取失败，原数据库已保留；自动覆盖已停止"
                }
                // Preserve the original manifest at its original body location;
                // subsequent input must not destroy a recoverable broken index.
                let backup = checkpointURL.appendingPathExtension("unreadable-" + UUID().uuidString + ".backup")
                do {
                    try FileManager.default.copyItem(at: checkpointURL, to: backup)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
                    continuityNotice! += "；原索引已保留备份，缺失正文修复后可恢复"
                } catch {
                    checkpointWriter = nil
                    checkpointError = "无法备份损坏的恢复索引；已暂停覆盖写入以保留原数据"
                }
            }
        }
        scheduleCooling()
        scheduleContextParsing()
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
    private var checkpointWriter: RealtimeActiveCheckpoint.Writer?
    private let checkpointQueue = DispatchQueue(label: "com.agentreins.active-checkpoint", qos: .utility)
    private var checkpointWork: DispatchWorkItem?
    private var checkpointGeneration = 0
    private var checkpointWorkID: UUID?
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
        let values = allEvidence()
        let tasks = projectedTasks()
        let candidates = RealtimeArtifactProjector.candidates(events: values, tasks: tasks)
        guard candidates != artifactCandidates else { return }
        artifactCandidates = candidates; refreshArtifacts()
    }
    nonisolated private static func checkpointRecords(_ snapshot: RealtimeLiveEvidenceBuffer.Snapshot, tasks: [RealtimeTask], readTaskIDs: Set<String>) -> [RealtimeLiveEvidenceBuffer.Record] {
        let dismissed = tasks.filter { ["completed", "failed", "cancelled", "stopped"].contains($0.lifecycleStatus) && readTaskIDs.contains($0.id) }
        let dismissedKeys = Set(dismissed.map { $0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn })
        let dismissedIDs = Set(dismissed.flatMap { $0.cards.flatMap(\.eventIDs) + [$0.requestEventID, $0.nativeTerminalEventID].compactMap { $0 } })
        let networkIDs = Set(snapshot.records.filter { $0.kind == "network" }.sorted { $0.ts > $1.ts }.prefix(100).map(\.id))
        // Agent names repeat across the entire history; normalize each distinct
        // name once rather than running Unicode searches for every record.
        var agents: [String: String] = [:]
        var unknownAgents = Set<String>()
        return snapshot.records.filter { record in
            if networkIDs.contains(record.id) { return true }
            guard record.model != "codex-auto-review", record.toolName != "codex.internal_review_context",
                  !dismissedIDs.contains(record.id.uuidString),
                  let session = record.session, let rawAgent = record.agent else { return false }
            guard !unknownAgents.contains(rawAgent) else { return false }
            let agent: String
            if let cached = agents[rawAgent] { agent = cached }
            else if let canonical = RealtimeWorkspaceProjector.canonicalAgent(rawAgent) {
                agents[rawAgent] = canonical; agent = canonical
            } else { unknownAgents.insert(rawAgent); return false }
            // Include newly observed turns even before their first UI projection.
            return !dismissedKeys.contains(agent + "\u{0}" + session + "\u{0}" + (record.turn ?? ""))
        }
    }
    func flushCheckpoint() {
        guard let checkpointWriter else { return }
        checkpointWork?.cancel(); checkpointWork = nil; checkpointWorkID = nil
        checkpointGeneration += 1
        checkpointQueue.sync {}
        do {
            let tasks = projectedTasks(force: true)
            let records = Self.checkpointRecords(evidence.snapshot(), tasks: tasks, readTaskIDs: readTaskIDs)
            _ = try checkpointWriter.save(records: records, readTaskIDs: Array(readTaskIDs), coverageTruncated: truncated)
            checkpointError = nil
        } catch { checkpointError = "退出时活跃任务保存失败：\(error.localizedDescription)" }
        revision += 1
    }
    private func scheduleCheckpoint() {
        guard let checkpointWriter else { return }
        checkpointGeneration += 1
        guard checkpointWork == nil else { return }
        let generation = checkpointGeneration, workID = UUID()
        checkpointWorkID = workID
        let snapshot = evidence.snapshot(), tasks = projectedTasks()
        let readIDs = readTaskIDs, coverage = truncated
        let work = DispatchWorkItem { [weak self] in
            var failure: String?
            do {
                let records = Self.checkpointRecords(snapshot, tasks: tasks, readTaskIDs: readIDs)
                _ = try checkpointWriter.save(records: records, readTaskIDs: Array(readIDs), coverageTruncated: coverage)
            } catch { failure = "活跃任务检查点保存失败：\(error.localizedDescription)；重启连续性未保证" }
            DispatchQueue.main.async {
                guard let self else { return }
                // A late result must not erase a newer shutdown/flush failure.
                guard self.checkpointWorkID == workID else { return }
                self.checkpointWork = nil; self.checkpointWorkID = nil
                if self.checkpointError != failure { self.checkpointError = failure; self.revision += 1 }
                if self.checkpointGeneration != generation { self.scheduleCheckpoint() }
            }
        }
        checkpointWork = work
        checkpointQueue.asyncAfter(deadline: .now() + .seconds(3), execute: work)
    }
    func ingest(_ events: [GuardEvent]) {
        var changed = false, projectionChanged = false
        for event in events where event.ts >= runtimeStartedAt || restoredIDs.contains(event.id) {
            // Startup EventStore replay can contain the old database projection
            // of this same source ID. It must not overwrite a newer repaired
            // live checkpoint. Fresh source observations still update normally.
            if restoredIDs.contains(event.id), event.ts < runtimeStartedAt, evidence.contains(event.id) { continue }
            if evidence.unchanged(event) { continue }
            changed = true
            if evidence.hasTaskAssociation(event.id) || (event.sessionId != nil && RealtimeWorkspaceProjector.canonicalAgent(event.agent) != nil) { projectionChanged = true }
            collectedByID.removeValue(forKey: event.id)
            evidence.insert(event)
            if event.kind == "model", event.model != "codex-auto-review", event.modelPrompt != nil, ["prompt", "network_prompt"].contains(event.op) { pendingContextEvents[event.id] = event }
        }
        // The byte/count budget bounds only the hot cache. No original request,
        // call boundary, result, or task identity is evicted to meet it.
        if changed { scheduleCooling(); collectedDirty = true }
        if projectionChanged { tasksDirty = true; contextsDirty = true; projectionGeneration += 1 }
        scheduleContextParsing()
        if changed { scheduleArtifacts(); scheduleCheckpoint(); revision += 1 }
    }
    private func scheduleContextParsing() {
        for event in Array(pendingContextEvents.values) where event.kind == "model" && event.model != "codex-auto-review" && ["prompt", "network_prompt"].contains(event.op) {
            guard event.modelPrompt != nil, !parsingContexts.contains(event.id) else { continue }
            let bodyDigest = event.hashValue
            guard contextInputs[event.id] != bodyDigest else { pendingContextEvents.removeValue(forKey: event.id); continue }
            parsingContexts.insert(event.id)
            contextQueue.async { [weak self] in
                let parsed = RealtimeContextProjector.parse(event)
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.parsingContexts.remove(event.id)
                    guard self.pendingContextEvents[event.id]?.hashValue == bodyDigest else {
                        self.scheduleContextParsing(); return
                    }
                    self.pendingContextEvents.removeValue(forKey: event.id)
                    self.contextInputs[event.id] = bodyDigest
                    self.parsedContexts[event.id] = parsed
                    self.contextsDirty = true; self.projectionGeneration += 1
                    self.scheduleLiveProjection()
                    self.revision += 1
                }
            }
        }
    }
    private func scheduleLiveProjection() {
        guard backgroundProjection, (tasksDirty || contextsDirty), !projectionInFlight else { return }
        projectionInFlight = true
        let generation = projectionGeneration, snapshot = evidence.snapshot(), since = since
        let contexts = Array(parsedContexts.values), cache = projectionCache, versions = contextInputs
        projectionQueue.async { [weak self] in
            let result: (tasks: [RealtimeTask], contexts: [RealtimeContextExchange], candidates: [RealtimeArtifactProjector.Candidate])
            do { result = try cache.project(snapshot, contexts: contexts, contextVersions: versions, since: since) }
            catch {
                DispatchQueue.main.async {
                    self?.projectionInFlight = false
                    self?.evidenceError = "实时证据读取失败：\(error.localizedDescription)"
                    self?.revision += 1
                }
                return
            }
            let tasks = result.tasks, exchanges = result.contexts, candidates = result.candidates
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
    private(set) var collectedBodyReads = 0
    private func projectedCollected() -> [RealtimeCollectedRecord] {
        guard collectedDirty else { return cachedCollected }
        let visible = evidence.latestCollected().records
        var nextByID: [UUID: RealtimeCollectedRecord] = [:]
        do {
            let rows = try visible.map { record -> RealtimeCollectedRecord in
                if let cached = collectedByID[record.id], cached.revision == record.revision.uuidString {
                    nextByID[record.id] = cached; return cached
                }
                let event = try record.read()
                collectedBodyReads += 1
                let display = CollectionRecordPresentation(event, receivedAt: event.ts)
                var row = RealtimeCollectedRecord(id: event.id.uuidString, agent: RealtimeWorkspaceProjector.canonicalAgent(event.agent) ?? "归属未确认", source: event.source ?? "来源未知",
                    kind: event.kind, op: event.op, summary: display.summary, preview: String(display.preview.prefix(16000)),
                    hasTaskIdentity: event.sessionId != nil && event.turnId != nil,
                    title: display.title, category: display.category, details: (display.details + ["路径：\(event.path)", "会话：\(event.sessionId ?? "未关联")", "轮次：\(event.turnId ?? "未关联")"]).joined(separator: "\n"), pid: event.processId,
                    session: event.sessionId, turn: event.turnId, call: event.toolCallId, timestamp: event.ts,
                    resource: event.kind == "network" ? RealtimeDetailProjector.resource(event:event,input:event.command,output:event.modelResponse,kind:"network") : nil)
                row.revision = record.revision.uuidString
                nextByID[event.id] = row; return row
            }
            cachedCollected = rows; collectedByID = nextByID
        } catch {
            evidenceError = "实时证据读取失败：\(error.localizedDescription)"; return cachedCollected
        }
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
    private var deliveryCacheVersion = -1
    private var deliveryCacheArtifacts: [RealtimeArtifact] = []
    private var deliveryCache: [RealtimeTask] = []
    private var addressCache: [String] = []
    func payload(processes: [ProcessSnapshotRecord], health: [CollectorHealthRecord], observing: Bool, error: String?, geolocation: IPGeolocationStore? = nil) -> RealtimeWorkspacePayload {
        let tasks = projectedTasks()
        if deliveryCacheVersion != taskProjectionBuilds || deliveryCacheArtifacts != artifacts {
            deliveryCache = RealtimeWorkspaceProjector.assessingDelivery(tasks, artifacts: artifacts)
            addressCache = Set(tasks.flatMap { $0.cards.flatMap { card in
                ([card.resource?.remoteIP].compactMap { $0 } + (card.resource?.addresses ?? []))
            } }.filter(IPGeolocationStore.isPublicIPAddress)).sorted()
            deliveryCacheVersion = taskProjectionBuilds; deliveryCacheArtifacts = artifacts
        }
        var value = RealtimeWorkspacePayload(tasks: deliveryCache,
            collected: projectedCollected(), unattributedCount: evidence.unattributedCount,
            processes: projectedProcesses(processes), health: health.map { RealtimeHealth(source: $0.source, state: $0.state.rawValue, accepted: $0.accepted, detail: $0.detail) },
            observing: observing, persistenceError: error, publishedAt: Date(), truncated: truncated, collectedCount: evidence.count, contexts: projectedContexts())
        if let geolocation {
            value.ipGeolocations = addressCache.map { ip in
                let record = geolocation.records[ip]
                return RealtimeIPLocation(ip: ip, location: record?.locationLabel, owner: record?.ownerLabel, source: "ipwho.is", updatedAt: record?.fetchedAt,
                    state: record != nil ? "ready" : geolocation.pending.contains(ip) ? "loading" : geolocation.failures[ip] != nil ? "failed" : "unqueried", error: geolocation.failures[ip])
            }
        }
        value.artifacts = artifacts; value.readTaskIDs = Array(readTaskIDs)
        let notices = [continuityNotice, evidenceError, checkpointError].compactMap { $0 }
        value.continuityNotice = notices.isEmpty ? nil : notices.joined(separator: " · ")
        return value
    }
}
