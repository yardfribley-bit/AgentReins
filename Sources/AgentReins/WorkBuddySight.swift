import Foundation
import SwiftUI
import CryptoKit
import Darwin

/// AgentSight 的 WorkBuddy-native 数据源：读取本地会话事件并投影成统一 GuardEvent。
/// macOS 无 eBPF record，因此这里使用 AgentSight 推荐的 agent-native session fallback。
@MainActor
final class WorkBuddySight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?
    var onHookSignals: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var watchers: [String: DispatchSourceFileSystemObject] = [:]
    private var watchOrder: [String] = []
    private var debounce: DispatchWorkItem?
    private var pendingTargets = Set<URL>()
    private var pendingWakeup = false
    private let hookRoot: URL
    private var seen = Set<UUID>()
    private var startupID: UUID?
    private var realtimeSince: Date?
    private var lastPoll = Date.distantPast
    private var fileSizes: [String: UInt64] = [:]
    struct ParserState: Codable {
        var offset: UInt64 = 0
        var fingerprint: String? = nil
        var lastIntent: [String: String] = [:]
        var lastReasoning: [String: String] = [:]
        var currentTurn: [String: String] = [:]
        var toolNames: [String: String] = [:]
        var lastModelEndpoint: [String: String] = [:]
        var callTurns: [String: String]? = nil
        var turnIntents: [String: String]? = nil
    }
    private var parserStates: [String: ParserState] = [:]
    private var isPolling = false
    private let evidenceDatabase: EvidenceDatabase?
    private let rootURL: URL

    init(rootURL: URL? = nil, database: EvidenceDatabase? = nil, hookRoot: URL? = nil) {
        self.rootURL = rootURL ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".workbuddy/projects")
        self.evidenceDatabase = database ?? (try? EvidenceDatabase.shared())
        self.hookRoot = hookRoot ?? WorkBuddyHookInbox.defaultURL
    }
    private var lastHealthPersist = Date.distantPast
    private var acceptedEvents = 0
    private var collectionFailures = 0
    private var malformedRows = 0
    private var partialRows = 0
    private let queue = DispatchQueue(label: "com.agentspec.workbuddysight", qos: .utility)

    func start(realtimeOnly: Bool = false) {
        guard timer == nil, startupID == nil else { return }
        if realtimeOnly {
            realtimeSince = Date()
            let id = UUID()
            startupID = id
            let root = rootURL, database = evidenceDatabase, startedAt = realtimeSince!
            queue.async { [weak self] in
                let offsets = RealtimeLogBaseline.offsets(root: root)
                let saved = (try? database?.parserStates(source: "workbuddy-live")) ?? [:]
                let marker = root.path + "/.agentreins-activation"
                let since = saved[marker].flatMap { try? JSONDecoder().decode(Date.self, from: $0) } ?? startedAt
                var states = offsets.mapValues { size in var state = ParserState(); state.offset = size; return state }
                for (path, size) in offsets {
                    let identity = Self.fileIdentity(URL(fileURLWithPath: path))
                    if let data = saved[path], let state = try? JSONDecoder().decode(ParserState.self, from: data),
                       state.offset <= size, state.fingerprint == identity, identity != nil { states[path] = state }
                    states[path]?.fingerprint = identity
                }
                do {
                    guard let database else { throw CocoaError(.fileWriteUnknown) }
                    var durable = try states.map { (source: "workbuddy-live", stream: $0.key, state: try JSONEncoder().encode($0.value)) }
                    durable.append((source: "workbuddy-live", stream: marker, state: try JSONEncoder().encode(since)))
                    try database.persistCollected(raw: [], events: [], checkpoints: [], parserStates: durable)
                } catch {
                    DispatchQueue.main.async {
                        guard let self, self.startupID == id else { return }
                        self.startupID = nil; self.collectionFailures += 1
                        database?.enqueueHealth(CollectorHealthRecord(source: "workbuddy", state: .failed,
                            lastSuccess: nil, lagSeconds: nil, accepted: 0, malformed: 1, dropped: 0,
                            detail: "Live installation boundary could not be saved; collection has not started"))
                    }
                    return
                }
                let restoredStates = states
                DispatchQueue.main.async {
                    guard let self, self.startupID == id else { return }
                    self.startupID = nil
                    self.realtimeSince = since
                    self.fileSizes = restoredStates.mapValues(\.offset)
                    self.parserStates = restoredStates
                    self.activate(realtimeOnly: true)
                }
            }
            return
        }
        if let states = try? evidenceDatabase?.parserStates(source: "workbuddy") {
            parserStates = states.compactMapValues { try? JSONDecoder().decode(ParserState.self, from: $0) }
        }
        if fileSizes.isEmpty, let saved = try? evidenceDatabase?.checkpoints(source: "workbuddy") {
            fileSizes = saved
        }
        activate(realtimeOnly: false)
    }

    private func activate(realtimeOnly: Bool) {
        try? FileManager.default.createDirectory(at: hookRoot, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        watch(hookRoot, isInbox: true)
        poll()
        // File/Hook events handle the hot path; scanning only backs up missed notifications.
        timer = Timer.scheduledTimer(withTimeInterval: realtimeOnly ? 2.0 : 30.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() {
        startupID = nil
        timer?.invalidate(); timer = nil
        debounce?.cancel(); debounce = nil
        for watcher in watchers.values { watcher.cancel() }
        watchers.removeAll(); watchOrder.removeAll(); pendingTargets.removeAll(); pendingWakeup = false
    }

    private func watch(_ url: URL, isInbox: Bool = false) {
        guard watchers[url.path] == nil else { return }
        if !isInbox && watchOrder.count >= 32 {
            let oldest = watchOrder.removeFirst()
            watchers.removeValue(forKey: oldest)?.cancel()
        }
        let descriptor = open(url.path, O_EVTONLY)
        guard descriptor >= 0 else { return }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: descriptor,
            eventMask: [.write, .extend, .rename, .delete], queue: queue)
        source.setEventHandler { [weak self] in
            Task { @MainActor in
                if let flags = self?.watchers[url.path]?.data, !flags.intersection([.rename, .delete]).isEmpty {
                    self?.watchers.removeValue(forKey: url.path)?.cancel()
                    self?.watchOrder.removeAll { $0 == url.path }
                }
                self?.requestCollection(targets: isInbox ? [] : [url])
            }
        }
        source.setCancelHandler { close(descriptor) }
        watchers[url.path] = source
        if !isInbox { watchOrder.append(url.path) }
        source.resume()
    }

    private func requestCollection(targets: [URL] = []) {
        guard timer != nil else { return }
        pendingTargets.formUnion(targets); pendingWakeup = true
        guard debounce == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.debounce = nil
            let targets = Array(self.pendingTargets)
            self.pendingTargets.removeAll(); self.pendingWakeup = false
            self.poll(targets: targets)
        }
        debounce = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05, execute: work)
    }

    private func poll(targets: [URL] = []) {
        guard !isPolling else {
            pendingTargets.formUnion(targets); pendingWakeup = true; return
        }
        isPolling = true
        let root = rootURL.path
        let changedAfter = lastPoll
        let previousSizes = fileSizes
        let database = evidenceDatabase
        let previousStates = parserStates
        let inbox = hookRoot
        let projects = rootURL
        let since = realtimeSince
        let cursorSource = since == nil ? "workbuddy" : "workbuddy-live"
        lastPoll = Date()
        queue.async { [weak self] in
            // Drain every decoded envelope only after durable acknowledgement.
            // Filtering before acknowledgement stranded pre-start files forever
            // and repeatedly decoded them at every live wakeup.
            let hooks = WorkBuddyHookInbox.read(root: inbox, projects: projects)
            let liveHooks = hooks.filter { since == nil || $0.event.ts >= since! }
            if !liveHooks.isEmpty {
                DispatchQueue.main.async { [weak self] in
                    guard let self, self.timer != nil else { return }
                    self.onHookSignals?(liveHooks.map(\.event))
                }
            }
            let hinted = Array(Set(targets + liveHooks.compactMap(\.transcript)))
            let batch = Self.readRecentEvents(root: root, changedAfter: changedAfter,
                                              previousSizes: previousSizes, previousStates: previousStates,
                                              targets: hinted)
            let collectedEvents = (liveHooks.map(\.event) + batch.events).filter { since == nil || $0.ts >= since! }
            let malformed = batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).malformedRows }
            let partial = batch.raw.reduce(0) { $0 + JSONLDiagnostics.inspect($1.payload).trailingPartialRows }
            var rawWriteFailed = false
            do {
                guard let database else { throw CocoaError(.fileWriteUnknown) }
                let states = try batch.states.map { path, state in
                    (source: cursorSource, stream: path, state: try JSONEncoder().encode(state))
                }
                let checkpoints = batch.states.map { path, state in
                    SourceCheckpoint(source: cursorSource, stream: path,
                        offset: Int64(state.offset), fingerprint: nil, updatedAt: Date())
                }
                if !liveHooks.isEmpty || !batch.raw.isEmpty || !collectedEvents.isEmpty || !checkpoints.isEmpty {
                    try database.persistCollected(raw: liveHooks.map(\.raw) + batch.raw, events: collectedEvents,
                        checkpoints: checkpoints, parserStates: states)
                }
                // Only acknowledge our own spool after the evidence transaction succeeds.
                for hook in hooks { try? FileManager.default.removeItem(at: hook.file) }
            } catch { rawWriteFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                self.isPolling = false
                guard self.timer != nil else { return }
                for path in batch.states.keys { self.watch(URL(fileURLWithPath: path)) }
                // A hook may arrive just before the transcript is created or appended.
                // Retry targeted paths; do not wait for the low-frequency scan.
                if !rawWriteFailed && !liveHooks.isEmpty {
                    self.pendingTargets.formUnion(liveHooks.compactMap(\.transcript))
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
                        self?.requestCollection(targets: liveHooks.compactMap(\.transcript))
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
                        self?.requestCollection(targets: liveHooks.compactMap(\.transcript))
                    }
                }
                if self.pendingWakeup { self.requestCollection() }
                guard !rawWriteFailed else {
                    self.collectionFailures += 1
                    self.evidenceDatabase?.enqueueHealth(CollectorHealthRecord(
                        source: "workbuddy", state: .degraded, lastSuccess: self.lastUpdate,
                        lagSeconds: nil, accepted: self.acceptedEvents,
                        malformed: self.collectionFailures + self.malformedRows, dropped: self.partialRows,
                        detail: "Live evidence write failed; source cursor retained for retry"))
                    return
                }
                self.parserStates.merge(batch.states) { _, new in new }
                let isConnected = FileManager.default.fileExists(atPath: root)
                if self.connected != isConnected { self.connected = isConnected }
                self.fileSizes.merge(batch.sizes) { _, new in new }
                let fresh = collectedEvents.filter { self.seen.insert($0.id).inserted }
                self.collectionFailures += batch.rawFailures
                self.malformedRows += malformed
                self.partialRows += partial
                if rawWriteFailed { self.collectionFailures += 1 }
                self.acceptedEvents += fresh.count
                if !fresh.isEmpty {
                    self.onEvents?(fresh)
                    self.lastUpdate = Date()
                }
                if Date().timeIntervalSince(self.lastHealthPersist) >= 10 || !self.connected {
                    self.lastHealthPersist = Date()
                    let state: CollectorHealthRecord.State = !self.connected ? .failed : self.collectionFailures + self.malformedRows > 0 ? .degraded : .healthy
                    self.evidenceDatabase?.enqueueHealth(CollectorHealthRecord(
                        source: "workbuddy", state: state, lastSuccess: self.connected ? Date() : nil,
                        lagSeconds: nil, accepted: self.acceptedEvents,
                        malformed: self.collectionFailures + self.malformedRows, dropped: self.partialRows,
                        detail: !self.connected ? "WorkBuddy session directory is unavailable" : self.collectionFailures > 0 || self.malformedRows > 0 ? "Raw read/write or malformed JSONL evidence detected" : self.partialRows > 0 ? "A trailing partial row is buffered for the next poll" : nil))
                }
            }
        }
    }

    private nonisolated static func fileIdentity(_ url: URL) -> String? {
        (try? url.resourceValues(forKeys: [.fileResourceIdentifierKey]))?.fileResourceIdentifier.map { String(describing: $0) }
    }

    nonisolated static func readRecentEvents(root: String, changedAfter: Date,
                                                     previousSizes: [String: UInt64], previousStates: [String: ParserState], targets: [URL] = [])
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], rawFailures: Int, states: [String: ParserState]) {
        let fm = FileManager.default
        var files: [(URL, Date, UInt64)] = []
        if !targets.isEmpty {
            for url in targets {
                guard let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey]),
                      let size = values.fileSize else { continue }
                files.append((url, values.contentModificationDate ?? .distantPast, UInt64(size)))
            }
        } else {
            guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey]) else { return ([], [:], [], 1, [:]) }
            let cutoff = Date().addingTimeInterval(-7 * 86_400)
            for case let url as URL in enumerator where url.pathExtension == "jsonl" {
                let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                let mtime = values?.contentModificationDate ?? .distantPast
                let size = UInt64(values?.fileSize ?? 0)
                if mtime >= cutoff && (mtime >= changedAfter || previousSizes[url.path] != size) {
                    files.append((url, mtime, size))
                }
            }
        }
        // Latest conversation seeds startup; subsequent sweeps cover concurrent sessions.
        let selected = files.filter { previousSizes[$0.0.path] != $0.2 }.sorted { $0.1 > $1.1 }.prefix(!targets.isEmpty || !previousStates.isEmpty ? 16 : 1)
        let raw = selected.compactMap { RawLogCapture.capture(url: $0.0, source: "workbuddy",
            previousOffset: previousSizes[$0.0.path], maximumInitialBytes: UInt64.max) }
        var sizes = Dictionary(uniqueKeysWithValues: selected.map { ($0.0.path, $0.2) })
        for record in raw { sizes[record.stream] = RawLogCapture.safeCheckpoint(for: record) }
        var states: [String: ParserState] = [:]
        var events: [GuardEvent] = []
        for (url, _, size) in selected {
            guard let captured = raw.first(where: { $0.stream == url.path }) else { continue }
            var state = previousStates[url.path] ?? ParserState()
            if state.offset > size { state = ParserState() }
            let emitFrom = previousStates[url.path] == nil
                ? (previousSizes[url.path] ?? 0) : state.offset
            if previousStates[url.path] == nil {
                // Existing transcript bodies belong to SessionLens. Start exactly
                // at the durable live boundary; never seed from old messages.
                state.offset = emitFrom
            }
            events += readIncremental(url, state: &state, emitFrom: emitFrom, through: UInt64(captured.offsetEnd))
            state.fingerprint = fileIdentity(url)
            states[url.path] = state
            sizes[url.path] = state.offset
        }
        return (events, sizes, raw, max(0, selected.count - raw.count), states)
    }

    nonisolated static func parseSession(_ url: URL, fullHistory: Bool = false,
                                         modelCatalogURL: URL? = nil) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: fullHistory) else { return [] }
        let configuredEndpoints = modelEndpoints(catalogURL: modelCatalogURL)
        var state = ParserState()
        return parseText(text, url: url, state: &state, configuredEndpoints: configuredEndpoints)
    }

    nonisolated static func readIncremental(_ url: URL, state: inout ParserState, emitFrom: UInt64? = nil, through end: UInt64? = nil) -> [GuardEvent] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        try? handle.seek(toOffset: state.offset)
        let threshold = emitFrom ?? state.offset
        let endpoints = modelEndpoints(catalogURL: nil)
        var pending = Data(), result: [GuardEvent] = []
        var readOffset = state.offset
        while end == nil || readOffset < end! {
            let remaining = end.map { min(UInt64(256 * 1_024), $0 - readOffset) } ?? UInt64(256 * 1_024)
            guard let chunk = try? handle.read(upToCount: Int(remaining)), !chunk.isEmpty else { break }
            readOffset += UInt64(chunk.count)
            pending.append(chunk)
            while let newline = pending.firstIndex(of: 0x0A) {
                let count = pending.distance(from: pending.startIndex, to: newline) + 1
                let rows = String(data: pending.prefix(count), encoding: .utf8) ?? ""
                let events = parseText(rows, url: url, state: &state, configuredEndpoints: endpoints)
                state.offset += UInt64(count)
                if state.offset > threshold { result += events }
                pending.removeFirst(count)
            }
        }
        return result
    }

    private nonisolated static func parseText(_ text: String, url: URL, state: inout ParserState,
                                               configuredEndpoints: [String: String]) -> [GuardEvent] {
        var lastIntent = state.lastIntent, lastReasoning = state.lastReasoning
        var currentTurn = state.currentTurn, toolNames = state.toolNames
        var lastModelEndpoint = state.lastModelEndpoint
        var callTurns = state.callTurns ?? [:], turnIntents = state.turnIntents ?? [:]
        defer {
            state.lastIntent = lastIntent; state.lastReasoning = lastReasoning
            state.currentTurn = currentTurn; state.toolNames = toolNames
            state.lastModelEndpoint = lastModelEndpoint
            state.callTurns = callTurns; state.turnIntents = turnIntents
        }
        var result: [GuardEvent] = []
        // 启动时只读取活跃窗口；完整历史已在 EventStore，避免重复解析巨型会话。
        let lines = text.split(whereSeparator: \.isNewline)
        for line in lines {
            guard let data = String(line).data(using: .utf8),
                  let row = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = row["id"] as? String else { continue }
            // WorkBuddy may reuse the same row id for parallel tool calls. Include the
            // call identity and timestamp so no call silently disappears.
            let identity = [rawId, row["type"] as? String, row["callId"] as? String,
                            String(describing: row["timestamp"] ?? "")].compactMap { $0 }.joined(separator: ":")
            let id = deterministicUUID(identity)
            let session = row["sessionId"] as? String ?? url.deletingPathExtension().lastPathComponent
            let type = row["type"] as? String ?? ""
            if type == "message", row["role"] as? String == "user", let intent = textContent(row["content"]) {
                let readableIntent = cleanUserIntent(intent)
                if intent.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<task-notification>"),
                   let range = intent.range(of: #"<tool-use-id>[^<]+</tool-use-id>"#, options: .regularExpression) {
                    let call = String(intent[range]).replacingOccurrences(of: "<tool-use-id>", with: "").replacingOccurrences(of: "</tool-use-id>", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
                    if let turn = callTurns[session + "\u{0}" + call], !turn.isEmpty {
                        currentTurn[session] = turn
                        lastIntent[session] = turnIntents[session + "\u{0}" + turn]
                        result.append(GuardEvent(id: id, kind: "context", ruleId: "workbuddy_background_continuation", path: row["cwd"] as? String ?? "-", command: nil, agent: "workbuddy", op: "recovered_context", severity: "info", ts: date(row["timestamp"]), action: "captured", sessionId: session, turnId: turn, toolCallId: call, modelPrompt: intent, source: "agentsight:workbuddy-local"))
                        continue
                    }
                }
                if let readableIntent { turnIntents[session + "\u{0}" + rawId] = String(readableIntent.prefix(1_000)) }
                lastIntent[session] = readableIntent.map { String($0.prefix(1_000)) }
                currentTurn[session] = rawId
                let provider = row["providerData"] as? [String: Any] ?? [:]
                result.append(GuardEvent(id: id, kind: readableIntent == nil ? "context" : "model",
                    ruleId: readableIntent == nil ? "workbuddy_recovered_context" : "agentsight_model_prompt",
                    path: row["cwd"] as? String ?? "-", command: nil, agent: "workbuddy",
                    op: readableIntent == nil ? "recovered_context" : "prompt",
                    severity: "info", ts: date(row["timestamp"]), action: readableIntent == nil ? "captured" : "sent", sessionId: session,
                    traceId: provider["traceId"] as? String, turnId: rawId, userIntent: readableIntent,
                    modelPrompt: intent, model: provider["model"] as? String,
                    source: "agentsight:workbuddy-local"))
                continue
            }
            if type == "message", row["role"] as? String == "assistant", let response = textContent(row["content"]) {
                let provider = row["providerData"] as? [String: Any] ?? [:]
                let configuredEndpoint = modelEndpoint(provider: provider, catalog: configuredEndpoints)
                if let configuredEndpoint { lastModelEndpoint[session] = configuredEndpoint }
                let usage = provider["rawUsage"] as? [String: Any] ?? provider["usage"] as? [String: Any] ?? [:]
                let rawAgent = provider["agent"] as? String
                let agent = (rawAgent == nil || rawAgent == "cli") ? "workbuddy" : rawAgent!
                result.append(GuardEvent(id: id, kind: "model", ruleId: "agentsight_model_response",
                    path: row["cwd"] as? String ?? "-", command: nil, agent: agent, op: "response",
                    severity: "info", ts: date(row["timestamp"]), action: row["status"] as? String ?? "received",
                    sessionId: session, traceId: provider["traceId"] as? String,
                    turnId: currentTurn[session],
                    userIntent: lastIntent[session], modelResponse: response,
                    model: provider["requestModelName"] as? String ?? provider["model"] as? String,
                    inputTokens: intValue(usage["prompt_tokens"] ?? usage["inputTokens"]),
                    outputTokens: intValue(usage["completion_tokens"] ?? usage["outputTokens"]),
                    cachedTokens: intValue((usage["prompt_tokens_details"] as? [String: Any])?["cached_tokens"]),
                    reasoningTokens: intValue((usage["completion_tokens_details"] as? [String: Any])?["reasoning_tokens"]),
                    costUSD: doubleValue(usage["cost"]),
                    source: "agentsight:workbuddy-local", attributionConfidence: configuredEndpoint == nil ? .inferred : .confirmed,
                    attributionMethod: configuredEndpoint == nil ? "adapter session/turn correlation" : "WorkBuddy model catalog endpoint",
                    remoteDomain: lastModelEndpoint[session]))
                continue
            }
            if type == "reasoning" {
                if let reasoning = recursiveText(row["content"]) ?? recursiveText(row["rawContent"]) {
                    lastReasoning[session] = reasoning
                    let provider = row["providerData"] as? [String: Any] ?? [:]
                    result.append(GuardEvent(id: id, kind: "model", ruleId: "agentsight_model_reasoning",
                        path: row["cwd"] as? String ?? "-", command: nil,
                        agent: "workbuddy", op: "reasoning_summary", severity: "info",
                        ts: date(row["timestamp"]), action: "captured", sessionId: session,
                        traceId: provider["traceId"] as? String, turnId: currentTurn[session],
                        userIntent: lastIntent[session], modelReasoning: reasoning,
                        model: provider["requestModelName"] as? String ?? provider["model"] as? String,
                        source: "agentsight:workbuddy-local"))
                }
                continue
            }
            guard type == "function_call" || type == "function_call_result" else { continue }
            let provider = row["providerData"] as? [String: Any] ?? [:]
            let configuredEndpoint = modelEndpoint(provider: provider, catalog: configuredEndpoints)
            if let configuredEndpoint { lastModelEndpoint[session] = configuredEndpoint }
            let usage = (provider["rawUsage"] as? [String: Any]) ?? (row["message"] as? [String: Any])?["usage"] as? [String: Any] ?? [:]
            let callId = row["callId"] as? String
            let recordedName = row["name"] as? String
            if type == "function_call", let callId, let recordedName { toolNames[callId] = recordedName }
            let callKey = callId.map { session + "\u{0}" + $0 }
            if type == "function_call", let key = callKey, let turn = currentTurn[session] {
                if let existing = callTurns[key], existing != turn { callTurns[key] = "" }
                else if callTurns[key] == nil { callTurns[key] = turn }
            }
            let knownTurn = callKey.flatMap { callTurns[$0] }
            let executionTurn = knownTurn.map { $0.isEmpty ? nil : $0 } ?? currentTurn[session]
            let name = recordedName ?? callId.flatMap { toolNames[$0] } ?? "unknown_tool"
            let args = row["arguments"] as? String
            let status = row["status"] as? String
            let timestamp = date(row["timestamp"])
            let rawAgent = provider["agent"] as? String
            let agent = (rawAgent == nil || rawAgent == "cli") ? "workbuddy" : rawAgent!
            let model = provider["requestModelName"] as? String ?? provider["model"] as? String
            let toolOutput = type == "function_call_result" ? recursiveText(row["output"] ?? provider["toolResult"]) : nil
            let command = type == "function_call" ? "\(name)(\(args ?? ""))" : nil
            let generatedCodeFindings = type == "function_call"
                ? CodeSecurityScanner.scanGenerated(toolName: name, arguments: args) : []
            result.append(GuardEvent(id: id, kind: "tool", ruleId: "agentsight_\(type)", path: row["cwd"] as? String ?? "-",
                command: command, agent: agent, op: type == "function_call" ? "call" : "result", severity: "info",
                ts: timestamp, action: status ?? (type == "function_call" ? "requested" : "completed"),
                sessionId: session, traceId: provider["traceId"] as? String, turnId: executionTurn, toolCallId: callId,
                userIntent: type == "function_call" ? lastIntent[session] : nil,
                modelDecision: type == "function_call" ? "The model selected \(name)" : nil,
                modelReasoning: type == "function_call" ? (provider["reasoning"] as? String ?? lastReasoning[session]) : nil,
                modelResponse: toolOutput,
                toolName: name, model: model,
                inputTokens: intValue(usage["prompt_tokens"] ?? usage["input_tokens"]),
                outputTokens: intValue(usage["completion_tokens"] ?? usage["output_tokens"]),
                cachedTokens: [intValue(usage["cached_tokens"]), intValue(usage["cache_read_input_tokens"]),
                               intValue((usage["prompt_tokens_details"] as? [String: Any])?["cached_tokens"])].compactMap { $0 }.max(),
                reasoningTokens: intValue((usage["completion_tokens_details"] as? [String: Any])?["reasoning_tokens"] ?? usage["completion_thinking_tokens"]),
                costUSD: doubleValue(usage["cost"]),
                codeFindings: generatedCodeFindings.isEmpty ? nil : generatedCodeFindings,
                source: "agentsight:workbuddy-local", remoteDomain: lastModelEndpoint[session]))
        }
        return result
    }

    private nonisolated static func modelEndpoints(catalogURL: URL?) -> [String: String] {
        let url = catalogURL ?? FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".workbuddy/models.json")
        guard let data = try? Data(contentsOf: url),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [:] }
        var result: [String: String] = [:]
        for row in rows {
            guard let endpoint = row["url"] as? String,
                  let host = URL(string: endpoint)?.host?.lowercased() else { continue }
            for key in [row["id"] as? String, row["name"] as? String].compactMap({ $0 }) {
                result[key.lowercased()] = host
            }
        }
        return result
    }

    private nonisolated static func modelEndpoint(provider: [String: Any], catalog: [String: String]) -> String? {
        let values = [provider["requestModelId"] as? String,
                      provider["requestModelName"] as? String,
                      provider["model"] as? String].compactMap { $0?.lowercased() }
        for value in values {
            if let endpoint = catalog[value] { return endpoint }
            if let suffix = value.split(separator: ":", maxSplits: 1).last,
               let endpoint = catalog[String(suffix)] { return endpoint }
        }
        return nil
    }

    private nonisolated static func sessionText(_ url: URL, fullHistory: Bool) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if fullHistory || size <= 512 * 1_024 {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        try? handle.seek(toOffset: size - 512 * 1_024)
        var data = handle.readDataToEndOfFile()
        if let newline = data.firstIndex(of: 0x0A) { data = data.suffix(from: data.index(after: newline)) }
        return String(data: data, encoding: .utf8)
    }

    private nonisolated static func textContent(_ value: Any?) -> String? {
        guard let items = value as? [[String: Any]] else { return nil }
        return items.compactMap { $0["text"] as? String }.joined(separator: "\n").nilIfEmpty
    }

    private nonisolated static func recursiveText(_ value: Any?) -> String? {
        var parts: [String] = []
        func walk(_ value: Any) {
            if let string = value as? String { parts.append(string); return }
            if let array = value as? [Any] { array.forEach(walk); return }
            if let dict = value as? [String: Any] {
                for key in ["text", "summary", "content", "reasoning"] {
                    if let nested = dict[key] { walk(nested) }
                }
            }
        }
        if let value { walk(value) }
        return parts.joined(separator: "\n").nilIfEmpty
    }

    /// WorkBuddy 会把系统注入块和用户原话放在同一 message 中；摘要只取用户真正输入，原文仍保存在 modelPrompt。
    nonisolated static func cleanUserIntent(_ text: String) -> String? {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<task-notification>") { return nil }
        var value = text
        let blockPatterns = [
            // Compaction includes old <user_query> examples. They are context,
            // never the human's current instruction.
            #"(?s)<cb_summary[^>]*>.*?</cb_summary>"#,
            #"(?s)<system-reminder[^>]*>.*?</system-reminder>"#,
            #"(?s)<product_identity>.*?</product_identity>"#,
            #"(?s)<tone_and_style>.*?</tone_and_style>"#,
            #"(?s)<project_context>.*?</project_context>"#,
            #"(?s)<additional_data>.*?</additional_data>"#,
            #"(?s)<memory_and_skills_reminder>.*?</memory_and_skills_reminder>"#
        ]
        for pattern in blockPatterns {
            value = value.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
        }
        if let match = value.range(of: #"(?s)<user_query>(.*?)</user_query>"#, options: .regularExpression) {
            let block = String(value[match])
            return block.replacingOccurrences(of: #"(?s)</?user_query>"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        }
        let cleaned = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.nilIfEmpty
    }

    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        if let uuid = UUID(uuidString: value) { return uuid }
        let hex = SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        let formatted = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))"
        return UUID(uuidString: formatted)!
    }

    private nonisolated static func date(_ value: Any?) -> Date {
        guard let number = value as? NSNumber else { return Date() }
        let raw = number.doubleValue
        return Date(timeIntervalSince1970: raw > 10_000_000_000 ? raw / 1_000 : raw)
    }

    private nonisolated static func intValue(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let string = value as? String { return Int(string) }
        return nil
    }

    private nonisolated static func doubleValue(_ value: Any?) -> Double? {
        if let value = value as? Double { return value }
        if let value = value as? NSNumber { return value.doubleValue }
        if let value = value as? String { return Double(value) }
        return nil
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
