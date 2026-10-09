import Foundation
import SwiftUI
import CryptoKit

/// Compatibility adapter for Codex's local rollout records. OpenAI does not
/// document this JSONL layout as a stable public API, so parsing is defensive
/// and every projected event retains a source label that states this boundary.
@MainActor
final class CodexSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var lastUpdate: Date?
    var onEvents: (([GuardEvent]) -> Void)?

    private var timer: Timer?
    private var seen = Set<UUID>()
    private var fileSizes: [String: UInt64] = [:]
    private var streamStates: [String: StreamState] = [:]

    /// Runtime-only framing and identity. No old message body is read to seed a
    /// realtime stream: Codex's rollout filename supplies its stable session ID.
    struct StreamState: Codable, Sendable {
        var session: String
        var workspace = "-"
        var model: String?
        var currentTurn: String?
        var lastIntent: String?
        var calls: [String: [CallBinding]] = [:]
        var fingerprint: String?
        var observedSize: UInt64 = 0
        var anchorOffset: UInt64 = 0
        var anchor = Data()

        init(url: URL) {
            let filename = url.deletingPathExtension().lastPathComponent
            session = filename.count >= 36 && UUID(uuidString: String(filename.suffix(36))) != nil
                ? String(filename.suffix(36)) : filename
        }
    }

    struct CallBinding: Codable, Equatable, Sendable {
        let name: String
        let turn: String?
    }
    struct LiveCursorCheckpoint: Codable {
        struct Cursor: Codable { let offset: UInt64; let state: StreamState }
        let version: Int
        let savedAt: Date
        let cursors: [String: Cursor]
    }
    struct CursorRestore {
        var sizes: [String: UInt64]
        var states: [String: StreamState]
        var savedAt: Date?
        var gaps: [GuardEvent]
    }
    private var pendingGaps: [GuardEvent] = []
    private let liveCursorURL = URL(fileURLWithPath: ("~/Library/Application Support/AgentGuard" as NSString).expandingTildeInPath)
        .appendingPathComponent("codex-live-cursors.json")
    private let evidenceDatabase = try? EvidenceDatabase.shared()
    private var acceptedEvents = 0
    private var collectionFailures = 0
    private var malformedRows = 0
    private var partialRows = 0
    private var startupID: UUID?
    private var realtimeSince: Date?
    private var isInitialPoll = true
    private var isPolling = false
    private let queue = DispatchQueue(label: "com.agentspec.codexsight", qos: .utility)

    func start(realtimeOnly: Bool = false) {
        guard timer == nil, startupID == nil else { return }
        if realtimeOnly {
            realtimeSince = Date()
            let id = UUID()
            startupID = id
            let root = URL(fileURLWithPath: ("~/.codex/sessions" as NSString).expandingTildeInPath)
            let cursorURL = liveCursorURL
            queue.async { [weak self] in
                let offsets = RealtimeLogBaseline.offsets(root: root)
                let restored = Self.restoreLiveCursorCheckpoint(root: root, baselineOffsets: offsets,
                                                                 from: cursorURL)
                DispatchQueue.main.async {
                    guard let self, self.startupID == id else { return }
                    self.startupID = nil
                    self.fileSizes = restored.sizes
                    self.streamStates = restored.states
                    self.pendingGaps = restored.gaps
                    if let savedAt = restored.savedAt { self.realtimeSince = savedAt }
                    self.isInitialPoll = false
                    self.activate(realtimeOnly: true)
                }
            }
            return
        }
        if fileSizes.isEmpty, let saved = try? evidenceDatabase?.checkpoints(source: "codex") {
            fileSizes = saved
        }
        activate(realtimeOnly: false)
    }

    private func activate(realtimeOnly: Bool) {
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: realtimeOnly ? 1.0 : 10.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() { startupID = nil; timer?.invalidate(); timer = nil }

    private func poll() {
        guard !isPolling else { return }
        isPolling = true
        let root = ("~/.codex/sessions" as NSString).expandingTildeInPath
        let previousSizes = fileSizes
        let previousStates = streamStates
        let database = evidenceDatabase
        let liveCursorURL = realtimeSince == nil ? nil : liveCursorURL
        let pendingGaps = pendingGaps
        let baselineOtherStreams = isInitialPoll
        let since = realtimeSince
        queue.async { [weak self] in
            let batch = Self.readLiveEvents(root: root, previousSizes: previousSizes,
                                            baselineOtherStreams: baselineOtherStreams, states: previousStates)
            let collectedEvents = pendingGaps + batch.events.filter { since == nil || $0.ts >= since! }
            let diagnostics = batch.raw.map { record -> JSONLDiagnosticResult in
                var payload = record.payload
                if record.offsetStart > 0, !Self.startsAtRowBoundary(URL(fileURLWithPath: record.stream), offset: UInt64(record.offsetStart)),
                   let newline = payload.firstIndex(of: 0x0A) {
                    payload = Data(payload.suffix(from: payload.index(after: newline)))
                }
                return JSONLDiagnostics.inspect(payload)
            }
            let malformed = diagnostics.reduce(0) { $0 + $1.malformedRows }
            let partial = diagnostics.reduce(0) { $0 + $1.trailingPartialRows }
            var rawWriteFailed = false
            var cursorWriteFailed = false
            do {
                guard let database else { throw CocoaError(.fileWriteUnknown) }
                let checkpoints = batch.sizes.map { stream, offset in
                    SourceCheckpoint(source: "codex", stream: stream, offset: Int64(offset),
                                     fingerprint: nil, updatedAt: Date())
                }
                try database.persistCollected(raw: batch.raw, events: collectedEvents, checkpoints: checkpoints)
                if let liveCursorURL {
                    var committedSizes = previousSizes
                    committedSizes.merge(batch.sizes) { _, new in new }
                    do { try Self.saveLiveCursorCheckpoint(sizes: committedSizes, states: batch.states, to: liveCursorURL) }
                    catch { cursorWriteFailed = true }
                }
            } catch { rawWriteFailed = true }
            DispatchQueue.main.async {
                guard let self else { return }
                let isConnected = FileManager.default.fileExists(atPath: root)
                self.isPolling = false
                guard !rawWriteFailed else { self.collectionFailures += 1; return }
                if isConnected { self.isInitialPoll = false }
                if self.connected != isConnected { self.connected = isConnected }
                self.fileSizes.merge(batch.sizes) { _, new in new }
                self.streamStates = batch.states
                self.pendingGaps = []
                if cursorWriteFailed { self.collectionFailures += 1 }
                self.collectionFailures += pendingGaps.count
                let fresh = collectedEvents.filter { self.seen.insert($0.id).inserted }
                self.collectionFailures += batch.rawFailures
                self.malformedRows += malformed
                self.partialRows = partial
                if rawWriteFailed { self.collectionFailures += 1 }
                self.acceptedEvents += fresh.count
                if !fresh.isEmpty {
                    self.onEvents?(fresh)
                    self.lastUpdate = Date()
                }
                let state: CollectorHealthRecord.State = !self.connected ? .failed : self.collectionFailures + self.malformedRows > 0 ? .degraded : .healthy
                let health = CollectorHealthRecord(
                    source: "codex", state: state, lastSuccess: self.connected ? Date() : nil,
                    lagSeconds: nil, accepted: self.acceptedEvents,
                    malformed: self.collectionFailures + self.malformedRows, dropped: 0,
                    detail: !self.connected ? "Codex session directory is unavailable" : self.collectionFailures > 0 || self.malformedRows > 0 ? "Raw read/write or malformed JSONL evidence detected" : self.partialRows > 0 ? "A trailing partial row is buffered for the next poll" : nil)
                self.queue.async { [weak self] in
                    guard let database else {
                        DispatchQueue.main.async { self?.collectionFailures += 1 }
                        return
                    }
                    var persistenceFailed = false
                    do { try database.updateHealth(health) }
                    catch { persistenceFailed = true }
                    if persistenceFailed {
                        DispatchQueue.main.async { self?.collectionFailures += 1 }
                    }
                }
            }
        }
    }

    /// Complete newline-delimited records are the commit boundary. A partial
    /// UTF-8/JSON row is captured as raw evidence, then reread at its start on the
    /// next poll. Identity survives every byte window instead of being inferred
    /// again from an arbitrary 64 KiB tail.
    nonisolated static func readLiveEvents(root: String, previousSizes: [String: UInt64],
                                           baselineOtherStreams: Bool,
                                           states previousStates: [String: StreamState] = [:])
        -> (events: [GuardEvent], sizes: [String: UInt64], raw: [RawEvidenceRecord], rawFailures: Int,
            states: [String: StreamState]) {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: URL(fileURLWithPath: root),
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey, .fileResourceIdentifierKey])
        else { return ([], [:], [], 1, previousStates) }
        let cutoff = Date().addingTimeInterval(-7 * 86_400)
        var files: [(URL, Date, UInt64, String?)] = []
        var states = previousStates
        for case let url as URL in enumerator where url.pathExtension == "jsonl" {
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey, .fileResourceIdentifierKey])
            let mtime = values?.contentModificationDate ?? .distantPast
            let size = UInt64(values?.fileSize ?? 0)
            let fingerprint = values?.fileResourceIdentifier.map { String(describing: $0) }
            let previous = states[url.path]
            let replaced = previous?.fingerprint != nil && previous?.fingerprint != fingerprint
            if mtime >= cutoff, previousSizes[url.path] != size || replaced {
                files.append((url, mtime, size, fingerprint))
            }
        }
        var sizes: [String: UInt64] = baselineOtherStreams
            ? Dictionary(uniqueKeysWithValues: files.map { ($0.0.path, $0.2) }) : [:]
        var raw: [RawEvidenceRecord] = []
        var events: [GuardEvent] = []
        var rawFailures = 0
        for (url, _, size, fingerprint) in files.sorted(by: { $0.1 > $1.1 }).prefix(baselineOtherStreams ? 1 : 16) {
            let previous = previousSizes[url.path]
            var state = states[url.path] ?? StreamState(url: url)
            let replaced = state.fingerprint != nil && state.fingerprint != fingerprint
            let truncated = previous.map { $0 > size } ?? false
            let rewritten = !state.anchor.isEmpty && !anchorMatches(state, url: url)
            if replaced || truncated || rewritten { state = StreamState(url: url) }
            state.fingerprint = fingerprint
            state.observedSize = size
            let offset: UInt64? = replaced || truncated || rewritten ? 0 : previous
            if size == 0 { sizes[url.path] = 0; states[url.path] = state; continue }
            guard let record = RawLogCapture.capture(url: url, source: "codex", previousOffset: offset,
                                                     maximumInitialBytes: baselineOtherStreams ? 512 * 1_024 : UInt64.max)
            else {
                // A transient read failure must not advance the checkpoint.
                rawFailures += 1
                states[url.path] = state
                continue
            }
            raw.append(record)
            let checkpoint = RawLogCapture.safeCheckpoint(for: record)
            sizes[url.path] = checkpoint
            let completeCount = Int(checkpoint - UInt64(record.offsetStart))
            if completeCount > 0 {
                state.anchor = Data(record.payload.prefix(completeCount).suffix(64))
                state.anchorOffset = checkpoint - UInt64(state.anchor.count)
            }
            if baselineOtherStreams, previous == nil {
                // Legacy on-demand startup mode retains its bounded recent read.
                // Realtime-only startup never enters this path.
                if let text = sessionText(url, fullHistory: false) {
                    events += parseSessionText(text, url: url, state: &state)
                }
            } else if let newline = record.payload.lastIndex(of: 0x0A) {
                var complete = Data(record.payload.prefix(through: newline))
                if record.offsetStart > 0, !startsAtRowBoundary(url, offset: UInt64(record.offsetStart)),
                   let firstNewline = complete.firstIndex(of: 0x0A) {
                    // Startup may have baselined an unfinished old row at EOF.
                    // Preserve its suffix as raw, but never invent a new event.
                    complete = Data(complete.suffix(from: complete.index(after: firstNewline)))
                }
                if let text = String(data: complete, encoding: .utf8) {
                    events += parseSessionText(text, url: url, state: &state)
                } else { rawFailures += 1 }
            }
            states[url.path] = state
        }
        return (events, sizes, raw, rawFailures, states)
    }

    private nonisolated static func startsAtRowBoundary(_ url: URL, offset: UInt64) -> Bool {
        guard offset > 0, let handle = try? FileHandle(forReadingFrom: url) else { return offset == 0 }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: offset - 1)
            return try handle.read(upToCount: 1)?.first == 0x0A
        } catch { return false }
    }

    private nonisolated static func baselineStates(_ offsets: [String: UInt64]) -> [String: StreamState] {
        offsets.reduce(into: [:]) { result, entry in
            let url = URL(fileURLWithPath: entry.key)
            var state = StreamState(url: url)
            state.observedSize = entry.value
            state.fingerprint = (try? url.resourceValues(forKeys: [.fileResourceIdentifierKey]))?
                .fileResourceIdentifier.map { String(describing: $0) }
            result[entry.key] = state
        }
    }

    /// Persists only runtime state already obtained from live records, not a
    /// reconstructed transcript. The private cursor is committed after evidence.
    nonisolated static func saveLiveCursorCheckpoint(sizes: [String: UInt64], states: [String: StreamState],
                                                     to url: URL, savedAt: Date = Date()) throws {
        let cursors = states.reduce(into: [String: LiveCursorCheckpoint.Cursor]()) { result, entry in
            guard let offset = sizes[entry.key], !entry.value.anchor.isEmpty else { return }
            result[entry.key] = .init(offset: offset, state: entry.value)
        }
        let data = try JSONEncoder().encode(LiveCursorCheckpoint(version: 1, savedAt: savedAt, cursors: cursors))
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    nonisolated static func restoreLiveCursorCheckpoint(root: URL, baselineOffsets: [String: UInt64],
                                                        from url: URL?) -> CursorRestore {
        var restored = CursorRestore(sizes: baselineOffsets, states: baselineStates(baselineOffsets), savedAt: nil, gaps: [])
        guard let url, FileManager.default.fileExists(atPath: url.path) else { return restored }
        guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size <= 8 * 1_024 * 1_024,
              let data = try? Data(contentsOf: url),
              let checkpoint = try? JSONDecoder().decode(LiveCursorCheckpoint.self, from: data), checkpoint.version == 1 else {
            restored.gaps.append(cursorGap(session: nil, turn: nil, reason: "实时游标损坏或版本不兼容；从当前文件末尾采集，重启期间的增量未恢复"))
            return restored
        }
        let rootPrefix = root.standardizedFileURL.path + "/"
        for (path, cursor) in checkpoint.cursors {
            guard URL(fileURLWithPath: path).standardizedFileURL.path.hasPrefix(rootPrefix) else { continue }
            let fileURL = URL(fileURLWithPath: path)
            let current = restored.states[path]
            guard let size = baselineOffsets[path], size >= cursor.offset,
                  let fingerprint = cursor.state.fingerprint, current?.fingerprint == fingerprint,
                  !cursor.state.anchor.isEmpty, anchorMatches(cursor.state, url: fileURL) else {
                restored.gaps.append(cursorGap(session: cursor.state.session, turn: cursor.state.currentTurn,
                    reason: "实时源被截断、替换或删除；该流从当前文件末尾采集，未拼接旧上下文"))
                continue
            }
            restored.sizes[path] = cursor.offset
            restored.states[path] = cursor.state
            restored.savedAt = checkpoint.savedAt
        }
        return restored
    }

    private nonisolated static func anchorMatches(_ state: StreamState, url: URL) -> Bool {
        guard !state.anchor.isEmpty, let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: state.anchorOffset)
            return try handle.read(upToCount: state.anchor.count) == state.anchor
        } catch { return false }
    }

    private nonisolated static func cursorGap(session: String?, turn: String?, reason: String) -> GuardEvent {
        GuardEvent(kind: "activity", ruleId: "codex_cursor_gap", path: "-", command: nil, agent: "codex",
                   op: "collection_gap", severity: "medium", ts: Date(), action: "gap",
                   sessionId: session, turnId: turn, modelResponse: reason,
                   source: "agentsight:codex-local-compat")
    }

    nonisolated static func parseSession(_ url: URL, fullHistory: Bool = false) -> [GuardEvent] {
        guard let text = sessionText(url, fullHistory: fullHistory) else { return [] }
        var state = StreamState(url: url)
        return parseSessionText(text, url: url, state: &state)
    }

    private nonisolated static func parseSessionText(_ text: String, url: URL, state: inout StreamState) -> [GuardEvent] {
        let lines = text.split(whereSeparator: \.isNewline)
        var session = state.session
        var workspace = state.workspace
        var model = state.model
        var currentTurn = state.currentTurn
        var lastIntent = state.lastIntent
        var calls = state.calls
        var result: [GuardEvent] = []
        defer {
            state.session = session; state.workspace = workspace; state.model = model
            state.currentTurn = currentTurn; state.lastIntent = lastIntent; state.calls = calls
        }
        func adoptTurn(_ turn: String?) {
            guard let turn, !turn.isEmpty, turn != currentTurn else { return }
            currentTurn = turn
            lastIntent = nil
        }
        func intent(for turn: String?) -> String? { turn == currentTurn ? lastIntent : nil }

        for line in lines {
            guard let row = dictionary(line), let payload = row["payload"] as? [String: Any] else { continue }
            let type = row["type"] as? String ?? ""
            let payloadType = payload["type"] as? String ?? ""
            let timestamp = date(row["timestamp"])
            let timestampKey = row["timestamp"] as? String ?? deterministicUUID(String(line)).uuidString
            if type == "session_meta" {
                let recordedSession = payload["id"] as? String ?? payload["session_id"] as? String ?? session
                if recordedSession != session { currentTurn = nil; lastIntent = nil; calls = [:] }
                session = recordedSession
                workspace = payload["cwd"] as? String ?? workspace
            }

            if type == "session_meta", let base = payload["base_instructions"] as? [String: Any],
               let instructions = base["text"] as? String, !instructions.isEmpty {
                let provenance = jsonString(base["provenance"]) ?? "unknown"
                result.append(event(identity: "\(session):base-instructions", kind: "context",
                    rule: "codex_base_instructions", workspace: workspace, op: "base_instructions",
                    timestamp: timestamp, action: "captured", session: session, trace: nil, turn: nil,
                    intent: nil, prompt: String(instructions.prefix(128_000)), response: nil,
                    toolCallId: nil, toolName: "codex.base_instructions", command: provenance, model: model))
                continue
            }

            if type == "turn_context" {
                adoptTurn(metadataTurn(payload))
                workspace = payload["cwd"] as? String ?? workspace
                model = payload["model"] as? String ?? model
                let context = selectedJSON(payload, keys: ["cwd", "current_date", "timezone", "model", "effort",
                    "approval_policy", "sandbox_policy", "permission_profile", "active_permission_profile",
                    "collaboration_mode", "workspace_roots", "realtime_active"])
                result.append(event(identity: "\(session):\(currentTurn ?? timestampKey):turn-context", kind: "context",
                    rule: "codex_turn_context", workspace: workspace, op: "turn_context", timestamp: timestamp,
                    action: "captured", session: session, trace: nil, turn: currentTurn, intent: lastIntent,
                    prompt: nil, response: nil, toolCallId: nil, toolName: "codex.turn_context",
                    command: context, model: model))
                continue
            }
            if type == "compacted" {
                let replacement = payload["replacement_history"] as? [Any] ?? []
                let guardian = payload["guardian_history"] as? [Any] ?? []
                let metadata: [String: Any] = [
                    "window_number": payload["window_number"] ?? NSNull(),
                    "previous_window_id": payload["previous_window_id"] ?? NSNull(),
                    "window_id": payload["window_id"] ?? NSNull(),
                    "compaction_response_id": payload["compaction_response_id"] ?? NSNull(),
                    "replacement_history_items": replacement.count,
                    "replacement_history_bytes": jsonByteCount(replacement),
                    "guardian_history_items": guardian.count,
                    "guardian_history_bytes": jsonByteCount(guardian)
                ]
                result.append(event(identity: "\(session):\(payload["window_id"] as? String ?? timestampKey):compaction",
                    kind: "context", rule: "codex_context_compaction", workspace: workspace,
                    op: "context_compaction", timestamp: timestamp, action: "captured", session: session,
                    trace: payload["compaction_response_id"] as? String, turn: currentTurn, intent: lastIntent,
                    prompt: nil, response: nil, toolCallId: nil, toolName: "codex.compaction",
                    command: jsonString(metadata), model: model))
                continue
            }
            if type == "world_state" {
                let state = payload["state"] as? [String: Any] ?? [:]
                let summary: [String: Any] = ["full": payload["full"] ?? false,
                    "state_keys": state.keys.sorted(), "state_bytes": jsonByteCount(state)]
                result.append(event(identity: "\(session):\(currentTurn ?? "none"):\(timestampKey):world-state",
                    kind: "context", rule: "codex_world_state", workspace: workspace, op: "world_state",
                    timestamp: timestamp, action: "captured", session: session, trace: nil, turn: currentTurn,
                    intent: lastIntent, prompt: nil, response: nil, toolCallId: nil,
                    toolName: "codex.world_state", command: jsonString(summary), model: model))
                continue
            }
            if type == "event_msg", payloadType == "task_complete" {
                let turn = payload["turn_id"] as? String ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):task-complete",
                    kind: "model", rule: "codex_task_complete", workspace: workspace, op: "response",
                    timestamp: timestamp, action: "completed", session: session, trace: nil, turn: turn,
                    intent: nil, prompt: nil, response: payload["last_agent_message"] as? String,
                    toolCallId: nil, toolName: nil, command: nil, model: model))
                continue
            }
            if type == "event_msg", payloadType == "task_started" {
                adoptTurn(metadataTurn(payload))
                result.append(event(identity: "\(session):\(currentTurn ?? "none"):\(timestampKey):task-started",
                    kind: "activity", rule: "codex_task_started", workspace: workspace, op: "task_started",
                    timestamp: timestamp, action: "started", session: session, trace: nil, turn: currentTurn,
                    intent: nil, prompt: nil, response: nil, toolCallId: nil, toolName: nil, command: nil, model: model))
                continue
            }
            if type == "event_msg", ["turn_aborted", "task_cancelled", "task_canceled", "task_failed", "error"].contains(payloadType) {
                let turn = metadataTurn(payload) ?? currentTurn
                let cancelled = ["turn_aborted", "task_cancelled", "task_canceled"].contains(payloadType)
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):\(payloadType)",
                    kind: "activity", rule: "codex_\(payloadType)", workspace: workspace,
                    op: cancelled ? "task_cancelled" : payloadType == "error" ? "model_error" : "task_failed", timestamp: timestamp,
                    action: cancelled ? "cancelled" : "failed", session: session, trace: nil, turn: turn,
                    intent: nil, prompt: nil, response: recursiveText(payload["message"] ?? payload["reason"] ?? payload["error"])
                        ?? (payload["error"] as? [String: Any])?["message"] as? String ?? jsonString(payload["error"]),
                    toolCallId: nil, toolName: nil, command: jsonString(payload), model: model))
                continue
            }
            if type == "event_msg", ["item_started", "item_completed"].contains(payloadType),
               let item = payload["item"] as? [String: Any],
               ["CommandExecution", "command_execution"].contains(item["type"] as? String ?? "") {
                let turn = metadataTurn(payload) ?? currentTurn
                // Native command item IDs are not function-call IDs in current
                // rollouts. Keep their execution lane separate unless the source
                // explicitly supplies call_id; time proximity is not a join key.
                let nativeID = item["id"] as? String ?? timestampKey
                let callID = item["call_id"] as? String ?? "execution:" + nativeID
                let started = payloadType == "item_started"
                let status = item["status"] as? String ?? ""
                let failed = status == "failed" || (int(item["exit_code"]).map { $0 != 0 } ?? false)
                let body = selectedJSON(item, keys: ["stdout", "stderr", "aggregated_output", "formatted_output",
                    "exit_code", "status", "process_id", "pid", "duration", "source"])
                result.append(event(identity: "\(session):\(turn ?? "none"):\(nativeID):\(payloadType)",
                    kind: "tool", rule: "codex_command_\(started ? "started" : "completed")",
                    workspace: item["cwd"] as? String ?? workspace, op: started ? "exec_start" : "result",
                    timestamp: timestamp, action: started ? "started" : failed ? "failed" : "completed",
                    session: session, trace: nil, turn: turn, intent: intent(for: turn), prompt: nil,
                    response: started ? nil : body, toolCallId: callID, toolName: "CommandExecution",
                    command: selectedJSON(item, keys: ["command", "cwd", "process_id", "pid"]), model: model,
                    processID: int32(item["pid"]), startedAt: epochDate(payload["started_at_ms"]),
                    endedAt: started ? nil : epochDate(payload["completed_at_ms"]), durationMS: durationMS(item["duration"])))
                continue
            }
            if type == "event_msg", ["exec_command_begin", "exec_command_output_delta", "exec_command_end"].contains(payloadType) {
                let callID = payload["call_id"] as? String
                let explicitTurn = metadataTurn(payload)
                var turn = explicitTurn ?? currentTurn
                if payloadType == "exec_command_begin", let callID {
                    let binding = CallBinding(name: "exec_command", turn: turn)
                    if !(calls[callID] ?? []).contains(binding) { calls[callID, default: []].append(binding) }
                }
                let candidates = callID.map { calls[$0] ?? [] } ?? []
                let matching = explicitTurn.map { explicit in candidates.filter { $0.turn == explicit } } ?? candidates
                if payloadType != "exec_command_begin", explicitTurn == nil { turn = matching.count == 1 ? matching.first?.turn : nil }
                let streaming = payloadType == "exec_command_output_delta"
                let begin = payloadType == "exec_command_begin"
                let delta = recursiveText(payload["delta"] ?? payload["text"])
                let output = streaming ? delta : selectedJSON(payload, keys: ["stdout", "stderr", "aggregated_output",
                    "formatted_output", "exit_code", "status", "process_id", "duration", "wall_time"])
                let command = streaming ? selectedJSON(payload, keys: ["channel", "stream", "execution_id", "process_id"])
                    : recursiveText(payload["command"]) ?? jsonString(payload["command"])
                result.append(event(identity: "\(session):\(turn ?? "none"):\(callID ?? "none"):\(payloadType):\(timestampKey)",
                    kind: "tool", rule: "codex_\(payloadType)", workspace: payload["cwd"] as? String ?? workspace,
                    op: begin ? "exec_start" : streaming ? "output" : "result", timestamp: timestamp,
                    action: begin ? "started" : streaming ? "streaming" : (int(payload["exit_code"]).map { $0 != 0 } ?? false) ? "failed" : "completed",
                    session: session, trace: nil, turn: turn, intent: begin ? intent(for: turn) : nil,
                    prompt: nil, response: begin ? nil : output, toolCallId: callID,
                    toolName: matching.count == 1 ? matching.first?.name : "exec_command", command: command, model: model,
                    processID: int32(payload["pid"]), durationMS: durationMS(payload["duration"])))
                continue
            }
            if (type == "event_msg" && payloadType == "user_message") ||
               (type == "response_item" && payloadType == "message" && payload["role"] as? String == "user"),
               let content = (payload["message"] as? String) ?? textContent(payload["content"]),
               !ChangeSetIndexer.isTranscriptBundle(content) {
                let turn = metadataTurn(payload) ?? currentTurn
                adoptTurn(turn)
                lastIntent = cleanUserIntent(content)
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):user-prompt",
                    kind: "model", rule: "codex_model_prompt", workspace: workspace, op: "prompt",
                    timestamp: timestamp, action: "sent", session: session, trace: nil, turn: turn,
                    intent: lastIntent, prompt: String(content.prefix(64_000)), response: nil,
                    toolCallId: nil, toolName: nil, command: nil, model: model))
                continue
            }
            if type == "event_msg", payloadType == "item_completed",
               let item = payload["item"] as? [String: Any], item["type"] as? String == "UserMessage",
               let content = textContent(item["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                adoptTurn(turn)
                if ChangeSetIndexer.isTranscriptBundle(content) {
                    let metadata = transcriptBundleMetadata(content)
                    result.append(event(identity: "\(session):\(turn ?? "none"):\(item["id"] as? String ?? timestampKey):transcript-bundle",
                        kind: "context", rule: "codex_recovered_transcript_bundle", workspace: workspace,
                        op: "recovered_transcript", timestamp: timestamp, action: "captured",
                        session: session, trace: nil, turn: turn, intent: nil, prompt: nil,
                        response: nil, toolCallId: nil, toolName: "codex.compacted_history",
                        command: jsonString(metadata), model: model))
                    continue
                }
                lastIntent = cleanUserIntent(content)
                result.append(event(identity: "\(session):\(turn ?? "none"):\(item["id"] as? String ?? timestampKey):prompt", kind: "model",
                    rule: "codex_model_prompt", workspace: workspace, op: "prompt", timestamp: timestamp,
                    action: "sent", session: session, trace: nil, turn: turn, intent: intent(for: turn),
                    prompt: String(content.prefix(64_000)), response: nil, toolCallId: nil,
                    toolName: nil, command: nil, model: model))
                let attachments = (item["content"] as? [[String: Any]] ?? []).filter {
                    ($0["type"] as? String) != "text" && ($0["type"] as? String) != "input_text"
                }
                if !attachments.isEmpty {
                    let kinds = attachments.compactMap { $0["type"] as? String }
                    result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):attachments",
                        kind: "context", rule: "codex_attachment", workspace: workspace, op: "attachment",
                        timestamp: timestamp, action: "captured", session: session, trace: nil, turn: turn,
                        intent: lastIntent, prompt: nil, response: nil, toolCallId: nil,
                        toolName: "codex.attachment", command: jsonString(["count": attachments.count, "types": kinds]),
                        model: model))
                }
                continue
            }
            if type == "response_item", payloadType == "message", payload["role"] as? String == "developer",
               let content = textContent(payload["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(payload["id"] as? String ?? timestampKey):developer",
                    kind: "context", rule: "codex_developer_instructions", workspace: workspace,
                    op: "developer_instructions", timestamp: timestamp, action: "captured", session: session,
                    trace: nil, turn: turn, intent: intent(for: turn), prompt: String(content.prefix(128_000)),
                    response: nil, toolCallId: nil, toolName: "codex.developer_instructions",
                    command: nil, model: model))
                continue
            }
            if type == "response_item", payloadType == "reasoning" {
                let summary = recursiveText(payload["summary"])
                if let summary {
                    let turn = metadataTurn(payload) ?? currentTurn
                    result.append(event(identity: "\(session):\(turn ?? "none"):\(payload["id"] as? String ?? timestampKey):reasoning",
                        kind: "model", rule: "codex_reasoning_summary", workspace: workspace,
                        op: "reasoning_summary", timestamp: timestamp, action: "captured", session: session,
                        trace: nil, turn: turn, intent: intent(for: turn), prompt: nil, response: nil,
                        toolCallId: nil, toolName: nil, command: nil, model: model,
                        reasoning: String(summary.prefix(64_000))))
                }
                continue
            }
            if type == "response_item", payloadType == "message", payload["role"] as? String == "assistant",
               let content = textContent(payload["content"]) {
                let turn = metadataTurn(payload) ?? currentTurn
                result.append(event(identity: "\(session):\(turn ?? "none"):\(timestampKey):response", kind: "model",
                    rule: "codex_model_response", workspace: workspace, op: "response", timestamp: timestamp,
                    action: payload["phase"] as? String ?? "received", session: session, trace: nil, turn: turn, intent: intent(for: turn),
                    prompt: nil, response: String(content.prefix(64_000)), toolCallId: nil,
                    toolName: nil, command: nil, model: model))
                continue
            }
            if type == "token_usage_record", let usage = payload["usage"] as? [String: Any] {
                let turn = payload["turn_id"] as? String ?? currentTurn
                let trace = payload["response_id"] as? String
                result.append(event(identity: "\(session):\(turn ?? "none"):\(trace ?? "none"):\(timestampKey):usage", kind: "model",
                    rule: "codex_model_usage", workspace: workspace, op: "usage", timestamp: timestamp,
                    action: "reported", session: session, trace: trace, turn: turn, intent: intent(for: turn),
                    prompt: nil, response: nil, toolCallId: nil, toolName: nil, command: nil, model: model,
                    inputTokens: int(usage["input_tokens"]), outputTokens: int(usage["output_tokens"]),
                    cachedTokens: int(usage["cached_input_tokens"]), reasoningTokens: int(usage["reasoning_output_tokens"])))
                continue
            }
            guard type == "response_item", ["custom_tool_call", "function_call", "custom_tool_call_output", "function_call_output"].contains(payloadType) else { continue }
            let isOutput = payloadType.hasSuffix("output")
            let callId = payload["call_id"] as? String
            let namespace = payload["namespace"] as? String
            let recordedName = payload["name"] as? String
            let qualifiedName = [namespace, recordedName].compactMap { $0 }.joined(separator: namespace == nil ? "" : "__")
            let explicitTurn = metadataTurn(payload)
            var turn = explicitTurn ?? currentTurn
            if !isOutput, let callId {
                let binding = CallBinding(name: nonEmpty(qualifiedName) ?? "unknown_tool", turn: turn)
                if !(calls[callId] ?? []).contains(binding) { calls[callId, default: []].append(binding) }
            }
            let candidates = callId.map { calls[$0] ?? [] } ?? []
            let matching = explicitTurn.map { explicit in candidates.filter { $0.turn == explicit } } ?? candidates
            let binding = matching.count == 1 ? matching.first : nil
            if isOutput, explicitTurn == nil {
                // A call ID is a relation only when unique in this stream. Never
                // attach a late result to whichever turn happens to be current.
                turn = binding?.turn
            }
            let name = nonEmpty(qualifiedName) ?? binding?.name ?? "unknown_tool"
            let command = isOutput ? nil : recursiveText(payload["input"] ?? payload["arguments"])
                ?? jsonString(payload["input"] ?? payload["arguments"])
            let output = isOutput ? recursiveText(payload["output"]) ?? jsonString(payload["output"]) : nil
            result.append(event(identity: "\(session):\(turn ?? "none"):\(callId ?? "none"):\(payloadType):\(timestampKey)",
                kind: "tool", rule: "codex_\(payloadType)", workspace: workspace,
                op: isOutput ? "result" : "call", timestamp: timestamp,
                action: isOutput ? "completed" : "requested", session: session, trace: nil,
                turn: turn, intent: isOutput ? nil : intent(for: turn), prompt: nil, response: output,
                toolCallId: callId, toolName: name, command: command, model: model))
        }
        return result
    }

    private nonisolated static func event(identity: String, kind: String, rule: String, workspace: String,
        op: String, timestamp: Date, action: String, session: String, trace: String?, turn: String?,
        intent: String?, prompt: String?, response: String?, toolCallId: String?, toolName: String?,
        command: String?, model: String?, inputTokens: Int? = nil, outputTokens: Int? = nil,
        cachedTokens: Int? = nil, reasoningTokens: Int? = nil, reasoning: String? = nil,
        processID: Int32? = nil, startedAt: Date? = nil, endedAt: Date? = nil, durationMS: Double? = nil) -> GuardEvent {
        GuardEvent(id: deterministicUUID(identity), kind: kind, ruleId: rule, path: workspace,
            command: command, agent: "codex", op: op, severity: "info", ts: timestamp,
            action: action, sessionId: session, traceId: trace, turnId: turn,
            toolCallId: toolCallId, userIntent: intent,
            modelDecision: op == "call" ? "The model selected \(toolName ?? "a tool")" : nil,
            modelReasoning: reasoning, modelPrompt: prompt, modelResponse: response, toolName: toolName, model: model,
            inputTokens: inputTokens, outputTokens: outputTokens, cachedTokens: cachedTokens,
            reasoningTokens: reasoningTokens, source: "agentsight:codex-local-compat",
            processId: processID, startedAt: startedAt, endedAt: endedAt, durationMS: durationMS)
    }

    private nonisolated static func dictionary(_ line: Substring) -> [String: Any]? {
        guard let data = String(line).data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    /// Keep startup bounded even when a long-running Codex task has produced a
    /// multi-megabyte rollout. The first record carries session metadata; recent
    /// records carry the active turns that the live monitor needs.
    private nonisolated static func sessionText(_ url: URL, fullHistory: Bool, startOffset: UInt64? = nil) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        if fullHistory {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        if let startOffset {
            try? handle.seek(toOffset: 0)
            let first = handle.readData(ofLength: 64 * 1_024)
            try? handle.seek(toOffset: min(startOffset, size))
            var tail = handle.readDataToEndOfFile()
            if startOffset > 0, let newline = tail.firstIndex(of: 0x0A) {
                tail = tail.suffix(from: tail.index(after: newline))
            }
            guard let headText = String(data: first, encoding: .utf8),
                  let tailText = String(data: tail, encoding: .utf8) else { return nil }
            let firstLine = headText.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
            return firstLine + "\n" + tailText
        }
        let tailBytes: UInt64 = 512 * 1_024
        guard size > tailBytes else {
            try? handle.seek(toOffset: 0)
            return String(data: handle.readDataToEndOfFile(), encoding: .utf8)
        }
        try? handle.seek(toOffset: 0)
        let first = handle.readData(ofLength: 64 * 1_024)
        try? handle.seek(toOffset: size - tailBytes)
        var tail = handle.readDataToEndOfFile()
        if let newline = tail.firstIndex(of: 0x0A) { tail = tail.suffix(from: tail.index(after: newline)) }
        guard let headText = String(data: first, encoding: .utf8),
              let tailText = String(data: tail, encoding: .utf8) else { return nil }
        let firstLine = headText.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        return firstLine + "\n" + tailText
    }

    private nonisolated static func textContent(_ value: Any?) -> String? {
        if let text = value as? String { return nonEmpty(text) }
        guard let items = value as? [[String: Any]] else { return nil }
        return nonEmpty(items.compactMap { $0["text"] as? String }.joined(separator: "\n"))
    }

    private nonisolated static func recursiveText(_ value: Any?) -> String? {
        if let value = value as? String { return nonEmpty(value) }
        if let items = value as? [[String: Any]] {
            return nonEmpty(items.compactMap { item in
                (item["text"] as? String) ?? (item["summary_text"] as? String)
            }.joined(separator: "\n"))
        }
        return nil
    }

    private nonisolated static func selectedJSON(_ object: [String: Any], keys: [String]) -> String? {
        jsonString(Dictionary(uniqueKeysWithValues: keys.compactMap { key in object[key].map { (key, $0) } }))
    }

    private nonisolated static func jsonString(_ value: Any?) -> String? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private nonisolated static func jsonByteCount(_ value: Any) -> Int {
        (try? JSONSerialization.data(withJSONObject: value)).map(\.count) ?? 0
    }

    private nonisolated static func metadataTurn(_ payload: [String: Any]) -> String? {
        (payload["turn_id"] as? String) ?? (payload["internal_chat_message_metadata_passthrough"] as? [String: Any])?["turn_id"] as? String
    }

    private nonisolated static func cleanUserIntent(_ value: String) -> String {
        if let range = value.range(of: #"(?s)## My request:\s*(.*)$"#, options: .regularExpression) {
            return String(value[range]).replacingOccurrences(of: #"(?s)^## My request:\s*"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private nonisolated static func transcriptBundleMetadata(_ value: String) -> [String: Any] {
        let roles = ["user", "assistant", "tool", "developer"]
        let counts = Dictionary(uniqueKeysWithValues: roles.map { role -> (String, Int) in
            let pattern = "(?m)^\\s*\\[\\d+\\]\\s+\(role):"
            let expression = try? NSRegularExpression(pattern: pattern)
            let range = NSRange(value.startIndex..<value.endIndex, in: value)
            return (role, expression?.numberOfMatches(in: value, range: range) ?? 0)
        })
        return ["byteCount": value.utf8.count, "roleCounts": counts,
                "sha256": SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()]
    }

    private nonisolated static func date(_ value: Any?) -> Date {
        guard let string = value as? String else { return Date() }
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: string) ?? ISO8601DateFormatter().date(from: string) ?? Date()
    }

    private nonisolated static func nonEmpty(_ value: String) -> String? {
        value.isEmpty ? nil : value
    }

    private nonisolated static func int32(_ value: Any?) -> Int32? {
        int(value).flatMap(Int32.init(exactly:))
    }

    private nonisolated static func epochDate(_ milliseconds: Any?) -> Date? {
        (milliseconds as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue / 1_000) }
    }

    private nonisolated static func durationMS(_ value: Any?) -> Double? {
        guard let duration = value as? [String: Any], let seconds = duration["secs"] as? NSNumber else { return nil }
        return seconds.doubleValue * 1_000 + ((duration["nanos"] as? NSNumber)?.doubleValue ?? 0) / 1_000_000
    }

    private nonisolated static func int(_ value: Any?) -> Int? {
        (value as? NSNumber)?.intValue ?? (value as? String).flatMap(Int.init)
    }

    private nonisolated static func deterministicUUID(_ value: String) -> UUID {
        let hex = SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
        return UUID(uuidString: "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))")!
    }
}
