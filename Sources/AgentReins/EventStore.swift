import Foundation

enum EventStoreReadError: LocalizedError {
    case databaseUnavailable
    case sessionNotFound(String)

    var errorDescription: String? {
        switch self {
        case .databaseUnavailable:
            return "本地证据数据库不可用"
        case .sessionNotFound(let sessionId):
            return "本地证据数据库中未找到会话：\(sessionId)"
        }
    }
}

/// 所有安全信号的统一、本地事件仓库。事件跨 App 重启保留，不上传网络。
@MainActor
final class EventStore: ObservableObject {
    /// A single revision publishes a coherent evidence snapshot. Publishing
    /// each derived array separately caused 4-7 full dashboard redraws for one
    /// collector batch.
    @Published private(set) var revision: UInt64 = 0
    private(set) var events: [GuardEvent] = []
    private(set) var incidents: [SecurityIncident] = []
    private(set) var sessions: [AgentSessionSnapshot] = []
    private(set) var influenceChains: [InfluenceChain] = []
    private(set) var webResourceChains: [WebResourceChain] = []
    private(set) var externalResources: [ExternalResource] = []
    private(set) var persistenceError: String?
    private(set) var collectorHealth: [CollectorHealthRecord] = []

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let database: EvidenceDatabase?
    private let evidenceBuffer: EvidenceBufferActor?
    private let persistenceQueue = DispatchQueue(label: "com.agentspec.eventstore.persistence", qos: .utility)
    private let projectionWorker = EventDerivedProjectionWorker()
    private let maximumEvents = 500
    private var projectionGeneration: UInt64 = 0

    init(fileURL: URL = EventStore.defaultURL()) {
        self.fileURL = fileURL
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let databaseURL = fileURL.standardizedFileURL == EventStore.defaultURL().standardizedFileURL
            ? EvidenceDatabase.defaultURL() : fileURL.appendingPathExtension("sqlite3")
        let openedDatabase = try? EvidenceDatabase.openRecovering(url: databaseURL)
        database = openedDatabase
        evidenceBuffer = openedDatabase.map(EvidenceBufferActor.init(database:))
        load()
        refreshCollectorHealth(publish: false)
    }

    nonisolated static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let directory = base.appendingPathComponent("AgentGuard", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("events.json")
    }

    func record(_ event: GuardEvent) {
        if let index = events.firstIndex(where: { $0.id == event.id }) {
            var updatedEvents = events
            updatedEvents[index] = event
            commitEvents(updatedEvents, evidence: [event])
            return
        }
        commitEvents([event] + events, evidence: [event])
    }

    func record(_ incoming: [GuardEvent]) {
        guard !incoming.isEmpty else { return }
        var updatedEvents = events
        var indexes = Dictionary(uniqueKeysWithValues: updatedEvents.enumerated().map { ($0.element.id, $0.offset) })
        var changed = false
        for event in incoming {
            if let index = indexes[event.id] {
                // 原生会话源可能后来补齐模型响应/上下文字段，允许富化已有事件。
                updatedEvents[index] = event
                changed = true
            } else {
                indexes[event.id] = updatedEvents.count
                updatedEvents.append(event)
                changed = true
            }
        }
        guard changed else { return }
        commitEvents(updatedEvents, evidence: incoming)
    }

    func unrecorded(_ incoming: [GuardEvent]) -> [GuardEvent] {
        let existing = Dictionary(uniqueKeysWithValues: events.map { ($0.id, $0) })
        return incoming.filter { candidate in
            guard let saved = existing[candidate.id] else { return true }
            // Allow adapters to enrich a previously stored event when a newer
            // scanner learns about inline code or a tool-provided website.
            if saved.codeFindings == nil, candidate.codeFindings?.isEmpty == false { return true }
            if saved.remoteDomain == nil, candidate.remoteDomain != nil { return true }
            if saved.inputTokens == nil, candidate.inputTokens != nil { return true }
            if saved.outputTokens == nil, candidate.outputTokens != nil { return true }
            if saved.costUSD == nil, candidate.costUSD != nil { return true }
            if saved.action != candidate.action { return true }
            if saved.modelResponse == nil, candidate.modelResponse != nil { return true }
            if saved.modelResponse != candidate.modelResponse, candidate.kind == "verification" { return true }
            if saved.afterContent == nil, candidate.afterContent != nil { return true }
            return false
        }
    }

    func events(on date: Date, calendar: Calendar = .current) -> [GuardEvent] {
        events.filter { calendar.isDate($0.ts, inSameDayAs: date) }
    }

    func refreshAlertPolicies() {
        scheduleDerivedProjection(events: events)
    }

    func loadSession(_ sessionId: String,
                     completion: @escaping (Result<AgentSessionSnapshot, Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable))
            return
        }
        persistenceQueue.async {
            let result: Result<AgentSessionSnapshot, Error>
            do {
                let sessions = AgentSessionSnapshot.build(from: try database.events(sessionId: sessionId))
                guard let session = sessions.first(where: { $0.id == sessionId }) else {
                    throw EventStoreReadError.sessionNotFound(sessionId)
                }
                result = .success(session)
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadHistoricalSecurityEvidence(limit: Int = 1_500,
                                        completion: @escaping (Result<[GuardEvent], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result { try database.historicalSecurityCandidates(limit: limit) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadProjectHistory(sessionIDs: [String], limitPerSession: Int = 500,
                            completion: @escaping (Result<[GuardEvent], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result { try database.projectEvidence(sessionIDs: sessionIDs, limitPerSession: limitPerSession) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func findFeatureProvenance(projectID: String, query: String, limit: Int = 20,
                               completion: @escaping (Result<[FeatureProvenanceRecord], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result {
                try Self.restoreCanonicalProjectHistoryIfNeeded(projectID: projectID, database: database)
                return FeatureProvenanceIndex.search(query: query, projectID: projectID,
                                                     events: try database.agentEvents(projectID: projectID),
                                                     limit: limit)
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadCodeChanges(projectID: String, path: String? = nil, limit: Int = 2_000,
                         completion: @escaping (Result<[IndexedCodeChange], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result {
                try Self.restoreCanonicalProjectHistoryIfNeeded(projectID: projectID, database: database)
                return try database.codeChanges(projectID: projectID, path: path, limit: limit)
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadChangeSets(projectID: String, limit: Int = 500,
                        completion: @escaping (Result<[IndexedChangeSet], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result {
                try Self.restoreCanonicalProjectHistoryIfNeeded(projectID: projectID, database: database)
                return try database.changeSets(projectID: projectID, limit: limit)
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func findFeatureProvenance(projectID: String, query: String,
                               using analyzer: SemanticAnalyzer,
                               limit: Int = 20) async throws -> [FeatureProvenanceRecord] {
        let understanding = await analyzer.understandFeatureQuery(query)
        guard let database else { throw EventStoreReadError.databaseUnavailable }
        return try await withCheckedThrowingContinuation { continuation in
            persistenceQueue.async {
                do {
                    try Self.restoreCanonicalProjectHistoryIfNeeded(projectID: projectID, database: database)
                    let records = FeatureProvenanceIndex.search(
                        query: query, projectID: projectID,
                        events: try database.agentEvents(projectID: projectID),
                        additionalTerms: understanding?.searchTerms ?? [], limit: limit)
                    continuation.resume(returning: records)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    nonisolated private static func restoreCanonicalProjectHistoryIfNeeded(
        projectID: String, database: EvidenceDatabase
    ) throws {
        guard try database.agentEvents(projectID: projectID, limit: 1).isEmpty else { return }
        let legacy = try database.legacyProjectEvents(projectID: projectID)
        for (sessionID, rows) in Dictionary(grouping: legacy.filter { $0.sessionId != nil },
                                             by: { $0.sessionId! }) {
            let canonical = LegacyGuardEventAdapter.project(rows, projectID: projectID,
                startingSequence: try database.nextAgentEventSequence(sessionID: sessionID) - 1)
            try database.appendAgentEvents(canonical)
            try database.upsertCodeChanges(CodeChangeIndexer.build(events: canonical))
        }
        let changes = try database.codeChanges(projectID: projectID)
        try database.replaceChangeSets(projectID: projectID,
            values: ChangeSetIndexer.build(projectID: projectID,
                events: try database.agentEvents(projectID: projectID), changes: changes))
    }

    func recordMemoryFindings(_ findings: [MemoryFinding], scannedAt: Date) {
        guard !findings.isEmpty else { return }
        let newEvents = findings.map { finding in
            GuardEvent(kind: "memory", ruleId: finding.ruleId,
                path: finding.src, command: nil, agent: nil, op: "scan",
                severity: finding.severity, ts: scannedAt, action: "seen")
        }
        commitEvents(events + newEvents, evidence: newEvents)
    }

    private func load() {
        // Historical evidence remains queryable in SQLite but is never loaded
        // into the live product. Native adapters provide exactly their latest
        // conversation, followed only by incremental changes.
        events = []
    }

    private func trimAndSave() {
        commitEvents(events, evidence: [])
    }

    /// Publish one coherent snapshot per ingest batch. Mutating the @Published
    /// array once per event made SwiftUI rebuild the entire dashboard hundreds
    /// of times while a live session was being tailed.
    private func commitEvents(_ incoming: [GuardEvent], evidence: [GuardEvent]) {
        var snapshot = incoming.sorted { $0.ts > $1.ts }
        if snapshot.count > maximumEvents { snapshot.removeLast(snapshot.count - maximumEvents) }
        events = snapshot
        scheduleDerivedProjection(events: snapshot)
        if let database, let evidenceBuffer {
            let affectedEvidence = evidenceForAffectedTurns(evidence)
            let affectedTurns = Array(Set(evidence.compactMap { event -> String? in
                guard let session = event.sessionId, let turn = event.turnId else { return nil }
                return "\(session)\u{0}\(turn)"
            })).compactMap { key -> (sessionId: String, turnId: String)? in
                let parts = key.split(separator: "\u{0}", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2 else { return nil }
                return (String(parts[0]), String(parts[1]))
            }
            persistenceQueue.async { [weak self] in
                do {
                    let grouped = Dictionary(grouping: evidence.filter { $0.sessionId != nil },
                                             by: { $0.sessionId! })
                    for (sessionID, sessionEvidence) in grouped {
                        let session = AgentSessionSnapshot.build(from: sessionEvidence).first
                        let projectID = Self.canonicalProjectID(session: session, sessionID: sessionID)
                        let next = try database.nextAgentEventSequence(sessionID: sessionID)
                        let canonical = LegacyGuardEventAdapter.project(
                            sessionEvidence, projectID: projectID, startingSequence: next - 1)
                        try database.appendAgentEvents(canonical)
                        if GitCheckpointIntegration.shouldInspect(sessionEvidence),
                           let workspace = session?.workspace,
                           let repository = GitRepositoryInspector.capture(workspace: workspace) {
                            let sessionEvents = try database.agentEvents(sessionID: sessionID)
                            let existingHashes = Set(sessionEvents.compactMap { event -> String? in
                                guard case let .checkpoint(value) = event.payload else { return nil }
                                return value.commitHash
                            })
                            let checkpointEvents = GitCheckpointIntegration.checkpointEvents(
                                projectID: repository.repositoryRoot,
                                agentID: session?.agent ?? sessionEvidence.compactMap(\.agent).last ?? "unknown",
                                sessionID: sessionID,
                                turnID: sessionEvidence.compactMap(\.turnId).last,
                                events: sessionEvents,
                                commits: GitCommitInspector.recent(repositoryRoot: repository.repositoryRoot, limit: 5),
                                existingCommitHashes: existingHashes,
                                startingSequence: try database.nextAgentEventSequence(sessionID: sessionID))
                            try database.appendAgentEvents(checkpointEvents)
                        }
                        try database.upsertCodeChanges(CodeChangeIndexer.build(
                            events: try database.agentEvents(sessionID: sessionID)))
                        let projectChanges = try database.codeChanges(projectID: projectID)
                        try database.replaceChangeSets(projectID: projectID,
                            values: ChangeSetIndexer.build(projectID: projectID,
                                events: try database.agentEvents(projectID: projectID), changes: projectChanges))
                    }
                    try database.upsertAssessments(ForensicAssessmentRecord.build(events: affectedEvidence))
                    try database.replaceModelRoutes(ModelRouteEvidence.build(events: affectedEvidence),
                                                    turns: affectedTurns)
                    try database.upsertMemoryCommits(MemoryCommitEvidence.build(events: affectedEvidence))
                    let health = try database.healthRecords()
                    DispatchQueue.main.async {
                        guard let self else { return }
                        self.persistenceError = nil
                        self.collectorHealth = health
                    }
                } catch {
                    let message = error.localizedDescription
                    DispatchQueue.main.async { [weak self] in self?.persistenceError = message }
                }
            }
            let urgent = evidence.contains { event in
                event.severity == "critical" || event.action == "blocked" || event.kind == "verification"
            }
            Task { await evidenceBuffer.enqueue(evidence, urgent: urgent) }
        } else {
            persistenceError = "SQLite evidence database is unavailable"
        }
    }

    private func evidenceForAffectedTurns(_ incoming: [GuardEvent]) -> [GuardEvent] {
        let keys = Set(incoming.compactMap { event -> String? in
            guard let session = event.sessionId, let turn = event.turnId else { return nil }
            return "\(session):\(turn)"
        })
        guard !keys.isEmpty else { return [] }
        return events.filter { event in
            guard let session = event.sessionId, let turn = event.turnId else { return false }
            return keys.contains("\(session):\(turn)")
        }
    }

    nonisolated private static func canonicalProjectID(session: AgentSessionSnapshot?,
                                                       sessionID: String) -> String {
        guard let raw = session?.workspace?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty, raw != "-" else { return "unattributed:\(sessionID)" }
        return URL(fileURLWithPath: raw).standardizedFileURL.path
    }

    func refreshCollectorHealth(publish: Bool) {
        guard let database else { return }
        persistenceQueue.async { [weak self] in
            let result: Result<[CollectorHealthRecord], Error>
            do {
                result = .success(try database.healthRecords())
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success(let snapshot):
                    if snapshot != self.collectorHealth {
                        self.collectorHealth = snapshot
                        if publish { self.revision &+= 1 }
                    }
                case .failure(let error):
                    self.persistenceError = error.localizedDescription
                }
            }
        }
    }

    private func scheduleDerivedProjection(events: [GuardEvent]) {
        projectionGeneration &+= 1
        let request = EventDerivedProjectionRequest(generation: projectionGeneration, events: events)
        Task { [weak self] in
            guard let self else { return }
            await projectionWorker.submit(request) { [weak self] generation, projection in
                guard let self, generation == self.projectionGeneration else { return }
                self.incidents = projection.incidents
                self.sessions = projection.sessions
                self.influenceChains = projection.influenceChains
                self.webResourceChains = projection.webResourceChains
                self.externalResources = []
                self.revision &+= 1
            }
        }
    }

    /// Parser v2 fixes user-query extraction and WorkBuddy's reused tool row IDs.
    /// Native AgentSight events are reproducible from JSONL, so discard only the
    /// old projection and let WorkBuddySight rebuild it on startup.
    private func rebuildAgentSightIndexOnce() {
        let key = "agr_agentsight_projection_v2"
        guard !UserDefaults.standard.bool(forKey: key) else { return }
        events.removeAll { $0.source?.hasPrefix("agentsight:") == true }
        trimAndSave()
        UserDefaults.standard.set(true, forKey: key)
    }

    /// 开发版兼容：首次启动把旧监测、拦截与记忆扫描 JSONL 合并进统一仓库。
    private func importLegacyLogsOnce() {
        let defaultsKey = "agr_legacyEventsImported_v1"
        guard !UserDefaults.standard.bool(forKey: defaultsKey) else { return }

        var roots = [URL(fileURLWithPath: FileManager.default.currentDirectoryPath)]
        roots.append(URL(fileURLWithPath: "/Users/jatsmith/AgentSpec"))
        var imported: [GuardEvent] = []
        for root in roots {
            imported += parseJSONL(root.appendingPathComponent("agentguard/agentguard_audit.jsonl"), source: "monitor")
            imported += parseJSONL(root.appendingPathComponent("agentguard-block/agentguard_block_audit.jsonl"), source: "block")
            imported += parseJSONL(root.appendingPathComponent("agentguard/agentguard_memory_scan.jsonl"), source: "memory")
        }

        var fingerprints = Set(events.map(fingerprint))
        for event in imported where fingerprints.insert(fingerprint(event)).inserted {
            events.append(event)
        }
        trimAndSave()
        UserDefaults.standard.set(true, forKey: defaultsKey)
    }

    private func parseJSONL(_ url: URL, source: String) -> [GuardEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(whereSeparator: \.isNewline).compactMap { line in
            guard let data = String(line).data(using: .utf8),
                  let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            let ts = parseDate(value["ts"] as? String) ?? Date()
            switch source {
            case "memory":
                return GuardEvent(kind: "memory", ruleId: value["rule_id"] as? String ?? "memory_sensitive",
                    path: value["src"] as? String ?? "-", command: nil, agent: nil, op: "scan",
                    severity: value["severity"] as? String ?? "high", ts: ts, action: "seen")
            case "block":
                let command = [value["cmd"] as? String, value["args"] as? String].compactMap { $0 }.joined(separator: " ")
                return GuardEvent(kind: "cmd", ruleId: value["rule"] as? String ?? "legacy_block",
                    path: "-", command: command, agent: nil, op: "exec",
                    severity: (value["decision"] as? String) == "block" ? "critical" : "high",
                    ts: ts, action: value["decision"] as? String ?? "seen")
            default:
                return GuardEvent(kind: "cmd", ruleId: value["rule"] as? String ?? "legacy_monitor",
                    path: "-", command: value["detail"] as? String, agent: value["agent"] as? String,
                    op: "exec", severity: value["severity"] as? String ?? "high", ts: ts,
                    action: value["action"] as? String ?? "seen")
            }
        }
    }

    private func parseDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: value) { return date }
        let local = DateFormatter()
        local.locale = Locale(identifier: "en_US_POSIX")
        local.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return local.date(from: value)
    }

    private func fingerprint(_ event: GuardEvent) -> String {
        "\(event.kind)|\(event.ruleId)|\(event.path)|\(event.command ?? "")|\(event.ts.timeIntervalSince1970)|\(event.action)"
    }
}
