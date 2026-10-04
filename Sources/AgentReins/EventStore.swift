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

/// 所有安全信号的统一、本地事件仓库。事件跨 App 重启保留；
/// 仅显式注册云审计后，由独立上传客户端发送启用后的新任务。
@MainActor
final class EventStore: ObservableObject {
    /// The overview shows only activity observed during this app run. Older
    /// evidence is available through the explicit history query instead.
    let liveSince = Date()
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
    private(set) var taskProgress: [String: TaskLiveProgress] = [:]
    @Published private(set) var historySummaryRevision: UInt64 = 0
    @Published private(set) var historySummariesReady = false
    @Published private(set) var historySummaryError: String?
    @Published private(set) var taskSearchIndexReady = false
    @Published private(set) var taskSearchIndexedCount = 0

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let database: EvidenceDatabase?
    private let taskSearchWriter: TaskSearchIndex?
    private let taskSearchReader: TaskSearchIndex?
    private let evidenceBuffer: EvidenceBufferActor?
    private let persistenceQueue = DispatchQueue(label: "com.agentspec.eventstore.persistence", qos: .utility)
    // UI reads must not wait behind a live collector's growing write backlog.
    // EvidenceDatabase serializes access to its SQLite handle internally.
    private let taskReadQueue = DispatchQueue(label: "com.agentspec.eventstore.task-read", qos: .userInitiated)
    private let historyMaintenanceQueue = DispatchQueue(label: "com.agentspec.eventstore.history-maintenance", qos: .background)
    private let taskSearchMaintenanceQueue = DispatchQueue(label: "com.agentspec.eventstore.task-search-maintenance", qos: .background)
    private let taskSearchReadQueue = DispatchQueue(label: "com.agentspec.eventstore.task-search-read", qos: .userInitiated)
    private let projectionWorker = EventDerivedProjectionWorker()
    private let maximumEvents = 500
    private var projectionGeneration: UInt64 = 0
    private var auditUploader: AuditUploadClient?
    private var historySummaryTask: Task<Void, Never>?
    private var historyBackfillBatchCount = 0
    private var durableProcessingTask: Task<Void, Never>?
    private var durableAnalysisTask: Task<Void, Never>?
    private var taskSearchTask: Task<Void, Never>?

    init(fileURL: URL = EventStore.defaultURL()) {
        self.fileURL = fileURL
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let databaseURL = fileURL.standardizedFileURL == EventStore.defaultURL().standardizedFileURL
            ? EvidenceDatabase.defaultURL() : fileURL.appendingPathExtension("sqlite3")
        let openedDatabase = try? EvidenceDatabase.shared(url: databaseURL)
        database = openedDatabase
        taskSearchWriter = openedDatabase.flatMap { _ in try? TaskSearchIndex(evidenceURL: databaseURL) }
        taskSearchReader = taskSearchWriter == nil ? nil : (try? TaskSearchIndex(evidenceURL: databaseURL))
        evidenceBuffer = openedDatabase.map(EvidenceBufferActor.init(database:))
        if openedDatabase == nil {
            historySummaryError = "本地证据数据库不可用，历史摘要暂时无法整理"
        }
        load()
        refreshCollectorHealth(publish: false)
        if fileURL.standardizedFileURL == EventStore.defaultURL().standardizedFileURL {
            if let openedDatabase { auditUploader = AuditUploadClient(database: openedDatabase) }
            openedDatabase?.setAuditUploadEnabled(auditUploader != nil)
            startHistorySummaryBackfill(database: openedDatabase)
            if let openedDatabase {
                startDurableProcessing(database: openedDatabase)
                startDurableAnalysis(database: openedDatabase)
                if let taskSearchWriter { startTaskSearchIndexing(database: openedDatabase, index: taskSearchWriter) }
            }
        }
    }

    deinit {
        durableProcessingTask?.cancel()
        durableAnalysisTask?.cancel()
        historySummaryTask?.cancel()
        taskSearchTask?.cancel()
    }

    private func startTaskSearchIndexing(database: EvidenceDatabase, index: TaskSearchIndex) {
        taskSearchTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(1))
            var needsBackfillReset = index.newlyCreated
            while !Task.isCancelled {
                guard let self else { return }
                let active = self.taskProgress.values.contains { progress in
                    switch progress.phase {
                    case .completed, .failed: return false
                    default: return true
                    }
                }
                let result: Result<(worked: Bool, count: Int), Error> = await withCheckedContinuation { continuation in
                    let reset = needsBackfillReset
                    self.taskSearchMaintenanceQueue.async {
                        let result = Result { () throws -> (worked: Bool, count: Int) in
                            let worked = try TaskSearchPump.step(database: database, index: index,
                                                                 active: active, initialize: reset)
                            return (worked, try index.indexedTaskCount())
                        }
                        continuation.resume(returning: result)
                    }
                }
                switch result {
                case .success(let outcome):
                    let worked = outcome.worked
                    needsBackfillReset = false
                    self.taskSearchIndexedCount = outcome.count
                    if worked { self.taskSearchIndexReady = false }
                    if !worked { self.taskSearchIndexReady = true }
                    try? await Task.sleep(for: .milliseconds(TaskSearchPump.delayMilliseconds(active: active, worked: worked)))
                case .failure(let error):
                    self.taskSearchIndexReady = false
                    self.historySummaryError = "历史检索索引暂时失败：\(error.localizedDescription)"
                    try? await Task.sleep(for: .seconds(5))
                }
            }
        }
    }

    private func startDurableProcessing(database: EvidenceDatabase) {
        let processor = DurableEvidenceProcessor(database: database)
        durableProcessingTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                do {
                    let count = try await processor.processSlice()
                    if count > 0 { self?.historySummaryRevision &+= 1 }
                    try await Task.sleep(for: .milliseconds(count > 0 ? 50 : 500))
                } catch is CancellationError { return }
                catch {
                    self?.persistenceError = error.localizedDescription
                    try? await Task.sleep(for: .seconds(5))
                }
            }
        }
    }

    private func startDurableAnalysis(database: EvidenceDatabase) {
        let processor = DurableAnalysisProcessor(database: database)
        durableAnalysisTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                do {
                    let processed = try await processor.processOne()
                    var queuedHistory = 0
                    let hasActiveTask = self?.taskProgress.values.contains { progress in
                        switch progress.phase {
                        case .completed, .failed: return false
                        default: return true
                        }
                    } ?? true
                    if !processed {
                        // Active tasks get a single legacy admission per idle
                        // slice. This guarantees progress without letting a
                        // backlog of old work dominate live collection.
                        queuedHistory = try await processor.enqueueHistoricalBatch(limit: hasActiveTask ? 1 : 25)
                    }
                    try await Task.sleep(for: .milliseconds(processed || queuedHistory > 0 ? 100 : 750))
                } catch is CancellationError { return }
                catch {
                    self?.persistenceError = error.localizedDescription
                    try? await Task.sleep(for: .seconds(5))
                }
            }
        }
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
            if saved.modelPrompt != candidate.modelPrompt, candidate.modelPrompt?.isEmpty == false { return true }
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

    /// Build the full task off the UI thread. Long tasks may have thousands
    /// of events and request bodies, so opening or refreshing one must not
    /// block interaction with the live overview.
    func loadTask(sessionID: String, turnID: String?,
                  completion: @escaping (Result<AgentTaskSnapshot, Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable))
            return
        }
        taskReadQueue.async {
            let result: Result<AgentTaskSnapshot, Error>
            do {
                if let turnID, let projection = try database.taskSnapshot(sessionID: sessionID, turnID: turnID) {
                    let commits = try database.memoryCommits(sessionId: sessionID, turnId: turnID)
                    result = .success(projection.includingMemoryCommits(commits))
                    DispatchQueue.main.async { completion(result) }
                    return
                }
                let rows = try database.events(sessionId: sessionID, turnID: turnID)
                let sessions = AgentSessionSnapshot.build(from: rows)
                guard let session = sessions.first(where: { $0.id == sessionID }) else {
                    throw EventStoreReadError.sessionNotFound(sessionID)
                }
                let boundary: Date?
                if let turnID, let prompt = rows.first(where: { $0.kind == "model" && $0.op == "prompt" }) {
                    boundary = try database.nextPromptDate(sessionID: sessionID, turnID: turnID, after: prompt.ts)
                } else { boundary = nil }
                let snapshot = AgentTaskSnapshot.build(session: session, turnID: turnID, nextPromptAt: boundary)
                let commits = try turnID.map { try database.memoryCommits(sessionId: sessionID, turnId: $0) } ?? []
                result = .success(snapshot.includingMemoryCommits(commits))
            } catch {
                result = .failure(error)
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadRecentTasks(limit: Int = 20, before: Date? = nil, offset: Int = 0,
                         after cursor: StoredTaskSummary? = nil,
                         completion: @escaping (Result<[StoredTaskSummary], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable))
            return
        }
        taskReadQueue.async {
            let result = Result { try database.recentTasks(limit: limit, before: before, offset: offset, after: cursor) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func searchHistoricalTasks(_ plan: HistoryQueryUnderstanding,
                               completion: @escaping (Result<(hits: [TaskSearchHit], aggregates: TaskAggregates), Error>) -> Void) {
        guard let taskSearchReader else {
            completion(.failure(EventStoreReadError.databaseUnavailable))
            return
        }
        taskSearchReadQueue.async {
            let result = Result { (hits: try taskSearchReader.search(plan), aggregates: try taskSearchReader.aggregate(plan)) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Exact-IP memory questions first query the structured memory-write facts,
    /// then append ordinary task mentions so the UI can distinguish the two.
    func searchHistoricalMemoryAddress(_ address: String,
                                       completion: @escaping (Result<(hits: [TaskSearchHit], aggregates: TaskAggregates), Error>) -> Void) {
        let plan = HistoryQueryUnderstanding(agent: nil, startDate: nil, endDate: nil,
            searchTerms: [address], evidenceKind: nil, requiresAddressInModelInput: false,
            explanation: "先查明确写入记忆正文的 IP，再列出仅提及该 IP 的任务。")
        searchHistoricalMemory(plan, address: address, completion: completion)
    }

    func searchHistoricalMemory(_ plan: HistoryQueryUnderstanding, address: String? = nil,
                                completion: @escaping (Result<(hits: [TaskSearchHit], aggregates: TaskAggregates), Error>) -> Void) {
        guard let taskSearchReader, let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable))
            return
        }
        taskSearchReadQueue.async {
            let result = Result { () -> (hits: [TaskSearchHit], aggregates: TaskAggregates) in
                // memory_commits is the canonical structured record and may
                // predate task_snapshot_projection. Query it directly so old
                // writes remain discoverable without reopening every source.
                let commits: [MemoryCommitEvidence]
                if let address {
                    commits = try database.searchMemoryCommits(address: address)
                } else {
                    commits = try database.searchMemoryCommits(terms: plan.searchTerms, agent: plan.agent,
                        startDate: plan.startDate, endDate: plan.endDate)
                }
                let groups = Dictionary(grouping: commits) { "\($0.sessionId)\u{0}\($0.turnId)" }
                let memory = groups.values.compactMap { writes -> TaskSearchHit? in
                    guard let latest = writes.max(by: { $0.observedAt < $1.observedAt }),
                          let earliest = writes.min(by: { $0.observedAt < $1.observedAt }) else { return nil }
                    let task = StoredTaskSummary(sessionID: latest.sessionId, turnID: latest.turnId,
                        agentID: latest.agent, title: "写入长期记忆 · \(latest.storagePath ?? "路径未采集")", startedAt: earliest.observedAt,
                        lastObservedAt: latest.observedAt, eventCount: writes.count)
                    let detail = writes.sorted { $0.observedAt > $1.observedAt }.map {
                        "\($0.observedAt.formatted(date: .abbreviated, time: .standard)) · \($0.storagePath ?? "路径未采集") · \($0.confidence.rawValue)"
                    }.joined(separator: "\n")
                    return TaskSearchHit(task: task, excerpt: detail, revision: 0, isMemoryWriteMatch: true)
                }.sorted { $0.task.lastObservedAt > $1.task.lastObservedAt }
                let memoryIDs = Set(memory.map(\.id))
                let mentions = try taskSearchReader.search(plan, limit: 100)
                    .filter { !memoryIDs.contains($0.id) }
                let hits = Array((memory + mentions).prefix(100))
                return (hits, try taskSearchReader.aggregate(plan))
            }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// Backfill legacy task summaries in small resumable batches. Active Agent
    /// work lowers throughput; it never stops historical progress entirely.
    private func startHistorySummaryBackfill(database: EvidenceDatabase?) {
        guard let database, historySummaryTask == nil else { return }
        historySummaryTask = Task { @MainActor [weak self] in
            // Let live collectors establish their current task before any
            // legacy scan competes for SQLite write time after launch.
            try? await Task.sleep(for: .seconds(20))
            var retryDelay: TimeInterval = 2
            while !Task.isCancelled {
                guard let self else { return }
                let hasActiveTask = self.taskProgress.values.contains { progress in
                    switch progress.phase {
                    case .completed, .failed: return false
                    default: return true
                    }
                }
                let result: Result<Bool, Error> = await withCheckedContinuation { continuation in
                    self.historyMaintenanceQueue.async {
                        let result = Result { () throws -> Bool in
                            let limit = hasActiveTask ? 1 : 25
                            let summariesDone = try database.backfillTaskSummaries(limit: limit)
                            return summariesDone ? try database.backfillTaskTitles(limit: limit) : false
                        }
                        DispatchQueue.main.async { continuation.resume(returning: result) }
                    }
                }
                switch result {
                case .success(let done):
                    retryDelay = 2
                    self.historySummaryError = nil
                    self.historySummariesReady = done
                    self.historyBackfillBatchCount += 1
                    // Avoid invalidating the entire SwiftUI environment on
                    // every tiny batch, but make the first newly prepared
                    // page visible immediately and refresh periodically.
                    if done || self.historyBackfillBatchCount == 1 || self.historyBackfillBatchCount.isMultiple(of: 5) {
                        self.historySummaryRevision &+= 1
                    }
                    if done { return }
                case .failure(let error):
                    self.historySummaryError = error.localizedDescription
                    try? await Task.sleep(for: .seconds(retryDelay))
                    retryDelay = min(60, retryDelay * 2)
                    continue
                }
                try? await Task.sleep(for: .seconds(hasActiveTask ? 5 : 2))
            }
        }
    }

    func loadRecentSecurityReview(completion: @escaping (Result<[GuardEvent], Error>) -> Void) {
        guard let database else {
            completion(.failure(EventStoreReadError.databaseUnavailable)); return
        }
        persistenceQueue.async {
            let result = Result { try database.recentSecurityReviewEvidence(limit: 200) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    func loadSecurityEvidence(ids: [String], completion: @escaping (Result<[GuardEvent], Error>) -> Void) {
        guard let database else { completion(.failure(EventStoreReadError.databaseUnavailable)); return }
        persistenceQueue.async {
            let result = Result { try database.securityEvidence(ids: ids) }
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
                try Self.refreshDirtyCodeIndexes(projectID: projectID, database: database)
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
                try Self.refreshDirtyCodeIndexes(projectID: projectID, database: database)
                // Change sets are a replaceable projection. Rebuild only when
                // the user opens this project's history so parser/indexer fixes
                // take effect without a costly all-project startup migration.
                let events = try database.agentEvents(projectID: projectID)
                let changes = try database.codeChanges(projectID: projectID)
                try database.replaceChangeSets(projectID: projectID,
                    values: ChangeSetIndexer.build(projectID: projectID,
                        events: events, changes: changes))
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

    nonisolated private static func refreshDirtyCodeIndexes(projectID: String, database: EvidenceDatabase) throws {
        // Only called on persistenceQueue: ingestion cannot invalidate a
        // session between rebuilding and acknowledging it.
        for sessionID in try database.dirtyCodeSessions(projectID: projectID) {
            try database.upsertCodeChanges(CodeChangeIndexer.build(events: try database.agentEvents(sessionID: sessionID)))
            try database.clearDirtyCodeSession(projectID: projectID, sessionID: sessionID)
        }
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
        // Live collection resumes from durable cursors; history stays on demand.
        events = []
    }

    private func trimAndSave() {
        commitEvents(events, evidence: [])
    }

    /// Publish one coherent snapshot per ingest batch. Mutating the @Published
    /// array once per event made SwiftUI rebuild the entire dashboard hundreds
    /// of times while a live session was being tailed.
    private func commitEvents(_ incoming: [GuardEvent], evidence: [GuardEvent], persist: Bool = true) {
        for event in evidence {
            guard let sessionID = event.sessionId, let turnID = event.turnId else { continue }
            let key = "\(sessionID)\u{0}\(turnID)"
            var progress = taskProgress[key] ?? TaskLiveProgress(
                sessionID: sessionID, turnID: turnID,
                startedAt: event.startedAt ?? event.ts, lastActivityAt: event.ts,
                phase: .preparing)
            progress.ingest(event)
            taskProgress[key] = progress
        }
        if taskProgress.count > 64 {
            // Never evict a live task: the history scheduler uses this map to
            // decide whether it may consume background I/O and database time.
            let active = taskProgress.values.filter { progress in
                switch progress.phase {
                case .completed, .failed: return false
                default: return true
                }
            }
            let terminal = taskProgress.values.filter { progress in
                switch progress.phase {
                case .completed, .failed: return true
                default: return false
                }
            }.sorted { $0.lastActivityAt > $1.lastActivityAt }
            let retained = active + Array(terminal.prefix(max(0, 64 - active.count)))
            taskProgress = Dictionary(uniqueKeysWithValues: retained.map {
                ("\($0.sessionID)\u{0}\($0.turnID)", $0)
            })
        }
        var snapshot = incoming.sorted { $0.ts > $1.ts }
        if snapshot.count > maximumEvents { snapshot.removeLast(snapshot.count - maximumEvents) }
        events = snapshot
        scheduleDerivedProjection(events: snapshot)
        guard persist else { return }
        if let database, let evidenceBuffer {
            persistenceQueue.async { [weak self] in
                do {
                    let grouped = Dictionary(grouping: evidence.filter { $0.sessionId != nil },
                                             by: { $0.sessionId! })
                    for (sessionID, sessionEvidence) in grouped {
                        let session = AgentSessionSnapshot.build(from: sessionEvidence).first
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
                        // Code indexes and change sets are rebuilt on demand.
                        // Live ingestion must not regroup the entire project.
                    }
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

    nonisolated private static func canonicalProjectID(session: AgentSessionSnapshot?,
                                                       sessionID: String) -> String {
        let workspace = SupervisedWorkspaceResolver.resolve(session?.workspace)
        return workspace.kind == .unassigned ? "unattributed:\(sessionID)" : workspace.id
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
