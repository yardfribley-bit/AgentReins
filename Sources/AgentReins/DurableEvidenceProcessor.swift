import Foundation

/// Resumes persisted normalization work on launch. The canonical events and
/// acknowledgement are committed atomically by EvidenceDatabase.
actor DurableEvidenceProcessor {
    private let database: EvidenceDatabase
    private var nextSecurityBackfill = Date.distantPast

    init(database: EvidenceDatabase) { self.database = database }

    func processSlice() throws -> Int {
        if Date() >= nextSecurityBackfill {
            try database.advanceSecurityInputIndex(limit: 4)
            nextSecurityBackfill = Date().addingTimeInterval(1)
        }
        let deadline = Date().addingTimeInterval(0.05)
        var processed = 0
        repeat {
            guard let job = try database.claimParseJob() else { break }
            do {
                let evidence = [job.event]
                let session = AgentSessionSnapshot.build(from: evidence).first
                let sessionID = job.event.sessionId ?? "unattributed:\(job.event.agent ?? "unknown")"
                let workspace = SupervisedWorkspaceResolver.resolve(session?.workspace)
                let projectID = workspace.kind == .unassigned
                    ? "unattributed:\(sessionID)" : workspace.id
                let next = try database.nextAgentEventSequence(sessionID: sessionID)
                let events = LegacyGuardEventAdapter.project(
                    evidence, projectID: projectID, startingSequence: next - 1)
                try database.appendAgentEvents(events, completing: job)
                processed += 1
            } catch {
                try database.retryParseJob(job, message: error.localizedDescription)
            }
        } while processed < 25 && Date() < deadline
        return processed
    }
}

actor DurableAnalysisProcessor {
    private let database: EvidenceDatabase

    init(database: EvidenceDatabase) { self.database = database }

    func enqueueHistoricalBatch(limit: Int = 25) throws -> Int {
        try database.enqueueHistoricalAnalysisJobs(limit: limit)
    }

    func processOne() throws -> Bool {
        guard let job = try database.claimAnalysisJob() else { return false }
        do {
            let evidence = try database.events(sessionId: job.sessionID, turnID: job.turnID)
            let assessments = ForensicAssessmentRecord.build(events: evidence)
            let routes = ModelRouteEvidence.build(events: evidence)
            let memory = MemoryCommitEvidence.build(events: evidence)
            guard let session = AgentSessionSnapshot.build(from: evidence).first(where: { $0.id == job.sessionID }) else {
                throw EventStoreReadError.sessionNotFound(job.sessionID)
            }
            let prompt = evidence.first { $0.kind == "model" && $0.op == "prompt" }
            let boundary = try prompt.flatMap {
                try database.nextPromptDate(sessionID: job.sessionID, turnID: job.turnID, after: $0.ts)
            }
            let snapshot = AgentTaskSnapshot.build(session: session, turnID: job.turnID, nextPromptAt: boundary)
            try database.completeAnalysisJob(job, assessments: assessments, routes: routes,
                                             memory: memory, snapshot: snapshot)
            return true
        } catch {
            try database.retryAnalysisJob(job, message: error.localizedDescription)
            return false
        }
    }
}
