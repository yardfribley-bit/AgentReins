import Foundation
import SQLite3
import XCTest
@testable import AgentReins

/// Architecture acceptance checks use isolated databases and injected SQLite
/// failures. A red test records an unmet contract, not an expected success.
final class PipelineArchitectureAcceptanceTests: XCTestCase {
    private var directory: URL!
    private var database: EvidenceDatabase!
    private var handle: OpaquePointer?

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("pipeline-acceptance-" + UUID().uuidString)
        let url = directory.appendingPathComponent("evidence.sqlite3")
        database = try EvidenceDatabase(url: url)
        guard sqlite3_open(url.path, &handle) == SQLITE_OK else { throw CocoaError(.fileReadUnknown) }
    }

    override func tearDownWithError() throws {
        sqlite3_close(handle); handle = nil
        database = nil
        if let directory { try FileManager.default.removeItem(at: directory) }
    }

    private func sql(_ statement: String) throws {
        guard sqlite3_exec(handle, statement, nil, nil, nil) == SQLITE_OK else {
            throw NSError(domain: "AcceptanceSQLite", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(handle))])
        }
    }

    private func count(_ table: String) throws -> Int {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM " + table, -1, &statement, nil) == SQLITE_OK else {
            throw CocoaError(.fileReadUnknown)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw CocoaError(.fileReadUnknown) }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func scalarDouble(_ sql: String) throws -> Double {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK else { throw CocoaError(.fileReadUnknown) }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw CocoaError(.fileReadUnknown) }
        return sqlite3_column_double(statement, 0)
    }

    private func event(_ session: String = "session", body: String = "hello") -> GuardEvent {
        GuardEvent(kind: "model", ruleId: "fixture", path: "/tmp/fixture", command: nil,
                   agent: "workbuddy", op: "prompt", severity: "info", ts: Date(),
                   action: "sent", sessionId: session, turnId: "turn",
                   userIntent: body, modelPrompt: body)
    }

    private func snapshot(_ rows: [GuardEvent]) throws -> AgentTaskSnapshot {
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: rows).first)
        return AgentTaskSnapshot.build(session: session, turnID: rows.first?.turnId)
    }

    func testReceptionRollbackWhenWorkRegistrationFails() throws {
        try sql("CREATE TRIGGER reject_work BEFORE INSERT ON evidence_parse_jobs BEGIN SELECT RAISE(ABORT,'injected registration failure'); END")
        XCTAssertThrowsError(try database.append([event()]))
        XCTAssertEqual(try count("evidence_records"), 0)
        XCTAssertEqual(try count("evidence_parse_jobs"), 0)
        try sql("DROP TRIGGER reject_work")
        try database.append([event()])
        XCTAssertNotNil(try database.claimParseJob())
    }

    func testCheckpointFailureRollsBackEntireCaptureBatch() throws {
        let checkpoint = SourceCheckpoint(source: "fixture", stream: "stream", offset: 4,
                                          fingerprint: nil, updatedAt: Date())
        let raw = RawEvidenceRecord(source: "fixture", stream: "stream", offsetStart: 0,
                                    offsetEnd: 4, fingerprint: nil, observedAt: Date(), payload: Data("data".utf8))
        let states = [(source: "fixture", stream: "stream", state: Data("{}".utf8))]
        try sql("CREATE TRIGGER reject_checkpoint BEFORE INSERT ON source_checkpoints BEGIN SELECT RAISE(ABORT,'injected checkpoint failure'); END")
        XCTAssertThrowsError(try database.persistCollected(raw: [raw], events: [event()],
            checkpoints: [checkpoint], parserStates: states))
        for table in ["raw_evidence", "raw_chain_state", "evidence_records", "evidence_parse_jobs",
                      "evidence_parse_order", "collector_parser_state", "source_checkpoints"] {
            XCTAssertEqual(try count(table), 0, table)
        }
        try sql("DROP TRIGGER reject_checkpoint")
        try database.persistCollected(raw: [raw], events: [event()],
            checkpoints: [checkpoint], parserStates: states)
        XCTAssertEqual(try database.checkpoint(source: "fixture", stream: "stream")?.offset, 4)
        XCTAssertEqual(try count("evidence_parse_jobs"), 1)
        XCTAssertEqual(try count("agent_event_stream"), 0, "Reception must defer normalization to the consumer")
        XCTAssertTrue(try database.verifyIntegrity())
    }

    func testConfirmationFailureRollsBackEventsAndSummary() throws {
        try database.append([event()])
        let job = try XCTUnwrap(database.claimParseJob())
        let events = LegacyGuardEventAdapter.project([job.event], projectID: "p", startingSequence: 0)
        XCTAssertFalse(events.isEmpty)
        try sql("CREATE TRIGGER reject_ack BEFORE UPDATE ON evidence_parse_jobs WHEN NEW.state='done' BEGIN SELECT RAISE(ABORT,'injected acknowledgement failure'); END")
        XCTAssertThrowsError(try database.appendAgentEvents(events, completing: job))
        XCTAssertEqual(try count("agent_event_stream"), 0)
        XCTAssertEqual(try count("task_summary"), 0)
        try sql("DROP TRIGGER reject_ack")
        try database.appendAgentEvents(events, completing: job)
        XCTAssertEqual(try count("agent_event_stream"), events.count)
        XCTAssertNil(try database.claimParseJob())
    }

    func testSameSessionCannotOvertakeRetryingPredecessor() throws {
        try database.append([event()])
        let first = try XCTUnwrap(database.claimParseJob())
        try database.retryParseJob(first, message: "injected transient failure")
        try database.append([event(body: "second")])
        XCTAssertNil(try database.claimParseJob(), "V2 requires ordering within a session; a retrying predecessor must fence later work.")
    }

    func testDifferentSessionCanProceedDuringRetry() throws {
        try database.append([event("first")])
        let first = try XCTUnwrap(database.claimParseJob())
        try database.retryParseJob(first, message: "injected transient failure")
        try database.append([event("second")])
        let next = try XCTUnwrap(database.claimParseJob())
        XCTAssertEqual(next.event.sessionId, "second")
    }

    func testSuccessorBecomesAvailableOnlyAfterPredecessorCompletes() throws {
        try database.append([event(body: "first"), event(body: "second")])
        let first = try XCTUnwrap(database.claimParseJob())
        XCTAssertEqual(first.event.modelPrompt, "first")
        XCTAssertNil(try database.claimParseJob())
        let canonical = LegacyGuardEventAdapter.project([first.event], projectID: "p", startingSequence: 0)
        try database.appendAgentEvents(canonical, completing: first)
        XCTAssertEqual(try database.claimParseJob()?.event.modelPrompt, "second")
    }

    func testLegacyQueueMigrationPreservesRetryFence() throws {
        try database.append([event(body: "first")])
        let first = try XCTUnwrap(database.claimParseJob())
        try database.retryParseJob(first, message: "temporary")
        try database.append([event(body: "second")])
        // Recreate the previous schema state without changing durable evidence.
        try sql("DROP TRIGGER evidence_parse_admission")
        try sql("DROP TABLE evidence_parse_order")
        try sql("DROP TABLE evidence_pipeline_migrations")
        database = nil
        database = try EvidenceDatabase(url: directory.appendingPathComponent("evidence.sqlite3"))
        XCTAssertEqual(try count("evidence_parse_order"), 2)
        XCTAssertNil(try database.claimParseJob())
        database = nil
        database = try EvidenceDatabase(url: directory.appendingPathComponent("evidence.sqlite3"))
        XCTAssertEqual(try count("evidence_parse_order"), 2)
        XCTAssertNil(try database.claimParseJob())
    }

    func testIsolatedPredecessorKeepsItsPartitionFenced() throws {
        try database.append([event(body: "bad")])
        try sql("UPDATE evidence_records SET payload=x'7b7d'")
        XCTAssertNil(try database.claimParseJob())
        try database.append([event(body: "later"), event("other")])
        XCTAssertEqual(try database.claimParseJob()?.event.sessionId, "other")
    }

    func testCorruptRecordIsIsolatedAndOtherWorkRemainsReadable() throws {
        try database.append([event()])
        // Valid JSON avoids the JSON expression index rejecting our injection;
        // missing required fields exercises the consumer's decoding failure.
        try sql("UPDATE evidence_records SET payload=x'7b7d'")
        XCTAssertNil(try database.claimParseJob())
        try database.append([event("healthy")])
        XCTAssertEqual(try database.claimParseJob()?.event.sessionId, "healthy")
    }

    func testProcessorPersistsResultsAndDoesNotReplayFinishedWork() async throws {
        try database.append([event()])
        let processor = DurableEvidenceProcessor(database: database)
        let firstCount = try await processor.processSlice()
        XCTAssertEqual(firstCount, 1)
        let stored = try database.agentEvents(sessionID: "session")
        XCTAssertFalse(stored.isEmpty)
        let secondCount = try await processor.processSlice()
        XCTAssertEqual(secondCount, 0)
        XCTAssertEqual(try database.agentEvents(sessionID: "session").count, stored.count)
    }

    func testAnalysisWorkIsDurableAndLateEvidenceCreatesNewRevision() async throws {
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let firstSlice = try await normalizer.processSlice()
        XCTAssertEqual(firstSlice, 1)
        let first = try XCTUnwrap(database.claimAnalysisJob())
        XCTAssertEqual(first.revision, 1)
        let firstRows = try database.events(sessionId: first.sessionID, turnID: first.turnID)
        try database.completeAnalysisJob(first, assessments: [], routes: [], memory: [], snapshot: try snapshot(firstRows))
        XCTAssertNil(try database.claimAnalysisJob())
        XCTAssertNotNil(try database.taskSnapshot(sessionID: first.sessionID, turnID: first.turnID))

        let late = event(body: "late evidence")
        try database.append([late])
        let secondSlice = try await normalizer.processSlice()
        XCTAssertEqual(secondSlice, 1)
        let second = try XCTUnwrap(database.claimAnalysisJob())
        XCTAssertEqual(second.revision, 2)
        let secondRows = try database.events(sessionId: second.sessionID, turnID: second.turnID)
        try database.completeAnalysisJob(second, assessments: [], routes: [], memory: [], snapshot: try snapshot(secondRows))
        XCTAssertNil(try database.claimAnalysisJob())
    }

    func testAnalysisConfirmationFailureRollsBackDerivedWrites() async throws {
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let slice = try await normalizer.processSlice()
        XCTAssertEqual(slice, 1)
        let job = try XCTUnwrap(database.claimAnalysisJob())
        let evidence = try database.events(sessionId: job.sessionID, turnID: job.turnID)
        try sql("CREATE TRIGGER reject_analysis_ack BEFORE UPDATE ON evidence_analysis_jobs WHEN NEW.state='done' BEGIN SELECT RAISE(ABORT,'injected analysis ack failure'); END")
        XCTAssertThrowsError(try database.completeAnalysisJob(job,
            assessments: ForensicAssessmentRecord.build(events: evidence),
            routes: ModelRouteEvidence.build(events: evidence),
            memory: MemoryCommitEvidence.build(events: evidence), snapshot: try snapshot(evidence)))
        XCTAssertEqual(try count("forensic_assessments"), 0)
        XCTAssertEqual(try count("model_route_evidence"), 0)
        XCTAssertEqual(try count("memory_commits"), 0)
        XCTAssertEqual(try count("task_snapshot_projection"), 0)
        try sql("DROP TRIGGER reject_analysis_ack")
        try database.completeAnalysisJob(job,
            assessments: ForensicAssessmentRecord.build(events: evidence),
            routes: ModelRouteEvidence.build(events: evidence),
            memory: MemoryCommitEvidence.build(events: evidence), snapshot: try snapshot(evidence))
        XCTAssertNil(try database.claimAnalysisJob())
    }

    func testAuditOutboxWaitsForMatchingProjectionAndSurvivesRestart() async throws {
        database.setAuditUploadEnabled(true)
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let normalized = try await normalizer.processSlice()
        XCTAssertEqual(normalized, 1)
        XCTAssertNil(try database.claimAuditUploadJob(), "Upload must never read an unfinished task projection")

        let analysis = try XCTUnwrap(database.claimAnalysisJob())
        let rows = try database.events(sessionId: analysis.sessionID, turnID: analysis.turnID)
        try database.completeAnalysisJob(analysis, assessments: [], routes: [], memory: [], snapshot: try snapshot(rows))

        database = nil
        database = try EvidenceDatabase(url: directory.appendingPathComponent("evidence.sqlite3"))
        let upload = try XCTUnwrap(database.claimAuditUploadJob())
        XCTAssertEqual(upload.revision, analysis.revision)
        XCTAssertEqual(upload.snapshot.task.sessionID, analysis.sessionID)
        try database.completeAuditUploadJob(upload, receiptID: "receipt-1")
        XCTAssertNil(try database.claimAuditUploadJob())
    }

    func testLateEvidenceInvalidatesCompletedAuditRevision() async throws {
        database.setAuditUploadEnabled(true)
        let normalizer = DurableEvidenceProcessor(database: database)
        try database.append([event(body: "first")])
        let firstNormalized = try await normalizer.processSlice()
        XCTAssertEqual(firstNormalized, 1)
        let firstAnalysis = try XCTUnwrap(database.claimAnalysisJob())
        let firstRows = try database.events(sessionId: firstAnalysis.sessionID, turnID: firstAnalysis.turnID)
        try database.completeAnalysisJob(firstAnalysis, assessments: [], routes: [], memory: [], snapshot: try snapshot(firstRows))
        let firstUpload = try XCTUnwrap(database.claimAuditUploadJob())
        try database.completeAuditUploadJob(firstUpload, receiptID: "receipt-1")

        try database.append([event(body: "late")])
        let secondNormalized = try await normalizer.processSlice()
        XCTAssertEqual(secondNormalized, 1)
        XCTAssertNil(try database.claimAuditUploadJob(), "The stale projection must not satisfy the new outbox revision")
        let secondAnalysis = try XCTUnwrap(database.claimAnalysisJob())
        let secondRows = try database.events(sessionId: secondAnalysis.sessionID, turnID: secondAnalysis.turnID)
        try database.completeAnalysisJob(secondAnalysis, assessments: [], routes: [], memory: [], snapshot: try snapshot(secondRows))
        let secondUpload = try XCTUnwrap(database.claimAuditUploadJob())
        XCTAssertEqual(secondUpload.revision, firstUpload.revision + 1)
    }

    func testAuditRetryHonorsServerRetryAfter() async throws {
        database.setAuditUploadEnabled(true)
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let normalized = try await normalizer.processSlice()
        XCTAssertEqual(normalized, 1)
        let analysis = try XCTUnwrap(database.claimAnalysisJob())
        let rows = try database.events(sessionId: analysis.sessionID, turnID: analysis.turnID)
        try database.completeAnalysisJob(analysis, assessments: [], routes: [], memory: [], snapshot: try snapshot(rows))
        let upload = try XCTUnwrap(database.claimAuditUploadJob())
        let now = Date().timeIntervalSince1970
        try database.retryAuditUploadJob(upload, message: "server busy", retryAfter: 42)
        let scheduled = try scalarDouble("SELECT not_before FROM audit_upload_outbox")
        XCTAssertGreaterThanOrEqual(scheduled, now + 41)
        XCTAssertLessThanOrEqual(scheduled, now + 43)
        XCTAssertNil(try database.claimAuditUploadJob(now: Date().addingTimeInterval(41)))
        XCTAssertNotNil(try database.claimAuditUploadJob(now: Date().addingTimeInterval(43)))
    }

    func testIdleBackfillMaterializesLegacyTasksWithoutUploadingThem() async throws {
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let normalized = try await normalizer.processSlice()
        XCTAssertEqual(normalized, 1)

        // Model a task that existed before analysis/outbox tables were added.
        try sql("DELETE FROM evidence_analysis_jobs")
        try sql("DELETE FROM audit_upload_outbox")
        let processor = DurableAnalysisProcessor(database: database)
        let queued = try await processor.enqueueHistoricalBatch(limit: 25)
        XCTAssertEqual(queued, 1)
        XCTAssertEqual(try count("audit_upload_outbox"), 0)
        let job = try XCTUnwrap(database.claimAnalysisJob())
        let rows = try database.events(sessionId: job.sessionID, turnID: job.turnID)
        try database.completeAnalysisJob(job, assessments: [], routes: [], memory: [], snapshot: try snapshot(rows))
        XCTAssertNotNil(try database.taskSnapshot(sessionID: job.sessionID, turnID: job.turnID))
        XCTAssertEqual(try count("audit_upload_outbox"), 0, "Historical materialization must remain local")
        let remaining = try await processor.enqueueHistoricalBatch(limit: 25)
        XCTAssertEqual(remaining, 0)
    }

    func testDisabledCloudAuditDoesNotAccumulateOutboxRows() async throws {
        try database.append([event()])
        let normalizer = DurableEvidenceProcessor(database: database)
        let normalized = try await normalizer.processSlice()
        XCTAssertEqual(normalized, 1)
        XCTAssertEqual(try count("evidence_analysis_jobs"), 1)
        XCTAssertEqual(try count("audit_upload_outbox"), 0,
                       "Local-only installs must not retain permanent unused upload work")
    }
}
