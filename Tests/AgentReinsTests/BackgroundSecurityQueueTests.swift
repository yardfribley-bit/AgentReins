import XCTest
import SQLite3
@testable import AgentReins

final class BackgroundSecurityQueueTests: XCTestCase {
    func testFailedTaskStopsAfterThreeAttemptsAndDoesNotBlockNextTask() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let evidenceURL = directory.appendingPathComponent("evidence.sqlite3")
        var source: OpaquePointer?
        XCTAssertEqual(sqlite3_open(evidenceURL.path, &source), SQLITE_OK)
        defer { sqlite3_close(source) }
        XCTAssertEqual(sqlite3_exec(source, "CREATE TABLE task_snapshot_projection(session_id TEXT,turn_id TEXT,revision INTEGER,generated_at REAL,payload BLOB); INSERT INTO task_snapshot_projection VALUES('a','turn',1,100,x'01'),('b','turn',1,50,x'01');", nil, nil, nil), SQLITE_OK)

        let queue = try BackgroundSecurityQueue(url: directory.appendingPathComponent("queue.sqlite3"), evidenceURL: evidenceURL)
        try await queue.discover()
        for attempt in 1...3 {
            let candidate = try await queue.next(now: .distantFuture)
            let job = try XCTUnwrap(candidate)
            XCTAssertEqual(job.session, "b")
            try await queue.fail(job, message: "timeout", now: Date(timeIntervalSince1970: Double(attempt)))
        }
        let candidate = try await queue.next(now: .distantFuture)
        let next = try XCTUnwrap(candidate)
        XCTAssertEqual(next.session, "a")
        let status = try await queue.status()
        XCTAssertEqual(status.failed, 1)
        XCTAssertEqual(status.pending, 2)
    }

    func testPartialCoveragePersistsAndYieldLetsAnotherTaskRun() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let evidenceURL = directory.appendingPathComponent("evidence.sqlite3")
        let queueURL = directory.appendingPathComponent("queue.sqlite3")
        var source: OpaquePointer?
        XCTAssertEqual(sqlite3_open(evidenceURL.path, &source), SQLITE_OK)
        defer { sqlite3_close(source) }
        XCTAssertEqual(sqlite3_exec(source, "CREATE TABLE task_snapshot_projection(session_id TEXT,turn_id TEXT,revision INTEGER,generated_at REAL,payload BLOB); INSERT INTO task_snapshot_projection VALUES('a','t',1,1,x'01'),('b','t',1,2,x'01');", nil, nil, nil), SQLITE_OK)
        let queue = try BackgroundSecurityQueue(url: queueURL, evidenceURL: evidenceURL)
        try await queue.discover()
        let candidate = try await queue.next()
        let job = try XCTUnwrap(candidate)
        XCTAssertEqual(job.session, "a")
        try await queue.registerSlices(job, context: "model-v1", chunks: ["first", "last"])
        let report = HistoricalSecurityAnalysis(findings: [], rules: [], generatedAt: nil, model: "test", examinationPasses: 2)
        try await queue.saveSlice(job, context: "model-v1", chunk: "first", report: report)
        try await queue.yieldJob(job)
        let next = try await queue.next()
        XCTAssertEqual(next?.session, "b")
        let reopened = try BackgroundSecurityQueue(url: queueURL, evidenceURL: evidenceURL)
        let partial = try await reopened.sliceCoverage(job)
        XCTAssertEqual(partial.total, 2)
        XCTAssertEqual(partial.completed, 1)
        do {
            try await reopened.complete(job, report: report)
            XCTFail("Partial work must not be marked complete")
        } catch { }
        try await reopened.saveSlice(job, context: "model-v1", chunk: "last", report: report)
        try await reopened.complete(job, report: report)
        let completed = try await reopened.status()
        XCTAssertEqual(completed.completed, 1)
        try await reopened.registerSlices(job, context: "model-v2", chunks: ["first", "last"])
        let changed = try await reopened.sliceCoverage(job)
        XCTAssertEqual(changed.completed, 0)
    }
}
