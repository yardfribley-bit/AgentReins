import Foundation
import SQLite3
import XCTest
@testable import AgentReins

final class RealtimeCheckpointDatabaseTests: XCTestCase {
    private func location() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root.appendingPathComponent("active.json")
    }
    private func event(_ session: String, id: UUID = UUID(), output: String = "hello", at: Date = Date()) -> GuardEvent {
        GuardEvent(id: id, kind: "model", ruleId: "fixture", path: "-", command: nil, agent: "codex",
            op: "prompt", severity: "info", ts: at, action: "sent", sessionId: session, turnId: "turn",
            userIntent: "真实原始需求", modelResponse: output)
    }
    private func sql(_ url: URL, _ query: String) throws {
        var handle: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &handle), SQLITE_OK)
        defer { sqlite3_close(handle) }
        XCTAssertEqual(sqlite3_exec(handle, query, nil, nil, nil), SQLITE_OK)
    }
    func testUnchangedBodyIsNotReadOrRewrittenAndRestartPreservesFullText() throws {
        let url = try location(), old = event("old", output: String(repeating: "完整命令输出\n", count: 1_000_000))
        var buffer = RealtimeLiveEvidenceBuffer(); buffer.insert(old)
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let writer = RealtimeActiveCheckpoint.Writer(url: url, useDatabase: true)
        XCTAssertEqual(try writer.save(records: buffer.snapshot().records, readTaskIDs: [], coverageTruncated: true).serializedEvents, 1)
        for record in buffer.snapshot().records {
            if case .cold(let lease, _, _) = record.body { try FileManager.default.removeItem(at: lease.url) }
        }
        let new = event("new"); buffer.insert(new)
        let metrics = try writer.save(records: buffer.snapshot().records, readTaskIDs: ["read"], coverageTruncated: true)
        XCTAssertEqual(metrics.serializedEvents, 1); XCTAssertEqual(metrics.reusedEvents, 1)
        let restored = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(restored.events.first { $0.id == old.id }, old)
        XCTAssertEqual(restored.events.first { $0.id == new.id }, new)
        XCTAssertEqual(restored.readTaskIDs, ["read"]); XCTAssertTrue(restored.coverageTruncated)
        let idle = try writer.save(records: buffer.snapshot().records, readTaskIDs: ["read"], coverageTruncated: true)
        XCTAssertEqual(idle.serializedEvents, 0)
    }
    func testRestartKeepsOnlyEventsInsideTheMemoryBudget() throws {
        let url = try location()
        let older = event("older", output: String(repeating: "x", count: 8_000), at: Date(timeIntervalSince1970: 1))
        let newer = event("newer", output: "kept", at: Date(timeIntervalSince1970: 2))
        var buffer = RealtimeLiveEvidenceBuffer()
        buffer.insert(older); buffer.insert(newer)
        try RealtimeActiveCheckpoint.Writer(url: url, useDatabase: true).save(records: buffer.snapshot().records, readTaskIDs: [], coverageTruncated: false)
        let restored = try XCTUnwrap(RealtimeCheckpointDatabase(url: RealtimeCheckpointDatabase.location(for: url)).load(maximumRawBytes: 2_000))
        XCTAssertEqual(restored.events.map(\.id), [newer.id])
        XCTAssertTrue(restored.coverageTruncated)
        let again = try XCTUnwrap(RealtimeActiveCheckpoint.load(url, maximumRawBytes: 2_000))
        XCTAssertEqual(again.events.map(\.id), [newer.id])
    }
    func testFailedTransactionKeepsPreviousEventsAndMetadata() throws {
        let url = try location(), old = event("old")
        var buffer = RealtimeLiveEvidenceBuffer(); buffer.insert(old)
        let writer = RealtimeActiveCheckpoint.Writer(url: url, useDatabase: true)
        try writer.save(records: buffer.snapshot().records, readTaskIDs: ["previous"], coverageTruncated: true)
        try sql(RealtimeCheckpointDatabase.location(for: url), "CREATE TRIGGER reject_new BEFORE INSERT ON live_events WHEN NEW.session='reject' BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        buffer.insert(event("reject"))
        XCTAssertThrowsError(try writer.save(records: buffer.snapshot().records, readTaskIDs: ["must rollback"], coverageTruncated: false))
        let restored = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(restored.events, [old]); XCTAssertEqual(restored.readTaskIDs, ["previous"])
        XCTAssertTrue(restored.coverageTruncated)
    }
    func testLegacyMigrationAndDatabaseChecksumFailureAreExplicit() throws {
        let url = try location(), old = event("old")
        let checkpoint = RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [old], readTaskIDs: [], coverageTruncated: true)
        try checkpoint.save(url)
        let legacyBytes = try Data(contentsOf: url)
        var buffer = RealtimeLiveEvidenceBuffer()
        for event in try XCTUnwrap(RealtimeActiveCheckpoint.load(url)).events { buffer.insert(event) }
        try RealtimeActiveCheckpoint.Writer(url: url, useDatabase: true).save(records: buffer.snapshot().records, readTaskIDs: [], coverageTruncated: true)
        XCTAssertEqual(try Data(contentsOf: url), legacyBytes, "Migration must preserve the previous recovery format")
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events, [old])
        try sql(RealtimeCheckpointDatabase.location(for: url), "UPDATE live_events SET sha256='corrupt'")
        XCTAssertThrowsError(try RealtimeActiveCheckpoint.load(url), "Never fall back silently to an older JSON checkpoint on database corruption")
    }
}
