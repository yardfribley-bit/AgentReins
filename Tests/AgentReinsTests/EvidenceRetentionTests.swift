import AgentReinsCore
import XCTest
@testable import AgentReins

final class EvidenceRetentionTests: XCTestCase {
    func testAgePruneKeepsRecentEvidence() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let old = GuardEvent(kind: "activity", ruleId: "old", path: "-", command: "old",
                              agent: "codex", op: "exec", severity: "info",
                              ts: Date().addingTimeInterval(-40 * 24 * 60 * 60), action: "observed", source: "retention")
        let recent = GuardEvent(kind: "activity", ruleId: "new", path: "-", command: "new",
                                agent: "codex", op: "exec", severity: "info",
                                ts: Date(), action: "observed", source: "retention")
        try database.append([old, recent])
        var policy = EvidenceRetentionPolicy.default
        policy.maxBytes = Int64.max
        policy.batchRows = 50
        policy.maxBatches = 5
        let result = try database.prune(policy: policy)
        XCTAssertGreaterThan(result.deletedRecords, 0)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [recent.id])
        XCTAssertLessThan(result.batches, 6)
    }

    func testSizeCapDeletesOldestFirstAndStopsAfterTheBatchCap() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let older = GuardEvent(kind: "activity", ruleId: "older", path: "-", command: "older",
                                agent: "codex", op: "exec", severity: "info",
                                ts: Date().addingTimeInterval(-3600), action: "observed", source: "retention")
        let newer = GuardEvent(kind: "activity", ruleId: "newer", path: "-", command: "newer",
                                agent: "codex", op: "exec", severity: "info",
                                ts: Date(), action: "observed", source: "retention")
        try database.append([older, newer])
        var policy = EvidenceRetentionPolicy.default
        policy.maxAge = 3650 * 24 * 60 * 60
        policy.maxBytes = 1
        policy.batchRows = 1
        policy.maxBatches = 1
        let result = try database.prune(policy: policy)
        XCTAssertEqual(result.batches, 1)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [newer.id])
        XCTAssertEqual(EvidenceRetentionDefaults.maxAge, 14 * 24 * 60 * 60)
        XCTAssertEqual(EvidenceRetentionDefaults.maxBytes, 2 * 1024 * 1024 * 1024)
    }
}
