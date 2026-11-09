import XCTest
import AgentReinsCore
@testable import AgentReins

final class FileLayerCaptureTests: XCTestCase {
    func testCredentialReadIsKeptUnderTmpAndPrivateTmp() {
        let hits = FileLayerCapture.hits(opens: [
            .init(path: "/tmp/fake.env", writable: false),
            .init(path: "/private/tmp/proj/.env.local", writable: false),
            .init(path: "/Users/me/.ssh/id_ed25519", writable: false),
            .init(path: "/Users/me/Library/Keychains/login.keychain-db", writable: false),
            .init(path: "/tmp/api_token", writable: false),
            .init(path: "/tmp/notes.txt", writable: false),
        ], workspace: "/Users/me/project")
        XCTAssertEqual(hits.map(\.path), [
            "/tmp/fake.env", "/private/tmp/proj/.env.local", "/Users/me/.ssh/id_ed25519",
            "/Users/me/Library/Keychains/login.keychain-db", "/tmp/api_token",
        ])
        XCTAssertTrue(hits.allSatisfy { $0.op == "read" && $0.credential })
    }

    func testWriteOutsideWorkspaceIsRecordedAndInsideWorkspaceIsNot() {
        let hits = FileLayerCapture.hits(opens: [
            .init(path: "/Users/me/project/note.txt", writable: true),
            .init(path: "/tmp/note.txt", writable: true),
            .init(path: "/Users/me/Library/Application Support/AgentGuard/evidence.sqlite3", writable: true),
        ], workspace: "/Users/me/project")
        XCTAssertEqual(hits.map(\.path), ["/tmp/note.txt"])
        XCTAssertEqual(hits.first?.op, "modify")
        XCTAssertEqual(hits.first?.credential, false)
    }

    func testBuiltinCredentialListDoesNotDependOnRules() {
        let files = FileLayerCapture.builtinCredentialFiles(home: "/Users/me")
        XCTAssertTrue(files.contains("/Users/me/.ssh/id_ed25519"))
        XCTAssertTrue(files.contains("/Users/me/.aws/credentials"))
        XCTAssertTrue(files.contains("/Users/me/Library/Keychains/login.keychain-db"))
    }

    func testCommandRedirectOutsideWorkspaceAndTmpEnv() {
        let hits = FileLayerCapture.commandTargets("curl https://example.test; cat /tmp/fake.env; echo hi > /tmp/note.txt")
        XCTAssertTrue(hits.contains { $0.path == "/tmp/fake.env" && $0.op == "read" && $0.credential })
        XCTAssertTrue(hits.contains { $0.path == "/tmp/note.txt" && $0.op == "modify" })
    }
}

final class MCPHealthAndStaleDataTests: XCTestCase {
    func testLegacyBundleIsReapedWithoutTheCurrentPid() {
        let procs = [
            MCPHTTPOrphans.Proc(pid: 10, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 11, ppid: 1, command: "/Users/me/AgentSpec/AgentGuardApp/.build/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 12, ppid: 1, command: "/Users/me/AgentSpec/AgentGuardApp/.build/AgentReinsMCP --http --port 19000"),
            MCPHTTPOrphans.Proc(pid: 13, ppid: 1, command: "/usr/bin/python3"),
        ]
        let victims = MCPHTTPOrphans.reapPIDs(procs, selfPid: 10, port: 18977, listenerPIDs: [10])
        XCTAssertEqual(victims, [11])
        let includingListener = MCPHTTPOrphans.reapPIDs(procs, selfPid: 99, port: 18977, listenerPIDs: [11])
        XCTAssertTrue(includingListener.contains(11))
        XCTAssertFalse(includingListener.contains(99))
        XCTAssertFalse(includingListener.contains(12))
    }

    func testHealthCheckKillsOnlyAnOldHttpProcessWhenThePortIsDown() {
        let now = Date(timeIntervalSince1970: 1_000)
        let procs = [
            MCPHTTPOrphans.Proc(pid: 4, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 5, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 19000"),
        ]
        let started = [
            4: now.addingTimeInterval(-30),
            5: now.addingTimeInterval(-30),
        ]
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: true, now: now, startedAt: started), [])
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: false, now: now, startedAt: started), [4])
        let young = [4: now.addingTimeInterval(-2)]
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: false, now: now, startedAt: young), [])
    }

    func testStaleSuggestionsSkipTheLiveDatabase() {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try? Data("live".utf8).write(to: root.appendingPathComponent("evidence.sqlite3"))
        try? Data("search".utf8).write(to: root.appendingPathComponent("evidence.search.sqlite3"))
        try? Data(Data(repeating: 1, count: 32)).write(to: root.appendingPathComponent("evidence.sqlite3.backup"))
        try? Data(Data(repeating: 2, count: 32)).write(to: root.appendingPathComponent("evidence-before-change-batch-reindex-20260920.sqlite3"))
        let items = StaleDataCatalog.suggestions(directory: root, cloudAuditBytes: 0)
        XCTAssertEqual(items.map(\.name), ["evidence-before-change-batch-reindex-20260920.sqlite3", "evidence.sqlite3.backup"])
        XCTAssertNil(StaleDataCatalog.canDelete(id: "evidence.sqlite3", directory: root))
        XCTAssertNil(StaleDataCatalog.canDelete(id: "../evidence.sqlite3", directory: root))
        XCTAssertNotNil(StaleDataCatalog.canDelete(id: "evidence.sqlite3.backup", directory: root))
    }

    func testBoundedProcessKillsAChildThatWouldFillThePipe() {
        let started = Date()
        let output = BoundedProcess.run("/bin/sleep", arguments: ["30"], timeout: 0.4)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        XCTAssertEqual(output, "")
    }
}

final class EvidenceReclaimTests: XCTestCase {
    func testNewDatabaseUsesIncrementalVacuumAndReclaimsACollapsedBlob() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        XCTAssertEqual(try database.autoVacuumMode(), 2)
        let blob = Data(repeating: 7, count: 200_000)
        try database.appendRaw([RawEvidenceRecord(source: "transport", stream: "blob", offsetStart: 0, offsetEnd: Int64(blob.count), fingerprint: nil, observedAt: Date().addingTimeInterval(-10 * 24 * 3600), payload: blob)])
        var policy = EvidenceRetentionPolicy.default
        policy.bulkMaxAge = 1
        let result = try database.prune(policy: policy)
        XCTAssertGreaterThan(result.collapsedRaw, 0)
        XCTAssertEqual(result.autoVacuum, 2)
        XCTAssertGreaterThan(result.reclaimedPages, 0)
    }

    func testSessionLogPayloadIsNotStoredWhole() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let body = Data(String(repeating: "session-line\n", count: 400).utf8)
        let record = RawEvidenceRecord(source: "codex", stream: "/Users/me/.codex/sessions/a.jsonl", offsetStart: 0, offsetEnd: Int64(body.count), fingerprint: nil, observedAt: Date(), payload: body)
        let stored = EvidenceDatabase.storedRawPayload(record)
        XCTAssertNil(stored.range(of: Data("session-line".utf8)))
        XCTAssertTrue(String(data: stored, encoding: .utf8)?.contains("summary") == true)
        try database.appendRaw([record])
        let bytes = try Data(contentsOf: root.appendingPathComponent("evidence.sqlite3"))
        XCTAssertNil(bytes.range(of: Data("session-line".utf8)))
    }

    func testSamplerTickIsBulkAndDropsWhenOverTheBackstop() throws {
        let tick = EvidenceValue.tier(EvidenceValueFields(op: "process_observation", source: "process-observation-libproc", processId: 9, payloadBytes: 80))
        XCTAssertEqual(tick, .bulk)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let keep = GuardEvent(kind: "file", ruleId: "credential_observe", path: "/tmp/fake.env", command: nil, agent: "cursor", op: "read", severity: "high", ts: Date().addingTimeInterval(-10 * 24 * 3600), action: "observed", source: "libproc-vnode")
        let sample = GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil, agent: "cursor", op: "process_observation", severity: "info", ts: Date().addingTimeInterval(-10 * 24 * 3600), action: "observed", source: "process-observation-libproc", processId: 9)
        try database.append([keep, sample])
        var policy = EvidenceRetentionPolicy.default
        policy.backstopBytes = 1
        _ = try database.prune(policy: policy)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [keep.id])
    }
}

final class TransportAuditRetentionTests: XCTestCase {
    func testOldSidecarsGoAndTheSummaryStays() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let run = root.appendingPathComponent("run-1", isDirectory: true)
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let summary = run.appendingPathComponent("transport.json")
        try Data("{\"invocation\":{}}".utf8).write(to: summary)
        let pack = run.appendingPathComponent("git-packfile.pack")
        try Data(repeating: 9, count: 128).write(to: pack)
        let old = Date().addingTimeInterval(-10 * 24 * 3600)
        try FileManager.default.setAttributes([.modificationDate: old], ofItemAtPath: run.path)
        let result = TransportAuditRetention.prune(root: root, now: Date(), maxAge: 3 * 24 * 3600)
        XCTAssertEqual(result.filesRemoved, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: summary.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: pack.path))
    }
}
