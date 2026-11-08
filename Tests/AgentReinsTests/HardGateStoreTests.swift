import XCTest
@testable import AgentReins

final class HardGateStoreTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgentReinsHardGate-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        HardGateStore.useRoot(tempDir)
    }

    override func tearDownWithError() throws {
        HardGateStore.useRoot(nil)
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testAgentCannotAppend() {
        XCTAssertThrowsError(try HardGateStore.append(actor: "agent", record: [
            "action": "deny", "kind": "egress", "subject": "host:evil.example", "actor": "agent",
        ])) { error in
            XCTAssertEqual(error as? HardGateStore.Failure, .agentWrite)
        }
        XCTAssertThrowsError(try HardGateStore.append(actor: "enforcer", record: [
            "action": "allow", "kind": "egress", "subject": "host:evil.example", "reason": "no",
        ])) { error in
            XCTAssertEqual(error as? HardGateStore.Failure, .agentWrite)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: HardGateStore.auditURL.path))
    }

    func testApproveRequiresReasonAndDenyRemovesIt() throws {
        XCTAssertThrowsError(try HardGateStore.approve(subject: "host:github.com", kind: "egress", reason: "  ")) { error in
            XCTAssertEqual(error as? HardGateStore.Failure, .reasonRequired)
        }
        try HardGateStore.approve(subject: "host:github.com", kind: "egress", reason: "发布需要")
        let snap = HardGateStore.snapshot()
        XCTAssertEqual(snap.allowlist.count, 1)
        XCTAssertEqual(snap.allowlist[0]["subject"] as? String, "host:github.com")
        XCTAssertEqual(snap.allowlist[0]["actor"] as? String, "user")
        XCTAssertEqual(snap.allowlist[0]["reason"] as? String, "发布需要")
        try HardGateStore.deny(subject: "host:github.com", kind: "egress", reason: "不再需要")
        XCTAssertTrue(HardGateStore.snapshot().allowlist.isEmpty)
        let rows = HardGateStore.loadRows()
        XCTAssertEqual(rows.map { $0["action"] as? String }, ["allow", "deny"])
        XCTAssertTrue(rows.allSatisfy { ($0["tier"] as? String) == "keep" && Self.flag($0["enforced"]) == false })
        XCTAssertTrue(HardGateStore.verifyChain())
    }

    func testAppendIsKeepTierAndDoesNotRewriteEarlierBytes() throws {
        let first = try HardGateStore.append(actor: "enforcer", record: [
            "action": "deny", "kind": "egress", "subject": "host:a.example",
            "reason": "default-deny egress", "inbox": true, "heartbeat": false,
            "enforced": true, "mechanism": "audit-proxy",
        ])
        let blob = try Data(contentsOf: HardGateStore.auditURL)
        _ = try HardGateStore.append(actor: "enforcer", record: [
            "action": "deny", "kind": "credential-read", "subject": "path:/tmp/proj/.env",
            "reason": "default-deny credential path", "inbox": true, "heartbeat": false,
            "enforced": true, "mechanism": "transport-wrapper",
        ])
        let after = try Data(contentsOf: HardGateStore.auditURL)
        XCTAssertTrue(after.starts(with: blob))
        XCTAssertEqual(first["tier"] as? String, "keep")
        XCTAssertEqual(first["prev"] as? String, String(repeating: "0", count: 64))
        XCTAssertTrue(HardGateStore.verifyChain())
        let mode = try FileManager.default.attributesOfItem(atPath: HardGateStore.auditURL.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
    }

    func testInboxSkipsHeartbeatsAndClosedSubjects() throws {
        _ = try HardGateStore.append(actor: "enforcer", record: [
            "action": "deny", "kind": "egress", "subject": "host:beat.example",
            "inbox": true, "heartbeat": true, "enforced": true, "mechanism": "audit-proxy",
            "reason": "default-deny egress",
        ])
        _ = try HardGateStore.append(actor: "enforcer", record: [
            "action": "deny", "kind": "egress", "subject": "host:new.example",
            "inbox": true, "heartbeat": false, "enforced": true, "mechanism": "audit-proxy",
            "reason": "default-deny egress", "detail": "第一次外联到新主机",
        ])
        _ = try HardGateStore.append(actor: "enforcer", record: [
            "action": "deny", "kind": "egress", "subject": "host:new.example",
            "inbox": false, "heartbeat": false, "enforced": true, "mechanism": "audit-proxy",
            "reason": "default-deny egress",
        ])
        let open = HardGateStore.snapshot().inbox
        XCTAssertEqual(open.map { $0["subject"] as? String }, ["host:new.example"])
        try HardGateStore.approve(subject: "host:new.example", kind: "egress", reason: "这次可以")
        XCTAssertTrue(HardGateStore.snapshot().inbox.isEmpty)
        let noted = HardGateStore.snapshot().receipts.filter { ($0["actor"] as? String) == "user" }
        XCTAssertEqual(Self.flag(noted.first?["enforced"]), false)
        XCTAssertNil(noted.first?["mechanism"] as? String)
    }

    private static func flag(_ value: Any?) -> Bool {
        if let value = value as? Bool { return value }
        if let value = value as? NSNumber { return value.boolValue }
        return false
    }
}
