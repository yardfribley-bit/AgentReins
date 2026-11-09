import AgentReinsCore
import XCTest
@testable import AgentReins

final class EvidenceRetentionTests: XCTestCase {
    func testValueTiersKeepSecurityAndDropHeartbeat() {
        let heartbeat = EvidenceValue.tier(EvidenceValueFields(
            op: "exec", userIntent: "<heartbeat>ping", path: "-", payloadBytes: 80))
        XCTAssertEqual(heartbeat, .noise)
        let missing = EvidenceValue.tier(EvidenceValueFields(
            op: "prompt", userIntent: "当前轮次 · 用户需求未采集", path: "-", payloadBytes: 40))
        XCTAssertEqual(missing, .noise)
        let egress = EvidenceValue.tier(EvidenceValueFields(
            kind: "network", op: "egress", ruleId: "S02", severity: "high",
            command: "curl https://example", path: "-", payloadBytes: 120))
        XCTAssertEqual(egress, .keep)
        let file = EvidenceValue.tier(EvidenceValueFields(
            kind: "file", op: "write", path: "/tmp/proj/.env", payloadBytes: 200))
        XCTAssertEqual(file, .keep)
        let unclaimed = EvidenceValue.tier(EvidenceValueFields(
            kind: "files", op: "modify", path: "/tmp/proj/unclaimed.txt", payloadBytes: 180))
        XCTAssertEqual(unclaimed, .keep)
        let mismatch = EvidenceValue.tier(EvidenceValueFields(
            op: "response", command: "curl https://cdn.example/x", toolName: "Bash",
            modelText: "我只读取，不联网", payloadBytes: 160))
        XCTAssertEqual(mismatch, .keep)
        let join = EvidenceValue.tier(EvidenceValueFields(
            op: "exec", command: "ls", path: "-", toolName: "Bash", processId: 42, payloadBytes: 90))
        XCTAssertEqual(join, .keep)
        let transcript = EvidenceValue.tier(EvidenceValueFields(
            op: "recovered_transcript", toolName: "codex.compacted_history",
            modelText: String(repeating: "x", count: 20_000), payloadBytes: 20_000))
        XCTAssertEqual(transcript, .bulk)
        XCTAssertFalse(EvidenceValue.policySummary.contains("2GB"))
    }

    func testPruneDropsHeartbeatAndKeepsSecurityAndReviewFile() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let review = root.appendingPathComponent("realtime-review-decisions-v1.json")
        try Data("{\"state\":\"return\",\"note\":\"缺交付物\"}".utf8).write(to: review)
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let security = GuardEvent(kind: "network", ruleId: "S02", path: "-", command: "curl https://example",
                                   agent: "codex", op: "egress", severity: "high",
                                   ts: Date().addingTimeInterval(-40 * 24 * 60 * 60), action: "observed", source: "retention")
        let heartbeat = GuardEvent(kind: "activity", ruleId: "fixture", path: "-", command: nil,
                                    agent: "codex", op: "exec", severity: "info",
                                    ts: Date().addingTimeInterval(-2 * 24 * 60 * 60), action: "observed",
                                    userIntent: "<heartbeat>ping", source: "retention")
        try database.append([security, heartbeat])
        let result = try database.prune()
        XCTAssertGreaterThan(result.deletedRecords, 0)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [security.id])
        XCTAssertEqual(try String(contentsOf: review, encoding: .utf8), "{\"state\":\"return\",\"note\":\"缺交付物\"}")
        XCTAssertGreaterThan(result.keptSkipped, 0)
    }

    func testBackstopDoesNotDropKeepTier() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let security = GuardEvent(kind: "network", ruleId: "S04", path: "-", command: "curl https://uploads.example",
                                   agent: "codex", op: "egress", severity: "high",
                                   ts: Date().addingTimeInterval(-3600), action: "blocked", source: "retention")
        let heartbeat = GuardEvent(kind: "activity", ruleId: "fixture", path: "-", command: nil,
                                    agent: "codex", op: "heartbeat", severity: "info",
                                    ts: Date(), action: "observed", userIntent: "<heartbeat>now", source: "retention")
        try database.append([security, heartbeat])
        var policy = EvidenceRetentionPolicy.default
        policy.backstopBytes = 1
        _ = try database.prune(policy: policy)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [security.id])
    }

    func testBulkTranscriptAgesOutAndJoinKeyStays() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let copy = GuardEvent(kind: "context", ruleId: "codex_recovered_transcript_bundle", path: "-", command: nil,
                               agent: "codex", op: "recovered_transcript", severity: "info",
                               ts: Date().addingTimeInterval(-5 * 24 * 60 * 60), action: "captured",
                               modelPrompt: String(repeating: "session ", count: 4_000),
                               toolName: "codex.compacted_history", source: "retention")
        let join = GuardEvent(kind: "tool", ruleId: "fixture", path: "-", command: "ls",
                               agent: "codex", op: "exec", severity: "info",
                               ts: Date().addingTimeInterval(-5 * 24 * 60 * 60), action: "observed",
                               toolName: "Bash", source: "retention", processId: 42)
        try database.append([copy, join])
        let stored = try database.recent(limit: 10)
        let storedCopy = try XCTUnwrap(stored.first { $0.id == copy.id })
        XCTAssertLessThanOrEqual(storedCopy.modelPrompt?.count ?? 0, EvidenceValue.excerptLimit)
        _ = try database.prune()
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [join.id])
    }

    func testHardCapSkipsAutomaticDeleteUntilTheUserConfirms() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let security = GuardEvent(kind: "network", ruleId: "S02", path: "-", command: "curl https://example",
                                   agent: "codex", op: "egress", severity: "high",
                                   ts: Date().addingTimeInterval(-3 * 24 * 60 * 60), action: "observed", source: "retention")
        let heartbeat = GuardEvent(kind: "activity", ruleId: "fixture", path: "-", command: nil,
                                    agent: "codex", op: "exec", severity: "info",
                                    ts: Date().addingTimeInterval(-2 * 24 * 60 * 60), action: "observed",
                                    userIntent: "<heartbeat>ping", source: "retention")
        try database.append([security, heartbeat])
        var policy = EvidenceRetentionPolicy.default
        policy.hardCapBytes = 1
        let held = try database.prune(policy: policy)
        XCTAssertEqual(held.deletedRecords, 0)
        XCTAssertTrue(held.overCap)
        XCTAssertEqual(try database.recent(limit: 10).count, 2)
        let cleaned = try database.prune(policy: policy, userConfirmed: true)
        XCTAssertGreaterThan(cleaned.deletedRecords, 0)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [security.id])
        XCTAssertFalse(cleaned.note.contains("VACUUM。") && cleaned.reclaimedPages > 0)
    }

    func testHardCapRefusesNewNoiseButKeepsEgress() {
        let heartbeat = GuardEvent(kind: "activity", ruleId: "fixture", path: "-", command: nil,
                                    agent: "codex", op: "heartbeat", severity: "info",
                                    ts: Date(), action: "observed", userIntent: "<heartbeat>ping", source: "retention")
        let egress = GuardEvent(kind: "network", ruleId: "S02", path: "-", command: "curl https://example",
                                 agent: "codex", op: "egress", severity: "high",
                                 ts: Date(), action: "blocked", source: "retention")
        let kept = EvidenceDatabase.rowsToStore([heartbeat, egress], onDiskBytes: 8, hardCap: 1)
        XCTAssertEqual(kept.map(\.id), [egress.id])
        XCTAssertEqual(EvidenceDatabase.rowsToStore([heartbeat, egress], onDiskBytes: 0, hardCap: 1).count, 2)
    }

    func testSecondAppCopyIsRefusedAndAHotProcessThrottles() {
        let selfPid: Int32 = 10
        let processes = [
            AppInstanceGate.Proc(pid: 10, path: "/Applications/AgentReins.app/Contents/MacOS/AgentReins"),
            AppInstanceGate.Proc(pid: 11, path: "/Users/me/Desktop/AgentReins copy.app/Contents/MacOS/AgentReins"),
            AppInstanceGate.Proc(pid: 12, path: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP"),
        ]
        let others = AppInstanceGate.others(selfPid: selfPid, processes: processes)
        XCTAssertEqual(others.map(\.pid), [11])
        XCTAssertTrue(AppInstanceGate.message(otherPath: others[0].path).contains("已经有一个 AgentReins"))
        let budget = RuntimeBudget()
        XCTAssertEqual(budget.observe(cpuPercent: 20, memoryPressure: false), "normal")
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "normal")
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "normal")
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "throttled")
        XCTAssertTrue(budget.isThrottled)
        XCTAssertEqual(RuntimeBudget.cpuPercent(userMicros: 1_000_000, systemMicros: 0, elapsed: 1), 100, accuracy: 0.1)
        let labels = BackgroundJobs.ownedLabels(["com.agentreins.mitm-proxy", "com.example.other"])
        XCTAssertTrue(labels.contains("com.agentreins.mcp-http"))
        XCTAssertTrue(labels.contains("com.agentreins.socket-sampler"))
        XCTAssertTrue(labels.contains("com.agentreins.mitm-proxy"))
        XCTAssertEqual(BackgroundJobs.bootoutArguments(uid: 501, label: "com.agentreins.mcp-http"), ["bootout", "gui/501/com.agentreins.mcp-http"])
    }
}
