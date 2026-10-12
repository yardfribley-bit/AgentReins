import CryptoKit
import Foundation
import XCTest
@testable import AgentReins

/// Opt-in, private field verification. Inputs/output are outside the repository.
/// Repairs only explicitly selected already-observed live task records.
final class RealtimeCapacityFieldRepairTests: XCTestCase {
    func testPrepareAndVerifySelectedLiveRecovery() throws {
        guard let path = ProcessInfo.processInfo.environment["AGENTREINS_CAPACITY_REPAIR_DIR"] else {
            throw XCTSkip("Requires an explicit private live-recovery fixture directory")
        }
        let root = URL(fileURLWithPath: path)
        let backup = try JSONDecoder().decode(RealtimeActiveCheckpoint.self, from: Data(contentsOf: root.appendingPathComponent("before-checkpoint.json")))
        let decoder = WorkBuddyNetworkEvidence.captureDecoder()
        let lines = try String(contentsOf: root.appendingPathComponent("active-records.jsonl"), encoding: .utf8)
        var byID: [UUID: GuardEvent] = [:]
        for line in lines.split(whereSeparator: \.isNewline) {
            let event = try decoder.decode(GuardEvent.self, from: Data(line.utf8))
            byID[event.id] = event
        }
        // Existing recovered attribution takes precedence over stale DB projections.
        for event in backup.events { byID[event.id] = event }
        let beforeCount = byID.count
        let paths = try JSONDecoder().decode([String].self, from: Data(contentsOf: root.appendingPathComponent("subagent-streams.json")))
        var repairs = 0, identities = 0, childTurns = Set<String>()
        for path in paths {
            guard let plan = CodexSight.subagentRepairPlan(at: URL(fileURLWithPath: path), maximumBytes: 32 * 1024 * 1024) else { continue }
            let candidates = byID.values.filter { event in
                event.source == "agentsight:codex-local-compat" && event.agent?.lowercased() == "codex" &&
                [plan.identity.session, plan.identity.parentSession].contains(event.sessionId ?? "") && plan.turnIDs.contains(event.turnId ?? "")
            }
            for event in candidates {
                byID[event.id] = event.attributed(sessionId: plan.identity.session, turnId: event.turnId!, toolCallId: event.toolCallId,
                    confidence: .confirmed, method: "native child stream turn identity repair; original event and body retained")
                repairs += 1
            }
            for turn in Set(candidates.compactMap(\.turnId)) {
                let timestamp = candidates.filter { $0.turnId == turn }.map(\.ts).min()!
                let marker = CodexSight.subagentIdentityEvent(plan.identity, turn: turn, timestamp: timestamp)
                byID[marker.id] = marker; identities += 1; childTurns.insert(turn)
            }
        }
        let events = byID.values.sorted { $0.ts == $1.ts ? $0.id.uuidString < $1.id.uuidString : $0.ts < $1.ts }
        XCTAssertGreaterThan(events.count, backup.events.count)
        XCTAssertGreaterThan(repairs, 0)
        let saved = RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: events,
                                             readTaskIDs: backup.readTaskIDs, coverageTruncated: true)
        let destination = root.appendingPathComponent("repaired.json")
        try saved.save(destination)
        let restored = try XCTUnwrap(RealtimeActiveCheckpoint.load(destination))
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let input = try encoder.encode(events), output = try encoder.encode(restored.events)
        XCTAssertEqual(input, output, "Every restored event field must match, not only task counts")
        let tasks = RealtimeWorkspaceProjector.tasks(events: restored.events, since: .distantPast)
        XCTAssertFalse(tasks.contains { childTurns.contains($0.turn) && $0.isPrimaryTask })
        let screenshotCall = "call_8853428767b243f4ae773e0e677ffc38"
        let screenshot = try XCTUnwrap(tasks.first { $0.cards.contains { $0.call == screenshotCall } })
        XCTAssertEqual(screenshot.subagentPath, "/root/checkpoint_audit")
        XCTAssertFalse(screenshot.isPrimaryTask)
        let summary: [String: Any] = ["events": events.count, "beforeUnion": beforeCount, "checkpointEventsBefore": backup.events.count,
            "repairedEvents": repairs, "childTurns": identities, "tasks": tasks.count, "primaryTasks": tasks.filter(\.isPrimaryTask).count,
            "manifestBytes": try Data(contentsOf: destination).count, "fullEventBytes": input.count,
            "roundTripSHA256": SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined(),
            "screenshotTaskTitle": screenshot.title, "priorCoverageGapRetained": restored.coverageTruncated]
        try JSONSerialization.data(withJSONObject: summary, options: [.prettyPrinted, .sortedKeys]).write(to: root.appendingPathComponent("verification.json"))
    }
}
