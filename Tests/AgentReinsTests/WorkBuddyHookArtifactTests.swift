import Foundation
import XCTest
@testable import AgentReins

final class WorkBuddyHookArtifactTests: XCTestCase {
    func testWriterArtifactCorrelatesSessionAndRejectsPIDReuse() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let directory = root.appendingPathComponent("session-hash")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let now = Date()
        let timestamp = UInt64(now.timeIntervalSince1970 * 1000)
        let record: [String: Any] = ["observed_at_ms": timestamp, "session_id": "session-proof", "hook_event_name": "SessionStart"]
        try JSONSerialization.data(withJSONObject: record).write(to: directory.appendingPathComponent("\(timestamp)-42-probe.json"))
        let process = ProcessSnapshotRecord(pid: "42", ppid: "41",
            command: "node /Users/test/.loongsuite-pilot/hooks/workbuddy-hook-event-writer.mjs session-start",
            agent: "workbuddy", birthIdentity: (timestamp - 1000) * 1000, executablePath: "/test/node")
        let reader = WorkBuddyHookArtifactReader(root: root)
        let events = reader.events(for: process, now: now.addingTimeInterval(1))
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?.sessionId, "session-proof")
        XCTAssertTrue(events.first?.afterContent?.contains("sha256") == true)
        let reused = ProcessSnapshotRecord(pid: "42", ppid: "41", command: process.command,
            agent: "workbuddy", birthIdentity: (timestamp + 1) * 1000, executablePath: "/test/node")
        XCTAssertTrue(reader.events(for: reused, now: now.addingTimeInterval(1)).isEmpty)
        let unrelated = ProcessSnapshotRecord(pid: "42", ppid: "41", command: "node unrelated.mjs",
            agent: "workbuddy", birthIdentity: process.birthIdentity, executablePath: "/test/node")
        XCTAssertTrue(reader.events(for: unrelated, now: now.addingTimeInterval(1)).isEmpty)
    }
}
