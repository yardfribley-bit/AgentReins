import Foundation
import XCTest
@testable import AgentReins

final class WorkBuddyLivePipelineTests: XCTestCase {
    func testReasoningFallsBackWhenContentIsEmpty() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("reasoning.jsonl")
        let rows: [[String: Any]] = [
            ["id": "task", "sessionId": "s", "type": "message", "role": "user", "timestamp": 1000,
             "content": [["text": "fixture task"]]],
            ["id": "reasoning", "sessionId": "s", "type": "reasoning", "timestamp": 1001,
             "content": [], "rawContent": [["type": "text", "text": "recorded reasoning fixture"]]],
            ["id": "response", "sessionId": "s", "type": "message", "role": "assistant", "timestamp": 1002,
             "content": [["text": "fixture answer"]]]
        ]
        let text = try rows.map { String(decoding: try JSONSerialization.data(withJSONObject: $0), as: UTF8.self) }.joined(separator: "\n")
        try text.write(to: file, atomically: true, encoding: .utf8)
        let events = WorkBuddySight.parseSession(file, fullHistory: true)
        XCTAssertEqual(events.first(where: { $0.op == "reasoning_summary" })?.modelReasoning, "recorded reasoning fixture")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: events).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: "task")
        XCTAssertEqual(snapshot.modelResponses.first?.recordedReasoning, "recorded reasoning fixture")
    }

    @MainActor
    func testExistingTaskNewResponseReachesCurrentTaskAndDatabase() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("session.jsonl")
        let storeURL = root.appendingPathComponent("events.json")
        let database = try EvidenceDatabase.shared(url: storeURL.appendingPathExtension("sqlite3"))
        func line(_ id: String, role: String, text: String, date: Date) throws -> Data {
            var data = try JSONSerialization.data(withJSONObject: [
                "id": id, "sessionId": "live-session", "type": "message", "role": role,
                "content": [["type": "text", "text": text]], "timestamp": date.timeIntervalSince1970 * 1000, "status": "completed"
            ])
            data.append(0x0a)
            return data
        }
        try line("task", role: "user", text: "live fixture task", date: Date().addingTimeInterval(-600)).write(to: file)
        let store = EventStore(fileURL: storeURL)
        let collector = WorkBuddySight(rootURL: root, database: database, hookRoot: root.appendingPathComponent("hooks"))
        collector.onEvents = { store.record($0) }
        collector.start()
        defer { collector.stop() }
        var deadline = Date().addingTimeInterval(8)
        while store.events.isEmpty && Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertFalse(store.events.isEmpty, "Initial parser state was not established")
        let handle = try FileHandle(forWritingTo: file)
        try handle.seekToEnd()
        try handle.write(contentsOf: line("response", role: "assistant", text: "new live response", date: Date()))
        try handle.close()
        deadline = Date().addingTimeInterval(8)
        while !store.events.contains(where: { $0.op == "response" }) && Date() < deadline {
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTAssertTrue(store.events.contains(where: { $0.op == "response" }))
        let progress = try XCTUnwrap(store.taskProgress["live-session\u{0}task"])
        XCTAssertLessThan(progress.startedAt, store.liveSince)
        XCTAssertTrue(progress.isCurrentTask(since: store.liveSince), "An ongoing task must not disappear after collector startup")
        XCTAssertTrue(try database.events(sessionId: "live-session", turnID: "task").contains(where: { $0.op == "response" }))
        deadline = Date().addingTimeInterval(5)
        while store.sessions.isEmpty && Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        XCTAssertFalse(store.sessions.isEmpty, "Published task projection did not receive live evidence")
    }
}
