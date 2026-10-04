import XCTest
import SQLite3
@testable import AgentReins

final class CollectorHealthResponsivenessTests: XCTestCase {
    func testSharedDatabaseReusesWriterForCanonicalPath() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("shared.sqlite3")
        let first = try EvidenceDatabase.shared(url: url)
        let second = try EvidenceDatabase.shared(url: root.appendingPathComponent("./shared.sqlite3"))
        XCTAssertTrue(first === second)
    }

    func testHealthEnqueueDoesNotWaitForDatabaseWriter() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("health.sqlite3")
        let database = try EvidenceDatabase(url: url)
        var blocker: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &blocker), SQLITE_OK)
        defer { sqlite3_close(blocker) }
        XCTAssertEqual(sqlite3_exec(blocker, "BEGIN IMMEDIATE", nil, nil, nil), SQLITE_OK)
        let start = Date()
        for i in 0..<100 {
            database.enqueueHealth(CollectorHealthRecord(source: "test", state: .healthy,
                lastSuccess: Date(), lagSeconds: nil, accepted: i, malformed: 0, dropped: 0, detail: nil))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.25)
        XCTAssertEqual(sqlite3_exec(blocker, "COMMIT", nil, nil, nil), SQLITE_OK)
        let deadline = Date().addingTimeInterval(3)
        var latest: Int?
        repeat {
            latest = try database.healthRecords().first?.accepted
            if latest == 99 { break }
            Thread.sleep(forTimeInterval: 0.02)
        } while Date() < deadline
        XCTAssertEqual(latest, 99)
    }
}
