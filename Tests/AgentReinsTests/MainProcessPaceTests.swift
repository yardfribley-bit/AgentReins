import AgentReinsCore
import XCTest

final class MainProcessPaceTests: XCTestCase {
    func testHotProcessSlowsMainLoopsAndLogsOnce() {
        MainProcessMeter.reset()
        let budget = RuntimeBudget()
        let start = Date(timeIntervalSince1970: 1_900_000_000)
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "normal")
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "normal")
        XCTAssertEqual(budget.observe(cpuPercent: 140, memoryPressure: false), "throttled")
        XCTAssertTrue(budget.allowMainLoop(lane: "file-layer", base: 0.4, previousChanged: true, now: start))
        XCTAssertFalse(budget.allowMainLoop(lane: "file-layer", base: 0.4, previousChanged: true, now: start.addingTimeInterval(1)))
        XCTAssertTrue(budget.allowMainLoop(lane: "file-layer", base: 0.4, previousChanged: true, now: start.addingTimeInterval(2.5)))
        XCTAssertGreaterThan(MainProcessMeter.mainLoopsSkipped, 0)
    }

    func testQuietLaneBacksOffUntilSomethingChanges() {
        let budget = RuntimeBudget()
        let start = Date(timeIntervalSince1970: 1_900_000_100)
        XCTAssertTrue(budget.allowMainLoop(lane: "codex-logs", base: 1, previousChanged: false, now: start))
        XCTAssertFalse(budget.allowMainLoop(lane: "codex-logs", base: 1, previousChanged: false, now: start.addingTimeInterval(1.5)))
        XCTAssertTrue(budget.allowMainLoop(lane: "codex-logs", base: 1, previousChanged: true, now: start.addingTimeInterval(1.5)))
    }

    func testSessionTreeWalkSkipsHeavyFoldersAndDoesNotRescan() throws {
        MainProcessMeter.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("pace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let noise = root.appendingPathComponent("node_modules/pkg", isDirectory: true)
        try FileManager.default.createDirectory(at: noise, withIntermediateDirectories: true)
        for index in 0..<40 {
            try Data("x".utf8).write(to: noise.appendingPathComponent("file-\(index).js"))
            try Data("{\"type\":\"function_call\"}\n".utf8).write(to: noise.appendingPathComponent("hidden-\(index).jsonl"))
        }
        let notes = root.appendingPathComponent("notes", isDirectory: true)
        try FileManager.default.createDirectory(at: notes, withIntermediateDirectories: true)
        for index in 0..<30 {
            try Data("note".utf8).write(to: notes.appendingPathComponent("plain-\(index).txt"))
        }
        for index in 0..<5 {
            let body = String(repeating: "abcdefghij", count: 200) + "\n"
            try Data(body.utf8).write(to: root.appendingPathComponent("session-\(index).jsonl"))
        }
        let cursor = JSONLTreeCursor()
        let first = cursor.refresh(root: root.path, now: Date(), fullInterval: 60, entryBudget: 5000)
        XCTAssertTrue(first.discoveryFinished)
        XCTAssertTrue(first.walked)
        XCTAssertEqual(cursor.sizes.count, 5)
        XCTAssertLessThan(first.entriesVisited, 80, "visited \(first.entriesVisited) entries; node_modules should not be entered")
        let walked = MainProcessMeter.fullTreeWalks
        XCTAssertGreaterThan(walked, 0)
        MainProcessMeter.reset()
        let second = cursor.refresh(root: root.path, now: Date().addingTimeInterval(1), fullInterval: 60, entryBudget: 5000)
        XCTAssertFalse(second.walked)
        XCTAssertEqual(second.entriesVisited, 5)
        XCTAssertEqual(MainProcessMeter.fullTreeWalks, 0)
        XCTAssertEqual(MainProcessMeter.directoryEntriesVisited, 5)
        let old = Date(timeIntervalSince1970: 1_700_000_000)
        var listed = first.listed
        listed.append(JSONLTreeCursor.Listed(path: "/tmp/brand-new.jsonl", modified: Date(), size: 12))
        let known = Dictionary(uniqueKeysWithValues: first.listed.map { ($0.path, $0.size) })
        let split = JSONLTreeCursor.partition(listed: listed, knownSizes: known, acceptNewSince: old)
        XCTAssertEqual(split.readable.map(\.path), ["/tmp/brand-new.jsonl"])
        XCTAssertTrue(split.baseline.isEmpty)
    }
}
