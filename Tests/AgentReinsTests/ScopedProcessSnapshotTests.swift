import Foundation
import XCTest
@testable import AgentReins

final class ScopedProcessSnapshotTests: XCTestCase {
    func testInvalidationDiscoversNewRootWhileExistingRootIsAlive() throws {
        let first = Process()
        first.executableURL = URL(fileURLWithPath: "/bin/sleep")
        first.arguments = ["30"]
        try first.run()
        let second = Process()
        defer {
            for process in [first, second] where process.isRunning { process.terminate(); process.waitUntilExit() }
        }
        let provider = DarwinLibprocSnapshotProvider(agentMarkers: ["sleep"])
        _ = provider.snapshot()
        second.executableURL = URL(fileURLWithPath: "/bin/sleep")
        second.arguments = ["30"]
        try second.run()
        provider.invalidateDiscovery()
        XCTAssertTrue(provider.snapshot().contains { $0.pid == String(second.processIdentifier) })
    }

    func testHotPathRetainsSingleDescendant() throws {
        let parent = Process()
        parent.executableURL = URL(fileURLWithPath: "/bin/sh")
        parent.arguments = ["-c", "sleep 30 & wait"]
        try parent.run()
        defer { if parent.isRunning { parent.terminate(); parent.waitUntilExit() } }
        let provider = DarwinLibprocSnapshotProvider(agentMarkers: ["/bin/sh", "/bin/bash"])
        var initial: [ProcessSnapshotRecord] = []
        for _ in 0..<20 {
            provider.invalidateDiscovery()
            initial = provider.snapshot()
            if initial.contains(where: { $0.ppid == String(parent.processIdentifier) }) { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let descendant = try XCTUnwrap(initial.first { $0.ppid == String(parent.processIdentifier) })
        defer { if let pid = Int32(descendant.pid) { kill(pid, SIGTERM) } }
        XCTAssertTrue(provider.snapshot().contains { $0.pid == descendant.pid }, "One-child subtree must remain visible on the hot path")
    }

    func testExitedTrackedRootIsNotReturnedFromCache() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        defer { if child.isRunning { child.terminate(); child.waitUntilExit() } }
        let provider = DarwinLibprocSnapshotProvider(agentMarkers: ["sleep"])
        let first = provider.snapshot()
        let record = try XCTUnwrap(first.first { $0.pid == String(child.processIdentifier) })
        XCTAssertEqual(record.agent, "sleep")
        XCTAssertNotNil(record.birthIdentity)
        XCTAssertNotNil(record.executablePath)
        XCTAssertTrue(first.allSatisfy { $0.agent == "sleep" }, "Unrelated processes must not leave the discovery index")
        child.terminate()
        child.waitUntilExit()
        let second = provider.snapshot()
        XCTAssertFalse(second.contains { $0.pid == String(child.processIdentifier) }, "Cached exited root must not survive until the next global discovery")
    }
}
