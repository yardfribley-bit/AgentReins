import Darwin
import Foundation
import XCTest
@testable import AgentReins

final class ProcessObservationCoordinatorTests: XCTestCase {
    private struct Sampler: ProcessActivitySampling {
        let resident: UInt64
        func sample(_ process: ProcessSnapshotRecord) -> ProcessObservationSample? {
            .init(identity: ProcessObservationCoordinator.identity(process), pid: Int32(process.pid)!,
                parentPID: Int32(process.ppid)!, executable: process.executablePath!,
                residentBytes: resident, virtualBytes: resident * 2, cpuTimeNanoseconds: 0,
                threadCount: 1, openFiles: [], resourceStatus: "sampled", fileStatus: "sampled_open_descriptors",
                unreadableDescriptors: 0, truncated: false)
        }
    }

    private func record(birth: UInt64 = 100) -> ProcessSnapshotRecord {
        .init(pid: "42", ppid: "1", command: "node", agent: "workbuddy",
              birthIdentity: birth, executablePath: "/test/node")
    }

    func testIdleSamplesDoNotCreateHeartbeatEvidence() {
        let coordinator = ProcessObservationCoordinator(sampler: Sampler(resident: 4096))
        let now = Date()
        _ = coordinator.collect(processes: [record()], now: now, includeSamples: false)
        for second in stride(from: 5, through: 120, by: 5) {
            XCTAssertTrue(coordinator.collect(processes: [record()], now: now.addingTimeInterval(Double(second))).isEmpty)
        }
        XCTAssertEqual(coordinator.collect(processes: [], now: now.addingTimeInterval(121), includeSamples: false).map(\.op), ["process_watch_detached"])
    }
    func testOnlySupportedTargetOwnersAreAccepted() {
        for target in ["codex", "WorkBuddy", "chatgpt"] { XCTAssertTrue(ProcessGuard.isTargetAgent(target)) }
        XCTAssertEqual(ProcessGuard.targetExecutableOwner("/usr/local/bin/codex --version"), "codex")
        XCTAssertNil(ProcessGuard.targetExecutableOwner("/bin/zsh -c cat /tmp/codex/file"))
        XCTAssertNil(ProcessGuard.targetExecutableOwner("python /tmp/workbuddy/script.py"))
        for other in ["cursor", "chrome", "claude-code", "", "node"] { XCTAssertFalse(ProcessGuard.isTargetAgent(other)) }
    }
    func testArmLifecycleUsesBirthIdentityAndDoesNotInventTask() throws {
        let coordinator = ProcessObservationCoordinator(sampler: Sampler(resident: 4096))
        let now = Date()
        let first = coordinator.collect(processes: [record()], now: now, includeSamples: false)
        XCTAssertEqual(first.map(\.op), ["process_watch_attached", "process_observation"])
        XCTAssertTrue(first.allSatisfy { $0.sessionId == nil && $0.toolCallId == nil })
        let observed = coordinator.collect(processes: [record()], now: now)
        XCTAssertTrue(observed.isEmpty)
        XCTAssertTrue(coordinator.collect(processes: [record()], now: now.addingTimeInterval(5)).isEmpty)
        let reused = coordinator.collect(processes: [record(birth: 200)], now: now.addingTimeInterval(6), includeSamples: false)
        XCTAssertEqual(Set(reused.map(\.op)), Set(["process_watch_detached", "process_watch_attached", "process_observation"]))
        XCTAssertTrue(reused.first { $0.op == "process_watch_attached" }!.afterContent!.contains("42:200"))
    }

    func testHookTriggerKeepsUnchangedSampleAndDoesNotInventTask() {
        let coordinator = ProcessObservationCoordinator(sampler: Sampler(resident: 4096))
        let now = Date()
        _ = coordinator.collect(processes: [record()], now: now, includeSamples: false)
        XCTAssertTrue(coordinator.collect(processes: [record()], now: now).isEmpty)
        let snapshot = coordinator.collect(processes: [record()], now: now, trigger: "hook-id:hook_tool_start")
        XCTAssertEqual(snapshot.map(\.op), ["process_observation"])
        XCTAssertTrue(snapshot[0].afterContent!.contains("hook-id:hook_tool_start"))
        XCTAssertNil(snapshot[0].toolCallId)
        XCTAssertNil(snapshot[0].sessionId)
    }

    func testLateResourceSnapshotCannotResurrectDetachedArm() {
        let coordinator = ProcessObservationCoordinator(sampler: Sampler(resident: 4096))
        _ = coordinator.collect(processes: [record()], includeSamples: false)
        XCTAssertEqual(coordinator.collect(processes: [], includeSamples: false).map(\.op), ["process_watch_detached"])
        XCTAssertTrue(coordinator.collect(processes: [record()]).isEmpty)
    }

    func testSocketSamplesStayWithOwningArm() throws {
        let coordinator = ProcessObservationCoordinator(sampler: Sampler(resident: 4096))
        _ = coordinator.collect(processes: [record()], includeSamples: false)
        let socket = NetworkConnectionRecord(pid: "42", localAddress: "127.0.0.1:1111", remoteHost: "example.test", remotePort: 443)
        let unrelated = NetworkConnectionRecord(pid: "99", localAddress: "127.0.0.1:2222", remoteHost: "unrelated.test", remotePort: 443)
        let events = coordinator.observeSockets(processes: [record()], connections: [socket, unrelated])
        XCTAssertEqual(events.count, 1)
        XCTAssertTrue(events[0].afterContent!.contains("example.test"))
        XCTAssertFalse(events[0].afterContent!.contains("unrelated.test"))
        XCTAssertTrue(coordinator.observeSockets(processes: [record()], connections: [socket]).isEmpty)
    }

    func testLibprocReadsOwnResourcesAndOpenDescriptorAndRejectsReusedPID() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data("probe".utf8).write(to: path)
        defer { try? FileManager.default.removeItem(at: path) }
        let handle = try FileHandle(forReadingFrom: path)
        defer { try? handle.close() }
        let pid = getpid()
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        let read = withUnsafeMutablePointer(to: &info) { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, $0, Int32(size)) }
        XCTAssertEqual(Int(read), size)
        let birth = UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
        let process = ProcessSnapshotRecord(pid: String(pid), ppid: String(info.pbi_ppid), command: "test",
            agent: "workbuddy", birthIdentity: birth, executablePath: "/test")
        let sampler = LibprocProcessActivitySampler()
        let sample = try XCTUnwrap(sampler.sample(process))
        XCTAssertNotNil(sample.residentBytes)
        XCTAssertTrue(sample.openFiles.contains { $0.path == path.path || URL(fileURLWithPath: $0.path).resolvingSymlinksInPath() == path.resolvingSymlinksInPath() })
        XCTAssertNil(sampler.sample(.init(pid: String(pid), ppid: "1", command: "test", birthIdentity: birth + 1)))
    }
}
