import Darwin
import XCTest
@testable import AgentReins

final class ProcessCommunicationEvidenceTests: XCTestCase {
    private let processes: [ProcessSnapshotRecord] = [
        .init(pid: "10", ppid: "1", command: "backend", agent: "workbuddy", birthIdentity: 100),
        .init(pid: "20", ppid: "10", command: "agent", agent: "workbuddy", birthIdentity: 200)
    ]
    private func socket(_ pid: String, _ local: String, _ host: String, _ port: Int, state: String = "ESTABLISHED") -> NetworkConnectionRecord {
        .init(pid: pid, localAddress: local, remoteHost: host, remotePort: port, state: state)
    }
    func testTCPNeedsBothEstablishedEndpointsAndDoesNotInventCallDirection() throws {
        let a = socket("10", "127.0.0.1:7000", "127.0.0.1", 8000)
        let b = socket("20", "127.0.0.1:8000", "127.0.0.1", 7000)
        XCTAssertTrue(ProcessCommunicationEvidence.tcp(processes: processes, connections: [a]).isEmpty)
        let edges = ProcessCommunicationEvidence.tcp(processes: processes, connections: [a,b])
        XCTAssertEqual(edges.count, 1)
        XCTAssertEqual(edges[0].firstIdentity, "10:100")
        XCTAssertEqual(edges[0].secondIdentity, "20:200")
        XCTAssertTrue(ProcessCommunicationEvidence.tcp(processes: processes, connections: [a, socket("20", "127.0.0.1:8000", "127.0.0.1", 7000, state: "CLOSED")]).isEmpty)
        XCTAssertTrue(ProcessCommunicationEvidence.tcp(processes: processes, connections: [a, socket("20", "127.0.0.1:8000", "127.0.0.1", 7001)]).isEmpty)
    }
    func testSharedOwnershipAndExternalEndpointsDoNotMakeAnInternalEdge() {
        let third = ProcessSnapshotRecord(pid: "30", ppid: "10", command: "other", birthIdentity: 300)
        let records = [socket("10", "127.0.0.1:7000", "127.0.0.1", 8000), socket("20", "127.0.0.1:8000", "127.0.0.1", 7000), socket("30", "127.0.0.1:8000", "127.0.0.1", 7000)]
        XCTAssertTrue(ProcessCommunicationEvidence.tcp(processes: processes + [third], connections: records).isEmpty)
        XCTAssertTrue(ProcessCommunicationEvidence.tcp(processes: processes, connections: [socket("10", "10.1.1.1:7000", "10.1.1.2", 8000), socket("20", "10.1.1.2:8000", "10.1.1.1", 7000)]).isEmpty)
    }
    func testUnixNeedsReciprocalHandlesAndMatchingProcessBirth() {
        let a = UnixSocketRecord(pid: "10", descriptor: "3", endpoint: "->0x22", processIdentity: "10:100", socketHandle: 11, peerSocketHandle: 22)
        var b = UnixSocketRecord(pid: "20", descriptor: "4", endpoint: "->0x11", processIdentity: "20:200", socketHandle: 22, peerSocketHandle: 11)
        XCTAssertEqual(ProcessCommunicationEvidence.unix(processes: processes, records: [a,b]).count, 1)
        b.processIdentity = "20:199"
        XCTAssertTrue(ProcessCommunicationEvidence.unix(processes: processes, records: [a,b]).isEmpty)
        b.processIdentity = "20:200"; b.peerSocketHandle = 33
        XCTAssertTrue(ProcessCommunicationEvidence.unix(processes: processes, records: [a,b]).isEmpty)
        let pathOnly = [UnixSocketRecord(pid: "10", descriptor: "3", endpoint: "/tmp/shared.sock"), UnixSocketRecord(pid: "20", descriptor: "4", endpoint: "/tmp/shared.sock")]
        XCTAssertTrue(ProcessCommunicationEvidence.unix(processes: processes, records: pathOnly).isEmpty)
    }
    private struct EmptySampler: ProcessActivitySampling {
        func sample(_ process: ProcessSnapshotRecord) -> ProcessObservationSample? { nil }
    }
    func testCoordinatorPersistsBothOwnersWithoutInventingTaskOrClosure() throws {
        let coordinator = ProcessObservationCoordinator(sampler: EmptySampler())
        _ = coordinator.collect(processes: processes, includeSamples: false)
        let connections = [socket("10", "127.0.0.1:7000", "127.0.0.1", 8000), socket("20", "127.0.0.1:8000", "127.0.0.1", 7000)]
        let events = coordinator.observeSockets(processes: processes, connections: connections)
        let edge = try XCTUnwrap(events.first { $0.op == "process_communication_observation" })
        XCTAssertNil(edge.sessionId)
        XCTAssertNil(edge.toolCallId)
        let payload = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(edge.afterContent!.utf8)) as? [String: Any])
        XCTAssertEqual(payload["firstProcessIdentity"] as? String, "10:100")
        XCTAssertEqual(payload["secondProcessIdentity"] as? String, "20:200")
        XCTAssertEqual(payload["direction"] as? String, "undetermined")
        XCTAssertTrue(coordinator.observeSockets(processes: processes, connections: connections).isEmpty)
        XCTAssertFalse(coordinator.observeSockets(processes: processes, connections: []).contains { $0.op == "process_communication_observation" })
        // A newly observed reconnection gets a fresh observation, without a fabricated close event.
        XCTAssertEqual(coordinator.observeSockets(processes: processes, connections: connections).filter { $0.op == "process_communication_observation" }.count, 1)
    }
    func testCrossApplicationConnectionIsNotAssignedToWorkBuddy() throws {
        let other = ProcessSnapshotRecord(pid: "20", ppid: "1", command: "other", agent: "other-agent", birthIdentity: 200)
        let scope = [processes[0], other]
        let coordinator = ProcessObservationCoordinator(sampler: EmptySampler())
        _ = coordinator.collect(processes: scope, includeSamples: false)
        let connections = [socket("10", "127.0.0.1:7000", "127.0.0.1", 8000), socket("20", "127.0.0.1:8000", "127.0.0.1", 7000)]
        let edge = try XCTUnwrap(coordinator.observeSockets(processes: scope, connections: connections).first { $0.op == "process_communication_observation" })
        XCTAssertNil(edge.agent)
    }
    func testLibprocCapturesActualSocketPairHandlesWithoutPayload() throws {
        var fds: [Int32] = [0,0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { _ = close(fds[0]); _ = close(fds[1]) }
        let records = LsofUnixSocketSnapshotProvider().snapshot(pids: [String(getpid())])
        let a = try XCTUnwrap(records.first { $0.descriptor == String(fds[0]) })
        let b = try XCTUnwrap(records.first { $0.descriptor == String(fds[1]) })
        XCTAssertNotNil(a.processIdentity)
        XCTAssertNotEqual(a.socketHandle, 0)
        XCTAssertEqual(a.peerSocketHandle, b.socketHandle)
        XCTAssertEqual(b.peerSocketHandle, a.socketHandle)
    }
}
