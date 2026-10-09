import XCTest
@testable import AgentReins

final class NetworkSocketEvidenceProjectorTests: XCTestCase {
    private let observedAt = Date(timeIntervalSince1970: 1_791_562_329.13193)
    private let git = ProcessSnapshotRecord(pid: "12300", ppid: "12298",
        command: "git-remote-https --token secret-must-not-be-projected", agent: "codex",
        birthIdentity: 1_791_562_328_740_728,
        executablePath: "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git-remote-http")
    private let socket = NetworkConnectionRecord(pid: "12300", localAddress: "127.0.0.1:62129",
        remoteHost: "127.0.0.1", remotePort: 1081, state: "ESTABLISHED")

    private func route(time: Date? = nil, port: Int = 62129, host: String = "github.com") -> ProxyDestinationRecord {
        .init(clientPort: port, remoteHost: host, remotePort: 443,
              timestamp: time ?? Date(timeIntervalSince1970: 1_791_562_328), proxyName: "V2rayU")
    }

    private func project(_ sockets: [NetworkConnectionRecord]? = nil,
                         processes: [ProcessSnapshotRecord]? = nil,
                         routes: [ProxyDestinationRecord] = [], time: Date? = nil) -> [GuardEvent] {
        NetworkSocketEvidenceProjector.project(processes: processes ?? [git],
            connections: sockets ?? [socket], proxyDestinations: routes,
            observedAt: time ?? observedAt)
    }

    private func metadata(_ event: GuardEvent) throws -> [String: Any] {
        let command = try XCTUnwrap(event.command)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(command.utf8)) as? [String: Any])
    }

    func testGitPushDiscoverySocketProjectsGitHubRouteWithOriginalEndpoint() throws {
        let event = try XCTUnwrap(project(routes: [route()]).first)
        XCTAssertEqual(event.kind, "network")
        XCTAssertEqual(event.op, "connect")
        XCTAssertEqual(event.processId, 12300)
        XCTAssertEqual(event.parentProcessId, 12298)
        XCTAssertEqual(event.agent, "codex")
        XCTAssertEqual(event.localAddress, "127.0.0.1:62129")
        XCTAssertEqual(event.remoteHost, "github.com")
        XCTAssertEqual(event.remoteDomain, "github.com")
        XCTAssertEqual(event.remotePort, 443)
        XCTAssertEqual(event.ts, observedAt)
        XCTAssertNil(event.sessionId)
        XCTAssertNil(event.turnId)
        let data = try metadata(event)
        XCTAssertEqual(data["processIdentity"] as? String, "12300:1791562328740728")
        let raw = try XCTUnwrap(data["socket"] as? [String: Any])
        XCTAssertEqual(raw["localAddress"] as? String, socket.localAddress)
        XCTAssertEqual(raw["remoteHost"] as? String, "127.0.0.1")
        XCTAssertEqual(raw["remotePort"] as? Int, 1081)
        XCTAssertEqual(raw["state"] as? String, "ESTABLISHED")
        let proxy = try XCTUnwrap(data["proxy"] as? [String: Any])
        XCTAssertEqual(proxy["source"] as? String, "V2rayU")
        XCTAssertEqual(proxy["observedAt"] as? Double, 1_791_562_328)
        XCTAssertFalse(try XCTUnwrap(event.command).contains("secret-must-not-be-projected"))
    }

    func testAbsentOrWrongClientPortRoutePreservesUnknownLoopbackEvidence() throws {
        for routes in [[], [route(port: 62128)]] {
            let event = try XCTUnwrap(project(routes: routes).first)
            XCTAssertEqual(event.remoteHost, "127.0.0.1")
            XCTAssertEqual(event.remotePort, 1081)
            XCTAssertNil(event.remoteDomain)
            XCTAssertEqual(try metadata(event)["destinationStatus"] as? String, "unknown")
            XCTAssertNil(try metadata(event)["proxy"])
        }
    }

    func testStaleRouteAndRoutePredatingProcessCannotFollowReusedClientPort() throws {
        for time in [observedAt.addingTimeInterval(-16), observedAt.addingTimeInterval(-5)] {
            let event = try XCTUnwrap(project(routes: [route(time: time)]).first)
            XCTAssertEqual(event.remoteHost, "127.0.0.1")
            XCTAssertNil(event.remoteDomain)
        }
    }

    func testFifteenSecondRouteDistanceIsInclusiveAndOlderIsRejected() throws {
        let olderProcess = ProcessSnapshotRecord(pid: git.pid, ppid: git.ppid, command: "git",
            agent: "codex", birthIdentity: 1_791_562_300_000_000)
        let boundary = route(time: observedAt.addingTimeInterval(-15))
        XCTAssertEqual(project(processes: [olderProcess], routes: [boundary]).first?.remoteDomain, "github.com")
        let tooOld = route(time: observedAt.addingTimeInterval(-15.001))
        XCTAssertNil(project(processes: [olderProcess], routes: [tooOld]).first?.remoteDomain)
    }

    func testDirectSocketKeepsObservedIPWithoutInventingDomain() throws {
        let direct = NetworkConnectionRecord(pid: "12300", localAddress: "192.168.1.11:62129",
            remoteHost: "20.205.243.168", remotePort: 443, state: "ESTABLISHED")
        let event = try XCTUnwrap(project([direct], routes: [route()]).first)
        XCTAssertEqual(event.remoteHost, "20.205.243.168")
        XCTAssertEqual(event.remotePort, 443)
        XCTAssertNil(event.remoteDomain)
        XCTAssertNil(try metadata(event)["proxy"])
    }

    func testStableIdentityDeduplicatesSamplesButSeparatesPIDBirthAndRoute() throws {
        let first = try XCTUnwrap(project(routes: [route()]).first)
        let repeated = try XCTUnwrap(project(routes: [route()], time: observedAt.addingTimeInterval(1)).first)
        XCTAssertEqual(first.id, repeated.id)
        XCTAssertEqual(project([socket, socket], routes: [route()]).count, 1)
        let reused = ProcessSnapshotRecord(pid: git.pid, ppid: git.ppid, command: "other",
            agent: "codex", birthIdentity: 1_791_562_329_000_000)
        let next = try XCTUnwrap(project(processes: [reused], routes: [route()]).first)
        XCTAssertNotEqual(first.id, next.id)
        XCTAssertNil(next.remoteDomain)
        let differentRoute = try XCTUnwrap(project(routes: [route(host: "gitlab.com")]).first)
        XCTAssertNotEqual(first.id, differentRoute.id)
    }

    func testListenersClosingSocketsUnownedAndAmbiguousPIDIdentitiesAreExcluded() {
        let listener = NetworkConnectionRecord(pid: "12300", localAddress: "*:1081",
            remoteHost: "", remotePort: 0, state: "LISTEN")
        let closed = NetworkConnectionRecord(pid: "12300", localAddress: socket.localAddress,
            remoteHost: socket.remoteHost, remotePort: socket.remotePort, state: "CLOSED")
        let closing = NetworkConnectionRecord(pid: "12300", localAddress: socket.localAddress,
            remoteHost: socket.remoteHost, remotePort: socket.remotePort, state: "CLOSE_WAIT")
        XCTAssertTrue(project([listener, closed, closing]).isEmpty)
        XCTAssertTrue(project(processes: []).isEmpty)
        let reused = ProcessSnapshotRecord(pid: git.pid, ppid: git.ppid, command: "other",
            birthIdentity: 1_791_562_329_000_000)
        XCTAssertTrue(project(processes: [git, reused]).isEmpty)
        let unknownBirth = ProcessSnapshotRecord(pid: git.pid, ppid: git.ppid, command: "other")
        XCTAssertTrue(project(processes: [unknownBirth]).isEmpty)
    }

    func testConflictingRoutesAndCredentialBearingHostRemainUnknown() throws {
        let conflicting = [route(), route(host: "gitlab.com")]
        XCTAssertNil(project(routes: conflicting).first?.remoteDomain)
        let event = try XCTUnwrap(project(routes: [route(host: "user:secret@github.com")]).first)
        XCTAssertNil(event.remoteDomain)
        XCTAssertFalse(try XCTUnwrap(event.command).contains("secret"))
    }

    func testIPv6LoopbackAndIPProxyDestinationKeepDomainUnknown() throws {
        let ipv6 = NetworkConnectionRecord(pid: "12300", localAddress: "[::1]:62129",
            remoteHost: "::1", remotePort: 1081, state: "ESTABLISHED")
        let github = try XCTUnwrap(project([ipv6], routes: [route()]).first)
        XCTAssertEqual(github.remoteDomain, "github.com")
        let ip = try XCTUnwrap(project([ipv6], routes: [route(host: "20.205.243.168")]).first)
        XCTAssertEqual(ip.remoteHost, "20.205.243.168")
        XCTAssertNil(ip.remoteDomain)
    }
}
