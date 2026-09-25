import XCTest
@testable import AgentReins

final class SecurityDecisionTests: XCTestCase {
    private func event(host: String? = nil, port: Int? = nil, domain: String? = nil) -> GuardEvent {
        GuardEvent(kind: "network", ruleId: "test", path: "-", command: nil, agent: "workbuddy",
            op: "connect", severity: "medium", ts: Date(), action: "observed",
            remoteHost: host, remotePort: port, remoteDomain: domain)
    }

    func testAddressDedupKeepsDifferentPortsAndDomains() {
        let rows = [event(host: "8.8.8.8", port: 443), event(host: "8.8.8.8", port: 443),
                    event(host: "8.8.8.8", port: 22), event(host: "8.8.8.8", port: 443, domain: "example.com"), event()]
        XCTAssertEqual(SecurityDestinationFacts.endpoints(rows).count, 3)
    }

    func testPortDoesNotProveServiceAndRelayDoesNotProveFinalRecipient() {
        XCTAssertTrue(SecurityDestinationFacts.service(event(host: "8.8.8.8", port: 22)).contains("不能仅凭端口"))
        XCTAssertTrue(SecurityDestinationFacts.service(event(domain: "openrouter.ai")).contains("后续接收方尚未验证"))
        XCTAssertFalse(SecurityDestinationFacts.service(event(domain: "openrouter.ai.attacker.example")).contains("模型中转入口"))
    }

    func testOnlyPublicAddressesAreSentToLocationService() {
        XCTAssertTrue(IPGeolocationStore.isIPAddress("192.168.1.1"))
        XCTAssertTrue(IPGeolocationStore.isIPAddress("198.51.100.9"))
        XCTAssertFalse(IPGeolocationStore.isIPAddress("example.com"))
        for host in ["localhost:443", "::", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.1", "2001:db8::1",
                     "192.168.1.1", "203.0.113.20", "192.0.2.1", "198.51.100.2", "100.64.0.1", "224.0.0.1", "1..2.3.4"] {
            XCTAssertFalse(IPGeolocationStore.isPublicIPAddress(host), host)
        }
        XCTAssertTrue(IPGeolocationStore.isPublicIPAddress("8.8.8.8"))
        XCTAssertTrue(IPGeolocationStore.isPublicIPAddress("2606:4700:4700::1111"))
    }

    func testQuestionClassificationDoesNotInventDestination() {
        XCTAssertFalse(SafetyQuestion.destination.matches([event()]))
        XCTAssertTrue(SafetyQuestion.destination.matches([event(host: "8.8.8.8")]))
        XCTAssertFalse(SafetyQuestion.command.matches([event(host: "8.8.8.8", port: 22)]))
    }
}
