import XCTest
@testable import AgentReins

final class AuditDeviceIdentityTests: XCTestCase {
    func testPrivateAddressClassification() {
        for ip in ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.11"] {
            XCTAssertTrue(AuditDeviceIdentity.isPrivateIPv4(ip))
        }
        for ip in ["127.0.0.1", "169.254.1.1", "172.32.0.1", "8.8.8.8", "::1", "10.0.0.999"] {
            XCTAssertFalse(AuditDeviceIdentity.isPrivateIPv4(ip))
        }
    }

    func testIdentityRoundTrip() throws {
        let identity = AuditDeviceIdentity(localUser: "employee", deviceName: "Office Mac",
            localIPs: ["192.168.1.11"], observedAt: Date(timeIntervalSince1970: 100))
        let decoded = try JSONDecoder().decode(AuditDeviceIdentity.self, from: JSONEncoder().encode(identity))
        XCTAssertEqual(decoded.localUser, "employee")
        XCTAssertEqual(decoded.deviceName, "Office Mac")
        XCTAssertEqual(decoded.localIPs, ["192.168.1.11"])
        XCTAssertEqual(decoded.observedAt, identity.observedAt)
    }
}
