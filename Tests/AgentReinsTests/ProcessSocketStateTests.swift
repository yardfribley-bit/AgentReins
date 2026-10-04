import XCTest
@testable import AgentReins

final class ProcessSocketStateTests: XCTestCase {
    func testListenersEstablishedAndClosedRemainDistinct() {
        let records = LsofNetworkSnapshotProvider.parse("""
        p10
        f3
        n*:8100
        TST=LISTEN
        f4
        n127.0.0.1:52926->127.0.0.1:52925
        TST=CLOSED
        p20
        f5
        n[::1]:1111->[::1]:8100
        TST=ESTABLISHED
        """)
        XCTAssertEqual(records.count, 3)
        XCTAssertTrue(records[0].isListener)
        XCTAssertEqual(records[0].localAddress, "*:8100")
        XCTAssertEqual(records[1].state, "CLOSED")
        XCTAssertEqual(records[2].state, "ESTABLISHED")
        XCTAssertEqual(records[2].remoteHost, "::1")
        XCTAssertEqual(records[2].remotePort, 8100)
    }

    func testUnixSocketDescriptorsDoNotCrossPIDBoundary() {
        let records = LsofUnixSocketSnapshotProvider.parse("""
        p10
        f5
        n/tmp/workbuddy-sandbox-center-test.sock
        p20
        ninvalid-without-fd
        f6
        n0x123 type=STREAM ->0x456
        """)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].pid, "10")
        XCTAssertEqual(records[1].pid, "20")
        XCTAssertEqual(records[1].descriptor, "6")
    }
}
