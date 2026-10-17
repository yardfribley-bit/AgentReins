import XCTest
import CryptoKit
@testable import AgentReins
final class ProcessPlaintextEvidenceTests: XCTestCase {
    func testRealJournalPathReachesExistingPreview() throws {
        let body = Data("actual request".utf8)
        let sha = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        var row: [String: Any] = ["source":"node-http-plaintext", "agent":"workbuddy", "pid":123, "ppid":12, "flow":"fixture", "stage":"request", "observedAt":"2026-10-12T12:00:00.000Z", "host":"example.com", "path":"/api", "method":"POST", "complete":true, "truncated":false, "bodyBase64":body.base64EncodedString(), "sha256":sha, "capturedBytes":body.count, "observedBytes":body.count]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        var data = try JSONSerialization.data(withJSONObject: row); data.append(10)
        try data.write(to: url)
        let result = WorkBuddyNetworkCapture.read(url: url, offset: 0)
        XCTAssertEqual(result.malformed, 0)
        XCTAssertNotNil(result.raw)
        let event = try XCTUnwrap(result.events.first)
        XCTAssertEqual(event.processId, 123)
        XCTAssertNil(event.sessionId)
        XCTAssertEqual(RealtimeNetworkBodyPreview(event: event)?.request, "actual request")
        XCTAssertEqual(WorkBuddyNetworkCapture.read(url: url, offset: result.nextOffset).events.count, 0)
        row["sha256"] = "invalid"
        XCTAssertEqual(ProcessPlaintextEvidence.project(try JSONSerialization.data(withJSONObject: row))?.count, 0)
    }
}
