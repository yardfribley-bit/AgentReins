import XCTest
@testable import AgentReins

final class NativeTransportAuditTests: XCTestCase {
    func testLiveEvidenceProjectionAndPathBoundary() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: outside) }
        for url in [root, outside] { try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true) }
        func write(_ name: String, _ mode: String, at base: URL) throws {
            let folder = base.appendingPathComponent(name)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let item: [String: Any] = ["invocation": ["agent": "Codex", "captureMode": mode, "tool": "curl", "startedAt": "2026-10-14T01:00:00Z", "codexThreadID": "native-session"], "fileResult": ["sha256": "verified-hash", "bytes": 227], "blocks": [["kind": "data", "observedBytes": 227]]]
            try JSONSerialization.data(withJSONObject: item).write(to: folder.appendingPathComponent("transport.json"))
        }
        try write("live", "agent-path", at: root)
        try write("fixture", "manual", at: root)
        try write("escape", "agent-path", at: outside)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("escape"), withDestinationURL: outside.appendingPathComponent("escape"))
        let rows = NativeTransportAudit.records(root: root)
        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(rows.first?["codexThreadID"] as? String, "native-session")
        XCTAssertEqual((rows.first?["fileResult"] as? [String: Any])?["sha256"] as? String, "verified-hash")
        XCTAssertTrue(rows.first?["task"] is NSNull)
    }
}
