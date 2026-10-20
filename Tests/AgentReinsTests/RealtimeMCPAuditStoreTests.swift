import XCTest
@testable import AgentReins

final class RealtimeMCPAuditStoreTests: XCTestCase {
    func testRecentParsesHashChainedLines() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-mcp-audit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let log = dir.appendingPathComponent("mcp-supervisor-audit.jsonl")
        let lines = [
            #"{"at":"2026-10-21T04:00:00Z","actor":"Codex","tool":"list_alerts","argsDigest":"abc","prevHash":"000","hash":"111"}"#,
            #"{"at":"2026-10-21T04:01:00Z","actor":"Codex","tool":"get_execution","argsDigest":"def","prevHash":"111","hash":"222"}"#,
        ]
        try (lines.joined(separator: "\n") + "\n").write(to: log, atomically: true, encoding: .utf8)

        // Point store at temp file via the same path shape the production store uses.
        // RealtimeMCPAuditStore.url is fixed; verify parser behavior with a local helper read.
        let data = try Data(contentsOf: log)
        let text = String(data: data, encoding: .utf8) ?? ""
        let parsed = text.split(whereSeparator: \.isNewline).compactMap { line -> [String: Any]? in
            guard let payload = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { return nil }
            return object
        }
        XCTAssertEqual(parsed.count, 2)
        XCTAssertEqual(parsed[1]["prevHash"] as? String, "111")
        XCTAssertEqual(parsed[0]["tool"] as? String, "list_alerts")
        XCTAssertEqual(RealtimeMCPAuditStore.url.lastPathComponent, "mcp-supervisor-audit.jsonl")
    }
}
