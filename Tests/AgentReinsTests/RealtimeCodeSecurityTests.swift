import XCTest
@testable import AgentReins

final class RealtimeCodeSecurityTests: XCTestCase {
    func testFindingsSurviveRequestResultPairAndHideSecret() throws {
        let finding = CodeFinding(ruleId: "hardcoded-secret", title: "Possible secret", severity: "critical", line: 2, evidence: "token = 'fixture-secret-only'")
        func event(_ op: String, findings: [CodeFinding]) -> GuardEvent {
            GuardEvent(kind: "tool", ruleId: "fixture", path: "/fixture", command: "{}", agent: "workbuddy", op: op, severity: "info", ts: Date(), action: "observed", sessionId: "s", turnId: "t", toolCallId: "call", toolName: "Write", codeFindings: findings)
        }
        let cards = RealtimeWorkspaceProjector.cards([event("call", findings: [finding]), event("result", findings: [finding])])
        let card = try XCTUnwrap(cards.first)
        XCTAssertEqual(card.codeFindings.count, 1)
        XCTAssertEqual(card.codeFindings.first?.line, 2)
        XCTAssertFalse(card.codeFindings[0].evidence.contains("fixture-secret-only"))
        let encoded = String(decoding: try JSONEncoder().encode(card), as: UTF8.self)
        XCTAssertTrue(encoded.contains("codeFindings"))
    }

    func testCodexNewCallIsScannedAndResultIsNotRescanned() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let rows = [
            #"{"type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"call","turn_id":"t","arguments":"{\"cmd\":\"chmod 777 example.sh\"}"}}"#,
            #"{"type":"response_item","payload":{"type":"function_call_output","call_id":"call","turn_id":"t","output":"chmod 777 example.sh"}}"#
        ]
        try rows.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        let events = CodexSight.parseSession(url)
        let call = try XCTUnwrap(events.first { $0.op == "call" })
        XCTAssertTrue(call.codeFindings?.contains { $0.ruleId == "world-writable" } == true)
        XCTAssertTrue(events.filter { $0.op == "result" }.allSatisfy { $0.codeFindings == nil })
        XCTAssertTrue(RealtimeWorkspaceProjector.cards(events).contains { !$0.codeFindings.isEmpty })
    }

    func testSafeCommandDoesNotCreateFinding() {
        XCTAssertTrue(CodeSecurityScanner.scanGenerated(toolName: "exec_command", arguments: #"{"cmd":"pwd"}"#).isEmpty)
    }
}
