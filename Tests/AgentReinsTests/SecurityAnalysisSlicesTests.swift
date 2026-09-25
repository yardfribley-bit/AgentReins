import XCTest
@testable import AgentReins

final class SecurityAnalysisSlicesTests: XCTestCase {
    func testLargeUnicodeBodyIncludesTailAndStableOffsets() {
        let body = String(repeating: "安全🧑🏽‍💻数据", count: 3000) + "END_OF_CAPTURE"
        let event = GuardEvent(kind: "model", ruleId: "test", path: "-", command: nil,
            agent: "test", op: "prompt", severity: "info", ts: Date(timeIntervalSince1970: 1),
            action: "seen", modelPrompt: body)
        let slices = SecurityAnalysisSlices.build([event])
        XCTAssertGreaterThan(slices.count, 1)
        XCTAssertEqual(slices.map(\.id), SecurityAnalysisSlices.build([event]).map(\.id))
        let rows = slices.flatMap(\.evidence).filter { $0["field"] == "model_prompt" }
        XCTAssertTrue(rows.last?["detail"]?.hasSuffix("END_OF_CAPTURE") == true)
        var coveredUntil = 0
        for row in rows {
            let offset = Int(row["character_offset"]!)!
            let detail = row["detail"]!
            XCTAssertLessThanOrEqual(offset, coveredUntil)
            let start = body.index(body.startIndex, offsetBy: offset)
            XCTAssertTrue(body[start...].hasPrefix(detail))
            coveredUntil = max(coveredUntil, offset + detail.count)
        }
        XCTAssertEqual(coveredUntil, body.count)
    }
}
