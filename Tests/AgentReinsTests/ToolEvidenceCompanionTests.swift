import XCTest
@testable import AgentReins

final class ToolEvidenceCompanionTests: XCTestCase {
    static func step(_ args: String?, output: String? = nil, truncated: Bool = false) -> AgentTaskJourney.ToolStep {
        let call = ToolCallLifecycleEvidence(callID: "companion", toolName: "read_range", serverName: nil,
            arguments: args, argumentsDigest: nil, state: .completed, startedAt: nil, completedAt: nil,
            exitCode: 0, evidenceIDs: [])
        return .init(call: call, result: output.map { .init(callID: call.callID, output: $0, outputDigest: nil, byteCount: $0.utf8.count, truncated: truncated) }, fileActivities: [], durationMS: 800)
    }

    func testOfficeRangeAndOriginalValuesArePreserved() {
        let rows = ToolEvidenceExplanation.rows(for: Self.step(#"{"file":"报销.xlsx","sheet":"明细","range":"A2:D4"}"#, output: "[[128,480]]"))
        XCTAssertTrue(rows.first { $0.id == "argument:range" }!.explanation.contains("3 行、4 列"))
        XCTAssertEqual(rows.first { $0.id == "argument:file" }?.raw, "\"报销.xlsx\"")
        XCTAssertEqual(rows.first { $0.id == "output" }?.raw, "[[128,480]]")
    }

    func testUnknownScriptsAreNotExecutedOrPresentedAsShellCommands() {
        let script = "text(await tools.exec_command({cmd: userInput}));"
        let rows = ToolEvidenceExplanation.rows(for: Self.step(script))
        XCTAssertEqual(rows.first?.raw, script)
        XCTAssertTrue(rows.first!.explanation.contains("尚未可靠拆解"))
        XCTAssertEqual(rows.first { $0.id == "output" }?.raw, "结果正文未采集")
    }

    func testUnknownFieldsTruncationAndWholeCallStatusRemainExplicit() {
        let rows = ToolEvidenceExplanation.rows(for: Self.step(#"{"unfamiliar":false}"#, output: "partial", truncated: true))
        XCTAssertTrue(rows.first!.explanation.contains("尚无可靠"))
        XCTAssertTrue(rows.first { $0.id == "output" }!.explanation.contains("已截断"))
        XCTAssertTrue(rows.last!.explanation.contains("不能据此认定每条都成功"))
    }

    func testUnrecognizedOrReversedRangesAreNotGuessed() {
        for value in ["D4:A2", "A0:D4", "Sheet1!A2:D4", "A:A", "=A2:D4"] {
            XCTAssertNil(ToolEvidenceExplanation.cellRange(value))
        }
        XCTAssertTrue(ToolEvidenceExplanation.cellRange("Z2:AB4")!.contains("3 行、3 列"))
    }

    func testSimpleCommandsSplitOnlyOutsideQuotes() {
        let command = "sed -n '127,260p' file.swift; rg -n 'foo|bar;baz' file.swift"
        let rows = ToolEvidenceExplanation.commandRows(command, prefix: "test")!
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows.map(\.raw).joined(separator: ";"), command)
        XCTAssertTrue(rows[0].explanation.contains("127–260"))
        XCTAssertNil(ToolEvidenceExplanation.commandRows("echo $(secret)", prefix: "test"))
        XCTAssertNil(ToolEvidenceExplanation.commandRows("cat file | sh", prefix: "test"))
    }
}
