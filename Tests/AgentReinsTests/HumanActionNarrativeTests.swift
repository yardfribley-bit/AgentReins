import Foundation
import XCTest
@testable import AgentReins

final class HumanActionNarrativeTests: XCTestCase {
    func testCommandIsExplainedWithoutInventingSuccess() {
        let call = ToolCallLifecycleEvidence(callID: "1", toolName: "exec", serverName: nil,
            arguments: #"{"command":"g++ hello.cpp -o hello"}"#, argumentsDigest: nil,
            state: .running, startedAt: Date(), completedAt: nil, exitCode: nil, evidenceIDs: [])
        let step = AgentTaskJourney.ToolStep(call: call, result: nil, fileActivities: [], durationMS: nil)
        let narrative = HumanActionNarrative.build(step)
        XCTAssertTrue(narrative.headline.contains("g++ hello.cpp -o hello"))
        XCTAssertTrue(narrative.headline.contains("编译程序"))
        XCTAssertEqual(narrative.command, "g++ hello.cpp -o hello")
        XCTAssertTrue(narrative.outcome.contains("尚未采集"))
    }

    func testNonzeroExitCodeAndOutputAreVisible() {
        let call = ToolCallLifecycleEvidence(callID: "3", toolName: "bash", serverName: nil,
            arguments: #"{"command":"swift test"}"#, argumentsDigest: nil,
            state: .completed, startedAt: Date(), completedAt: Date(), exitCode: 1, evidenceIDs: [])
        let result = ToolOutputEvidence(callID: "3", output: "Test failed: expected 2, got 1",
            outputDigest: nil, byteCount: 30, truncated: false)
        let step = AgentTaskJourney.ToolStep(call: call, result: result, fileActivities: [], durationMS: 1200)
        let narrative = HumanActionNarrative.build(step)
        XCTAssertTrue(narrative.headline.contains("运行测试"))
        XCTAssertTrue(narrative.outcome.contains("退出码 1"))
        XCTAssertTrue(narrative.outcome.contains("Test failed"))
    }

    func testFileWriteUsesObservedFileAndStatesMissingResult() {
        let call = ToolCallLifecycleEvidence(callID: "2", toolName: "write_file", serverName: nil,
            arguments: #"{"path":"hello.cpp"}"#, argumentsDigest: nil,
            state: .completed, startedAt: Date(), completedAt: Date(), exitCode: nil, evidenceIDs: [])
        let file = FileActivityEvidence(operation: .create, path: "src/hello.cpp",
            beforeDigest: nil, afterDigest: "abc", patch: nil, toolCallID: "2", attribution: .confirmed)
        let step = AgentTaskJourney.ToolStep(call: call, result: nil, fileActivities: [file], durationMS: 800)
        let narrative = HumanActionNarrative.build(step)
        XCTAssertEqual(narrative.target, "src/hello.cpp")
        XCTAssertEqual(narrative.duration, "0.8 秒")
        XCTAssertTrue(narrative.outcome.contains("未采集"))
    }
}
