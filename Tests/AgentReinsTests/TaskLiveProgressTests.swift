import Foundation
import XCTest
@testable import AgentReins

final class TaskLiveProgressTests: XCTestCase {
    func testIncrementalProgressSurvivesLongTaskAndRepeatedEvidence() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        var progress = TaskLiveProgress(sessionID: "session", turnID: "turn",
                                        startedAt: start, lastActivityAt: start, phase: .preparing)
        let prompt = GuardEvent(kind: "model", ruleId: "test", path: "-", command: nil,
                                agent: "WorkBuddy", op: "prompt", severity: "info",
                                ts: start, action: "sent", sessionId: "session", turnId: "turn",
                                inputTokens: 120)
        progress.ingest(prompt)
        progress.ingest(prompt)
        for index in 1...600 {
            progress.ingest(GuardEvent(kind: "context", ruleId: "test", path: "-", command: nil,
                                       agent: "WorkBuddy", op: "observation", severity: "info",
                                       ts: start.addingTimeInterval(Double(index)), action: "seen",
                                       sessionId: "session", turnId: "turn"))
        }
        let call = GuardEvent(kind: "tool", ruleId: "test", path: "-", command: nil,
                              agent: "WorkBuddy", op: "call", severity: "info",
                              ts: start.addingTimeInterval(601), action: "requested",
                              sessionId: "session", turnId: "turn", toolCallId: "call-1",
                              toolName: "write_file")
        progress.ingest(call)
        XCTAssertEqual(progress.modelRequests.count, 1)
        XCTAssertEqual(progress.toolCalls.count, 1)
        XCTAssertEqual(progress.inputTokens, 120)
        XCTAssertEqual(progress.phase, .runningTool)
        XCTAssertEqual(progress.lastTool, "write_file")
        XCTAssertEqual(progress.startedAt, start)
    }
}
