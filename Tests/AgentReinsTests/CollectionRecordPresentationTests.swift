import Foundation
import XCTest
@testable import AgentReins

final class CollectionRecordPresentationTests: XCTestCase {
    func testContextSummaryShowsActualRolesWithoutInventingFileOrigins() {
        let event = GuardEvent(kind: "model", ruleId: "network", path: "-", command: nil, agent: "workbuddy", op: "network_prompt", severity: "info", ts: Date(), action: "captured_complete", userIntent: "检查视频", modelPrompt: #"{"messages":[{"role":"system","content":"instructions"},{"role":"user","content":"检查视频"},{"role":"tool","content":"duration=5"}],"tools":[{"type":"function"}]}"#, source: "agentsight:workbuddy-network-body")
        let row = CollectionRecordPresentation(event, receivedAt: Date())
        XCTAssertTrue(row.summary.contains("检查视频"))
        XCTAssertTrue(row.summary.contains("工具结果 1 条"))
        XCTAssertTrue(row.summary.contains("工具定义 1 项"))
        XCTAssertNil(row.pid)
        XCTAssertEqual(row.state, "已收到")
    }
    func testNativeToolSummaryUsesPayloadNotInventedToolResult() {
        let event = GuardEvent(kind: "activity", ruleId: "native", path: "-", command: nil, agent: "workbuddy", op: "hook_tool_start", severity: "info", ts: Date(), action: "observed", toolCallId: "call-1", toolName: "Bash", afterContent: #"{"payload":{"tool_input":{"command":"ffprobe video.mp4"}}}"#, source: "workbuddy-hook")
        let row = CollectionRecordPresentation(event, receivedAt: Date())
        XCTAssertTrue(row.summary.contains("ffprobe video.mp4"))
        XCTAssertFalse(row.summary.contains("5.04"))
        XCTAssertTrue(row.details.contains { $0.contains("来源进程不等于工具执行进程") })
    }
    func testToolPairUsesCallAndSessionIdentity() {
        func event(_ op: String, call: String, body: String) -> GuardEvent {
            GuardEvent(kind: "activity", ruleId: "native", path: "-", command: nil, agent: "workbuddy", op: op, severity: "info", ts: Date(), action: "observed", sessionId: "session-1", toolCallId: call, toolName: "Bash", afterContent: body, source: "workbuddy-hook")
        }
        let request = event("hook_tool_start", call: "call-1", body: #"{"payload":{"tool_input":{"command":"ffprobe video.mp4"}}}"#)
        let result = event("hook_tool_finish", call: "call-1", body: #"{"payload":{"tool_response":"duration=5.041667"}}"#)
        let row = CollectionRecordPresentation(result, receivedAt: Date(), toolRequest: request)
        XCTAssertTrue(row.summary.contains("ffprobe video.mp4"))
        XCTAssertTrue(row.summary.contains("duration=5.041667"))
        let unrelated = event("hook_tool_start", call: "other-call", body: #"{"payload":{"tool_input":{"command":"unrelated-command"}}}"#)
        XCTAssertFalse(CollectionRecordPresentation(result, receivedAt: Date(), toolRequest: unrelated).summary.contains("unrelated-command"))
    }

    func testFileSnapshotSummaryKeepsContentBoundaryAndPreviewBounded() {
        let event = GuardEvent(kind: "activity", ruleId: "process", path: "-", command: nil, agent: "workbuddy", op: "process_resource_observation", severity: "info", ts: Date(), action: "observed", afterContent: #"{"sample":{"residentBytes":1048576,"openFiles":[{"path":"/tmp/MEMORY.md"}]}}"#, source: "process-observation-libproc", processId: 10)
        let row = CollectionRecordPresentation(event, receivedAt: Date())
        XCTAssertTrue(row.summary.contains("1.0 MB"))
        XCTAssertTrue(row.summary.contains("MEMORY.md"))
        XCTAssertTrue(row.summary.contains("没有读取内存正文或文件全文"))
        let large = GuardEvent(kind: "model", ruleId: "model", path: "-", command: nil, agent: "workbuddy", op: "network_prompt", severity: "info", ts: Date(), action: "captured_complete", modelPrompt: String(repeating: "a", count: 1_100_000))
        XCTAssertLessThanOrEqual(CollectionRecordPresentation(large, receivedAt: Date()).preview.count, 2_000)
    }
    func testReplayIsBoundedAndKeepsRecordedState() {
        var buffer = CollectionReplayBuffer(capacity: 2)
        var registry = CollectionProcessRegistry()
        registry.update([.init(pid: "10", ppid: "1", command: "node", agent: "workbuddy", birthIdentity: 1)], now: Date())
        buffer.append(.init(time: Date(timeIntervalSince1970: 1), registry: registry, records: []))
        registry.update([], now: Date())
        buffer.append(.init(time: Date(timeIntervalSince1970: 2), registry: registry, records: []))
        XCTAssertEqual(buffer.frame(at: 0)?.registry.nodes.values.first?.active, true)
        XCTAssertEqual(buffer.frame(at: 1)?.registry.nodes.values.first?.active, false)
        buffer.append(.init(time: Date(timeIntervalSince1970: 3), registry: registry, records: []))
        XCTAssertEqual(buffer.frames.count, 2)
        XCTAssertEqual(buffer.frame(at: 0)?.time.timeIntervalSince1970, 2)
        XCTAssertNil(buffer.frame(at: 2))
    }
}
