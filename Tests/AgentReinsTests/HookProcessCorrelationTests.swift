import Foundation
import XCTest
@testable import AgentReins

final class HookProcessCorrelationTests: XCTestCase {
    private let base = Date(timeIntervalSince1970: 1_791_050_000)
    private func process(_ pid: String, parent: String, after: Double, command: String) -> ProcessSnapshotRecord {
        .init(pid: pid, ppid: parent, command: command, agent: "workbuddy",
              birthIdentity: UInt64(base.addingTimeInterval(after).timeIntervalSince1970 * 1_000_000), executablePath: "/test/node")
    }
    private var root: ProcessSnapshotRecord { process("10", parent: "1", after: -100, command: "workbuddy-sdk") }
    private func hook(call: String = "call", session: String = "session", after: Double = 0,
                      op: String = "hook_tool_start", ancestry: Bool = true, command: String = "echo fixture") throws -> GuardEvent {
        var record: [String: Any] = ["payload": ["tool_input": ["command": command]]]
        if ancestry { record["caller_ancestors"] = [["pid": 10, "birth_identity": root.birthIdentity!]] }
        let text = String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
        return .init(kind: "activity", ruleId: "workbuddy_hook_native", path: "-", command: nil,
            agent: "workbuddy", op: op, severity: "info", ts: base.addingTimeInterval(after), action: "observed",
            sessionId: session, toolCallId: call, toolName: "Bash", afterContent: text, source: "workbuddy-hook")
    }
    func testBranchCommandAndNativeIdentityProduceCandidateOnly() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(3)
        _ = coordinator.observeProcesses([root], now: now)
        _ = coordinator.observeHook(try hook(), now: now)
        let candidate = process("20", parent: "10", after: 1, command: "/bin/bash -c echo fixture")
        let events = coordinator.observeProcesses([root, candidate], now: now)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].sessionId, "session")
        XCTAssertEqual(events[0].toolCallId, "call")
        XCTAssertEqual(events[0].attributionConfidence, .inferred)
        XCTAssertTrue(events[0].afterContent!.contains("candidate"))
        let payload = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(events[0].afterContent!.utf8)) as? [String: Any])
        XCTAssertEqual(payload["callerProcessIdentity"] as? String, ProcessObservationCoordinator.identity(root))
        XCTAssertTrue(coordinator.observeProcesses([root, candidate], now: now).isEmpty)
    }
    func testSamplingTargetsStayInNativeCallerBranch() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(3)
        let child = process("20", parent: "10", after: -1, command: "existing helper")
        let unrelated = process("30", parent: "1", after: -10, command: "unrelated workbuddy process")
        let records = [root, child, unrelated]
        _ = coordinator.observeProcesses(records, now: now)
        _ = coordinator.observeHook(try hook(), now: now)
        XCTAssertEqual(Set(coordinator.samplingTargets(records, now: now).map(\.pid)), Set(["10", "20"]))
    }

    func testWebSearchHasObservedCallerWithoutInventingExecutor() throws {
        let coordinator = HookProcessCorrelation()
        let record: [String: Any] = ["payload": ["tool_input": ["query": "fixture"]],
            "caller_ancestors": [["pid": 10, "parent_pid": 1, "birth_identity": root.birthIdentity!,
                "executable": "/Applications/WorkBuddy.app/Contents/MacOS/Electron"]],
            "caller_snapshot": ["processes": [["pid": 10]], "truncated": false]]
        let text = String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
        let event = GuardEvent(kind: "activity", ruleId: "workbuddy_hook_native", path: "-", command: nil,
            agent: "workbuddy", op: "hook_tool_start", severity: "info", ts: base, action: "observed",
            sessionId: "session", toolCallId: "web", toolName: "WebSearch", afterContent: text, source: "workbuddy-hook")
        let events = coordinator.observeHook(event, now: base)
        XCTAssertEqual(events.map(\.op), ["hook_caller_observation"])
        XCTAssertEqual(events.first?.processId, 10)
        XCTAssertEqual(events.first?.attributionConfidence, .confirmed)
        XCTAssertTrue(events.first!.afterContent!.contains("hook_caller"))
        XCTAssertTrue(coordinator.observeHook(event, now: base).isEmpty)
        XCTAssertTrue(coordinator.observeProcesses([root], now: base).isEmpty)
    }

    func testSamplingIncludesValidatedBackendAncestors() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(3)
        let backend = process("5", parent: "1", after: -200, command: "workbuddy backend")
        let unrelated = process("30", parent: "1", after: -10, command: "unrelated app")
        let records = [root, backend, unrelated]
        _ = coordinator.observeProcesses(records, now: now)
        let record: [String: Any] = ["payload": [:], "caller_ancestors": [
            ["pid": 10, "birth_identity": root.birthIdentity!], ["pid": 5, "birth_identity": backend.birthIdentity!]]]
        let text = String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
        let event = GuardEvent(kind: "activity", ruleId: "workbuddy_hook_native", path: "-", command: nil,
            agent: "workbuddy", op: "hook_user_prompt", severity: "info", ts: base, action: "observed",
            sessionId: "session", afterContent: text, source: "workbuddy-hook")
        _ = coordinator.observeHook(event, now: now)
        XCTAssertEqual(Set(coordinator.samplingTargets(records, now: now).map(\.pid)), ["5", "10"])
    }

    func testTimeOverlapAloneOrDifferentCommandDoesNotJoin() throws {
        for (ancestry, command) in [(false, "echo fixture"), (true, "different command")] {
            let coordinator = HookProcessCorrelation()
            let now = base.addingTimeInterval(3)
            _ = coordinator.observeProcesses([root], now: now)
            _ = coordinator.observeHook(try hook(ancestry: ancestry), now: now)
            XCTAssertTrue(coordinator.observeProcesses([root, process("20", parent: "10", after: 1, command: command)], now: now).isEmpty)
        }
    }
    func testReusedCallerPIDCannotJoinNewDescendant() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(3)
        _ = coordinator.observeProcesses([root], now: now)
        _ = coordinator.observeHook(try hook(), now: now)
        let reusedRoot = process("10", parent: "1", after: 0.5, command: "new-workbuddy-sdk")
        XCTAssertTrue(coordinator.observeProcesses([reusedRoot, process("20", parent: "10", after: 1, command: "echo fixture")], now: now).isEmpty)
    }
    func testOutOfOrderFinishBoundsLateProcessEvidence() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(4)
        _ = coordinator.observeProcesses([root], now: now)
        _ = coordinator.observeHook(try hook(after: 2, op: "hook_tool_finish"), now: now)
        _ = coordinator.observeHook(try hook(), now: now)
        let before = process("20", parent: "10", after: 1, command: "echo fixture")
        let after = process("21", parent: "10", after: 3, command: "echo fixture")
        let events = coordinator.observeProcesses([root, before, after], now: now)
        XCTAssertEqual(events.map(\.processId), [20])
    }
    func testParallelSameCommandsRemainAmbiguousAcrossSessions() throws {
        let coordinator = HookProcessCorrelation()
        let now = base.addingTimeInterval(3)
        _ = coordinator.observeProcesses([root], now: now)
        _ = coordinator.observeHook(try hook(call: "one", session: "one"), now: now)
        _ = coordinator.observeHook(try hook(call: "two", session: "two", after: 0.1), now: now)
        let events = coordinator.observeProcesses([root, process("20", parent: "10", after: 1, command: "echo fixture")], now: now)
        XCTAssertEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.attributionConfidence == .unknown && $0.afterContent!.contains("ambiguous") })
    }
}
