import AppKit
import SwiftUI
import WebKit
import XCTest
@testable import AgentReins

/// Optional acceptance against privately retained bytes of the user's actual
/// installation turn. Never substitute a generated fixture for field evidence.
final class WorkBuddyInstallFieldTests: XCTestCase {
    @MainActor func testActualStoppedInstallKeepsOriginalRequestAndAllNativeReturns() async throws {
        guard let source = ProcessInfo.processInfo.environment["AGENTREINS_INSTALL_FIELD_DIR"] else {
            throw XCTSkip("需指定本次安装任务的私有原始采集切片")
        }
        let directory = URL(fileURLWithPath: source)
        let parsed = WorkBuddySight.parseSession(directory.appendingPathComponent("current-install-turn.jsonl"), fullHistory: true)
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let captured = try decoder.decode([GuardEvent].self, from: Data(contentsOf: directory.appendingPathComponent("captured-install-all.json")))
        let hooks = try decoder.decode([GuardEvent].self, from: Data(contentsOf: directory.appendingPathComponent("captured-install-hooks.json")))
        var byID = Dictionary(captured.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
        for event in parsed + hooks { byID[event.id] = event }
        let captureDecoder = WorkBuddyNetworkEvidence.captureDecoder()
        let networkLines = try Data(contentsOf: directory.appendingPathComponent("actual-install-network.jsonl")).split(separator: 0x0a)
        for line in networkLines {
            let record = try captureDecoder.decode(WorkBuddyNetworkCaptureRecord.self, from: Data(line))
            for event in WorkBuddyNetworkEvidence.project(record) { byID[event.id] = event }
        }
        let events = RealtimeWorkspaceProjector.normalizedEvents(Array(byID.values))
        XCTAssertEqual(parsed.filter { $0.op == "call" }.count, 20)
        XCTAssertEqual(parsed.filter { $0.op == "result" }.count, 20)
        let raw = "https://github.com/qingjian-team/qingjian 帮我安装 这个项目，我本地已经下载了"
        let tasks = RealtimeWorkspaceProjector.tasks(events: events, since: .distantPast)
        let actual = try XCTUnwrap(tasks.first { $0.turn == "b1e18ff8-d028-4b83-bb37-fd55b4643f7a" })
        XCTAssertEqual(actual.originalRequest, raw)
        XCTAssertEqual(actual.requestSource, "workbuddy-hook")
        XCTAssertEqual(actual.lifecycleStatus, "stopped")
        XCTAssertEqual(actual.executionState, "stopped")
        XCTAssertEqual(actual.completionEvidence, "unknown")
        XCTAssertFalse(actual.reportedComplete)
        XCTAssertTrue(actual.nativeEndMessage?.contains("不能") == true || actual.nativeEndMessage?.contains("无法") == true)
        XCTAssertTrue(actual.nativeEndMessage?.contains("a password is required") == true)
        XCTAssertNil(actual.stopReason, "Do not invent a structured stop reason from prose")
        let nativeIDs = Set(parsed.filter { $0.op == "call" }.compactMap(\.toolCallId))
        let calls = actual.cards.filter { $0.id.hasPrefix("call:") && $0.call.map(nativeIDs.contains) == true }
        XCTAssertEqual(Set(calls.compactMap(\.call)).count, 20)
        XCTAssertTrue(calls.allSatisfy { ["returned", "failed"].contains($0.phase) })
        XCTAssertTrue(calls.contains { $0.output.contains("a password is required") && $0.execution?.exitCode == 0 }, "Outer shell exit zero must not prove installation success")
        XCTAssertEqual(events.filter { $0.op == "network_prompt" }.count, 13)
        XCTAssertTrue(events.filter { $0.op == "network_prompt" }.allSatisfy { $0.turnId == actual.turn })
        XCTAssertFalse(tasks.contains { $0.originalRequest?.contains("SL-20261007") == true }, "Compaction summaries cannot become new human tasks")
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let contexts = RealtimeContextProjector.assemble(events.compactMap(RealtimeContextProjector.parse), events: events)
        let payload = RealtimeWorkspacePayload(tasks: [actual], collected: [], unattributedCount: 0, processes: [], health: [], observing: false, persistenceError: nil, publishedAt: Date(), truncated: false, contexts: contexts)
        try encoder.encode(payload).write(to: directory.appendingPathComponent("actual-install-payload.json"))
        // Prepare a bounded repair of this already-captured live task, preserving
        // all other checkpoint records and all native source IDs.
        if let checkpointPath = ProcessInfo.processInfo.environment["AGENTREINS_REPAIR_CHECKPOINT"] {
            let old = try XCTUnwrap(RealtimeActiveCheckpoint.load(URL(fileURLWithPath: checkpointPath)))
            var restored = Dictionary(old.events.map { ($0.id, $0) }, uniquingKeysWith: { _, last in last })
            for event in events { restored[event.id] = event }
            let repaired = RealtimeActiveCheckpoint(version: old.version, savedAt: Date(), events: Array(restored.values), readTaskIDs: old.readTaskIDs)
            try repaired.save(directory.appendingPathComponent("repaired-active-checkpoint.json"))
        }
        _ = NSApplication.shared
        let host = NSHostingView(rootView: RealtimeWorkspaceView(payload: payload))
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1536, height: 1100), styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false; window.contentView = host; host.frame = window.contentLayoutRect; window.orderBack(nil)
        defer { window.close() }
        func find(_ v: NSView) -> WKWebView? { (v as? WKWebView) ?? v.subviews.compactMap { find($0) }.first }
        var web: WKWebView?
        for _ in 0..<50 {
            try await Task.sleep(for: .milliseconds(100)); web = find(host)
            if let web, (try? await web.evaluateJavaScript("document.querySelector('.task-head h1')?.textContent")) as? String == actual.title { break }
        }
        let browser = try XCTUnwrap(web)
        let title = try await browser.evaluateJavaScript("document.querySelector('.task-head h1').textContent") as? String
        XCTAssertEqual(title, raw)
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-flow-node=closure]').click()")
        let detail = try await browser.evaluateJavaScript("document.querySelector('#detail-code').textContent") as? String
        XCTAssertTrue(detail?.contains("a password is required") == true)
        let nodeCount = try await browser.evaluateJavaScript("document.querySelectorAll('[data-flow-node]').length") as? Int
        XCTAssertEqual(nodeCount, 16)
        let image = try await browser.takeSnapshot(configuration: nil)
        let bitmap = try XCTUnwrap(NSBitmapImageRep(data: try XCTUnwrap(image.tiffRepresentation)))
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: directory.appendingPathComponent("actual-install-native.png"))
        _ = try await browser.evaluateJavaScript("document.querySelector('[data-view=results]').click()")
        let stopped = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=stopped] .board-card').length") as? Int
        XCTAssertEqual(stopped, 1)
        let completed = try await browser.evaluateJavaScript("document.querySelectorAll('[data-status=completed] .board-card').length") as? Int
        XCTAssertEqual(completed, 0)
    }
}
