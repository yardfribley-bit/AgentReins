import CryptoKit
import Foundation
import XCTest
@testable import AgentReins

final class WorkBuddyNetworkEvidenceTests: XCTestCase {
    func testDefaultProxyArgumentsAreLoopbackOnlyAndUseBundledAddon() throws {
        let addon = URL(fileURLWithPath: "/Applications/AgentReins.app/Contents/Resources/workbuddy_network_capture.py")
        let arguments = WorkBuddyNetworkCapture.proxyArguments(addon: addon)

        XCTAssertTrue(arguments.contains("127.0.0.1"))
        XCTAssertTrue(arguments.contains(String(WorkBuddyNetworkCapture.proxyPort)))
        XCTAssertTrue(arguments.contains(addon.path))
    }

    func testProjectsCompleteRequestAndStreamingReasoningWithoutTruncation() throws {
        let longContext = String(repeating: "project-context-", count: 8_000)
        let request = try JSONSerialization.data(withJSONObject: [
            "model": "test-model",
            "messages": [
                ["role": "system", "content": longContext],
                ["role": "user", "content": [["type": "text", "text": "<user_query>Review this change</user_query>"]]]
            ]
        ])
        let response = """
        data: {"model":"test-model","choices":[{"delta":{"reasoning_content":"inspect "}}]}
        data: {"choices":[{"delta":{"reasoning_content":"carefully","content":"Done"}}],"usage":{"prompt_tokens":6225,"completion_tokens":63,"completion_tokens_details":{"reasoning_tokens":52}}}
        data: [DONE]
        """.data(using: .utf8)!
        let record = captureRecord(request: request, response: response)

        let events = WorkBuddyNetworkEvidence.project(record)

        XCTAssertEqual(events.count, 2)
        XCTAssertEqual(events[0].action, "captured_complete")
        XCTAssertEqual(events[0].userIntent, "Review this change")
        XCTAssertEqual(events[0].modelPrompt?.utf8.count, request.count)
        XCTAssertTrue(events[0].modelPrompt?.contains(longContext) == true)
        XCTAssertEqual(events[1].modelReasoning, "inspect carefully")
        XCTAssertEqual(events[1].modelResponse, "Done")
        XCTAssertEqual(events[1].inputTokens, 6_225)
        XCTAssertEqual(events[1].reasoningTokens, 52)
        XCTAssertEqual(events[0].remoteDomain, "copilot.tencent.com")
        XCTAssertEqual(events[0].remoteHost, "203.0.113.19")
        XCTAssertEqual(events[0].remotePort, 443)
        XCTAssertEqual(events[0].localAddress, "127.0.0.1:53124")
        XCTAssertTrue(events[0].attributionMethod?.contains("same-flow") == true)
        XCTAssertTrue(events[0].command?.contains(events[0].remoteHost ?? "missing") == true)

        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: events).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)
        XCTAssertTrue(audit.dataClassifications.contains { row in
            row.category == .systemInstructions && row.evidence.contains { $0.content == longContext }
        })
        XCTAssertTrue(audit.dataClassifications.contains { row in
            row.category == .userInput && row.evidence.contains { $0.content.contains("Review this change") }
        })
        XCTAssertEqual(audit.coverage, .complete)
    }

    func testRejectsTamperedRequestBody() throws {
        let request = Data(#"{"messages":[]}"#.utf8)
        let record = WorkBuddyNetworkCaptureRecord(
            observedAt: Date(), host: "copilot.tencent.com", path: "/v2/chat/completions",
            method: "POST", httpVersion: "HTTP/2", contentEncoding: nil,
            declaredContentLength: request.count, capturedWireBodyBytes: request.count,
            requestBodyBase64: request.base64EncodedString(), requestSHA256: String(repeating: "0", count: 64),
            responseStatus: 200, responseComplete: true, responseBodyBase64: nil)

        XCTAssertTrue(WorkBuddyNetworkEvidence.project(record).isEmpty)
    }

    func testAcceptsCurrentWorkBuddyV1ChatEndpoint() throws {
        let request = Data(#"{"messages":[{"role":"user","content":"hello"}]}"#.utf8)
        let record = WorkBuddyNetworkCaptureRecord(
            observedAt: Date(), host: "copilot.tencent.com", path: "/v1/chat/completions",
            method: "POST", httpVersion: "HTTP/2", contentEncoding: nil,
            declaredContentLength: request.count, capturedWireBodyBytes: request.count,
            requestBodyBase64: request.base64EncodedString(), requestSHA256: sha256(request),
            responseStatus: 200, responseComplete: true, responseBodyBase64: nil,
            clientAddress: "127.0.0.1:53001", remoteHost: "203.0.113.20", remotePort: 443)

        XCTAssertEqual(WorkBuddyNetworkEvidence.project(record).first?.remoteHost, "203.0.113.20")
    }

    @MainActor
    func testUniqueUserTextCorrelatesNetworkBodyToNativeTurn() throws {
        let resolver = EventAttributionResolver(window: 45)
        let now = Date()
        resolver.observe([
            GuardEvent(kind: "model", ruleId: "prompt", path: "/tmp/project", command: nil,
                agent: "workbuddy", op: "prompt", severity: "info", ts: now, action: "sent",
                sessionId: "native-session", turnId: "native-turn", userIntent: "Review this change")
        ], now: now)
        let request = try JSONSerialization.data(withJSONObject: [
            "messages": [["role": "user", "content": "Review this change"]]
        ])
        let network = try XCTUnwrap(WorkBuddyNetworkEvidence.project(captureRecord(
            request: request, response: Data(), observedAt: now.addingTimeInterval(1))).first)

        let resolved = resolver.resolveWorkBuddyNetworkBody(network)

        XCTAssertEqual(resolved.sessionId, "native-session")
        XCTAssertEqual(resolved.turnId, "native-turn")
        XCTAssertEqual(resolved.attributionConfidence, .confirmed)
    }

    func testReaderWaitsForCompleteJSONLine() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("workbuddy-network-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let request = Data(#"{"messages":[{"role":"user","content":"hello"}]}"#.utf8)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let line = try encoder.encode(captureRecord(request: request, response: Data()))
        try line.prefix(line.count / 2).write(to: url)

        let partial = WorkBuddyNetworkCapture.read(url: url, offset: 0)
        XCTAssertTrue(partial.events.isEmpty)
        XCTAssertEqual(partial.nextOffset, 0)

        try (line + Data([0x0A])).write(to: url)
        let complete = WorkBuddyNetworkCapture.read(url: url, offset: 0)
        XCTAssertEqual(complete.events.count, 2)
        XCTAssertEqual(complete.nextOffset, UInt64(line.count + 1))
    }

    private func captureRecord(request: Data, response: Data, observedAt: Date = Date()) -> WorkBuddyNetworkCaptureRecord {
        WorkBuddyNetworkCaptureRecord(
            observedAt: observedAt, host: "copilot.tencent.com", path: "/v2/chat/completions",
            method: "POST", httpVersion: "HTTP/2", contentEncoding: nil,
            declaredContentLength: request.count, capturedWireBodyBytes: request.count,
            requestBodyBase64: request.base64EncodedString(), requestSHA256: sha256(request),
            responseStatus: 200, responseComplete: true,
            responseBodyBase64: response.base64EncodedString(),
            clientAddress: "127.0.0.1:53124", remoteHost: "203.0.113.19", remotePort: 443)
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
