import Foundation
import XCTest
@testable import AgentReins

final class RealtimeNetworkBodyPreviewTests: XCTestCase {
    func testAgentHTTPSExchangeIsNotCrowdedOutByProcessObservations() {
        var buffer = RealtimeLiveEvidenceBuffer()
        let request = GuardEvent(kind: "model", ruleId: "request", path: "-", command: nil,
            agent: "workbuddy", op: "network_prompt", severity: "info", ts: Date(timeIntervalSince1970: 1),
            action: "captured_complete", traceId: "workbuddy-http:flow", modelPrompt: "actual request",
            source: "agentsight:workbuddy-network-body")
        buffer.insert(request)
        for index in 0..<500 {
            buffer.insert(GuardEvent(kind: "activity", ruleId: "process", path: "-", command: nil,
                agent: "workbuddy", op: "process_observation", severity: "info",
                ts: Date(timeIntervalSince1970: Double(index + 2)), action: "observed"))
        }
        XCTAssertTrue(buffer.latestCollected().records.contains { $0.id == request.id })
    }
    func testToolOnlyModelReplyAndPartialBoundaryRemainVisible() throws {
        let event = GuardEvent(kind: "model", ruleId: "response", path: "-", command: nil,
            agent: "workbuddy", op: "network_response", severity: "info", ts: Date(), action: "received_partial",
            traceId: "workbuddy-http:flow", modelDecision: "{\"tool_calls\":[]}",
            modelReasoning: "reasoning", source: "agentsight:workbuddy-network-body")
        let preview = try XCTUnwrap(RealtimeNetworkBodyPreview(event: event))
        XCTAssertNotNil(preview.toolInstructions)
        XCTAssertEqual(preview.reasoning, "reasoning")
        XCTAssertEqual(preview.responseComplete, false)
        XCTAssertNil(preview.response)
    }
    func testToolArgumentsAreNotTransmittedBodyEvidence() {
        let event = GuardEvent(kind: "network", ruleId: "intent", path: "-", command: "curl example.com",
            agent: "workbuddy", op: "connect", severity: "info", ts: Date(), action: "observed",
            traceId: "tool", modelPrompt: "arguments", source: "tool-intent")
        XCTAssertNil(RealtimeNetworkBodyPreview(event: event))
    }
    func testSameFlowBodyPreviewPreservesRepresentationAndOriginal() throws {
        let body = String(repeating: "发送数据", count: 5_000)
        let event = GuardEvent(kind: "model", ruleId: "request", path: "-", command: nil,
            agent: "workbuddy", op: "network_prompt", severity: "info", ts: Date(), action: "captured_complete",
            traceId: "workbuddy-http:exact-flow", modelPrompt: body, modelResponse: "parsed answer",
            source: "agentsight:workbuddy-network-body")
        let preview = try XCTUnwrap(RealtimeNetworkBodyPreview(event: event))
        XCTAssertEqual(preview.flow, "workbuddy-http:exact-flow")
        XCTAssertEqual(preview.request?.count, 16_000)
        XCTAssertEqual(preview.requestBytes, body.utf8.count)
        XCTAssertTrue(preview.requestTruncated)
        XCTAssertEqual(preview.responseRepresentation, "parsed_model_output")
        XCTAssertEqual(event.modelPrompt, body)
    }
}
