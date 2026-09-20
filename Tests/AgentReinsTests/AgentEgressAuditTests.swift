import XCTest
@testable import AgentReins

final class AgentEgressAuditTests: XCTestCase {
    func testRelayWithLargeSensitiveContextIsCriticalAndPartial() throws {
        let now = Date()
        let prompt = GuardEvent(kind: "model", ruleId: "model_request", path: "/tmp/project",
            command: nil, agent: "workbuddy", op: "request", severity: "info", ts: now,
            action: "observed", sessionId: "session", turnId: "turn",
            userIntent: "Deploy this service", modelPrompt: "Memory reminder: password: secret123\nSKILL.md\nProject context",
            model: "deepseek-chat", inputTokens: 82_433, source: "agentsight:workbuddy-local")
        let configured = GuardEvent(kind: "network", ruleId: "configured_model_endpoint", path: "-",
            command: nil, agent: "workbuddy", op: "connect", severity: "info", ts: now,
            action: "observed", sessionId: "session", turnId: "turn", model: "deepseek-chat",
            source: "agentsight:workbuddy-local", attributionConfidence: .confirmed,
            attributionMethod: "WorkBuddy model catalog endpoint", processId: 42,
            remoteHost: "openrouter.ai", remotePort: 443, remoteDomain: "openrouter.ai")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [prompt, configured]).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)

        XCTAssertEqual(audit.inputTokens, 82_433)
        XCTAssertEqual(audit.risk, .critical)
        XCTAssertEqual(audit.coverage, .partial)
        XCTAssertEqual(audit.primaryDestination, "openrouter.ai")
        XCTAssertTrue(audit.exposedCategories.contains(.memory))
        XCTAssertTrue(audit.exposedCategories.contains(.skills))
        XCTAssertTrue(audit.sensitiveFindings.contains { $0.category == .password })
        XCTAssertEqual(audit.routeIdentity, "unverified")
        let assessments = ForensicAssessmentRecord.build(events: [prompt, configured], generatedAt: now)
        XCTAssertTrue(assessments.contains { $0.kind == .egressAudit && $0.turnId == "turn" })
    }

    func testOfficialProviderWithoutSensitiveContextCanBeLowRisk() throws {
        let now = Date()
        let prompt = GuardEvent(kind: "model", ruleId: "model_request", path: "/tmp/project",
            command: nil, agent: "codex", op: "request", severity: "info", ts: now,
            action: "observed", sessionId: "session", turnId: "turn",
            userIntent: "Explain this function", modelPrompt: String(repeating: "safe context ", count: 500),
            model: "gpt-5", inputTokens: 500, source: "agentsight:codex-local")
        let network = GuardEvent(kind: "network", ruleId: "network_connection", path: "-",
            command: nil, agent: "codex", op: "connect", severity: "info", ts: now,
            action: "observed", sessionId: "session", turnId: "turn", model: "gpt-5",
            source: "agentsight:codex-local", attributionConfidence: .confirmed,
            processId: 77, remoteHost: "api.openai.com", remotePort: 443,
            remoteDomain: "api.openai.com")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [prompt, network]).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)

        XCTAssertEqual(audit.primaryDestination, "api.openai.com")
        XCTAssertEqual(audit.routeIdentity, "consistent")
        XCTAssertEqual(audit.coverage, .complete)
        XCTAssertEqual(audit.risk, .low)
        XCTAssertTrue(audit.sensitiveFindings.isEmpty)
    }

    func testModelRequestWithoutNetworkRouteIsNotReportedSafe() throws {
        let event = GuardEvent(kind: "model", ruleId: "model_request", path: "/tmp/project",
            command: nil, agent: "zcode", op: "request", severity: "info", ts: Date(),
            action: "observed", sessionId: "session", turnId: "turn",
            userIntent: "Write code", modelPrompt: "small prompt", model: "unknown",
            inputTokens: 12, source: "agentsight:zcode-local")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [event]).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)

        XCTAssertEqual(audit.coverage, .missingRoute)
        XCTAssertNotEqual(audit.risk, .low)
        XCTAssertTrue(audit.findings.contains { $0.contains("no request-level network route") })
    }
}
