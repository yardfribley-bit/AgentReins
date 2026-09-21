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
        XCTAssertFalse(audit.dataClassifications.contains { $0.category == .notCaptured })
        XCTAssertTrue(audit.dataClassifications.flatMap(\.evidence)
            .contains { $0.content.contains("password: secret123") })
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

    func testClassifiedContextPreservesActualContentAndSendOrder() throws {
        let now = Date()
        let events = [
            GuardEvent(kind: "context", ruleId: "base", path: "/tmp/project", command: nil,
                agent: "codex", op: "base_instructions", severity: "info", ts: now,
                action: "captured", sessionId: "session", turnId: "turn",
                modelPrompt: "SYSTEM: protect user data", source: "codex-jsonl"),
            GuardEvent(kind: "context", ruleId: "developer", path: "/tmp/project", command: nil,
                agent: "codex", op: "developer_instructions", severity: "info",
                ts: now.addingTimeInterval(1), action: "captured", sessionId: "session", turnId: "turn",
                modelPrompt: "DEVELOPER: inspect before editing", source: "codex-jsonl"),
            GuardEvent(kind: "model", ruleId: "prompt", path: "/tmp/project", command: nil,
                agent: "codex", op: "prompt", severity: "info", ts: now.addingTimeInterval(2),
                action: "sent", sessionId: "session", turnId: "turn", userIntent: "Explain the parser",
                modelPrompt: "USER: explain Parser.swift", model: "gpt-5", source: "codex-jsonl"),
            GuardEvent(kind: "tool", ruleId: "read", path: "/tmp/project/Parser.swift", command: nil,
                agent: "codex", op: "result", severity: "info", ts: now.addingTimeInterval(3),
                action: "completed", sessionId: "session", turnId: "turn", modelResponse: "struct Parser {}",
                toolName: "Read", source: "codex-jsonl", relatedPath: "/tmp/project/Parser.swift"),
            GuardEvent(kind: "model", ruleId: "usage", path: "/tmp/project", command: nil,
                agent: "codex", op: "usage", severity: "info", ts: now.addingTimeInterval(4),
                action: "recorded", sessionId: "session", turnId: "turn", model: "gpt-5",
                inputTokens: 120, source: "codex-jsonl")
        ]
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: events).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)
        let evidence = audit.dataClassifications.flatMap(\.evidence).sorted { $0.sequence < $1.sequence }

        XCTAssertEqual(evidence.map(\.category), [.systemInstructions, .developerInstructions, .userInput, .sourceCode])
        XCTAssertEqual(evidence.map(\.content), ["SYSTEM: protect user data", "DEVELOPER: inspect before editing",
                                                 "USER: explain Parser.swift", "struct Parser {}"])
        XCTAssertEqual(evidence.last?.source, "Read")
    }

    func testZCodeModelIOSeparatesMessagesSkillsToolsAndRequestMetadata() throws {
        let context: [String: Any] = [
            "messages": [
                ["role": "system", "content": "System policy"],
                ["role": "user", "content": "Earlier request"],
                ["role": "user", "content": "。"],
                ["role": "system", "content": "The following skills are available: /tmp/example/SKILL.md"]
            ],
            "tools": [["name": "Read", "description": "Read a file"]],
            "requestMetadata": ["model": "GLM-5.3", "thinking": ["type": "enabled"]]
        ]
        let data = try JSONSerialization.data(withJSONObject: context)
        let prompt = try XCTUnwrap(String(data: data, encoding: .utf8))
        let request = GuardEvent(kind: "model", ruleId: "zcode_model_io_request", path: "/tmp/model-io.jsonl",
            command: nil, agent: "zcode", op: "network_prompt", severity: "info", ts: Date(),
            action: "captured_pre_encryption", sessionId: "session", turnId: "turn",
            userIntent: "。", modelPrompt: prompt, model: "GLM-5.3",
            source: "agentsight:zcode-model-io", attributionConfidence: .confirmed)
        let usage = GuardEvent(kind: "model", ruleId: "zcode_model_io_response", path: "/tmp/model-io.jsonl",
            command: nil, agent: "zcode", op: "network_response", severity: "info", ts: Date(),
            action: "received", sessionId: "session", turnId: "turn", model: "GLM-5.3",
            inputTokens: 100, source: "agentsight:zcode-model-io")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [request, usage]).first)
        let audit = try XCTUnwrap(AgentEgressAudit.build(session: session).first)

        XCTAssertEqual(audit.dataClassifications.first { $0.category == .systemInstructions }?.evidence.first?.content,
                       "System policy")
        XCTAssertEqual(audit.dataClassifications.first { $0.category == .conversationHistory }?.evidence.first?.content,
                       "Earlier request")
        XCTAssertEqual(audit.dataClassifications.first { $0.category == .userInput }?.evidence.first?.content, "。")
        XCTAssertTrue(audit.dataClassifications.first { $0.category == .agentRules }?.evidence.first?.content
            .contains("SKILL.md") == true)
        XCTAssertTrue(audit.dataClassifications.first { $0.category == .toolCalls }?.evidence.first?.content
            .contains("Read a file") == true)
        XCTAssertTrue(audit.dataClassifications.first { $0.category == .otherCaptured }?.evidence.first?.content
            .contains("GLM-5.3") == true)
    }
}
