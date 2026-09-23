import XCTest
@testable import AgentReins

final class AgentEventProtocolTests: XCTestCase {
    private func event(sequence: UInt64, payload: AgentEventPayload,
                       source: AgentEventSource = .agentProtocol) -> AgentEventEnvelope {
        AgentEventEnvelope(id: "e-\(sequence)", projectID: "project", agentID: "codex",
                           sessionID: "session", turnID: "turn", sequence: sequence,
                           occurredAt: Date(timeIntervalSince1970: TimeInterval(sequence)),
                           observedAt: Date(timeIntervalSince1970: TimeInterval(sequence)),
                           source: source, confidence: .observed, payload: payload)
    }

    func testCorrelationRoundTripsAndCanonicalKindsRemainStable() throws {
        let value = AgentEventEnvelope(
            id: "event-1", projectID: "project", agentID: "codex",
            sessionID: "session", turnID: "turn", sequence: 1,
            occurredAt: Date(timeIntervalSince1970: 1),
            observedAt: Date(timeIntervalSince1970: 2), source: .agentProtocol,
            confidence: .confirmed,
            payload: .contextPrepared(ContextAssemblySnapshot(
                capturedAt: Date(timeIntervalSince1970: 1), userPromptDigest: nil,
                finalPromptDigest: nil, layers: [], totalBytes: 10,
                estimatedTokens: nil, model: "gpt", provider: "openai", route: nil)),
            correlation: AgentEventCorrelation(
                taskID: "task-1", traceID: "trace-1", spanID: "span-1",
                parentSpanID: "span-0", requestID: "request-1",
                actionID: nil, sourceEventID: "native-1"))

        let data = try JSONEncoder().encode(value)
        let restored = try JSONDecoder().decode(AgentEventEnvelope.self, from: data)

        XCTAssertEqual(restored.correlation?.traceID, "trace-1")
        XCTAssertEqual(restored.correlation?.requestID, "request-1")
        XCTAssertEqual(restored.canonicalKind, .llmRequest)
        XCTAssertEqual(restored.effectiveTaskID, "task-1")
    }

    func testLegacyEnvelopeWithoutCorrelationStillDecodes() throws {
        let legacy = event(sequence: 1, payload: .turnState(.queued))
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(legacy)) as? [String: Any])
        object.removeValue(forKey: "correlation")
        let restored = try JSONDecoder().decode(
            AgentEventEnvelope.self, from: JSONSerialization.data(withJSONObject: object))

        XCTAssertNil(restored.correlation)
        XCTAssertEqual(restored.effectiveTaskID, "session:turn")
    }

    func testUniformMetricsDeduplicateToolLifecycleAndCountCanonicalEvents() {
        let usage = event(sequence: 1, payload: .contextUsage(ContextUsageEvidence(
            usedTokens: 15, windowTokens: nil, inputTokens: 10,
            outputTokens: 5, cost: 0.25, compacting: false)))
        let request = event(sequence: 2, payload: .contextPrepared(ContextAssemblySnapshot(
            capturedAt: Date(), userPromptDigest: nil, finalPromptDigest: nil,
            layers: [], totalBytes: 100, estimatedTokens: nil,
            model: "gpt", provider: "openai", route: nil)))
        let running = event(sequence: 3, payload: .toolCall(ToolCallLifecycleEvidence(
            callID: "call-1", toolName: "exec_command", serverName: nil,
            arguments: "swift test", argumentsDigest: nil, state: .running,
            startedAt: nil, completedAt: nil, exitCode: nil, evidenceIDs: [])))
        let completed = event(sequence: 4, payload: .toolCall(ToolCallLifecycleEvidence(
            callID: "call-1", toolName: "exec_command", serverName: nil,
            arguments: "swift test", argumentsDigest: nil, state: .completed,
            startedAt: nil, completedAt: nil, exitCode: 0, evidenceIDs: [])))
        let result = event(sequence: 5, payload: .toolOutput(ToolOutputEvidence(
            callID: "call-1", output: "ok", outputDigest: nil,
            byteCount: 2, truncated: false)))

        let metrics = AgentEventMetrics.build(events: [usage, request, running, completed, result])

        XCTAssertEqual(metrics.eventCount, 5)
        XCTAssertEqual(metrics.llmRequestCount, 1)
        XCTAssertEqual(metrics.toolCallCount, 1)
        XCTAssertEqual(metrics.toolResultCount, 1)
        XCTAssertEqual(metrics.commandExecutionCount, 1)
        XCTAssertEqual(metrics.inputTokens, 10)
        XCTAssertEqual(metrics.outputTokens, 5)
        XCTAssertEqual(metrics.totalCost, 0.25)
    }

    func testUsageAddsDistinctModelStepsEvenWhenTraceIsReused() {
        func usage(_ id: String, sourceID: String, input: Int, output: Int) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "workbuddy",
                sessionID: "session", turnID: "turn", sequence: UInt64(id.count),
                occurredAt: Date(), observedAt: Date(), source: .agentTranscript,
                confidence: .observed,
                payload: .contextUsage(ContextUsageEvidence(
                    usedTokens: nil, windowTokens: nil, inputTokens: input,
                    outputTokens: output, cost: nil, compacting: false)),
                correlation: AgentEventCorrelation(traceID: "reused-trace",
                    requestID: "reused-trace", sourceEventID: sourceID))
        }
        let metrics = AgentEventMetrics.build(events: [
            usage("first", sourceID: "tool-decision", input: 74_727, output: 108),
            usage("second", sourceID: "final-answer", input: 74_878, output: 119),
            usage("replay", sourceID: "tool-decision", input: 74_727, output: 108)
        ])
        XCTAssertEqual(metrics.inputTokens, 149_605)
        XCTAssertEqual(metrics.outputTokens, 227)
    }

    func testTaskJSONExportContainsSourceAndNormalizedWorkBuddyEvidence() throws {
        let prompt = GuardEvent(kind: "model", ruleId: "prompt", path: "/tmp/project",
            command: nil, agent: "workbuddy", op: "prompt", severity: "info",
            ts: Date(timeIntervalSince1970: 1), action: "sent", sessionId: "session-1",
            traceId: "trace-1", turnId: "turn-1", userIntent: "Fix login",
            modelPrompt: "system + user", model: "model-a",
            source: "agentsight:workbuddy-local")
        let response = GuardEvent(kind: "model", ruleId: "response", path: "/tmp/project",
            command: nil, agent: "workbuddy", op: "response", severity: "info",
            ts: Date(timeIntervalSince1970: 2), action: "received", sessionId: "session-1",
            traceId: "trace-1", turnId: "turn-1", modelResponse: "Done",
            model: "model-a", inputTokens: 10, outputTokens: 2,
            source: "agentsight:workbuddy-local")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [prompt, response]).first)

        let export = AgentTaskJSONExport.build(session: session, turnID: "turn-1")
        let json = try export.prettyJSON()

        XCTAssertEqual(export.task.agentID, "workbuddy")
        XCTAssertEqual(export.sourceEvents.count, 2)
        XCTAssertFalse(export.revision.isEmpty)
        XCTAssertEqual(export.capture.eventCount, export.events.count)
        XCTAssertEqual(export.conversation.userInputs, ["Fix login"])
        XCTAssertEqual(export.conversation.modelResponses, ["Done"])
        XCTAssertNotNil(export.analysis.modelEconomics)
        XCTAssertFalse(export.evidenceReferences.isEmpty)
        XCTAssertEqual(export.outboundRequests.count, 1)
        XCTAssertEqual(export.outboundRequests.first?.captureMode, .agentRecordedContext)
        XCTAssertEqual(export.outboundRequests.first?.completeness, .unknown)
        XCTAssertEqual(export.outboundRequests.first?.body, "system + user")
        XCTAssertTrue(export.events.contains { $0.canonicalKind == .agentInput })
        XCTAssertTrue(export.events.contains { $0.canonicalKind == .llmResponse })
        XCTAssertTrue(json.contains("Fix login"))
        XCTAssertTrue(json.contains("trace-1"))
        XCTAssertTrue(json.contains("sourceEvents"))
    }

    func testTaskJSONMarksVerifiedWorkBuddyNetworkBodyAsComplete() throws {
        let request = GuardEvent(kind: "model", ruleId: "workbuddy_network_request_body",
            path: "/tmp", command: nil, agent: "workbuddy", op: "network_prompt",
            severity: "info", ts: Date(timeIntervalSince1970: 1),
            action: "captured_complete", sessionId: "network-session",
            traceId: "trace-network", turnId: "turn-network",
            userIntent: "Review code", modelPrompt: #"{"model":"m","messages":[]}"#,
            model: "m", source: "agentsight:workbuddy-network-body",
            attributionConfidence: .confirmed,
            attributionMethod: "complete HTTPS request body")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [request]).first)

        let export = AgentTaskJSONExport.build(session: session, turnID: "turn-network")

        XCTAssertEqual(export.outboundRequests.first?.captureMode, .completeHTTPSRequestBody)
        XCTAssertEqual(export.outboundRequests.first?.completeness, .complete)
        XCTAssertEqual(export.outboundRequests.first?.destination, nil)
        XCTAssertFalse(export.outboundRequests.first?.bodySHA256.isEmpty ?? true)
        XCTAssertEqual(export.capture.state, .healthy)
    }

    func testZCodeModelIOProjectionDoesNotClaimWireCompleteBody() throws {
        let event = GuardEvent(kind: "model", ruleId: "zcode_model_io_request",
            path: "/tmp/model-io.jsonl", command: nil, agent: "zcode",
            op: "network_prompt", severity: "info", ts: Date(timeIntervalSince1970: 1),
            action: "captured_pre_encryption", sessionId: "s", turnId: "t",
            modelPrompt: #"{"messages":[],"requestMetadata":{"messageCount":2}}"#,
            source: "agentsight:zcode-model-io",
            attributionMethod: "ZCode native Model I/O record captured before TLS encryption")
        let request = try XCTUnwrap(AgentOutboundRequestEvidence.build(events: [event]).first)
        XCTAssertEqual(request.captureMode, .preEncryptionRequestProjection)
        XCTAssertEqual(request.completeness, .partial)
    }

    func testTaskJourneyKeepsMultipleModelRoundsAndToolCode() throws {
        func request(_ second: TimeInterval, body: String) -> AgentOutboundRequestEvidence {
            let event = GuardEvent(kind: "model", ruleId: "request", path: "-",
                command: nil, agent: "workbuddy", op: "network_prompt", severity: "info",
                ts: Date(timeIntervalSince1970: second), action: "captured_complete",
                sessionId: "s", turnId: "t", modelPrompt: body,
                source: "agentsight:workbuddy-network-body")
            return AgentOutboundRequestEvidence.build(events: [event])[0]
        }
        let first = request(10, body: #"{"messages":[{"role":"user","content":"Write C++"}]}"#)
        let second = request(30, body: #"{"messages":[{"role":"tool","content":"file written"}]}"#)
        let responses = [
            AgentModelResponseEvidence(eventID: "r1", receivedAt: Date(timeIntervalSince1970: 12),
                traceID: nil, model: "m", content: "Use Write", recordedReasoning: "Plan summary",
                evidenceSource: "test"),
            AgentModelResponseEvidence(eventID: "r2", receivedAt: Date(timeIntervalSince1970: 35),
                traceID: nil, model: "m", content: "Done", recordedReasoning: nil,
                evidenceSource: "test")]
        let tool = ToolCallLifecycleEvidence(callID: "write-1", toolName: "Write",
            serverName: nil, arguments: "Write hello.cpp: int main() { return 0; }",
            argumentsDigest: nil, state: .completed,
            startedAt: Date(timeIntervalSince1970: 13),
            completedAt: Date(timeIntervalSince1970: 18), exitCode: 0, evidenceIDs: [])
        let journey = AgentTaskJourney.build(requests: [first, second], responses: responses,
            tools: [tool], toolResults: [ToolOutputEvidence(callID: "write-1", output: "created",
                outputDigest: nil, byteCount: 7, truncated: false)], files: [])

        XCTAssertEqual(journey.rounds.count, 2)
        XCTAssertEqual(journey.rounds[0].response?.content, "Use Write")
        XCTAssertEqual(journey.rounds[0].requestSections.first?.category, "message.user")
        XCTAssertEqual(journey.rounds[0].toolSteps.first?.durationMS, 5_000)
        XCTAssertTrue(journey.rounds[0].toolSteps.first?.call.arguments?.contains("int main()") == true)
        XCTAssertEqual(journey.rounds[1].response?.content, "Done")
        XCTAssertTrue(journey.unassignedResponses.isEmpty)
    }

    func testTaskJSONSeparatesOneToolLifecycleFromRelatedFileNetworkAndUsageSnapshots() throws {
        let base = Date(timeIntervalSince1970: 1_000)
        func row(_ kind: String, _ op: String, _ seconds: TimeInterval,
                 toolName: String? = nil, command: String? = nil,
                 response: String? = nil, input: Int? = nil, output: Int? = nil,
                 remoteHost: String? = nil) -> GuardEvent {
            GuardEvent(kind: kind, ruleId: "test", path: kind == "file" ? "/tmp/hello.cpp" : "/tmp",
                command: command, agent: "workbuddy", op: op, severity: "info",
                ts: base.addingTimeInterval(seconds), action: op == "result" ? "completed" : "observed",
                sessionId: "session", traceId: "same-trace", turnId: "turn",
                toolCallId: kind == "model" ? nil : "call-1",
                userIntent: kind == "model" && op == "prompt" ? "Write hello world" : nil,
                modelPrompt: kind == "model" && op == "prompt" ? "recorded context" : nil,
                modelResponse: response, toolName: toolName,
                inputTokens: input, outputTokens: output,
                source: kind == "network" ? "lsof-network" : "agentsight:workbuddy-local",
                remoteHost: remoteHost)
        }
        let rows = [
            row("model", "prompt", 0),
            row("tool", "call", 1, toolName: "Write", command: "Write hello.cpp", input: 74_727, output: 108),
            row("file", "update", 2, toolName: "Write", command: "Write hello.cpp"),
            row("tool", "result", 3, toolName: "Write", response: "created"),
            row("network", "connect", 4, toolName: "Write", remoteHost: "203.0.113.1"),
            row("model", "response", 5, response: "Done", input: 74_878, output: 119)
        ]
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: rows).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: "turn")

        XCTAssertEqual(snapshot.activities.tools.count, 1)
        XCTAssertEqual(snapshot.activities.tools.first?.state, .completed)
        XCTAssertEqual(snapshot.activities.toolResults.count, 1)
        XCTAssertEqual(snapshot.activities.files.count, 1)
        XCTAssertEqual(snapshot.activities.network.count, 1)
        XCTAssertEqual(snapshot.metrics.toolCallCount, 1)
        XCTAssertEqual(snapshot.metrics.llmResponseCount, 1)
        XCTAssertEqual(snapshot.metrics.inputTokens, 149_605)
        XCTAssertEqual(snapshot.metrics.outputTokens, 227)
        XCTAssertEqual(snapshot.capture.state, .degraded)
        XCTAssertTrue(snapshot.capture.missingCapabilities.contains("completeModelRequestBody"))
    }

    func testMemoryReminderIsRecordedAsInstructionWithoutInventingMemoryContents() throws {
        let prompt = GuardEvent(kind: "model", ruleId: "prompt", path: "/tmp/project",
            command: nil, agent: "workbuddy", op: "prompt", severity: "info",
            ts: Date(timeIntervalSince1970: 1), action: "sent", sessionId: "session",
            turnId: "turn", userIntent: "Hello",
            modelPrompt: "<memory_and_skills_reminder>Write to MEMORY.md after substantive work.</memory_and_skills_reminder><user_query>Hello</user_query>",
            source: "agentsight:workbuddy-local")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [prompt]).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: "turn")

        XCTAssertEqual(snapshot.schemaVersion, 4)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.assessment, .instructionsOnly)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.contextSegments.count, 1)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.contextSegments.first?.kind, .usageInstructions)
        XCTAssertTrue(snapshot.activities.memory.isEmpty)
        XCTAssertTrue(snapshot.analysis.memoryEvidence.contentMatches.isEmpty)
        XCTAssertEqual(snapshot.analysis.contextExposure?.items.first { $0.category == .memory }?.present, false)
    }

    func testMemoryFileContentMatchCarriesBothEvidenceIDsAndCaptureBoundary() throws {
        let content = "Persistent user preference: answer in Chinese and cite the source."
        let change = GuardEvent(kind: "file", ruleId: "memory", path: "/tmp/.workbuddy/memory/MEMORY.md",
            command: nil, agent: "workbuddy", op: "modify", severity: "info",
            ts: Date(timeIntervalSince1970: 1), action: "observed", sessionId: "session",
            turnId: "turn", afterContent: content, source: "memory-live:workbuddy")
        let request = GuardEvent(kind: "model", ruleId: "network-body", path: "/tmp",
            command: nil, agent: "workbuddy", op: "network_prompt", severity: "info",
            ts: Date(timeIntervalSince1970: 2), action: "captured_complete", sessionId: "session",
            turnId: "turn", modelPrompt: "<memory_context>\(content)</memory_context>",
            source: "agentsight:workbuddy-network-body")
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [change, request]).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: "turn")

        XCTAssertEqual(snapshot.activities.memory.count, 1)
        XCTAssertEqual(snapshot.activities.memory.first?.operation, .update)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.assessment, .memoryContentInCompleteRequest)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.contentMatches.first?.memoryEventID, change.id.uuidString)
        XCTAssertEqual(snapshot.analysis.memoryEvidence.contentMatches.first?.requestEventID, request.id.uuidString)
    }

    func testIdentityContextInLocalTraceIsMemoryContentNotJustInstructions() throws {
        let prompt = GuardEvent(kind: "model", ruleId: "prompt", path: "/tmp/project",
            command: nil, agent: "workbuddy", op: "prompt", severity: "info",
            ts: Date(timeIntervalSince1970: 100), action: "sent", sessionId: "session",
            turnId: "turn", userIntent: "Create a skill", modelPrompt: "<user_query>Create a skill</user_query>",
            source: "agentsight:workbuddy-local")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let traceURL = root.appendingPathComponent("trace_example.json")
        let body = #"[{"content":"<identity_context>\n## USER.md\nPath: /tmp/.workbuddy/USER.md\n# USER.md - About Your Human\nPrefers Chinese answers.\n</identity_context>"}]"#
        let trace: [String: Any] = [
            "trace": ["traceId": "trace_example", "workerPid": 42,
                      "startedAt": "1970-01-01T00:01:41.000Z"],
            "spans": [["type": "generation", "spanId": "span_1",
                       "startedAt": "1970-01-01T00:01:42.000Z", "toolInput": body]]]
        try JSONSerialization.data(withJSONObject: trace).write(to: traceURL)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 103)],
            ofItemAtPath: traceURL.path)
        let requests = WorkBuddyTraceRequests.load(events: [prompt], root: root)
        let report = AgentMemoryEvidenceReport.build(events: [prompt], requests: requests)

        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.completeness, .partial)
        XCTAssertEqual(report.assessment, .memoryContentObservedLocally)
        XCTAssertEqual(report.contextSegments.first?.sourcePaths, ["/tmp/.workbuddy/USER.md"])
        XCTAssertEqual(report.contextSegments.first { $0.kind == .memoryFileContent }?.sourcePaths,
            ["/tmp/.workbuddy/USER.md"])
        XCTAssertTrue(report.contentMatches.isEmpty)
    }

    func testNetworkSocketInModelTurnIsNotAutomaticallyModelTraffic() {
        let prompt = GuardEvent(kind: "model", ruleId: "prompt", path: "-",
            command: nil, agent: "workbuddy", op: "prompt", severity: "info",
            ts: Date(timeIntervalSince1970: 1), action: "sent", sessionId: "s",
            turnId: "t", source: "agentsight:workbuddy-local")
        let socket = GuardEvent(kind: "network", ruleId: "socket", path: "-",
            command: nil, agent: "workbuddy", op: "connect", severity: "info",
            ts: Date(timeIntervalSince1970: 2), action: "observed", sessionId: "s",
            turnId: "t", source: "lsof-network", remoteHost: "203.0.113.9", remotePort: 443)
        let flows = NetworkFlowEvidence.build(events: [prompt, socket])
        XCTAssertEqual(flows.first?.category, .unknown)
        XCTAssertEqual(flows.first?.grade, .correlated)
    }

    func testNetworkFlowsSeparateSSHAndAgentWebAccess() {
        let at = Date(timeIntervalSince1970: 10)
        let webCall = GuardEvent(kind: "tool", ruleId: "tool", path: "-",
            command: "WebFetch(https://example.org)", agent: "workbuddy", op: "call",
            severity: "info", ts: at, action: "requested", toolCallId: "web-1",
            toolName: "WebFetch", source: "agentsight:workbuddy-local")
        let webSocket = GuardEvent(kind: "network", ruleId: "socket", path: "-",
            command: nil, agent: "workbuddy", op: "connect", severity: "info",
            ts: at.addingTimeInterval(1), action: "observed", toolCallId: "web-1",
            source: "lsof-network", remoteHost: "203.0.113.8", remotePort: 443)
        let sshSocket = GuardEvent(kind: "network", ruleId: "socket", path: "-",
            command: nil, agent: "workbuddy", op: "connect", severity: "info",
            ts: at.addingTimeInterval(2), action: "observed", source: "lsof-network",
            remoteHost: "203.0.113.7", remotePort: 22)
        let flows = NetworkFlowEvidence.build(events: [webCall, webSocket, sshSocket])
        XCTAssertTrue(flows.contains { $0.category == .web })
        XCTAssertTrue(flows.contains { $0.category == .remote })
    }

    func testOptionalHistoricalWorkBuddyTraceRoundTrip() throws {
        guard let path = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_SESSION"],
              let turnID = ProcessInfo.processInfo.environment["AGENTREINS_WORKBUDDY_TURN"] else {
            throw XCTSkip("Set WorkBuddy session and turn environment variables for local validation")
        }
        let events = WorkBuddySight.parseSession(URL(fileURLWithPath: path), fullHistory: true)
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: events).first)
        let snapshot = AgentTaskSnapshot.build(session: session, turnID: turnID)
        let traceRequests = snapshot.outboundRequests.filter { $0.evidenceSource == "workbuddy-local-trace" }
        let fileSegments = snapshot.analysis.memoryEvidence.contextSegments.filter {
            $0.kind == .memoryFileContent
        }
        XCTAssertGreaterThanOrEqual(traceRequests.count, 20)
        XCTAssertEqual(snapshot.journey.rounds.count, traceRequests.count)
        XCTAssertEqual(Set(traceRequests.compactMap(\.traceID)).count, 2)
        XCTAssertTrue(snapshot.journey.rounds.allSatisfy {
            $0.requestSections.contains { $0.category == "identity_context" }
        })
        XCTAssertEqual(Set(fileSegments.flatMap(\.sourcePaths).map { URL(fileURLWithPath: $0).lastPathComponent }),
            Set(["SOUL.md", "IDENTITY.md", "USER.md"]))
        XCTAssertEqual(snapshot.analysis.memoryEvidence.coverage, .partialOrUnverifiedContext)
    }

    func testCaptureHealthDetectsSequenceGap() {
        let events = [
            event(sequence: 1, payload: .turnState(.preparingContext)),
            event(sequence: 3, payload: .turnState(.requestingModel))
        ]
        let health = AgentCaptureHealth.evaluate(events)
        XCTAssertEqual(health.state, .degraded)
        XCTAssertEqual(health.gaps.first?.expectedSequence, 2)
        XCTAssertEqual(health.gaps.first?.observedSequence, 3)
    }

    func testCaptureHealthReportsMissingRequiredSource() {
        let events = [event(sequence: 1, payload: .turnState(.preparingContext))]
        let health = AgentCaptureHealth.evaluate(events, required: [.agentProtocol, .operatingSystem])
        XCTAssertEqual(health.state, .degraded)
        XCTAssertEqual(health.missingCapabilities, ["operatingSystem"])
    }

    func testContextSeparatesUserInputFromInjectedLayers() {
        let layers = [
            ContextLayerEvidence(id: "user", kind: .userInput, sourceLocator: nil,
                                 summary: "Fix login", contentDigest: "u", byteCount: 9,
                                 estimatedTokens: 2, sensitiveDataKinds: [], evidenceIDs: [],
                                 confidence: .confirmed),
            ContextLayerEvidence(id: "memory", kind: .sharedMemory, sourceLocator: "MEMORY.md",
                                 summary: "Use OAuth", contentDigest: "m", byteCount: 9,
                                 estimatedTokens: 2, sensitiveDataKinds: [], evidenceIDs: ["raw-1"],
                                 confidence: .observed)
        ]
        let snapshot = ContextAssemblySnapshot(capturedAt: Date(), userPromptDigest: "u",
                                               finalPromptDigest: "f", layers: layers,
                                               totalBytes: 18, estimatedTokens: 4,
                                               model: "gpt", provider: "openai", route: nil)
        XCTAssertEqual(snapshot.injectedLayers.map(\.kind), [.sharedMemory])
    }

    func testSupervisorProjectsCurrentWorkWithoutInventingHistory() {
        let context = ContextAssemblySnapshot(capturedAt: Date(), userPromptDigest: nil,
                                              finalPromptDigest: nil, layers: [], totalBytes: 0,
                                              estimatedTokens: nil, model: nil, provider: nil, route: nil)
        let events = [
            event(sequence: 1, payload: .userPrompt(UserPromptEvidence(rawText: "Add auth", digest: nil,
                                                                       requirementIDs: ["req-auth"]))),
            event(sequence: 2, payload: .contextPrepared(context)),
            event(sequence: 3, payload: .turnState(.requestingModel))
        ]
        let snapshot = ProjectSupervisorSnapshot.build(projectID: "project", events: events,
                                                        now: Date(timeIntervalSince1970: 3))
        XCTAssertEqual(snapshot.currentState, .requestingModel)
        XCTAssertEqual(snapshot.currentRequirementIDs, ["req-auth"])
        XCTAssertNotNil(snapshot.context)
        XCTAssertEqual(snapshot.captureHealth.state, .healthy)
    }

    func testCanonicalAgentEventsPersistIdempotently() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-agent-events-\(UUID().uuidString).sqlite3")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(atPath: url.path + "-wal")
            try? FileManager.default.removeItem(atPath: url.path + "-shm")
        }
        let database = try EvidenceDatabase(url: url)
        let value = event(sequence: 1, payload: .turnState(.preparingContext))
        try database.appendAgentEvents([value, value])
        let restored = try database.agentEvents(sessionID: "session")
        XCTAssertEqual(restored.count, 1)
        XCTAssertEqual(restored.first?.id, value.id)
        XCTAssertEqual(try database.agentEvents(projectID: "project").count, 1)
        XCTAssertEqual(try database.nextAgentEventSequence(sessionID: "session"), 2)
    }

    func testRecentTaskIndexUsesCapturedUserTitle() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-task-index-\(UUID().uuidString).sqlite3")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(atPath: url.path + "-wal")
            try? FileManager.default.removeItem(atPath: url.path + "-shm")
        }
        let database = try EvidenceDatabase(url: url)
        try database.appendAgentEvents([
            event(sequence: 1, payload: .userPrompt(UserPromptEvidence(
                rawText: "编写 hello.cpp", digest: nil, requirementIDs: []))),
            event(sequence: 2, payload: .turnState(.executingTool))
        ])
        let tasks = try database.recentTasks(limit: 10)
        XCTAssertEqual(tasks.count, 1)
        XCTAssertEqual(tasks.first?.title, "编写 hello.cpp")
        XCTAssertEqual(tasks.first?.eventCount, 2)
    }

    func testLegacyProjectionContinuesPersistedSessionSequence() {
        let first = GuardEvent(kind: "model", ruleId: "", path: "/tmp/project",
                               command: nil, agent: "codex", op: "prompt", severity: "info",
                               ts: Date(), action: "sent", sessionId: "s", turnId: "t1",
                               userIntent: "First")
        let second = GuardEvent(kind: "model", ruleId: "", path: "/tmp/project",
                                command: nil, agent: "codex", op: "prompt", severity: "info",
                                ts: Date().addingTimeInterval(1), action: "sent", sessionId: "s",
                                turnId: "t2", userIntent: "Second")
        XCTAssertEqual(LegacyGuardEventAdapter.project([first], projectID: "p").map(\.sequence), [1])
        XCTAssertEqual(LegacyGuardEventAdapter.project([second], projectID: "p",
                                                       startingSequence: 1).map(\.sequence), [2])
    }

    func testLegacyEvidenceProjectsPromptContextToolAndNetworkWithoutInventingLayerType() {
        let prompt = GuardEvent(kind: "model", ruleId: "", path: "-",
                               command: nil, agent: "codex", op: "prompt",
                               severity: "info", ts: Date(), action: "seen",
                               sessionId: "s", turnId: "t",
                               userIntent: "Check the endpoint", modelPrompt: "system + user prompt",
                               model: "gpt", source: "codex-jsonl")
        let tool = GuardEvent(kind: "tool", ruleId: "", path: "-",
                               command: "curl https://example.com", agent: "codex", op: "call",
                               severity: "info", ts: Date().addingTimeInterval(1), action: "requested",
                               sessionId: "s", turnId: "t", toolCallId: "call-1",
                               toolName: "shell", model: "gpt", source: "codex-jsonl")
        let network = GuardEvent(kind: "network", ruleId: "", path: "-",
                               command: nil, agent: "codex", op: "connect",
                               severity: "info", ts: Date().addingTimeInterval(2), action: "seen",
                               sessionId: "s", turnId: "t", toolCallId: "call-1",
                               inputTokens: 120, outputTokens: 30, source: "codex-jsonl",
                               attributionConfidence: .confirmed, remoteHost: "93.184.216.34",
                               remoteDomain: "example.com")
        let projected = LegacyGuardEventAdapter.project([prompt, tool, network], projectID: "project")
        XCTAssertTrue(projected.contains { if case .userPrompt = $0.payload { return true }; return false })
        let context = projected.compactMap { envelope -> ContextAssemblySnapshot? in
            if case let .contextPrepared(value) = envelope.payload { return value }
            return nil
        }.first
        XCTAssertEqual(context?.layers.first?.kind, .unknown)
        XCTAssertTrue(projected.contains { if case .toolCall = $0.payload { return true }; return false })
        XCTAssertTrue(projected.contains { if case .networkActivity = $0.payload { return true }; return false })
        XCTAssertEqual(projected.map(\.sequence), Array(1...projected.count).map(UInt64.init))
    }

    func testSessionCommitAttributionConfirmsSurvivingAgentContent() {
        let content = Data("final content".utf8)
        let file = FileActivityEvidence(operation: .modify, path: "Sources/App.swift",
                                        beforeDigest: nil,
                                        afterDigest: SessionCommitAttributor.digest(content),
                                        patch: nil, toolCallID: "call-1", attribution: .observed)
        let write = event(sequence: 1, payload: .fileActivity(file))
        let commit = GitCommitObservation(commitHash: "abc", authoredAt: write.occurredAt.addingTimeInterval(60),
                                          branchDescription: "main",
                                          files: [GitCommitFileEvidence(path: "Sources/App.swift",
                                                                         contentDigest: SessionCommitAttributor.digest(content))])
        let checkpoint = SessionCommitAttributor.attribute(events: [write], commits: [commit]).first
        XCTAssertEqual(checkpoint?.attribution, .confirmed)
        XCTAssertEqual(checkpoint?.survivingPaths, ["Sources/App.swift"])
        XCTAssertEqual(checkpoint?.evidenceIDs, [write.id])
    }

    func testSessionCommitAttributionRefusesTimestampOnlyGuess() {
        let commit = GitCommitObservation(commitHash: "abc", authoredAt: Date(timeIntervalSince1970: 2),
                                          branchDescription: "main",
                                          files: [GitCommitFileEvidence(path: "Sources/App.swift",
                                                                         contentDigest: "different")])
        XCTAssertTrue(SessionCommitAttributor.attribute(
            events: [event(sequence: 1, payload: .turnState(.modifyingFiles))],
            commits: [commit]).isEmpty)
    }

    func testGitCommitInspectorReadsCommittedFileDigest() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-git-attribution-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        func git(_ args: [String]) throws {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
            process.arguments = ["-C", root.path] + args; process.standardOutput = Pipe(); process.standardError = Pipe()
            try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
        }
        try git(["init", "-q"])
        try git(["config", "user.email", "test@example.com"])
        try git(["config", "user.name", "AgentReins Test"])
        let content = Data("print(\"hello\")\n".utf8)
        try content.write(to: root.appendingPathComponent("main.py"))
        try git(["add", "main.py"]); try git(["commit", "-q", "-m", "add main"])
        let commit = try XCTUnwrap(GitCommitInspector.recent(repositoryRoot: root.path, limit: 1).first)
        XCTAssertEqual(commit.files.first?.path, "main.py")
        XCTAssertEqual(commit.files.first?.contentDigest, SessionCommitAttributor.digest(content))
    }

    func testGitCheckpointIntegrationRecognizesCommitCommand() {
        let commit = GuardEvent(kind: "tool", ruleId: "", path: "/tmp/project",
                                command: "git -c user.name=test commit -m 'ship it'",
                                agent: "codex", op: "result", severity: "info",
                                ts: Date(), action: "seen", sessionId: "s")
        XCTAssertTrue(GitCheckpointIntegration.shouldInspect([commit]))
        let status = GuardEvent(kind: "tool", ruleId: "", path: "/tmp/project",
                                command: "git status", agent: "codex", op: "result",
                                severity: "info", ts: Date(), action: "seen", sessionId: "s")
        XCTAssertFalse(GitCheckpointIntegration.shouldInspect([status]))
    }

    func testGitCheckpointIntegrationPersistsOneCheckpointPerCommit() {
        let content = Data("final\n".utf8)
        let file = FileActivityEvidence(operation: .modify,
                                        path: "/tmp/repository/Sources/App.swift",
                                        beforeDigest: nil,
                                        afterDigest: SessionCommitAttributor.digest(content),
                                        patch: nil, toolCallID: "call-1", attribution: .observed)
        let write = event(sequence: 1, payload: .fileActivity(file))
        let commit = GitCommitObservation(
            commitHash: "abc", authoredAt: write.occurredAt.addingTimeInterval(1),
            branchDescription: "HEAD -> main",
            files: [GitCommitFileEvidence(path: "Sources/App.swift",
                                          contentDigest: SessionCommitAttributor.digest(content))])
        let generated = GitCheckpointIntegration.checkpointEvents(
            projectID: "/tmp/repository", agentID: "codex", sessionID: "session",
            turnID: "turn", events: [write], commits: [commit],
            existingCommitHashes: [], startingSequence: 2)
        XCTAssertEqual(generated.count, 1)
        XCTAssertEqual(generated.first?.sequence, 2)
        XCTAssertEqual(generated.first?.source, .git)
        guard case let .checkpoint(checkpoint) = generated.first?.payload else {
            return XCTFail("Expected checkpoint payload")
        }
        XCTAssertEqual(checkpoint.attribution, .confirmed)
        XCTAssertEqual(checkpoint.survivingPaths, ["Sources/App.swift"])
        XCTAssertTrue(GitCheckpointIntegration.checkpointEvents(
            projectID: "/tmp/repository", agentID: "codex", sessionID: "session",
            turnID: "turn", events: [write], commits: [commit],
            existingCommitHashes: ["abc"], startingSequence: 3).isEmpty)
    }

    func testFeatureProvenanceFindsPromptAgentToolsFilesCommitAndVerification() {
        let base = Date(timeIntervalSince1970: 100)
        func envelope(_ sequence: UInt64, _ payload: AgentEventPayload) -> AgentEventEnvelope {
            AgentEventEnvelope(id: "feature-\(sequence)", projectID: "/projects/shop",
                               agentID: "codex", sessionID: "session-auth", turnID: "turn-7",
                               sequence: sequence, occurredAt: base.addingTimeInterval(Double(sequence)),
                               observedAt: base.addingTimeInterval(Double(sequence)),
                               source: .agentProtocol, confidence: .confirmed, payload: payload)
        }
        let events = [
            envelope(1, .userPrompt(UserPromptEvidence(rawText: "Add OAuth login to the account page",
                                                       digest: nil, requirementIDs: ["auth-login"]))),
            envelope(2, .contextPrepared(ContextAssemblySnapshot(
                capturedAt: base, userPromptDigest: nil, finalPromptDigest: nil, layers: [],
                totalBytes: 100, estimatedTokens: 25, model: "gpt-5", provider: "openai", route: nil))),
            envelope(3, .toolCall(ToolCallLifecycleEvidence(
                callID: "tool-1", toolName: "apply_patch", serverName: nil,
                arguments: "Update Sources/LoginView.swift", argumentsDigest: nil,
                state: .completed, startedAt: base, completedAt: base.addingTimeInterval(2),
                exitCode: 0, evidenceIDs: []))),
            envelope(4, .toolOutput(ToolOutputEvidence(callID: "tool-1", output: "Done",
                                                       outputDigest: nil, byteCount: 4, truncated: false))),
            envelope(5, .fileActivity(FileActivityEvidence(operation: .modify,
                path: "Sources/LoginView.swift", beforeDigest: "before", afterDigest: "after",
                patch: "+ OAuthButton()", toolCallID: "tool-1", attribution: .confirmed))),
            envelope(6, .checkpoint(AgentCheckpointEvidence(commitHash: "abc123", branch: "main",
                touchedPaths: ["Sources/LoginView.swift"], survivingPaths: ["Sources/LoginView.swift"],
                attribution: .confirmed, evidenceIDs: ["feature-5"]))),
            envelope(7, .verification(VerificationEvidence(kind: .test, outcome: .passed,
                independentOfAgentClaim: true, summary: "OAuth login tests passed", evidenceIDs: [])))
        ]
        let result = FeatureProvenanceIndex.search(query: "OAuth 登录", projectID: "/projects/shop", events: events)
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.first?.agentID, "codex")
        XCTAssertEqual(result.first?.userPrompt, "Add OAuth login to the account page")
        XCTAssertEqual(result.first?.model, "gpt-5")
        XCTAssertEqual(result.first?.tools.first?.name, "apply_patch")
        XCTAssertEqual(result.first?.tools.first?.resultPreview, "Done")
        XCTAssertEqual(result.first?.files, ["Sources/LoginView.swift"])
        XCTAssertEqual(result.first?.commits, ["abc123"])
        XCTAssertEqual(result.first?.verification.first?.outcome, .passed)
    }

    func testFeatureProvenanceDoesNotReturnUnrelatedOrFabricatedHistory() {
        let events = [event(sequence: 1, payload: .userPrompt(UserPromptEvidence(
            rawText: "Improve weather cache", digest: nil, requirementIDs: [])))]
        XCTAssertTrue(FeatureProvenanceIndex.search(query: "payment checkout",
                                                    projectID: "project", events: events).isEmpty)
    }

    func testFeatureProvenanceUsesModelTermsAsHintsButReturnsOnlyRecordedEvidence() {
        let recorded = event(sequence: 1, payload: .userPrompt(UserPromptEvidence(
            rawText: "Implement OAuth authentication", digest: nil, requirementIDs: [])))
        let result = FeatureProvenanceIndex.search(
            query: "登录", projectID: "project", events: [recorded],
            additionalTerms: ["OAuth", "authentication", "sign in"])
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.first?.userPrompt, "Implement OAuth authentication")
        XCTAssertEqual(result.first?.matchedEvidenceIDs, [recorded.id])
        XCTAssertTrue(result.first?.tools.isEmpty == true)
        XCTAssertTrue(result.first?.commits.isEmpty == true)
    }

    func testFeatureProvenanceKeepsZCodeQueryTurnScopedAndRejectsMalformedPaths() {
        let base = Date(timeIntervalSince1970: 500)
        func envelope(_ id: String, turn: String, sequence: UInt64,
                      payload: AgentEventPayload) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "/projects/agentreins", agentID: "codex",
                sessionID: "long-session", turnID: turn, sequence: sequence,
                occurredAt: base.addingTimeInterval(Double(sequence)),
                observedAt: base.addingTimeInterval(Double(sequence)), source: .agentProtocol,
                confidence: .confirmed, payload: payload)
        }
        let events = [
            envelope("z-prompt", turn: "zcode", sequence: 1,
                payload: .userPrompt(UserPromptEvidence(rawText: "新增 ZCode 采集器",
                    digest: nil, requirementIDs: []))),
            envelope("z-call", turn: "zcode", sequence: 2,
                payload: .toolCall(ToolCallLifecycleEvidence(callID: "call-1", toolName: "apply_patch",
                    serverName: nil, arguments: "update ZCodeSight.swift", argumentsDigest: nil,
                    state: .requested, startedAt: base, completedAt: nil, exitCode: nil,
                    evidenceIDs: ["z-call"]))),
            envelope("z-output", turn: "zcode", sequence: 3,
                payload: .toolCall(ToolCallLifecycleEvidence(callID: "call-1", toolName: "unknown_tool",
                    serverName: nil, arguments: nil, argumentsDigest: nil, state: .completed,
                    startedAt: nil, completedAt: base.addingTimeInterval(3), exitCode: 0,
                    evidenceIDs: ["z-output"]))),
            envelope("z-file", turn: "zcode", sequence: 4,
                payload: .fileActivity(FileActivityEvidence(operation: .create,
                    path: "Sources/AgentReins/ZCodeSight.swift", beforeDigest: nil,
                    afterDigest: "digest", patch: nil, toolCallID: "call-1", attribution: .confirmed))),
            envelope("z-bad-file", turn: "zcode", sequence: 5,
                payload: .fileActivity(FileActivityEvidence(operation: .modify,
                    path: "/Users/example/1000\",\"workdir\":\"/project\",\"max_output_tokens\":1000}",
                    beforeDigest: nil, afterDigest: nil, patch: nil,
                    toolCallID: "call-1", attribution: .inferred))),
            envelope("z-checkpoint", turn: "zcode", sequence: 6,
                payload: .checkpoint(AgentCheckpointEvidence(commitHash: "abc", branch: "main",
                    touchedPaths: ["120;", "30;", "90,170p", "Sources/AgentReins/ZCodeSight.swift"],
                    survivingPaths: [], attribution: .inferred, evidenceIDs: []))),
            envelope("other", turn: "article", sequence: 7,
                payload: .userPrompt(UserPromptEvidence(rawText: "将这些发现写进公众号文章，修改文件",
                    digest: nil, requirementIDs: [])))
        ]

        let result = FeatureProvenanceIndex.search(
            query: "ZCode 那个需求修改了哪些文件", projectID: "/projects/agentreins", events: events)

        XCTAssertEqual(result.count, 1)
        XCTAssertEqual(result.first?.turnID, "zcode")
        XCTAssertEqual(result.first?.tools.first?.name, "apply_patch")
        XCTAssertEqual(result.first?.tools.first?.state, .completed)
        XCTAssertEqual(result.first?.files, ["Sources/AgentReins/ZCodeSight.swift"])
        XCTAssertEqual(result.first?.memoryReads, 0)
        XCTAssertEqual(result.first?.memoryWrites, 0)
    }

    func testLegacyProjectEventsRestoreOnlySelectedProject() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-feature-history-\(UUID().uuidString).sqlite3")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(atPath: url.path + "-wal")
            try? FileManager.default.removeItem(atPath: url.path + "-shm")
        }
        let database = try EvidenceDatabase(url: url)
        let selected = GuardEvent(kind: "model", ruleId: "", path: "/projects/shop",
            command: nil, agent: "codex", op: "prompt", severity: "info", ts: Date(),
            action: "seen", sessionId: "shop-session", turnId: "turn-1",
            userIntent: "Build checkout payments")
        let nested = GuardEvent(kind: "file", ruleId: "", path: "/projects/shop/Sources/Pay.swift",
            command: nil, agent: "codex", op: "modify", severity: "info", ts: Date(),
            action: "seen", sessionId: "shop-session", turnId: "turn-1",
            toolCallId: "write-1", afterContent: "func pay() {}")
        let unrelated = GuardEvent(kind: "model", ruleId: "", path: "/projects/weather",
            command: nil, agent: "workbuddy", op: "prompt", severity: "info", ts: Date(),
            action: "seen", sessionId: "weather-session", userIntent: "Show weather")
        try database.append([selected, nested, unrelated])
        let restored = try database.legacyProjectEvents(projectID: "/projects/shop")
        XCTAssertEqual(Set(restored.compactMap(\.sessionId)), ["shop-session"])
        XCTAssertEqual(Set(restored.map(\.id)), [selected.id, nested.id])
    }

    func testApplyPatchArgumentsExposeObservedFileOperations() {
        let command = """
        *** Begin Patch
        *** Add File: /project/New.swift
        *** Update File: /project/App.swift
        *** Delete File: /project/Old.swift
        *** End Patch
        """
        let files = LegacyGuardEventAdapter.patchFileActivities(command: command, toolCallID: "patch-1")
        XCTAssertEqual(files.map(\.path), ["/project/New.swift", "/project/App.swift", "/project/Old.swift"])
        XCTAssertEqual(files.map(\.operation), [.create, .modify, .delete])
        XCTAssertTrue(files.allSatisfy { $0.attribution == .observed && $0.afterDigest == nil })
    }

    func testApplyPatchArgumentsDecodeLiteralNewlinesFromRealCodexEvidence() {
        let command = "const patch = \"*** Begin Patch\\n*** Update File: /project/App.swift\\n*** End Patch\";"
        let files = LegacyGuardEventAdapter.patchFileActivities(command: command, toolCallID: "patch-real")
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(files.first?.path, "/project/App.swift")
        XCTAssertEqual(files.first?.operation, .modify)
    }

    func testCodeChangeIsPrimaryAndCommitIsOptionalMetadata() {
        let prompt = event(sequence: 1, payload: .userPrompt(UserPromptEvidence(
            rawText: "Add OAuth login", digest: nil, requirementIDs: ["login"])))
        let tool = event(sequence: 2, payload: .toolCall(ToolCallLifecycleEvidence(
            callID: "patch-1", toolName: "apply_patch", serverName: nil,
            arguments: "Update Login.swift", argumentsDigest: nil, state: .completed,
            startedAt: nil, completedAt: nil, exitCode: 0, evidenceIDs: [])))
        let file = event(sequence: 3, payload: .fileActivity(FileActivityEvidence(
            operation: .modify, path: "Sources/Login.swift", beforeDigest: "a", afterDigest: "b",
            patch: "+ OAuth", toolCallID: "patch-1", attribution: .confirmed)))
        let uncommitted = CodeChangeIndexer.build(events: [prompt, tool, file])
        XCTAssertEqual(uncommitted.count, 1)
        XCTAssertEqual(uncommitted.first?.userPrompt, "Add OAuth login")
        XCTAssertEqual(uncommitted.first?.toolName, "apply_patch")
        XCTAssertFalse(uncommitted.first?.committed ?? true)

        let checkpoint = event(sequence: 4, payload: .checkpoint(AgentCheckpointEvidence(
            commitHash: "abc123", branch: "main", touchedPaths: ["Sources/Login.swift"],
            survivingPaths: ["Sources/Login.swift"], attribution: .confirmed,
            evidenceIDs: [file.id])))
        let committed = CodeChangeIndexer.build(events: [prompt, tool, file, checkpoint])
        XCTAssertEqual(committed.first?.commitHashes, ["abc123"])
        XCTAssertTrue(committed.first?.committed == true)
        XCTAssertEqual(committed.first?.id, file.id)
    }

    func testCodeChangeIndexerAcceptsRepeatedToolLifecycleEvents() {
        let requested = event(sequence: 1, payload: .toolCall(ToolCallLifecycleEvidence(
            callID: "patch-1", toolName: "apply_patch", serverName: nil,
            arguments: "Update App.swift", argumentsDigest: nil, state: .requested,
            startedAt: Date(timeIntervalSince1970: 1), completedAt: nil,
            exitCode: nil, evidenceIDs: [])))
        let completed = event(sequence: 2, payload: .toolCall(ToolCallLifecycleEvidence(
            callID: "patch-1", toolName: "apply_patch", serverName: nil,
            arguments: "Update App.swift", argumentsDigest: nil, state: .completed,
            startedAt: Date(timeIntervalSince1970: 1), completedAt: Date(timeIntervalSince1970: 2),
            exitCode: 0, evidenceIDs: [])))
        let file = event(sequence: 3, payload: .fileActivity(FileActivityEvidence(
            operation: .modify, path: "Sources/App.swift", beforeDigest: "a", afterDigest: "b",
            patch: "+ fixed", toolCallID: "patch-1", attribution: .confirmed)))

        let changes = CodeChangeIndexer.build(events: [requested, completed, file])

        XCTAssertEqual(changes.count, 1)
        XCTAssertEqual(changes.first?.toolName, "apply_patch")
    }

    func testCodeChangeIndexPersistsAndQueriesByProjectAndPath() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-code-change-\(UUID().uuidString).sqlite3")
        defer {
            try? FileManager.default.removeItem(at: url)
            try? FileManager.default.removeItem(atPath: url.path + "-wal")
            try? FileManager.default.removeItem(atPath: url.path + "-shm")
        }
        let database = try EvidenceDatabase(url: url)
        let file = event(sequence: 1, payload: .fileActivity(FileActivityEvidence(
            operation: .create, path: "Sources/New.swift", beforeDigest: nil, afterDigest: "digest",
            patch: nil, toolCallID: "write-1", attribution: .observed)))
        let changes = CodeChangeIndexer.build(events: [file])
        try database.upsertCodeChanges(changes)
        try database.upsertCodeChanges(changes)
        XCTAssertEqual(try database.codeChanges(projectID: "project").count, 1)
        XCTAssertEqual(try database.codeChanges(projectID: "project", path: "Sources/New.swift").first?.operation,
                       .create)
        XCTAssertTrue(try database.codeChanges(projectID: "other").isEmpty)
    }

    func testChangeSetFollowsOneUserRequestAcrossDialogue() {
        func change(id: String, session: String, turn: String, agent: String,
                    path: String, prompt: String, time: TimeInterval) -> IndexedCodeChange {
            IndexedCodeChange(id: id, projectID: "project", agentID: agent,
                sessionID: session, turnID: turn, path: path, operation: .modify,
                beforeDigest: nil, afterDigest: id, patch: nil, toolCallID: nil,
                toolName: nil, userPrompt: prompt, requirementIDs: ["oauth-login"], model: nil,
                startedAt: Date(timeIntervalSince1970: time),
                lastObservedAt: Date(timeIntervalSince1970: time + 1), attribution: .observed,
                commitHashes: [], verification: [], evidenceIDs: [id])
        }
        func prompt(_ id: String, _ turn: String, _ text: String, _ time: TimeInterval) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "codex",
                sessionID: "codex-session", turnID: turn, sequence: UInt64(time),
                occurredAt: Date(timeIntervalSince1970: time), observedAt: Date(timeIntervalSince1970: time),
                source: .agentTranscript, confidence: .confirmed,
                payload: .userPrompt(UserPromptEvidence(rawText: text, digest: nil, requirementIDs: [])))
        }
        let events = [prompt("p1", "t1", "增加登录功能", 100),
                      prompt("p2", "t2", "好", 200),
                      prompt("p3", "t3", "我认为登录按钮应该放在右边", 300)]
        let changes = [change(id: "c1", session: "codex-session", turn: "t1", agent: "codex",
                              path: "Sources/Login.swift", prompt: "增加登录功能", time: 110),
                       change(id: "c2", session: "codex-session", turn: "t3", agent: "codex",
                              path: "Sources/Login.swift", prompt: "我认为登录按钮应该放在右边", time: 310)]
        let sets = ChangeSetIndexer.build(projectID: "project", events: events, changes: changes)
        XCTAssertEqual(sets.count, 1)
        XCTAssertEqual(sets.first?.contextCount, 3)
        XCTAssertEqual(sets.first?.dialogue.map(\.role), [.start, .continueWork, .refine])
        XCTAssertEqual(sets.first?.codeChangeIDs, ["c1", "c2"])
    }

    func testChangeSetDoesNotMergeUnrelatedNearbyWork() {
        func change(id: String, path: String, prompt: String, requirement: String) -> IndexedCodeChange {
            IndexedCodeChange(id: id, projectID: "project", agentID: "codex",
                sessionID: "session", turnID: id, path: path, operation: .modify,
                beforeDigest: nil, afterDigest: id, patch: nil, toolCallID: nil,
                toolName: nil, userPrompt: prompt, requirementIDs: [requirement], model: nil,
                startedAt: Date(timeIntervalSince1970: 100),
                lastObservedAt: Date(timeIntervalSince1970: 101), attribution: .observed,
                commitHashes: [], verification: [], evidenceIDs: [id])
        }
        let values = [
            change(id: "auth", path: "Auth.swift", prompt: "Add OAuth login", requirement: "auth"),
            change(id: "weather", path: "Weather.swift", prompt: "Cache weather", requirement: "weather")
        ]
        func prompt(_ id: String, _ turn: String, _ text: String, _ time: TimeInterval) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "codex", sessionID: "session",
                turnID: turn, sequence: UInt64(time), occurredAt: Date(timeIntervalSince1970: time),
                observedAt: Date(timeIntervalSince1970: time), source: .agentTranscript,
                confidence: .confirmed, payload: .userPrompt(UserPromptEvidence(
                    rawText: text, digest: nil, requirementIDs: [])))
        }
        let events = [prompt("auth-prompt", "auth", "增加 OAuth 登录和账号认证功能", 90),
                      prompt("weather-prompt", "weather", "建立全新的天气缓存和预报刷新功能", 200)]
        XCTAssertEqual(ChangeSetIndexer.build(projectID: "project", events: events, changes: values).count, 2)
    }

    func testChangeSetKeepsCorrectionsAndAcknowledgementsInOneSessionRequirement() {
        func prompt(_ id: String, _ turn: String, _ text: String, _ time: TimeInterval) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "codex", sessionID: "article-session",
                turnID: turn, sequence: UInt64(time), occurredAt: Date(timeIntervalSince1970: time),
                observedAt: Date(timeIntervalSince1970: time), source: .agentTranscript,
                confidence: .confirmed, payload: .userPrompt(UserPromptEvidence(
                    rawText: text, digest: nil, requirementIDs: [])))
        }
        let events = [prompt("p1", "t1", "写一篇公众号文章", 10),
                      prompt("p2", "t2", "不应该这样，重新调整文章结构", 20),
                      prompt("p3", "t3", "好", 30),
                      prompt("p4", "t4", "行", 40)]

        let sets = ChangeSetIndexer.build(projectID: "project", events: events, changes: [])

        // Dialogue without an observed state mutation is activity, not a
        // change batch.
        XCTAssertTrue(sets.isEmpty)
    }

    func testChangeSetNeverFallsBackAcrossSessionBoundary() {
        func prompt(_ id: String, _ session: String, _ turn: String, _ text: String, _ time: TimeInterval) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "codex", sessionID: session,
                turnID: turn, sequence: UInt64(time), occurredAt: Date(timeIntervalSince1970: time),
                observedAt: Date(timeIntervalSince1970: time), source: .agentTranscript,
                confidence: .confirmed, payload: .userPrompt(UserPromptEvidence(
                    rawText: text, digest: nil, requirementIDs: [])))
        }
        let change = IndexedCodeChange(id: "orphan", projectID: "project", agentID: "workbuddy",
            sessionID: "session-b", turnID: nil, path: "Secret.swift", operation: .modify,
            beforeDigest: nil, afterDigest: "new", patch: nil, toolCallID: nil, toolName: nil,
            userPrompt: nil, requirementIDs: [], model: nil,
            startedAt: Date(timeIntervalSince1970: 30), lastObservedAt: Date(timeIntervalSince1970: 31),
            attribution: .inferred, commitHashes: [], verification: [], evidenceIDs: ["orphan"])

        let sets = ChangeSetIndexer.build(projectID: "project",
            events: [prompt("p1", "session-a", "t1", "修改登录功能", 10)], changes: [change])

        XCTAssertEqual(sets.count, 1)
        XCTAssertEqual(sets.first?.codeChangeIDs, ["orphan"])
        XCTAssertTrue(sets.first?.dialogue.isEmpty == true)
    }

    func testChangeSetSplitsOneLongLivedTurnAfterStableGap() {
        func change(_ id: String, _ time: TimeInterval) -> IndexedCodeChange {
            IndexedCodeChange(id: id, projectID: "project", agentID: "codex",
                sessionID: "long-session", turnID: "long-turn", path: "Sources/App.swift",
                operation: .modify, beforeDigest: nil, afterDigest: id, patch: nil,
                toolCallID: nil, toolName: nil, userPrompt: "Improve the app",
                requirementIDs: [], model: nil, startedAt: Date(timeIntervalSince1970: time),
                lastObservedAt: Date(timeIntervalSince1970: time + 1), attribution: .observed,
                commitHashes: [], verification: [], evidenceIDs: [id])
        }

        let sets = ChangeSetIndexer.build(projectID: "project", events: [],
            changes: [change("morning", 100), change("next-day", 86_500)])

        XCTAssertEqual(sets.count, 2)
    }

    func testChangeSetIgnoresCompactedTranscriptBundleAndDeduplicatesOneTurnPrompt() {
        func prompt(_ id: String, _ turn: String, _ text: String, _ time: TimeInterval) -> AgentEventEnvelope {
            AgentEventEnvelope(id: id, projectID: "project", agentID: "codex", sessionID: "session",
                turnID: turn, sequence: UInt64(time), occurredAt: Date(timeIntervalSince1970: time),
                observedAt: Date(timeIntervalSince1970: time), source: .agentTranscript,
                confidence: .inferred, payload: .userPrompt(UserPromptEvidence(
                    rawText: text, digest: nil, requirementIDs: [])))
        }
        let replay = """
        [126] user: 我现在下载了 ZCode，需要新增 ZCode 采集器
        [127] assistant: 我开始处理
        [128] tool: apply_patch
        """
        let events = [prompt("replay", "t0", replay, 1),
                      prompt("p1", "t1", "新增 ZCode 采集器", 2),
                      prompt("p1-duplicate", "t1", "新增 ZCode 采集器", 3),
                      prompt("p2", "t2", "好", 4)]

        let sets = ChangeSetIndexer.build(projectID: "project", events: events, changes: [])

        // Replayed or genuine prompts cannot create a change batch without a
        // captured state transition.
        XCTAssertTrue(sets.isEmpty)
    }
}
