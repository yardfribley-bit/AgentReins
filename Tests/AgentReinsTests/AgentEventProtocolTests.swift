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
        let event = GuardEvent(kind: "network", ruleId: "", path: "-",
                               command: "curl https://example.com", agent: "codex", op: "connect",
                               severity: "info", ts: Date(), action: "seen",
                               sessionId: "s", turnId: "t", toolCallId: "call-1",
                               userIntent: "Check the endpoint", modelPrompt: "system + user prompt",
                               modelResponse: "Endpoint is healthy", toolName: "shell", model: "gpt",
                               inputTokens: 120, outputTokens: 30, source: "codex-jsonl",
                               attributionConfidence: .confirmed, remoteHost: "93.184.216.34",
                               remoteDomain: "example.com")
        let projected = LegacyGuardEventAdapter.project([event], projectID: "project")
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
}
