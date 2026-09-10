import Foundation

enum DevelopmentTraceNodeKind: String, Equatable, CaseIterable {
    case understand, plan, build, test, deliver
    var title: String { rawValue.capitalized }
    var icon: String {
        switch self {
        case .understand: return "person.crop.circle"
        case .plan: return "brain.head.profile"
        case .build: return "chevron.left.forwardslash.chevron.right"
        case .test: return "checkmark.seal"
        case .deliver: return "flag.checkered"
        }
    }
}

enum DevelopmentTraceNodeStatus: String, Equatable { case completed, running, pending, attention }

struct DevelopmentTraceEvidence: Identifiable { let id: String; let title: String; let value: String }
struct DevelopmentTraceActivity: Identifiable {
    let id: String; let title: String; let summary: String; let timestamp: Date?; let status: DevelopmentTraceNodeStatus
}
struct DevelopmentTraceNode: Identifiable {
    let id: String
    let kind: DevelopmentTraceNodeKind
    let title: String
    let summary: String
    let status: DevelopmentTraceNodeStatus
    let confidence: EvidenceConfidence
    let timestamp: Date?
    let activities: [DevelopmentTraceActivity]
    let context: [DevelopmentTraceEvidence]
    let tools: [AgentToolCall]
    let evidence: [DevelopmentTraceEvidence]
}

struct DevelopmentTaskTrace {
    let id: String
    let nodes: [DevelopmentTraceNode]

    static func build(session: AgentSessionSnapshot, turn: AgentTurn,
                      journal: AgentTurnJournal?, verificationState: VerificationState?) -> DevelopmentTaskTrace {
        let intent = turn.userInput ?? session.latestIntent
        let prompt = turn.fullPrompt
        let response = turn.finalResponse
        let calls = turn.toolCalls
        let planCalls = calls.filter { classify($0) == .plan }
        let testCalls = calls.filter { classify($0) == .test }
        let deliveryCalls = calls.filter { classify($0) == .deliver }
        let buildCalls = calls.filter { !planCalls.contains(id: $0.id) && !testCalls.contains(id: $0.id) && !deliveryCalls.contains(id: $0.id) }
        let mutations = journal?.mutations ?? []
        let runs = journal?.verificationRuns ?? []
        let verificationRunning = verificationState == .running
        let verificationFailed = runs.contains { $0.exitCode != 0 }
        let verificationPassed = !runs.isEmpty && !verificationFailed

        let understand = DevelopmentTraceNode(id: "understand", kind: .understand,
            title: "Understand the requirement", summary: intent ?? "The original requirement was not captured",
            status: intent == nil ? .attention : .completed, confidence: intent == nil ? .unknown : .confirmed,
            timestamp: turn.startedAt,
            activities: intent.map { [activity("requirement", "Requirement captured", String($0.prefix(180)), turn.startedAt, .completed)] } ?? [],
            context: field("Original user input", intent), tools: [],
            evidence: field("Session ID", session.id) + field("Turn ID", turn.id) + field("Original user input", intent))

        let plan = DevelopmentTraceNode(id: "plan", kind: .plan, title: "Prepare the approach",
            summary: prompt == nil ? "Waiting for captured model context" : "\(session.agent.capitalized) prepared context for \(turn.modelNames)",
            status: prompt == nil && calls.isEmpty ? .pending : .completed, confidence: prompt == nil ? .unknown : .confirmed,
            timestamp: turn.exchanges.first?.startedAt,
            activities: [activity("model-request", "Model request prepared", tokenSummary(turn), turn.exchanges.first?.startedAt, prompt == nil ? .pending : .completed),
                         activity("model-direction", "Model selected the next actions", turn.modelInstructionSummary, turn.exchanges.last?.startedAt, calls.isEmpty && response == nil ? .pending : .completed)]
                + groupedActivities(planCalls, purpose: "Project context inspected"),
            context: field("Captured model context", prompt) + field("Model response", response) + field("Model", turn.modelNames) + field("Token usage", tokenSummary(turn)),
            tools: planCalls, evidence: field("Captured model context", prompt) + field("Recorded model response", response))

        let mutationConfidence: EvidenceConfidence = mutations.contains { $0.attribution == .unknown }
            ? .unknown : (mutations.contains { $0.attribution == .inferred } ? .inferred : .confirmed)
        let buildSummary = !mutations.isEmpty ? "\(mutations.count) workspace changes detected" : (!buildCalls.isEmpty ? "\(buildCalls.count) implementation actions observed" : "Waiting for implementation activity")
        let build = DevelopmentTraceNode(id: "build", kind: .build, title: "Build the feature", summary: buildSummary,
            status: buildCalls.contains { $0.completedAt == nil } ? .running : ((buildCalls.isEmpty && mutations.isEmpty) ? .pending : .completed),
            confidence: !mutations.isEmpty ? mutationConfidence : (!buildCalls.isEmpty ? .confirmed : .unknown), timestamp: buildCalls.first?.startedAt,
            activities: groupedActivities(buildCalls, purpose: "Implementation work") + mutations.map {
                activity("mutation-\($0.id)", "Changed \($0.path)", "\($0.baselineStatus ?? "clean") → \($0.finalStatus ?? "clean")", journal?.finalSnapshot?.capturedAt, .completed)
            }, context: [], tools: buildCalls,
            evidence: mutations.map { DevelopmentTraceEvidence(id: "mutation-\($0.id)", title: $0.path, value: "\($0.baselineStatus ?? "clean") → \($0.finalStatus ?? "clean")\n\($0.evidence)") })

        let testStatus: DevelopmentTraceNodeStatus = verificationRunning ? .running : (verificationFailed ? .attention : (verificationPassed ? .completed : (!testCalls.isEmpty ? .running : .pending)))
        let testSummary = verificationPassed ? "Independent checks passed" : (verificationFailed ? "Independent checks failed" : (!testCalls.isEmpty ? "\(testCalls.count) build or test actions observed" : "Independent verification has not run"))
        let test = DevelopmentTraceNode(id: "test", kind: .test, title: "Test and verify", summary: testSummary,
            status: testStatus, confidence: runs.isEmpty ? (!testCalls.isEmpty ? .confirmed : .unknown) : .confirmed,
            timestamp: runs.last?.startedAt ?? testCalls.first?.startedAt,
            activities: groupedActivities(testCalls, purpose: "Build and test") + runs.map {
                activity("verification-\($0.id)", $0.command, $0.exitCode == 0 ? "Passed" : "Failed with exit code \($0.exitCode)", $0.startedAt, $0.exitCode == 0 ? .completed : .attention)
            }, context: [], tools: testCalls,
            evidence: runs.flatMap { field("Verification command", $0.command) + field("Exit code", String($0.exitCode)) + field("Output", $0.standardOutput) + field("Error output", $0.standardError) })

        let deliver = DevelopmentTraceNode(id: "deliver", kind: .deliver, title: "Deliver the result",
            summary: response.map { String($0.replacingOccurrences(of: "\n", with: " ").prefix(180)) } ?? "Waiting for the final response",
            status: response == nil ? (!deliveryCalls.isEmpty ? .running : .pending) : .completed,
            confidence: response == nil ? .unknown : .confirmed, timestamp: turn.exchanges.last?.startedAt,
            activities: groupedActivities(deliveryCalls, purpose: "Delivery") + (response.map { [activity("final-response", "Agent reported the result", String($0.prefix(180)), turn.exchanges.last?.startedAt, .completed)] } ?? []),
            context: field("Final model response", response), tools: deliveryCalls, evidence: field("Final response", response))
        return DevelopmentTaskTrace(id: "\(session.id):\(turn.id)", nodes: [understand, plan, build, test, deliver])
    }

    private static func classify(_ call: AgentToolCall) -> DevelopmentTraceNodeKind {
        let value = "\(call.name) \(call.arguments ?? "")".lowercased()
        if ["test", "build", "lint", "typecheck", "package_app", "codesign", "lipo"].contains(where: value.contains) { return .test }
        if ["git push", "git commit", "release", "publish", "deploy", "upload"].contains(where: value.contains) { return .deliver }
        if ["read", "search", "find", "list", "rg ", "sed -n", "open"].contains(where: value.contains) { return .plan }
        return .build
    }

    private static func groupedActivities(_ calls: [AgentToolCall], purpose: String) -> [DevelopmentTraceActivity] {
        guard !calls.isEmpty else { return [] }
        let completed = calls.filter { $0.completedAt != nil }.count
        let running = calls.count - completed
        return [activity("\(purpose)-group", purpose, "\(calls.count) actions · \(completed) completed" + (running > 0 ? " · \(running) running" : ""), calls.first?.startedAt, running > 0 ? .running : .completed)]
    }
    private static func activity(_ id: String, _ title: String, _ summary: String, _ timestamp: Date?, _ status: DevelopmentTraceNodeStatus) -> DevelopmentTraceActivity {
        DevelopmentTraceActivity(id: id, title: title, summary: summary, timestamp: timestamp, status: status)
    }
    private static func tokenSummary(_ turn: AgentTurn) -> String {
        let parts = [turn.inputTokens.map { "\($0.formatted()) input tokens" }, turn.outputTokens.map { "\($0.formatted()) output" }, turn.cachedTokens.map { "\($0.formatted()) cached" }].compactMap { $0 }
        return parts.isEmpty ? "Exact token usage was not captured" : parts.joined(separator: " · ")
    }
    private static func field(_ title: String, _ value: String?) -> [DevelopmentTraceEvidence] {
        guard let value, !value.isEmpty else { return [] }
        return [DevelopmentTraceEvidence(id: "\(title)-\(value.hashValue)", title: title, value: value)]
    }
}

private extension Array where Element == AgentToolCall {
    func contains(id: String) -> Bool { contains { $0.id == id } }
}
