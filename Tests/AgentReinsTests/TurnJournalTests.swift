import Foundation
import XCTest
@testable import AgentReins

final class TurnJournalTests: XCTestCase {
    func testToolSecurityAssessmentSeparatesToolMCPAndSkillRisk() {
        let shell = ToolSecurityAssessment.assess(name: "Bash", command: "rm project.txt")
        XCTAssertEqual(shell.kind, .tool)
        XCTAssertEqual(shell.risk, .high)
        XCTAssertEqual(shell.capability, "Arbitrary command execution")

        let mcp = ToolSecurityAssessment.assess(name: "mcp__github__create_issue", command: nil)
        XCTAssertEqual(mcp.kind, .mcp)
        XCTAssertEqual(mcp.risk, .medium)

        let skill = ToolSecurityAssessment.assess(name: "Skill", command: "load audit skill")
        XCTAssertEqual(skill.kind, .skill)
        XCTAssertEqual(skill.risk, .medium)

        let unknown = ToolSecurityAssessment.assess(name: nil, command: nil)
        XCTAssertEqual(unknown.risk, .unknown)
    }

    func testModelContextRemainsAssociatedWithEachTurnWhenTraceIsMissingOrReused() throws {
        let session = "session"
        let first = GuardEvent(kind: "model", ruleId: "prompt", path: "-", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date(timeIntervalSince1970: 1),
            action: "sent", sessionId: session, turnId: "turn-1", userIntent: "first request",
            modelPrompt: "first complete context")
        let second = GuardEvent(kind: "model", ruleId: "prompt", path: "-", command: nil,
            agent: "workbuddy", op: "prompt", severity: "info", ts: Date(timeIntervalSince1970: 2),
            action: "sent", sessionId: session, turnId: "turn-2", userIntent: "second request",
            modelPrompt: "second complete context")
        let firstCall = GuardEvent(kind: "tool", ruleId: "call", path: "-", command: "read()",
            agent: "workbuddy", op: "call", severity: "info", ts: Date(timeIntervalSince1970: 3),
            action: "requested", sessionId: session, traceId: "reused-trace", turnId: "turn-1",
            toolCallId: "call-1", toolName: "read")
        let secondCall = GuardEvent(kind: "tool", ruleId: "call", path: "-", command: "write()",
            agent: "workbuddy", op: "call", severity: "info", ts: Date(timeIntervalSince1970: 4),
            action: "requested", sessionId: session, traceId: "reused-trace", turnId: "turn-2",
            toolCallId: "call-2", toolName: "write")

        let snapshot = try XCTUnwrap(AgentSessionSnapshot.build(from: [first, second, firstCall, secondCall]).first)

        XCTAssertEqual(snapshot.turns.count, 2)
        XCTAssertEqual(snapshot.turns[0].fullPrompt, "first complete context")
        XCTAssertEqual(snapshot.turns[1].fullPrompt, "second complete context")
        XCTAssertEqual(snapshot.turns[0].toolCalls.map(\.name), ["read"])
        XCTAssertEqual(snapshot.turns[1].toolCalls.map(\.name), ["write"])
    }

    func testContextGrowthPreservesEveryModelRequest() throws {
        let inputs = [34_994, 37_186, 38_278, 39_074, 42_815, 45_789, 53_220, 53_731, 54_261, 56_147]
        let samples = inputs.enumerated().map { index, input in
            ContextUsageSample(id: "request-\(index)", timestamp: Date(timeIntervalSince1970: Double(index)),
                inputTokens: input, outputTokens: index == 0 ? 1_000 : 1_854,
                cachedTokens: 0, reasoningTokens: nil, model: "Hy4 preview")
        }

        let metrics = try XCTUnwrap(ContextGrowthMetrics(samples: samples))

        XCTAssertEqual(metrics.requestCount, 10)
        XCTAssertEqual(metrics.initialInputTokens, 34_994)
        XCTAssertEqual(metrics.latestInputTokens, 56_147)
        XCTAssertEqual(metrics.growthTokens, 21_153)
        XCTAssertEqual(metrics.cumulativeInputTokens, 455_495)
        XCTAssertEqual(metrics.cumulativeOutputTokens, 17_686)
        XCTAssertEqual(metrics.cumulativeCachedTokens, 0)
        XCTAssertEqual(metrics.largestInputIncrease, 7_431)
        XCTAssertEqual(metrics.growthPercent, 60.4475, accuracy: 0.001)
        XCTAssertTrue(metrics.needsAttention)
    }

    func testPorcelainParserHandlesOrdinaryAndRenamedFiles() {
        let input = Data(" M Sources/App.swift\0?? New File.md\0R  NewName.swift\0OldName.swift\0".utf8)

        let states = GitRepositoryInspector.parsePorcelainV1(input)

        XCTAssertEqual(states, [
            GitFileState(path: "New File.md", status: "??"),
            GitFileState(path: "NewName.swift", status: "R "),
            GitFileState(path: "Sources/App.swift", status: " M")
        ])
    }

    func testMutationComparisonIgnoresUnchangedPreExistingWork() {
        let baseline = snapshot(files: [
            GitFileState(path: "Existing.swift", status: " M"),
            GitFileState(path: "RemovedLater.swift", status: " M")
        ])
        let final = snapshot(files: [
            GitFileState(path: "Existing.swift", status: " M"),
            GitFileState(path: "Created.swift", status: "??")
        ])

        let mutations = GitRepositoryInspector.mutations(between: baseline, and: final)

        XCTAssertEqual(mutations.map(\.path), ["Created.swift", "RemovedLater.swift"])
        XCTAssertFalse(mutations.contains { $0.path == "Existing.swift" })
        XCTAssertTrue(mutations.allSatisfy { $0.attribution == .inferred })
    }

    func testMutationWithoutBaselineIsUnknown() {
        let final = snapshot(files: [GitFileState(path: "New.swift", status: "??")])

        let mutations = GitRepositoryInspector.mutations(between: nil, and: final)

        XCTAssertEqual(mutations.count, 1)
        XCTAssertEqual(mutations[0].attribution, .unknown)
    }

    func testGitSnapshotCapturesRepositoryState() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-git-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        try runGit(["init", "-q"], at: root)
        try runGit(["config", "user.email", "tests@agentreins.local"], at: root)
        try runGit(["config", "user.name", "AgentReins Tests"], at: root)
        try "baseline\n".write(to: root.appendingPathComponent("Tracked.txt"), atomically: true, encoding: .utf8)
        try runGit(["add", "Tracked.txt"], at: root)
        try runGit(["commit", "-qm", "Create baseline"], at: root)
        try "changed\n".write(to: root.appendingPathComponent("Tracked.txt"), atomically: true, encoding: .utf8)
        try "new\n".write(to: root.appendingPathComponent("New.txt"), atomically: true, encoding: .utf8)

        let snapshot = try XCTUnwrap(GitRepositoryInspector.capture(workspace: root.path))

        XCTAssertFalse(snapshot.head?.isEmpty ?? true)
        XCTAssertEqual(URL(fileURLWithPath: snapshot.repositoryRoot).standardizedFileURL.path,
                       root.standardizedFileURL.path)
        XCTAssertEqual(snapshot.files, [
            GitFileState(path: "New.txt", status: "??"),
            GitFileState(path: "Tracked.txt", status: " M")
        ])
        XCTAssertTrue(snapshot.patch.contains("-baseline"))
        XCTAssertTrue(snapshot.patch.contains("+changed"))
    }

    func testIndependentVerificationRecordsRealExitCodeAndOutput() {
        let command = ProjectVerifier.Command(
            executable: "/bin/sh",
            arguments: ["-c", "printf verified; printf warning >&2; exit 7"],
            displayName: "fixture verification")

        let run = ProjectVerifier.run(command, workspace: FileManager.default.temporaryDirectory.path)

        XCTAssertEqual(run.exitCode, 7)
        XCTAssertEqual(run.standardOutput, "verified")
        XCTAssertEqual(run.standardError, "warning")
        XCTAssertGreaterThanOrEqual(run.duration, 0)
    }

    func testProjectVerifierDetectsSupportedProjectTypes() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-verifier-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        try "// swift-tools-version:6.0\n".write(to: root.appendingPathComponent("Package.swift"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectVerifier.commands(for: root.path).map(\.displayName), ["swift build"])
        try FileManager.default.removeItem(at: root.appendingPathComponent("Package.swift"))

        try #"{"scripts":{"build":"echo build","test":"echo test"}}"#.write(
            to: root.appendingPathComponent("package.json"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectVerifier.commands(for: root.path).map(\.displayName), ["npm run build", "npm run test"])
        try FileManager.default.removeItem(at: root.appendingPathComponent("package.json"))

        try "[tool.pytest.ini_options]\n".write(to: root.appendingPathComponent("pyproject.toml"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectVerifier.commands(for: root.path).map(\.displayName), ["python3 -m pytest"])
        try FileManager.default.removeItem(at: root.appendingPathComponent("pyproject.toml"))

        try "module fixture\n".write(to: root.appendingPathComponent("go.mod"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectVerifier.commands(for: root.path).map(\.displayName), ["go test ./..."])
        try FileManager.default.removeItem(at: root.appendingPathComponent("go.mod"))

        try "[package]\n".write(to: root.appendingPathComponent("Cargo.toml"), atomically: true, encoding: .utf8)
        XCTAssertEqual(ProjectVerifier.commands(for: root.path).map(\.displayName), ["cargo test"])
    }

    func testRecoveryRestoresCleanTrackedStateAndRemovesRecordedUntrackedFiles() throws {
        let root = try makeRepository()
        defer { try? FileManager.default.removeItem(at: root) }
        let head = try gitOutput(["rev-parse", "HEAD"], at: root).trimmingCharacters(in: .whitespacesAndNewlines)
        try "agent change\n".write(to: root.appendingPathComponent("Tracked.txt"), atomically: true, encoding: .utf8)
        try "created\n".write(to: root.appendingPathComponent("Created.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(at: root.appendingPathComponent("Deleted.txt"))
        try FileManager.default.moveItem(at: root.appendingPathComponent("Renamed.txt"),
                                         to: root.appendingPathComponent("RenamedByAgent.txt"))

        let finalSnapshot = try XCTUnwrap(GitRepositoryInspector.capture(workspace: root.path))
        let untracked = finalSnapshot.files.filter { $0.status == "??" }.map(\.path)

        let result = GitRecovery.restoreCleanBaseline(
            workspace: root.path, head: head, untrackedPaths: untracked)

        XCTAssertTrue(result.success)
        XCTAssertEqual(try String(contentsOf: root.appendingPathComponent("Tracked.txt")), "baseline\n")
        XCTAssertEqual(try String(contentsOf: root.appendingPathComponent("Deleted.txt")), "delete baseline\n")
        XCTAssertEqual(try String(contentsOf: root.appendingPathComponent("Renamed.txt")), "rename baseline\n")
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("Created.txt").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("RenamedByAgent.txt").path))
        XCTAssertTrue(try gitOutput(["status", "--porcelain"], at: root).isEmpty)
    }

    func testRecoveryEligibilityRejectsPreExistingChanges() {
        let baseline = snapshot(files: [GitFileState(path: "UserWork.swift", status: " M")])
        let final = snapshot(files: [GitFileState(path: "UserWork.swift", status: " M"),
                                     GitFileState(path: "Agent.swift", status: "??")])
        let journal = AgentTurnJournal(
            id: "session:turn", sessionId: "session", turnId: "turn", agent: "fixture",
            workspace: "/tmp/repository", startedAt: Date(), completedAt: Date(), status: .completed,
            captureComplete: true, baseline: baseline, finalSnapshot: final,
            mutations: GitRepositoryInspector.mutations(between: baseline, and: final),
            verificationRuns: [], toolCallIds: [])

        XCTAssertFalse(journal.canRecoverSafely)
    }

    private func snapshot(files: [GitFileState]) -> GitSnapshot {
        GitSnapshot(capturedAt: Date(), repositoryRoot: "/tmp/repository", head: "abc",
                    porcelainV2: "", patch: "", stagedPatch: "", diffStat: "", numStat: "",
                    files: files)
    }

    private func runGit(_ arguments: [String], at root: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", root.path] + arguments
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0, "git \(arguments.joined(separator: " ")) failed")
    }

    private func gitOutput(_ arguments: [String], at root: URL) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", root.path] + arguments
        process.standardOutput = output
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        return String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }

    private func makeRepository() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("agentreins-recovery-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try runGit(["init", "-q"], at: root)
        try runGit(["config", "user.email", "tests@agentreins.local"], at: root)
        try runGit(["config", "user.name", "AgentReins Tests"], at: root)
        try "baseline\n".write(to: root.appendingPathComponent("Tracked.txt"), atomically: true, encoding: .utf8)
        try "delete baseline\n".write(to: root.appendingPathComponent("Deleted.txt"), atomically: true, encoding: .utf8)
        try "rename baseline\n".write(to: root.appendingPathComponent("Renamed.txt"), atomically: true, encoding: .utf8)
        try runGit(["add", "Tracked.txt", "Deleted.txt", "Renamed.txt"], at: root)
        try runGit(["commit", "-qm", "Create baseline"], at: root)
        return root
    }
}
