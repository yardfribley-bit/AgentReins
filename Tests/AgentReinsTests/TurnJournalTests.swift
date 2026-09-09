import Foundation
import XCTest
@testable import AgentReins

final class TurnJournalTests: XCTestCase {
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
}
