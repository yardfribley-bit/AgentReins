import Foundation
import XCTest
@testable import AgentReins

final class ToolActivityEvidenceProjectorTests: XCTestCase {
    private func temporaryRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("agentreins-git-intent-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }

    private func write(_ text: String, to path: URL) throws {
        try FileManager.default.createDirectory(at: path.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: path, atomically: true, encoding: .utf8)
    }

    private func json(_ value: [String: Any]) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
    }

    private func call(_ command: String, workspace: String, turn: String = "turn", op: String = "call", response: String? = nil, tool: String = "exec_command") -> GuardEvent {
        GuardEvent(kind: "tool", ruleId: "fixture", path: workspace, command: command,
            agent: "codex", op: op, severity: "info", ts: Date(timeIntervalSince1970: 100),
            action: op == "result" ? "completed" : "requested", sessionId: "session", turnId: turn,
            toolCallId: "native-call", modelResponse: response, toolName: tool, source: "agentsight:codex-local-compat")
    }

    private func metadata(_ event: GuardEvent) throws -> [String: Any] {
        try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(try XCTUnwrap(event.command).utf8)) as? [String: Any])
    }

    @MainActor
    func testGitIntentUsesStructuredWorkdirAndOriginInsteadOfFirstRemote() throws {
        let root = try temporaryRoot(), repo = root.appendingPathComponent("nested repo")
        try write("[remote \"unrelated\"]\nurl = https://unrelated.example/repo.git\n[remote \"origin\"]\nurl = https://github.com/example/repo.git\n", to: repo.appendingPathComponent(".git/config"))
        let input = try json(["cmd": "GIT_TERMINAL_PROMPT=0 git push -u origin main", "workdir": repo.path])
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call(input, workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "github.com")
        XCTAssertEqual(event.path, repo.path)
        XCTAssertEqual(try metadata(event)["requestedURL"] as? String, "https://github.com/example/repo.git")
        XCTAssertTrue((try metadata(event)["destinationBasis"] as? String)?.contains("remote origin") == true)
    }

    @MainActor
    func testGitIntentResolvesWorktreeGitdirAndRelativeCommondir() throws {
        let root = try temporaryRoot(), repo = root.appendingPathComponent("checkout"), common = root.appendingPathComponent("source/.git")
        try write("[remote \"origin\"]\nurl = git@github.com:example/repo.git\n", to: common.appendingPathComponent("config"))
        try write("../..\n", to: common.appendingPathComponent("worktrees/checkout/commondir"))
        try write("gitdir: ../source/.git/worktrees/checkout\n", to: repo.appendingPathComponent(".git"))
        let input = try json(["command": ["/bin/zsh", "-lc", "git push origin main"], "cwd": repo.absoluteString])
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call(input, workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "github.com")
        XCTAssertEqual(event.remotePort, 22)
        XCTAssertEqual(event.path, repo.path)
        XCTAssertEqual(try metadata(event)["requestedURL"] as? String, "git@github.com:example/repo.git")
    }

    @MainActor
    func testGitIntentUsesExplicitRemoteAndItsPushURL() throws {
        let root = try temporaryRoot()
        try write("[remote \"origin\"]\nurl = https://origin.example/repo.git\n[remote \"release\"]\nurl = https://fetch.example/repo.git\npushurl = ssh://deploy@push.example:2222/repo.git\n", to: root.appendingPathComponent(".git/config"))
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call("git push release main", workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "push.example")
        XCTAssertEqual(event.remotePort, 2222)
        let fetch = try XCTUnwrap(ToolActivityEvidenceProjector().project([call("git fetch release", workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(fetch.remoteDomain, "fetch.example")
    }

    @MainActor
    func testGitIntentUsesQuotedGitCAndDefaultOrigin() throws {
        let root = try temporaryRoot(), repo = root.appendingPathComponent("repo with spaces")
        try write("[remote \"origin\"]\nurl = https://github.com/example/repo.git\n", to: repo.appendingPathComponent(".git/config"))
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call("git -C 'repo with spaces' push", workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "github.com")
        XCTAssertEqual(try metadata(event)["destinationBasis"] as? String, "Git remote origin in \(repo.path)")
    }

    @MainActor
    func testGitIntentDirectURLHonorsPortAndDoesNotNeedARepository() throws {
        let root = try temporaryRoot()
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call("git push https://push.example:8443/team/repo.git main", workspace: root.path)]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "push.example")
        XCTAssertEqual(event.remotePort, 8443)
        XCTAssertEqual(try metadata(event)["requestedURL"] as? String, "https://push.example:8443/team/repo.git")
    }

    @MainActor
    func testGitIntentParsesExecutorLiteralWorkdirAndIgnoresJustification() throws {
        let root = try temporaryRoot(), repo = root.appendingPathComponent("checkout")
        try write("[remote \"origin\"]\nurl = https://github.com/example/repo.git\n", to: repo.appendingPathComponent(".git/config"))
        let wrapper = "text(await tools.exec_command({cmd:\"git push origin main\",workdir:\"\(repo.path)\",justification:\"https://unrelated.example and workdir: '/wrong'\"}));"
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call(wrapper, workspace: root.path, tool: "exec")]).first { $0.kind == "network" })
        XCTAssertEqual(event.remoteDomain, "github.com")
        XCTAssertEqual(event.path, repo.path)
    }

    @MainActor
    func testGitIntentDoesNotBorrowParentRemoteWhenNearestRepoLacksNamedRemote() throws {
        let root = try temporaryRoot(), repo = root.appendingPathComponent("child")
        try write("[remote \"origin\"]\nurl = https://parent.example/repo.git\n", to: root.appendingPathComponent(".git/config"))
        try write("[remote \"other\"]\nurl = https://other.example/repo.git\n", to: repo.appendingPathComponent(".git/config"))
        XCTAssertFalse(ToolActivityEvidenceProjector().project([call("git push origin main", workspace: repo.path)]).contains { $0.kind == "network" })
        XCTAssertFalse(ToolActivityEvidenceProjector().project([call("git push", workspace: repo.path)]).contains { $0.kind == "network" })
    }

    @MainActor
    func testCompletedNativeCommandProjectsTargetWithoutClaimingSocketOrHTTP() throws {
        let root = try temporaryRoot()
        try write("[remote \"origin\"]\nurl = https://github.com/example/repo.git\n", to: root.appendingPathComponent(".git/config"))
        let input = try json(["command": ["/bin/zsh", "-lc", "git push origin main"], "cwd": root.absoluteString])
        let result = call(input, workspace: "-", op: "result", response: try json(["exit_code": 0, "status": "completed"]), tool: "CommandExecution")
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([result]).first { $0.kind == "network" })
        XCTAssertEqual(event.toolCallId, result.toolCallId)
        XCTAssertEqual(event.source, "tool-intent")
        XCTAssertEqual(event.action, "completed")
        XCTAssertEqual(event.remoteDomain, "github.com")
        let body = try metadata(event)
        XCTAssertEqual(body["wireObserved"] as? Bool, false)
        XCTAssertEqual(body["evidenceType"] as? String, "execution_derived_target")
        XCTAssertNil(body["method"])
        XCTAssertNil(body["remoteIP"])
        XCTAssertTrue(event.attributionMethod?.contains("no socket or HTTP request observed") == true)
    }

    @MainActor
    func testFailedCompletedNativeCommandKeepsFailureWithoutClaimingNetworkSuccess() throws {
        let root = try temporaryRoot()
        let input = try json(["command": ["git", "push", "https://github.com/example/repo.git", "main"], "cwd": root.path])
        let result = call(input, workspace: root.path, op: "result", response: try json(["exit_code": 128, "stderr": "fatal: unable to resolve host"]), tool: "CommandExecution")
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([result]).first { $0.kind == "network" })
        XCTAssertEqual(event.action, "failed")
        XCTAssertEqual(try metadata(event)["wireObserved"] as? Bool, false)
    }

    @MainActor
    func testResultTextCannotCreateDestinationOrTurnFailedCallIntoWireEvidence() throws {
        let root = try temporaryRoot()
        let result = GuardEvent(kind: "tool", ruleId: "fixture", path: root.path, command: nil,
            agent: "codex", op: "result", severity: "info", ts: Date(), action: "failed",
            sessionId: "session", turnId: "turn", toolCallId: "native-call",
            modelResponse: "git push https://github.com/example/repo.git failed", toolName: "CommandExecution")
        XCTAssertTrue(ToolActivityEvidenceProjector().project([result]).isEmpty)
        let projector = ToolActivityEvidenceProjector()
        let request = call("git push https://github.com/example/repo.git main", workspace: root.path)
        _ = projector.project([request])
        let event = try XCTUnwrap(projector.project([result]).first { $0.kind == "network" })
        XCTAssertEqual(event.action, "failed")
        XCTAssertEqual(try metadata(event)["wireObserved"] as? Bool, false)
    }

    @MainActor
    func testURLIntentPreservesRequestedURLWithoutInventingHTTPMethod() throws {
        let event = try XCTUnwrap(ToolActivityEvidenceProjector().project([call(#"{"url":"https://example.test/search?q=test"}"#, workspace: "/tmp", tool: "web_fetch")]).first { $0.kind == "network" })
        let body = try metadata(event)
        XCTAssertEqual(body["requestedURL"] as? String, "https://example.test/search?q=test")
        XCTAssertEqual(body["wireObserved"] as? Bool, false)
        XCTAssertNil(body["method"])
        XCTAssertNil(body["statusCode"])
        XCTAssertEqual(event.action, "requested")
    }

    @MainActor
    func testPendingCorrelationDoesNotPairReusedCallIDAcrossTurns() throws {
        let projector = ToolActivityEvidenceProjector()
        _ = projector.project([call("git push https://github.com/example/repo.git main", workspace: "/tmp", turn: "first")])
        let result = GuardEvent(kind: "tool", ruleId: "fixture", path: "/tmp", command: nil,
            agent: "codex", op: "result", severity: "info", ts: Date(), action: "completed",
            sessionId: "session", turnId: "second", toolCallId: "native-call", modelResponse: "Process exited with code 0", toolName: "exec_command")
        XCTAssertTrue(projector.project([result]).isEmpty)
    }

    @MainActor
    func testRuntimeGitConfigOverrideDoesNotProjectDiskRemote() throws {
        let root = try temporaryRoot()
        try write("[remote \"origin\"]\nurl = https://disk.example/repo.git\n", to: root.appendingPathComponent(".git/config"))
        for command in ["git -c remote.origin.url=https://override.example/repo.git push origin main",
                        "git -cremote.origin.url=https://override.example/repo.git push origin main",
                        "git -c http.extraHeader=fixture push https://explicit.example/repo.git main"] {
            XCTAssertFalse(ToolActivityEvidenceProjector().project([call(command, workspace: root.path)]).contains { $0.kind == "network" }, command)
        }
    }

    @MainActor
    func testImplicitRemoteDoesNotAssumeOriginWhenDefaultsAreConfigured() throws {
        let root = try temporaryRoot(), config = root.appendingPathComponent(".git/config")
        let origin = "[remote \"origin\"]\nurl = https://origin.example/repo.git\n"
        for defaults in ["[remote]\npushDefault = release\n", "[branch \"main\"]\npushRemote = release\n", "[branch \"main\"]\nremote = upstream\n"] {
            try write(origin + defaults, to: config)
            XCTAssertFalse(ToolActivityEvidenceProjector().project([call("git push", workspace: root.path)]).contains { $0.kind == "network" }, defaults)
            let explicit = try XCTUnwrap(ToolActivityEvidenceProjector().project([call("git push origin main", workspace: root.path)]).first { $0.kind == "network" })
            XCTAssertEqual(explicit.remoteDomain, "origin.example")
        }
        try write(origin + "[branch \"main\"]\nremote = upstream\n", to: config)
        XCTAssertFalse(ToolActivityEvidenceProjector().project([call("git pull", workspace: root.path)]).contains { $0.kind == "network" })
        XCTAssertFalse(ToolActivityEvidenceProjector().project([call("git fetch --all", workspace: root.path)]).contains { $0.kind == "network" })
    }

    @MainActor
    func testExecutorExamplesInJSStringsAndCommentsDoNotProjectCommands() throws {
        let samples = [
            #"const example='tools.exec_command({cmd:"git push https://not-used.example/repo.git main",workdir:"/tmp"})'; text(example);"#,
            #"const example="tools.exec_command({cmd:\"git push https://not-used.example/repo.git main\",workdir:\"/tmp\"})"; text(example);"#,
            #"const example=`tools.exec_command({cmd:"git push https://not-used.example/repo.git main",workdir:"/tmp"})`; text(example);"#,
            #"// tools.exec_command({cmd:"git push https://not-used.example/repo.git main",workdir:"/tmp"})"#,
            #"/* tools.exec_command({cmd:"git push https://not-used.example/repo.git main",workdir:"/tmp"}) */ text('fixture');"#
        ]
        for sample in samples {
            XCTAssertTrue(ToolActivityEvidenceProjector().project([call(sample, workspace: "/tmp", tool: "exec")]).isEmpty, sample)
        }
    }

    @MainActor
    func testExecutorDynamicCommandOrWorkspaceDoesNotGuessTarget() throws {
        let root = try temporaryRoot()
        try write("[remote \"origin\"]\nurl = https://disk.example/repo.git\n", to: root.appendingPathComponent(".git/config"))
        let samples = [
            #"text(await tools.exec_command({cmd:"git push https://literal.example/repo.git " + branch,workdir:"/tmp"}));"#,
            #"text(await tools.exec_command({cmd:"git push origin main",workdir:directory}));"#,
            #"text(await tools.exec_command({cmd:command,workdir:"/tmp"}));"#,
            #"text(await tools.exec_command({cmd:`git push https://literal.example/${repo}.git main`,workdir:"/tmp"}));"#
        ]
        for sample in samples {
            XCTAssertTrue(ToolActivityEvidenceProjector().project([call(sample, workspace: root.path, tool: "exec")]).isEmpty, sample)
        }
    }

    @MainActor
    func testExecutorCommentsCannotSupplyArgumentsAndRealCallStillProjects() throws {
        let wrapper = #"/* tools.exec_command({cmd:"git push https://fake.example/repo.git main"}) */ text(await tools.exec_command({cmd: "git push https://actual.example/repo.git main" /* suffix */, /* workdir:"/wrong" */ workdir: "/tmp"}));"#
        let events = ToolActivityEvidenceProjector().project([call(wrapper, workspace: "/tmp", tool: "exec")]).filter { $0.kind == "network" }
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?.remoteDomain, "actual.example")
        XCTAssertEqual(events.first?.path, "/tmp")
    }
}
