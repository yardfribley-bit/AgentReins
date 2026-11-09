import SQLite3
import XCTest
import AgentReinsCore
@testable import AgentReins

final class FileLayerCaptureTests: XCTestCase {
    func testCredentialReadIsKeptUnderTmpAndPrivateTmp() {
        let hits = FileLayerCapture.hits(opens: [
            .init(path: "/tmp/fake.env", writable: false),
            .init(path: "/private/tmp/proj/.env.local", writable: false),
            .init(path: "/Users/me/.ssh/id_ed25519", writable: false),
            .init(path: "/Users/me/Library/Keychains/login.keychain-db", writable: false),
            .init(path: "/tmp/api_token", writable: false),
            .init(path: "/tmp/notes.txt", writable: false),
        ], workspace: "/Users/me/project")
        XCTAssertEqual(hits.map(\.path), [
            "/tmp/fake.env", "/private/tmp/proj/.env.local", "/Users/me/.ssh/id_ed25519",
            "/Users/me/Library/Keychains/login.keychain-db", "/tmp/api_token",
        ])
        XCTAssertTrue(hits.allSatisfy { $0.op == "read" && $0.credential })
    }

    func testWriteOutsideWorkspaceIsRecordedAndInsideWorkspaceIsNot() {
        let hits = FileLayerCapture.hits(opens: [
            .init(path: "/Users/me/project/note.txt", writable: true),
            .init(path: "/tmp/note.txt", writable: true),
            .init(path: "/Users/me/Library/Application Support/AgentGuard/evidence.sqlite3", writable: true),
        ], workspace: "/Users/me/project")
        XCTAssertEqual(hits.map(\.path), ["/tmp/note.txt"])
        XCTAssertEqual(hits.first?.op, "modify")
        XCTAssertEqual(hits.first?.credential, false)
    }

    func testBuiltinCredentialListDoesNotDependOnRules() {
        let files = FileLayerCapture.builtinCredentialFiles(home: "/Users/me")
        XCTAssertTrue(files.contains("/Users/me/.ssh/id_ed25519"))
        XCTAssertTrue(files.contains("/Users/me/.aws/credentials"))
        XCTAssertTrue(files.contains("/Users/me/Library/Keychains/login.keychain-db"))
    }

    func testAccessTimeReadIsDistinctFromAWriteAndGradeFollowsTheOpenDescriptor() {
        let before = FileLayerCapture.AccessStamp(access: 100, modified: 50)
        let read = FileLayerCapture.AccessStamp(access: 140, modified: 50)
        let write = FileLayerCapture.AccessStamp(access: 180, modified: 180)
        XCTAssertTrue(FileLayerCapture.isAccessRead(previous: before, current: read))
        XCTAssertFalse(FileLayerCapture.isAccessRead(previous: before, current: write))
        XCTAssertFalse(FileLayerCapture.isAccessRead(previous: before, current: before))
        XCTAssertEqual(FileLayerCapture.readGrade(descriptorStillOpen: true), "confirmed")
        XCTAssertEqual(FileLayerCapture.readGrade(descriptorStillOpen: false), "possible")
    }

    func testWatchSetIncludesKnownCredentialDirsAndDotEnvOnly() {
        let home = "/Users/me"
        let ssh = "/Users/me/.ssh"
        let tmp = "/tmp"
        let workspace = "/Users/me/project"
        let files = FileLayerCapture.watchFiles(home: home, workspaces: [workspace], directoryNames: [
            ssh: ["id_ed25519", "config"],
            "/Users/me/.config/gcloud": ["application_default_credentials.json"],
            "/Users/me/Library/Keychains": ["login.keychain-db"],
            tmp: ["fake.env", "notes.txt", ".env.local"],
            workspace: [".env", "main.swift"],
        ])
        XCTAssertTrue(files.contains("/Users/me/.ssh/id_ed25519"))
        XCTAssertTrue(files.contains("/Users/me/.aws/credentials"))
        XCTAssertTrue(files.contains("/Users/me/.config/gcloud/application_default_credentials.json"))
        XCTAssertTrue(files.contains("/Users/me/.npmrc"))
        XCTAssertTrue(files.contains("/Users/me/.pypirc"))
        XCTAssertTrue(files.contains("/Users/me/Library/Keychains/login.keychain-db"))
        XCTAssertTrue(files.contains("/tmp/fake.env"))
        XCTAssertTrue(files.contains("/tmp/.env.local"))
        XCTAssertTrue(files.contains("/Users/me/project/.env"))
        XCTAssertFalse(files.contains("/tmp/notes.txt"))
        XCTAssertFalse(files.contains("/Users/me/project/main.swift"))
        XCTAssertLessThanOrEqual(files.count, FileLayerCapture.watchCap)
    }

    /// Build 204 missed Python open() of /tmp/<dir>/.env. The watch listed only
    /// the names directly inside /tmp, so the nested file was never registered.
    /// libproc also misses the read once that process has exited. A later atime
    /// move with no open descriptor is possible, not confirmed, and not a block.
    func testNestedTmpDotEnvIsRegisteredAndAClosedReadIsPossible() throws {
        let shallow = FileLayerCapture.watchFiles(home: "/Users/me", workspaces: [], directoryNames: [
            "/tmp": ["job", "notes.txt"],
        ])
        XCTAssertFalse(shallow.contains { $0.hasSuffix("/job/.env") })
        let files = FileLayerCapture.watchFiles(home: "/Users/me", workspaces: ["/Users/me/project"], directoryNames: [
            "/tmp": ["job", "notes.txt", ".env"],
            "/tmp/job": [".env", "out.txt"],
            "/private/tmp": ["job"],
            "/private/tmp/job": [".env"],
            "/Users/me/project": ["src"],
            "/Users/me/project/src": [".env"],
        ])
        func has(_ suffix: String) -> Bool { files.contains { $0.hasSuffix(suffix) } }
        XCTAssertTrue(has("/job/.env"))
        XCTAssertTrue(has("/.env"))
        XCTAssertTrue(has("/src/.env"))
        XCTAssertFalse(has("/job/out.txt"))
        XCTAssertFalse(has("/notes.txt"))
        XCTAssertLessThanOrEqual(files.count, FileLayerCapture.watchCap)
        let before = FileLayerCapture.AccessStamp(access: 10, modified: 10)
        let afterRead = FileLayerCapture.AccessStamp(access: 11, modified: 10)
        XCTAssertTrue(FileLayerCapture.isAccessRead(previous: before, current: afterRead))
        XCTAssertEqual(FileLayerCapture.readGrade(descriptorStillOpen: false), "possible")
        XCTAssertEqual(FileLayerCapture.readGrade(descriptorStillOpen: true), "confirmed")
        let log = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("obs-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: log) }
        let row = CredentialObservationLog.Row(
            path: "/tmp/job/.env", grade: "possible", agent: "cursor",
            at: "2026-11-09T07:55:00Z", source: "credential-kqueue", blocked: false)
        CredentialObservationLog.append(row, to: log)
        CredentialObservationLog.append(row, to: log)
        let recent = CredentialObservationLog.recent(from: log, limit: 10)
        XCTAssertEqual(recent.count, 1)
        XCTAssertEqual(recent.first?.grade, "possible")
        XCTAssertEqual(recent.first?.blocked, false)
        XCTAssertEqual(recent.first?.path, "/tmp/job/.env")
    }

    func testCommandRedirectOutsideWorkspaceAndTmpEnv() {
        let hits = FileLayerCapture.commandTargets("curl https://example.test; cat /tmp/fake.env; echo hi > /tmp/note.txt")
        XCTAssertTrue(hits.contains { $0.path == "/tmp/fake.env" && $0.op == "read" && $0.credential })
        XCTAssertTrue(hits.contains { $0.path == "/tmp/note.txt" && $0.op == "modify" })
    }
}

final class MCPHealthAndStaleDataTests: XCTestCase {
    func testLegacyBundleIsReapedWithoutTheCurrentPid() {
        let procs = [
            MCPHTTPOrphans.Proc(pid: 10, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 11, ppid: 1, command: "/Users/me/AgentSpec/AgentGuardApp/.build/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 12, ppid: 1, command: "/Users/me/AgentSpec/AgentGuardApp/.build/AgentReinsMCP --http --port 19000"),
            MCPHTTPOrphans.Proc(pid: 13, ppid: 1, command: "/usr/bin/python3"),
        ]
        let victims = MCPHTTPOrphans.reapPIDs(procs, selfPid: 10, port: 18977, listenerPIDs: [10])
        XCTAssertEqual(victims, [11])
        let includingListener = MCPHTTPOrphans.reapPIDs(procs, selfPid: 99, port: 18977, listenerPIDs: [11])
        XCTAssertTrue(includingListener.contains(11))
        XCTAssertFalse(includingListener.contains(99))
        XCTAssertFalse(includingListener.contains(12))
    }

    func testHealthCheckKillsOnlyAnOldHttpProcessWhenThePortIsDown() {
        let now = Date(timeIntervalSince1970: 1_000)
        let procs = [
            MCPHTTPOrphans.Proc(pid: 4, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977"),
            MCPHTTPOrphans.Proc(pid: 5, ppid: 1, command: "/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 19000"),
        ]
        let started: [Int32: Date] = [
            4: now.addingTimeInterval(-30),
            5: now.addingTimeInterval(-30),
        ]
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: true, now: now, startedAt: started), [])
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: false, now: now, startedAt: started), [4])
        let young: [Int32: Date] = [4: now.addingTimeInterval(-2)]
        XCTAssertEqual(MCPHTTPOrphans.healthVictims(procs, port: 18977, portListening: false, now: now, startedAt: young), [])
    }

    func testKickstartExitNegativeNineIsNotAHealthError() {
        let kickstart = """
        state = running
        last exit code = -9
        """
        XCTAssertTrue(MCPHTTPOrphans.isKickstartExit(kickstart))
        XCTAssertTrue(MCPHTTPOrphans.isKickstartExit("last terminating signal = Killed: 9"))
        XCTAssertFalse(MCPHTTPOrphans.launchdExitIsHealthError(kickstart))
        XCTAssertFalse(MCPHTTPOrphans.launchdExitIsHealthError("last exit code = 0"))
        XCTAssertFalse(MCPHTTPOrphans.launchdExitIsHealthError(""))
        XCTAssertTrue(MCPHTTPOrphans.launchdExitIsHealthError("last exit code = 1"))
        XCTAssertEqual(MCPHTTPOrphans.healthLogLines(victims: [], port: 18977, launchdText: kickstart), [])
        XCTAssertEqual(MCPHTTPOrphans.healthGrace(launchdText: kickstart), 45)
        XCTAssertEqual(MCPHTTPOrphans.healthGrace(launchdText: "last exit code = 1"), 12)
        let lines = MCPHTTPOrphans.healthLogLines(victims: [4], port: 18977, launchdText: kickstart)
        XCTAssertEqual(lines.count, 1)
        XCTAssertFalse(lines[0].localizedCaseInsensitiveContains("error"))
        XCTAssertFalse(lines[0].contains("-9"))
    }

    func testWrapperInstallCopiesBundleAndLeavesTheAgentSpecTree() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("wrap-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("bundle/transport-audit", isDirectory: true)
        let bin = source.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try Data("transport-wrappers/2\n".utf8).write(to: source.appendingPathComponent("VERSION"))
        try Data("#!/usr/bin/env python3\nprint('gate')\n".utf8).write(to: source.appendingPathComponent("auto.py"))
        try FileManager.default.createSymbolicLink(atPath: bin.appendingPathComponent("curl").path, withDestinationPath: "../auto.py")
        let home = root.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let old = "# AgentReins\nexport PATH='/Users/me/AgentSpec/AgentGuardApp/tools/transport-audit/bin':$PATH\ncurl() { /Users/me/AgentSpec/AgentGuardApp/tools/transport-audit/bin/curl \"$@\"; }\n"
        let auditDir = home.appendingPathComponent(".agentreins", isDirectory: true)
        try FileManager.default.createDirectory(at: auditDir, withIntermediateDirectories: true)
        try Data(old.utf8).write(to: auditDir.appendingPathComponent("audit.sh"))
        let dest = home.appendingPathComponent("Library/Application Support/AgentReins/transport-audit")
        let first = TransportWrapperInstall.install(bundleRoot: source, destination: dest, home: home)
        XCTAssertTrue(first.copied)
        XCTAssertTrue(first.auditUpdated)
        XCTAssertTrue(first.shellHookAdded)
        let installed = try String(contentsOf: dest.appendingPathComponent("auto.py"))
        XCTAssertTrue(installed.contains("gate"))
        let link = try FileManager.default.destinationOfSymbolicLink(atPath: dest.appendingPathComponent("bin/curl").path)
        XCTAssertEqual(link, "../auto.py")
        let script = try String(contentsOf: auditDir.appendingPathComponent("audit.sh"))
        XCTAssertFalse(script.contains("AgentSpec"))
        XCTAssertTrue(script.contains(dest.appendingPathComponent("bin").path))
        let zsh = try String(contentsOf: home.appendingPathComponent(".zshenv"))
        XCTAssertTrue(zsh.contains("# BEGIN AgentReins transport"))
        let second = TransportWrapperInstall.install(bundleRoot: source, destination: dest, home: home)
        XCTAssertFalse(second.copied)
        XCTAssertFalse(second.auditUpdated)
        XCTAssertFalse(second.shellHookAdded)
    }

    func testPythonChildOfTheAgentShellIsInTheTree() {
        let pids: [Int32] = [10, 11, 12]
        let parents: [Int32: Int32] = [10: 1, 11: 10, 12: 11]
        let paths = [
            10: "/Applications/WorkBuddy.app/Contents/MacOS/codebuddy",
            11: "/bin/zsh",
            12: "/usr/bin/python3",
        ]
        let tree = FileLayerCapture.agentTree(pids: pids, parents: parents, paths: paths)
        XCTAssertEqual(tree[10], "workbuddy")
        XCTAssertTrue(FileLayerCapture.isShell(paths[11]!))
        XCTAssertTrue(FileLayerCapture.isPython(paths[12]!))
        XCTAssertEqual(tree[12], "workbuddy")
        let files = FileLayerCapture.watchFiles(home: "/Users/me", workspaces: [], directoryNames: [
            "/tmp": ["job"],
            "/private/tmp": ["job"],
            "/tmp/job": [".env"],
            "/private/tmp/job": [".env"],
        ])
        XCTAssertTrue(files.contains { $0.hasSuffix("/job/.env") })
    }

    func testAuditScriptWithASpaceParsesAndRetargetIsIdempotent() throws {
        let bin = FileManager.default.temporaryDirectory
            .appendingPathComponent("Library/Application Support/AgentReins/transport-audit/bin-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: bin.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()) }
        try Data("#!/bin/sh\n".utf8).write(to: bin.appendingPathComponent("curl"))
        let script = TransportWrapperInstall.auditScript(binDir: bin.path, home: "/Users/me")
        XCTAssertTrue(script.contains(TransportWrapperInstall.shellQuote(bin.path)))
        XCTAssertFalse(script.contains("export PATH=\(bin.path)"))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID().uuidString).sh")
        try script.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }
        for shell in ["/bin/zsh", "/bin/bash"] {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: shell)
            process.arguments = ["-n", file.path]
            let pipe = Pipe()
            process.standardError = pipe
            try process.run()
            process.waitUntilExit()
            let err = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            XCTAssertEqual(process.terminationStatus, 0, "\(shell) -n failed: \(err)")
        }
        XCTAssertEqual(TransportWrapperInstall.retarget(script, binDir: bin.path), script)
        let broken = "case \":$PATH:\" in\n*:/Users/me/Library/Application Support/old/transport-audit/bin:*) ;;\nesac\n"
        let fixed = TransportWrapperInstall.retarget(broken, binDir: bin.path)
        XCTAssertTrue(fixed.contains(TransportWrapperInstall.shellQuote(bin.path)))
        let brokenFile = FileManager.default.temporaryDirectory.appendingPathComponent("audit-broken-\(UUID().uuidString).sh")
        try fixed.write(to: brokenFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: brokenFile) }
        let zsh = Process()
        zsh.executableURL = URL(fileURLWithPath: "/bin/zsh")
        zsh.arguments = ["-n", brokenFile.path]
        try zsh.run()
        zsh.waitUntilExit()
        XCTAssertEqual(zsh.terminationStatus, 0)
    }

    func testStaleSuggestionsSkipTheLiveDatabase() {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try? Data("live".utf8).write(to: root.appendingPathComponent("evidence.sqlite3"))
        try? Data("search".utf8).write(to: root.appendingPathComponent("evidence.search.sqlite3"))
        try? Data(Data(repeating: 1, count: 32)).write(to: root.appendingPathComponent("evidence.sqlite3.backup"))
        try? Data(Data(repeating: 2, count: 32)).write(to: root.appendingPathComponent("evidence-before-change-batch-reindex-20260920.sqlite3"))
        let items = StaleDataCatalog.suggestions(directory: root, cloudAuditBytes: 0)
        XCTAssertEqual(items.map(\.name), ["evidence-before-change-batch-reindex-20260920.sqlite3", "evidence.sqlite3.backup"])
        XCTAssertNil(StaleDataCatalog.canDelete(id: "evidence.sqlite3", directory: root))
        XCTAssertNil(StaleDataCatalog.canDelete(id: "../evidence.sqlite3", directory: root))
        XCTAssertNotNil(StaleDataCatalog.canDelete(id: "evidence.sqlite3.backup", directory: root))
    }

    func testBoundedProcessKillsAChildThatWouldFillThePipe() {
        let started = Date()
        let output = BoundedProcess.run("/bin/sleep", arguments: ["30"], timeout: 0.4)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        XCTAssertEqual(output, "")
    }
}

final class EvidenceReclaimTests: XCTestCase {
    func testNewDatabaseUsesIncrementalVacuumAndReclaimsACollapsedBlob() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let url = root.appendingPathComponent("evidence.sqlite3")
        let database = try EvidenceDatabase(url: url)
        XCTAssertEqual(try database.autoVacuumMode(), 2)
        // New appends already store a short summary for oversized blobs. This row
        // imitates a blob that was written before that rule.
        var raw: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &raw), SQLITE_OK)
        var insert: OpaquePointer?
        XCTAssertEqual(sqlite3_prepare_v2(raw, "INSERT INTO raw_evidence(evidence_key,source,stream,offset_start,offset_end,observed_at,payload,payload_sha256) VALUES('legacy-blob','transport','blob',0,200000,0,?, 'abc')", -1, &insert, nil), SQLITE_OK)
        let blob = Data(repeating: 7, count: 200_000)
        _ = blob.withUnsafeBytes { sqlite3_bind_blob(insert, 1, $0.baseAddress, Int32(blob.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
        XCTAssertEqual(sqlite3_step(insert), SQLITE_DONE)
        sqlite3_finalize(insert)
        sqlite3_close(raw)
        var policy = EvidenceRetentionPolicy.default
        policy.bulkMaxAge = 1
        let result = try database.prune(policy: policy)
        XCTAssertGreaterThan(result.collapsedRaw, 0)
        XCTAssertEqual(result.autoVacuum, 2)
        XCTAssertGreaterThan(result.reclaimedPages, 0)
    }

    func testSessionLogPayloadIsNotStoredWhole() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let body = Data(String(repeating: "session-line\n", count: 400).utf8)
        let record = RawEvidenceRecord(source: "codex", stream: "/Users/me/.codex/sessions/a.jsonl", offsetStart: 0, offsetEnd: Int64(body.count), fingerprint: nil, observedAt: Date(), payload: body)
        let stored = EvidenceDatabase.storedRawPayload(record)
        XCTAssertNil(stored.range(of: Data("session-line".utf8)))
        XCTAssertTrue(String(data: stored, encoding: .utf8)?.contains("summary") == true)
        try database.appendRaw([record])
        let bytes = try Data(contentsOf: root.appendingPathComponent("evidence.sqlite3"))
        XCTAssertNil(bytes.range(of: Data("session-line".utf8)))
    }

    func testSamplerTickIsBulkAndDropsWhenOverTheBackstop() throws {
        let tick = EvidenceValue.tier(EvidenceValueFields(op: "process_observation", source: "process-observation-libproc", processId: 9, payloadBytes: 80))
        XCTAssertEqual(tick, .bulk)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let database = try EvidenceDatabase(url: root.appendingPathComponent("evidence.sqlite3"))
        let keep = GuardEvent(kind: "file", ruleId: "credential_observe", path: "/tmp/fake.env", command: nil, agent: "cursor", op: "read", severity: "high", ts: Date().addingTimeInterval(-10 * 24 * 3600), action: "observed", source: "libproc-vnode")
        let sample = GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil, agent: "cursor", op: "process_observation", severity: "info", ts: Date().addingTimeInterval(-10 * 24 * 3600), action: "observed", source: "process-observation-libproc", processId: 9)
        try database.append([keep, sample])
        var policy = EvidenceRetentionPolicy.default
        policy.backstopBytes = 1
        _ = try database.prune(policy: policy)
        XCTAssertEqual(try database.recent(limit: 10).map(\.id), [keep.id])
    }
}

final class TransportAuditRetentionTests: XCTestCase {
    func testOldSidecarsGoAndTheSummaryStays() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let run = root.appendingPathComponent("run-1", isDirectory: true)
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let summary = run.appendingPathComponent("transport.json")
        try Data("{\"invocation\":{}}".utf8).write(to: summary)
        let pack = run.appendingPathComponent("git-packfile.pack")
        try Data(repeating: 9, count: 128).write(to: pack)
        let old = Date().addingTimeInterval(-10 * 24 * 3600)
        try FileManager.default.setAttributes([.modificationDate: old], ofItemAtPath: run.path)
        let result = TransportAuditRetention.prune(root: root, now: Date(), maxAge: 3 * 24 * 3600)
        XCTAssertEqual(result.filesRemoved, 1)
        XCTAssertTrue(FileManager.default.fileExists(atPath: summary.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: pack.path))
    }
}
