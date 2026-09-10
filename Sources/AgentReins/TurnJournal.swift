import Foundation

enum TurnJournalStatus: String, Codable, Sendable {
    case thinking
    case running
    case waiting
    case completed
    case failed
    case cancelled
    case stuck
}

enum EvidenceConfidence: String, Codable, Sendable, Equatable {
    case confirmed
    case inferred
    case unknown
}

struct GitFileState: Codable, Hashable, Sendable {
    let path: String
    let status: String
    let contentFingerprint: String?

    init(path: String, status: String, contentFingerprint: String? = nil) {
        self.path = path
        self.status = status
        self.contentFingerprint = contentFingerprint
    }
}

struct GitSnapshot: Codable, Sendable {
    let capturedAt: Date
    let repositoryRoot: String
    let head: String?
    let porcelainV2: String
    let patch: String
    let stagedPatch: String
    let diffStat: String
    let numStat: String
    let files: [GitFileState]
}

struct FileMutation: Identifiable, Codable, Sendable {
    let id: UUID
    let path: String
    let baselineStatus: String?
    let finalStatus: String?
    let attribution: EvidenceConfidence
    let evidence: String

    init(path: String, baselineStatus: String?, finalStatus: String?,
         attribution: EvidenceConfidence, evidence: String) {
        id = UUID()
        self.path = path
        self.baselineStatus = baselineStatus
        self.finalStatus = finalStatus
        self.attribution = attribution
        self.evidence = evidence
    }
}

struct VerificationRun: Identifiable, Codable, Sendable {
    let id: UUID
    let command: String
    let startedAt: Date
    let duration: TimeInterval
    let exitCode: Int32
    let standardOutput: String
    let standardError: String
    let testsPassed: Int?
    let testsFailed: Int?

    init(command: String, startedAt: Date, duration: TimeInterval, exitCode: Int32,
         standardOutput: String, standardError: String,
         testsPassed: Int? = nil, testsFailed: Int? = nil) {
        id = UUID()
        self.command = command
        self.startedAt = startedAt
        self.duration = duration
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.testsPassed = testsPassed
        self.testsFailed = testsFailed
    }
}

struct AgentTurnJournal: Identifiable, Codable, Sendable {
    let id: String
    let sessionId: String
    let turnId: String
    let agent: String
    var workspace: String?
    let startedAt: Date
    var completedAt: Date?
    var status: TurnJournalStatus
    var captureComplete: Bool
    /// True only when the snapshot was captured from a prompt before any observed tool activity.
    /// Nil represents journals written by older AgentReins versions.
    var baselinePrecedesMutation: Bool?
    var baseline: GitSnapshot?
    var finalSnapshot: GitSnapshot?
    var mutations: [FileMutation]
    var verificationRuns: [VerificationRun]
    var toolCallIds: [String]

    var hasPreExistingChanges: Bool {
        guard let baseline else { return false }
        return !baseline.files.isEmpty
    }

    var canRecoverSafely: Bool {
        guard let baseline, let finalSnapshot else { return false }
        return baseline.files.isEmpty && baseline.head == finalSnapshot.head && !mutations.isEmpty
    }
}

enum VerificationState: Equatable {
    case idle
    case running
    case finished(Int32)
}

enum GitRepositoryInspector {
    static func capture(workspace: String, at date: Date = Date()) -> GitSnapshot? {
        guard let root = gitOutput(["-C", workspace, "rev-parse", "--show-toplevel"])?.trimmed,
              !root.isEmpty else { return nil }

        let head = gitOutput(["-C", root, "rev-parse", "HEAD"])?.trimmed.nilIfEmpty
        let porcelainV2 = gitOutput(["-C", root, "status", "--porcelain=v2", "--untracked-files=all"]) ?? ""
        let patch = gitOutput(["-C", root, "diff", "--no-ext-diff", "--binary"]) ?? ""
        let stagedPatch = gitOutput(["-C", root, "diff", "--cached", "--no-ext-diff", "--binary"]) ?? ""
        let diffStat = gitOutput(["-C", root, "diff", "--stat", "HEAD"]) ?? ""
        let numStat = gitOutput(["-C", root, "diff", "--numstat", "HEAD"]) ?? ""
        let rawFiles = gitData(["-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all"]) ?? Data()
        let files = parsePorcelainV1(rawFiles).map { state in
            GitFileState(path: state.path, status: state.status,
                         contentFingerprint: fingerprint(root: root, path: state.path))
        }

        return GitSnapshot(capturedAt: date, repositoryRoot: root, head: head,
                           porcelainV2: porcelainV2, patch: patch, stagedPatch: stagedPatch,
                           diffStat: diffStat, numStat: numStat,
                           files: files)
    }

    static func mutations(between baseline: GitSnapshot?, and final: GitSnapshot?,
                          baselinePrecedesMutation: Bool? = nil) -> [FileMutation] {
        guard let final else { return [] }
        let before = Dictionary(uniqueKeysWithValues: (baseline?.files ?? []).map { ($0.path, $0) })
        let after = Dictionary(uniqueKeysWithValues: final.files.map { ($0.path, $0) })
        return Set(before.keys).union(after.keys).sorted().compactMap { path in
            let old = before[path]
            let new = after[path]
            guard old != new else { return nil }
            let confidence: EvidenceConfidence = baseline != nil && baselinePrecedesMutation == true ? .inferred : .unknown
            let evidence: String
            if baseline == nil {
                evidence = "No pre-turn Git baseline was captured."
            } else if baselinePrecedesMutation != true {
                evidence = "A Git baseline exists, but AgentReins cannot prove it preceded the first mutation."
            } else {
                evidence = "The file content or Git state changed after the prompt baseline; attribution is temporal, not hook-confirmed."
            }
            return FileMutation(path: path, baselineStatus: old?.status, finalStatus: new?.status,
                                attribution: confidence, evidence: evidence)
        }
    }

    private static func fingerprint(root: String, path: String) -> String? {
        let rootURL = URL(fileURLWithPath: root).standardizedFileURL
        let fileURL = rootURL.appendingPathComponent(path).standardizedFileURL
        guard fileURL.path.hasPrefix(rootURL.path + "/"),
              let handle = try? FileHandle(forReadingFrom: fileURL) else { return nil }
        defer { try? handle.close() }
        var hash: UInt64 = 14_695_981_039_346_656_037
        while let data = try? handle.read(upToCount: 64 * 1024), !data.isEmpty {
            for byte in data {
                hash ^= UInt64(byte)
                hash = hash &* 1_099_511_628_211
            }
        }
        return String(format: "%016llx", hash)
    }

    static func parsePorcelainV1(_ data: Data) -> [GitFileState] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        let records = text.split(separator: "\0", omittingEmptySubsequences: true).map(String.init)
        var result: [GitFileState] = []
        var index = 0
        while index < records.count {
            let record = records[index]
            guard record.count >= 4 else { index += 1; continue }
            let status = String(record.prefix(2))
            let path = String(record.dropFirst(3))
            result.append(GitFileState(path: path, status: status))
            if status.contains("R") || status.contains("C") { index += 1 }
            index += 1
        }
        return result.sorted { $0.path < $1.path }
    }

    private static func gitOutput(_ arguments: [String]) -> String? {
        guard let data = gitData(arguments) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func gitData(_ arguments: [String]) -> Data? {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            return output.fileHandleForReading.readDataToEndOfFile()
        } catch {
            return nil
        }
    }
}

enum ProjectVerifier {
    struct Command: Sendable {
        let executable: String
        let arguments: [String]
        let displayName: String
    }

    static func commands(for workspace: String) -> [Command] {
        let root = URL(fileURLWithPath: workspace)
        let fm = FileManager.default
        if fm.fileExists(atPath: root.appendingPathComponent("Package.swift").path) {
            var commands = [Command(executable: "/usr/bin/swift", arguments: ["build"], displayName: "swift build")]
            if fm.fileExists(atPath: root.appendingPathComponent("Tests").path) {
                commands.append(Command(executable: "/usr/bin/swift", arguments: ["test"], displayName: "swift test"))
            }
            return commands
        }
        if fm.fileExists(atPath: root.appendingPathComponent("package.json").path) {
            let manager: String
            if fm.fileExists(atPath: root.appendingPathComponent("pnpm-lock.yaml").path) { manager = "pnpm" }
            else if fm.fileExists(atPath: root.appendingPathComponent("yarn.lock").path) { manager = "yarn" }
            else { manager = "npm" }
            let packageURL = root.appendingPathComponent("package.json")
            let scripts = (try? Data(contentsOf: packageURL))
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["scripts"] as? [String: Any] ?? [:]
            return ["build", "test"].compactMap { script in
                guard scripts[script] != nil else { return nil }
                return Command(executable: "/usr/bin/env", arguments: [manager, "run", script],
                               displayName: "\(manager) run \(script)")
            }
        }
        if fm.fileExists(atPath: root.appendingPathComponent("pyproject.toml").path) ||
            fm.fileExists(atPath: root.appendingPathComponent("pytest.ini").path) {
            return [Command(executable: "/usr/bin/python3", arguments: ["-m", "pytest"], displayName: "python3 -m pytest")]
        }
        if fm.fileExists(atPath: root.appendingPathComponent("go.mod").path) {
            return [Command(executable: "/usr/bin/env", arguments: ["go", "test", "./..."], displayName: "go test ./...")]
        }
        if fm.fileExists(atPath: root.appendingPathComponent("Cargo.toml").path) {
            return [Command(executable: "/usr/bin/env", arguments: ["cargo", "test"], displayName: "cargo test")]
        }
        return []
    }

    static func run(_ command: Command, workspace: String, timeout: TimeInterval = 300) -> VerificationRun {
        let startedAt = Date()
        let process = Process()
        let outputURL = FileManager.default.temporaryDirectory.appendingPathComponent("agentreins-verify-\(UUID().uuidString).out")
        let errorURL = FileManager.default.temporaryDirectory.appendingPathComponent("agentreins-verify-\(UUID().uuidString).err")
        FileManager.default.createFile(atPath: outputURL.path, contents: nil)
        FileManager.default.createFile(atPath: errorURL.path, contents: nil)
        guard let output = try? FileHandle(forWritingTo: outputURL),
              let error = try? FileHandle(forWritingTo: errorURL) else {
            return VerificationRun(command: command.displayName, startedAt: startedAt, duration: 0,
                                   exitCode: -1, standardOutput: "", standardError: "Unable to create verification logs.")
        }
        defer {
            try? output.close()
            try? error.close()
            try? FileManager.default.removeItem(at: outputURL)
            try? FileManager.default.removeItem(at: errorURL)
        }
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        process.currentDirectoryURL = URL(fileURLWithPath: workspace)
        process.standardOutput = output
        process.standardError = error
        do {
            try process.run()
        } catch {
            return VerificationRun(command: command.displayName, startedAt: startedAt,
                                   duration: Date().timeIntervalSince(startedAt), exitCode: -1,
                                   standardOutput: "", standardError: error.localizedDescription)
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        try? output.synchronize()
        try? error.synchronize()
        let stdout = (try? String(contentsOf: outputURL, encoding: .utf8)) ?? ""
        var stderr = (try? String(contentsOf: errorURL, encoding: .utf8)) ?? ""
        if Date() >= deadline { stderr += "\nVerification timed out after \(Int(timeout)) seconds." }
        return VerificationRun(command: command.displayName, startedAt: startedAt,
                               duration: Date().timeIntervalSince(startedAt),
                               exitCode: process.terminationStatus,
                               standardOutput: String(stdout.suffix(64_000)),
                               standardError: String(stderr.suffix(64_000)))
    }
}

enum GitRecovery {
    struct Result: Sendable {
        let success: Bool
        let message: String
    }

    static func restoreCleanBaseline(workspace: String, head: String, untrackedPaths: [String]) -> Result {
        guard let root = GitRepositoryInspector.capture(workspace: workspace)?.repositoryRoot else {
            return Result(success: false, message: "Recovery failed because the Git repository is unavailable.")
        }
        let reset = runGit(["-C", root, "reset", "--hard", head])
        guard reset == 0 else {
            return Result(success: false, message: "Git could not restore the tracked files.")
        }
        let rootURL = URL(fileURLWithPath: root).standardizedFileURL
        for path in untrackedPaths {
            let candidate = rootURL.appendingPathComponent(path).standardizedFileURL
            guard candidate.path.hasPrefix(rootURL.path + "/") else {
                return Result(success: false, message: "Recovery stopped because a path escaped the repository.")
            }
            try? FileManager.default.removeItem(at: candidate)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return Result(success: false, message: "Recovery could not remove \(path).")
            }
        }
        return Result(success: true, message: "The clean Git baseline was restored and verified.")
    }

    private static func runGit(_ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus }
        catch { return -1 }
    }
}

@MainActor
final class TurnJournalStore: ObservableObject {
    @Published private(set) var journals: [AgentTurnJournal] = []
    @Published private(set) var verificationStates: [String: VerificationState] = [:]
    @Published private(set) var recoveryMessages: [String: String] = [:]

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private var scheduledSave: Task<Void, Never>?

    init(fileURL: URL = TurnJournalStore.defaultURL()) {
        self.fileURL = fileURL
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        load()
        recoverInterruptedJournals()
    }

    func ingest(_ incoming: [GuardEvent]) {
        let ordered = incoming.sorted { $0.ts < $1.ts }
        for event in ordered {
            guard let sessionId = event.sessionId, let turnId = event.turnId else { continue }
            let id = Self.journalId(sessionId: sessionId, turnId: turnId)
            if let index = journals.firstIndex(where: { $0.id == id }) {
                update(event, at: index)
            } else {
                create(event, id: id, sessionId: sessionId, turnId: turnId)
            }
        }
        scheduleSave()
    }

    func runVerification(journalId: String) {
        guard verificationStates[journalId] != .running,
              let journal = journals.first(where: { $0.id == journalId }),
              let workspace = journal.workspace else { return }
        let commands = ProjectVerifier.commands(for: workspace)
        guard !commands.isEmpty else {
            recoveryMessages[journalId] = "No supported verification command was detected."
            return
        }
        verificationStates[journalId] = .running
        Task {
            let runs = await Task.detached {
                var completed: [VerificationRun] = []
                for command in commands {
                    let run = ProjectVerifier.run(command, workspace: workspace)
                    completed.append(run)
                    if run.exitCode != 0 { break }
                }
                return completed
            }.value
            guard let index = journals.firstIndex(where: { $0.id == journalId }) else { return }
            journals[index].verificationRuns.append(contentsOf: runs)
            verificationStates[journalId] = .finished(runs.last?.exitCode ?? -1)
            save()
        }
    }

    func recoverCleanBaseline(journalId: String) {
        guard let index = journals.firstIndex(where: { $0.id == journalId }),
              journals[index].canRecoverSafely,
              let workspace = journals[index].workspace,
              let head = journals[index].baseline?.head,
              let recordedFinal = journals[index].finalSnapshot else {
            recoveryMessages[journalId] = "Recovery was blocked because the baseline was not clean or HEAD changed."
            return
        }
        let untracked = journals[index].finalSnapshot?.files
            .filter { $0.status == "??" }.map(\.path) ?? []
        Task {
            let current = await Task.detached { GitRepositoryInspector.capture(workspace: workspace) }.value
            guard let current,
                  current.head == recordedFinal.head,
                  current.porcelainV2 == recordedFinal.porcelainV2 else {
                recoveryMessages[journalId] = "Recovery was blocked because the workspace changed after the recorded turn."
                return
            }
            let outcome = await Task.detached {
                let result = GitRecovery.restoreCleanBaseline(workspace: workspace, head: head, untrackedPaths: untracked)
                let snapshot = result.success ? GitRepositoryInspector.capture(workspace: workspace) : nil
                return (result, snapshot)
            }.value
            guard let current = journals.firstIndex(where: { $0.id == journalId }) else { return }
            recoveryMessages[journalId] = outcome.0.message
            if let snapshot = outcome.1 {
                journals[current].finalSnapshot = snapshot
                journals[current].mutations = GitRepositoryInspector.mutations(
                    between: journals[current].baseline, and: snapshot,
                    baselinePrecedesMutation: journals[current].baselinePrecedesMutation)
            }
            save()
        }
    }

    private func create(_ event: GuardEvent, id: String, sessionId: String, turnId: String) {
        let workspace = normalizedWorkspace(event.path)
        let isPrompt = event.kind == "model" && event.op == "prompt"
        let baseline = workspace.flatMap { GitRepositoryInspector.capture(workspace: $0, at: event.ts) }
        let journal = AgentTurnJournal(
            id: id, sessionId: sessionId, turnId: turnId,
            agent: event.agent ?? "Agent", workspace: workspace,
            startedAt: event.ts, completedAt: nil,
            status: status(for: event), captureComplete: isPrompt,
            baselinePrecedesMutation: isPrompt && baseline != nil,
            baseline: baseline, finalSnapshot: nil, mutations: [], verificationRuns: [],
            toolCallIds: event.toolCallId.map { [$0] } ?? [])
        journals.append(journal)
        journals.sort { $0.startedAt > $1.startedAt }
        if isTerminal(event), let index = journals.firstIndex(where: { $0.id == id }) {
            finish(&journals[index], with: event)
        }
    }

    private func update(_ event: GuardEvent, at index: Int) {
        if journals[index].workspace == nil, let workspace = normalizedWorkspace(event.path) {
            journals[index].workspace = workspace
            journals[index].baseline = GitRepositoryInspector.capture(workspace: workspace, at: event.ts)
            journals[index].baselinePrecedesMutation = event.kind == "model" && event.op == "prompt" && journals[index].baseline != nil
        }
        if event.kind == "model" && event.op == "prompt" {
            journals[index].captureComplete = true
        }
        if let callId = event.toolCallId, !journals[index].toolCallIds.contains(callId) {
            journals[index].toolCallIds.append(callId)
        }
        journals[index].status = status(for: event)
        if isTerminal(event) { finish(&journals[index], with: event) }
    }

    private func finish(_ journal: inout AgentTurnJournal, with event: GuardEvent) {
        journal.completedAt = event.ts
        journal.status = status(for: event)
        if let workspace = journal.workspace {
            captureSnapshot(journalId: journal.id, workspace: workspace, baseline: false)
        }
    }

    private func captureSnapshot(journalId: String, workspace: String, baseline: Bool) {
        Task {
            let snapshot = await Task.detached { GitRepositoryInspector.capture(workspace: workspace) }.value
            guard let index = journals.firstIndex(where: { $0.id == journalId }) else { return }
            if baseline, journals[index].baseline == nil { journals[index].baseline = snapshot }
            if !baseline { journals[index].finalSnapshot = snapshot }
            journals[index].mutations = GitRepositoryInspector.mutations(
                between: journals[index].baseline, and: journals[index].finalSnapshot,
                baselinePrecedesMutation: journals[index].baselinePrecedesMutation)
            save()
        }
    }

    private func status(for event: GuardEvent) -> TurnJournalStatus {
        let value = event.action.lowercased()
        if ["failed", "error"].contains(value) { return .failed }
        if value == "cancelled" { return .cancelled }
        if isTerminal(event) { return .completed }
        if event.kind == "tool" { return event.op == "result" ? .thinking : .running }
        return .thinking
    }

    private func isTerminal(_ event: GuardEvent) -> Bool {
        (event.kind == "model" && event.op == "response" &&
            (event.source != "agentsight:codex-local-compat" || event.action == "final_answer")) ||
        ["failed", "error", "cancelled"].contains(event.action.lowercased())
    }

    private func normalizedWorkspace(_ path: String) -> String? {
        guard path != "-", FileManager.default.fileExists(atPath: path) else { return nil }
        return path
    }

    private func recoverInterruptedJournals() {
        var changed = false
        for index in journals.indices where journals[index].completedAt == nil {
            journals[index].status = .stuck
            changed = true
        }
        if changed { save() }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let saved = try? decoder.decode([AgentTurnJournal].self, from: data) else { return }
        journals = saved.sorted { $0.startedAt > $1.startedAt }
    }

    private func save() {
        scheduledSave?.cancel()
        scheduledSave = nil
        if journals.count > 1_000 { journals.removeLast(journals.count - 1_000) }
        guard let data = try? encoder.encode(journals) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    /// Live adapters may deliver several enrichment batches for the same turn.
    /// Coalesce persistence so JSON encoding cannot monopolize the main actor.
    private func scheduleSave() {
        scheduledSave?.cancel()
        scheduledSave = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(1))
            guard !Task.isCancelled else { return }
            self?.save()
        }
    }

    nonisolated static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let directory = base.appendingPathComponent("AgentGuard", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("turn-journals.json")
    }

    nonisolated static func journalId(sessionId: String, turnId: String) -> String {
        "\(sessionId):\(turnId)"
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
