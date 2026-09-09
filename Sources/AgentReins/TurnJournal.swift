import Foundation

enum TurnJournalStatus: String, Codable {
    case thinking
    case running
    case waiting
    case completed
    case failed
    case cancelled
    case stuck
}

enum EvidenceConfidence: String, Codable {
    case confirmed
    case inferred
    case unknown
}

struct GitFileState: Codable, Hashable {
    let path: String
    let status: String
}

struct GitSnapshot: Codable {
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

struct FileMutation: Identifiable, Codable {
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

struct VerificationRun: Identifiable, Codable {
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

struct AgentTurnJournal: Identifiable, Codable {
    let id: String
    let sessionId: String
    let turnId: String
    let agent: String
    var workspace: String?
    let startedAt: Date
    var completedAt: Date?
    var status: TurnJournalStatus
    var captureComplete: Bool
    var baseline: GitSnapshot?
    var finalSnapshot: GitSnapshot?
    var mutations: [FileMutation]
    var verificationRuns: [VerificationRun]
    var toolCallIds: [String]

    var hasPreExistingChanges: Bool {
        guard let baseline else { return false }
        return !baseline.files.isEmpty
    }
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

        return GitSnapshot(capturedAt: date, repositoryRoot: root, head: head,
                           porcelainV2: porcelainV2, patch: patch, stagedPatch: stagedPatch,
                           diffStat: diffStat, numStat: numStat,
                           files: parsePorcelainV1(rawFiles))
    }

    static func mutations(between baseline: GitSnapshot?, and final: GitSnapshot?) -> [FileMutation] {
        guard let final else { return [] }
        let before = Dictionary(uniqueKeysWithValues: (baseline?.files ?? []).map { ($0.path, $0.status) })
        let after = Dictionary(uniqueKeysWithValues: final.files.map { ($0.path, $0.status) })
        return Set(before.keys).union(after.keys).sorted().compactMap { path in
            let old = before[path]
            let new = after[path]
            guard old != new else { return nil }
            let confidence: EvidenceConfidence = baseline == nil ? .unknown : .inferred
            let evidence = baseline == nil
                ? "No pre-turn Git baseline was captured."
                : "The Git working-tree state changed between the turn snapshots."
            return FileMutation(path: path, baselineStatus: old, finalStatus: new,
                                attribution: confidence, evidence: evidence)
        }
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

@MainActor
final class TurnJournalStore: ObservableObject {
    @Published private(set) var journals: [AgentTurnJournal] = []

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

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
        save()
    }

    private func create(_ event: GuardEvent, id: String, sessionId: String, turnId: String) {
        let workspace = normalizedWorkspace(event.path)
        let isPrompt = event.kind == "model" && event.op == "prompt"
        let baseline = workspace.flatMap { GitRepositoryInspector.capture(workspace: $0, at: event.ts) }
        var journal = AgentTurnJournal(
            id: id, sessionId: sessionId, turnId: turnId,
            agent: event.agent ?? "Agent", workspace: workspace,
            startedAt: event.ts, completedAt: nil,
            status: status(for: event), captureComplete: isPrompt,
            baseline: baseline, finalSnapshot: nil, mutations: [], verificationRuns: [],
            toolCallIds: event.toolCallId.map { [$0] } ?? [])
        if isTerminal(event) { finish(&journal, with: event) }
        journals.append(journal)
        journals.sort { $0.startedAt > $1.startedAt }
    }

    private func update(_ event: GuardEvent, at index: Int) {
        if journals[index].workspace == nil, let workspace = normalizedWorkspace(event.path) {
            journals[index].workspace = workspace
            journals[index].baseline = GitRepositoryInspector.capture(workspace: workspace, at: event.ts)
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
        journal.finalSnapshot = journal.workspace.flatMap { GitRepositoryInspector.capture(workspace: $0, at: event.ts) }
        journal.mutations = GitRepositoryInspector.mutations(between: journal.baseline, and: journal.finalSnapshot)
    }

    private func status(for event: GuardEvent) -> TurnJournalStatus {
        let value = event.action.lowercased()
        if ["failed", "error"].contains(value) { return .failed }
        if value == "cancelled" { return .cancelled }
        if event.kind == "model" && event.op == "response" { return .completed }
        if event.kind == "tool" { return event.op == "result" ? .thinking : .running }
        return .thinking
    }

    private func isTerminal(_ event: GuardEvent) -> Bool {
        (event.kind == "model" && event.op == "response") ||
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
        if journals.count > 1_000 { journals.removeLast(journals.count - 1_000) }
        guard let data = try? encoder.encode(journals) else { return }
        try? data.write(to: fileURL, options: .atomic)
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
