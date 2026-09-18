import CryptoKit
import Foundation

struct GitCommitFileEvidence: Codable, Sendable {
    let path: String
    let contentDigest: String?
}

struct GitCommitObservation: Codable, Identifiable, Sendable {
    var id: String { commitHash }
    let commitHash: String
    let authoredAt: Date
    let branchDescription: String?
    let files: [GitCommitFileEvidence]
}

enum SessionCommitAttributor {
    /// Content equality is confirmed attribution. A path observed through an
    /// actual tool call inside a bounded pre-commit window is only inferred.
    /// Timestamp proximity alone never creates a relationship.
    static func attribute(events: [AgentEventEnvelope],
                          commits: [GitCommitObservation],
                          inferredWindow: TimeInterval = 3_600) -> [AgentCheckpointEvidence] {
        let writes = events.compactMap { event -> (AgentEventEnvelope, FileActivityEvidence)? in
            guard case let .fileActivity(file) = event.payload,
                  [.create, .modify, .rename].contains(file.operation) else { return nil }
            return (event, file)
        }
        return commits.compactMap { commit in
            var confirmedPaths = Set<String>()
            var inferredPaths = Set<String>()
            var evidenceIDs = Set<String>()
            for file in commit.files {
                for (event, write) in writes where pathsMatch(write.path, file.path) {
                    if let after = write.afterDigest, let committed = file.contentDigest, after == committed {
                        confirmedPaths.insert(file.path)
                        evidenceIDs.insert(event.id)
                        continue
                    }
                    let age = commit.authoredAt.timeIntervalSince(event.occurredAt)
                    if write.toolCallID != nil, age >= 0, age <= inferredWindow,
                       event.confidence != .unknown {
                        inferredPaths.insert(file.path)
                        evidenceIDs.insert(event.id)
                    }
                }
            }
            guard !confirmedPaths.isEmpty || !inferredPaths.isEmpty else { return nil }
            let confidence: AlignmentConfidence = confirmedPaths.isEmpty ? .inferred : .confirmed
            return AgentCheckpointEvidence(
                commitHash: commit.commitHash, branch: commit.branchDescription,
                touchedPaths: Array(confirmedPaths.union(inferredPaths)).sorted(),
                survivingPaths: Array(confirmedPaths).sorted(), attribution: confidence,
                evidenceIDs: Array(evidenceIDs).sorted())
        }
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func normalized(_ path: String) -> String {
        path.replacingOccurrences(of: "\\", with: "/").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    /// Agent adapters often report absolute paths while Git reports paths
    /// relative to the repository root. Requiring an exact component suffix
    /// preserves that relationship without reducing it to an unsafe basename
    /// comparison.
    private static func pathsMatch(_ observed: String, _ committed: String) -> Bool {
        let lhs = normalized(observed)
        let rhs = normalized(committed)
        return lhs == rhs || lhs.hasSuffix("/\(rhs)") || rhs.hasSuffix("/\(lhs)")
    }
}

enum GitCheckpointIntegration {
    static func shouldInspect(_ evidence: [GuardEvent]) -> Bool {
        evidence.contains { event in
            let value = "\(event.command ?? "") \(event.toolName ?? "") \(event.modelDecision ?? "")"
                .lowercased()
            return value.range(of: #"\bgit\b[^\n;&|]*\bcommit\b"#,
                               options: .regularExpression) != nil
        }
    }

    static func checkpointEvents(projectID: String,
                                 agentID: String,
                                 sessionID: String,
                                 turnID: String?,
                                 events: [AgentEventEnvelope],
                                 commits: [GitCommitObservation],
                                 existingCommitHashes: Set<String>,
                                 startingSequence: UInt64,
                                 observedAt: Date = Date()) -> [AgentEventEnvelope] {
        let checkpoints = SessionCommitAttributor.attribute(events: events, commits: commits)
            .filter { !existingCommitHashes.contains($0.commitHash) }
        return checkpoints.enumerated().map { offset, checkpoint in
            AgentEventEnvelope(
                id: "git-checkpoint:\(sessionID):\(checkpoint.commitHash)",
                projectID: projectID, agentID: agentID, sessionID: sessionID,
                turnID: turnID, sequence: startingSequence + UInt64(offset),
                occurredAt: commits.first(where: { $0.commitHash == checkpoint.commitHash })?.authoredAt ?? observedAt,
                observedAt: observedAt, source: .git,
                confidence: checkpoint.attribution, payload: .checkpoint(checkpoint))
        }
    }
}

/// On-demand Git reader. It intentionally does not run on the live ingestion
/// path; callers schedule it after a ref change or when the user opens history.
enum GitCommitInspector {
    static func recent(repositoryRoot: String, limit: Int = 20) -> [GitCommitObservation] {
        guard let raw = run(["-C", repositoryRoot, "log", "-n", String(max(1, min(limit, 100))),
                             "--format=%H%x1f%ct%x1f%D%x1e"]) else { return [] }
        return raw.split(separator: "\u{1e}").compactMap { record in
            let fields = record.split(separator: "\u{1f}", omittingEmptySubsequences: false)
            guard fields.count >= 2, let epoch = TimeInterval(fields[1].trimmingCharacters(in: .whitespacesAndNewlines)) else {
                return nil
            }
            let hash = fields[0].trimmingCharacters(in: .whitespacesAndNewlines)
            let branchText = fields.count > 2 ? fields[2].trimmingCharacters(in: .whitespacesAndNewlines) : ""
            let branch = branchText.isEmpty ? nil : branchText
            let names = runData(["-C", repositoryRoot, "diff-tree", "--root", "--no-commit-id",
                                 "--name-only", "-r", "-z", hash])
                .flatMap { String(data: $0, encoding: .utf8) }?
                .split(separator: "\0").map(String.init) ?? []
            let files = names.prefix(300).map { path -> GitCommitFileEvidence in
                let content = runData(["-C", repositoryRoot, "show", "\(hash):\(path)"])
                return GitCommitFileEvidence(path: path,
                                             contentDigest: content.map(SessionCommitAttributor.digest))
            }
            return GitCommitObservation(commitHash: hash, authoredAt: Date(timeIntervalSince1970: epoch),
                                        branchDescription: branch, files: files)
        }
    }

    private static func run(_ arguments: [String]) -> String? {
        runData(arguments).flatMap { String(data: $0, encoding: .utf8) }
    }

    private static func runData(_ arguments: [String], timeout: TimeInterval = 5) -> Data? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = Pipe()
        do {
            try process.run()
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
            if process.isRunning { process.terminate(); process.waitUntilExit(); return nil }
            guard process.terminationStatus == 0 else { return nil }
            return output.fileHandleForReading.readDataToEndOfFile()
        } catch { return nil }
    }
}
