import Foundation

enum SupervisedWorkspaceKind: String, Codable, Sendable {
    case repository
    case task
    case unassigned
}

struct SupervisedWorkspaceIdentity: Hashable, Sendable {
    let id: String
    let path: String?
    let repositoryRoot: String?
    let kind: SupervisedWorkspaceKind
}

/// Resolves an Agent working directory into the product concept that owns its
/// evidence. A working directory is not automatically a software project.
enum SupervisedWorkspaceResolver {
    /// Resolve a session from repeated workspace observations instead of the
    /// last path in the stream. File events and shell arguments may contain a
    /// target path, but they are not evidence that the project root changed.
    static func resolve(events: [GuardEvent], fileManager: FileManager = .default) -> SupervisedWorkspaceIdentity {
        let candidates = events.compactMap { event -> SupervisedWorkspaceIdentity? in
            let raw = event.path.trimmingCharacters(in: .whitespacesAndNewlines)
            guard plausibleWorkspace(raw, fileManager: fileManager) else { return nil }
            let identity = resolve(raw, fileManager: fileManager)
            return identity.kind == .unassigned ? nil : identity
        }
        guard !candidates.isEmpty else { return resolve(nil, fileManager: fileManager) }
        let grouped = Dictionary(grouping: candidates, by: \.id)
        return grouped.values.compactMap { rows -> (SupervisedWorkspaceIdentity, Int)? in
            guard let first = rows.first else { return nil }
            let repositoryBonus = first.kind == .repository ? 10_000 : 0
            return (first, repositoryBonus + rows.count)
        }.sorted {
            if $0.1 == $1.1 { return $0.0.id.count < $1.0.id.count }
            return $0.1 > $1.1
        }.first?.0 ?? resolve(nil, fileManager: fileManager)
    }

    static func resolve(_ rawWorkspace: String?, fileManager: FileManager = .default) -> SupervisedWorkspaceIdentity {
        guard let raw = rawWorkspace?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty, raw != "-" else {
            return SupervisedWorkspaceIdentity(id: "Unassigned", path: nil,
                                               repositoryRoot: nil, kind: .unassigned)
        }

        var workspace = URL(fileURLWithPath: raw).standardizedFileURL
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: workspace.path, isDirectory: &isDirectory) {
            if !isDirectory.boolValue { workspace.deleteLastPathComponent() }
        } else if !workspace.pathExtension.isEmpty {
            workspace.deleteLastPathComponent()
        }

        if let repositoryRoot = gitRoot(containing: workspace, fileManager: fileManager) {
            return SupervisedWorkspaceIdentity(id: repositoryRoot, path: repositoryRoot,
                                               repositoryRoot: repositoryRoot, kind: .repository)
        }
        return SupervisedWorkspaceIdentity(id: workspace.path, path: workspace.path,
                                           repositoryRoot: nil, kind: .task)
    }

    private static func plausibleWorkspace(_ raw: String, fileManager: FileManager) -> Bool {
        guard raw.hasPrefix("/"), raw.count <= 1_024 else { return false }
        guard !raw.contains("\"") && !raw.contains("{") && !raw.contains("}")
                && !raw.contains(";") && !raw.contains(",") && !raw.contains("\n") else { return false }
        var isDirectory: ObjCBool = false
        if fileManager.fileExists(atPath: raw, isDirectory: &isDirectory) { return true }
        // A non-existent path is accepted only when its nearest existing
        // ancestor is a directory; command fragments do not pass this check.
        var candidate = URL(fileURLWithPath: raw).standardizedFileURL
        for _ in 0..<8 {
            candidate.deleteLastPathComponent()
            guard candidate.path != "/" else { return false }
            if fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory) {
                return isDirectory.boolValue
            }
        }
        return false
    }

    private static func gitRoot(containing workspace: URL,
                                fileManager: FileManager) -> String? {
        var candidate = workspace
        while candidate.path != "/" {
            if fileManager.fileExists(atPath: candidate.appendingPathComponent(".git").path) {
                return candidate.path
            }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path { break }
            candidate = parent
        }
        return nil
    }
}
