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
