import Foundation

/// Which open files become file evidence. Observation does not read rules.json
/// and does not restore or block anything. Enforcement stays in the policy store.
public enum FileLayerCapture {
    /// What actually sees a read: an in-process libproc vnode sample of the agent
    /// process tree (`proc_listpids` + `proc_pidfdinfo` / `PROC_PIDFDVNODEPATHINFO`).
    /// Not Endpoint Security, not `fs_usage`, and not a wrapper around cat/open.
    public static let mechanism = "libproc vnode sample on the agent process tree (proc_pidinfo / proc_pidfdinfo). Not Endpoint Security, not fs_usage, not a command wrapper."

    /// libproc only sees descriptors still open. A second kqueue watch on a
    /// bounded credential set uses access-time (NOTE_ATTRIB). APFS may skip
    /// or coalesce atime, so a kqueue hit without an open descriptor is only
    /// "possible (sampled)". This is not a full-disk watch and not Endpoint Security.
    public static let limits = "libproc sees only descriptors still open, so a short read between samples can be missed. A kqueue NOTE_ATTRIB watch on known credential paths and .env* under the agent working directory, /tmp, and /private/tmp records an access-time move. If the agent still has the file open, the read is confirmed. If not, it is possible (sampled): APFS often does not update atime on every read. File bytes are not copied."

    public static let watchCap = 256

    public struct AccessStamp: Equatable, Sendable {
        public var access: TimeInterval
        public var modified: TimeInterval
        public init(access: TimeInterval, modified: TimeInterval) {
            self.access = access
            self.modified = modified
        }
    }

    /// Access time moved, and the move is not the same moment as a content write.
    public static func isAccessRead(previous: AccessStamp, current: AccessStamp) -> Bool {
        guard current.access > previous.access + 0.000_001 else { return false }
        let wrote = current.modified > previous.modified + 0.000_001
        if wrote && abs(current.access - current.modified) < 1 { return false }
        return true
    }

    /// `confirmed` when a tracked agent still holds the descriptor. Otherwise the
    /// access-time signal is only `possible` (sampled).
    public static func readGrade(descriptorStillOpen: Bool) -> String {
        descriptorStillOpen ? "confirmed" : "possible"
    }

    public struct OpenFile: Equatable, Sendable {
        public var path: String
        public var writable: Bool
        public init(path: String, writable: Bool) {
            self.path = path
            self.writable = writable
        }
    }

    public struct Hit: Equatable, Sendable {
        public var path: String
        public var op: String
        public var credential: Bool
        public init(path: String, op: String, credential: Bool) {
            self.path = path
            self.op = op
            self.credential = credential
        }
    }

    public static func isCredentialPath(_ path: String) -> Bool {
        let value = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return false }
        if value.range(of: #"(?i)(\.ssh/|/\.aws/|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json|\.pem\b|secrets?\.|keychains?/|\.keychain(?:-db)?)"#, options: .regularExpression) != nil {
            return true
        }
        let name = (value as NSString).lastPathComponent
        return name.range(of: #"(?i)(?:^|[^A-Za-z])tokens?(?:[^A-Za-z]|$)|(?:^|[-_.])token(?:[-_.]|$)"#, options: .regularExpression) != nil
    }

    /// Editor caches, our own store, and device nodes are not agent file evidence.
    public static func isNoisePath(_ path: String) -> Bool {
        if path.isEmpty || path == "-" || path == "/dev/null" { return true }
        if path.hasPrefix("/dev/") || path.hasPrefix("/System/") { return true }
        let lower = path.lowercased()
        if lower.contains("/library/caches/") { return true }
        if lower.contains("/application support/agentguard/") { return true }
        if lower.contains("/application support/agentreins/") { return true }
        if lower.contains("/.git/") { return true }
        if lower.hasSuffix(".sock") { return true }
        if lower.contains("/private/var/folders/") { return true }
        return false
    }

    public static func isOutside(_ path: String, workspace: String) -> Bool {
        let root = URL(fileURLWithPath: workspace).standardizedFileURL.path
        let target = URL(fileURLWithPath: path).standardizedFileURL.path
        guard root != "/" else { return false }
        return target != root && !target.hasPrefix(root + "/")
    }

    /// Credential paths are recorded in any directory, including `/tmp`.
    /// Writable files are recorded when they sit outside `workspace`.
    /// With no workspace, only `/tmp` and `/private/tmp` writes are recorded,
    /// so an editor's own project buffers are not listed as unclaimed changes.
    public static func hits(opens: [OpenFile], workspace: String?) -> [Hit] {
        var seen = Set<String>()
        var out: [Hit] = []
        for file in opens {
            guard !isNoisePath(file.path) else { continue }
            let credential = isCredentialPath(file.path)
            let op: String
            if credential {
                op = file.writable ? "modify" : "read"
            } else if file.writable {
                let outside: Bool
                if let workspace, workspace.hasPrefix("/") {
                    outside = isOutside(file.path, workspace: workspace)
                } else {
                    outside = file.path.hasPrefix("/tmp/") || file.path.hasPrefix("/private/tmp/")
                }
                guard outside else { continue }
                op = "modify"
            } else {
                continue
            }
            let key = "\(op)|\(file.path)"
            guard seen.insert(key).inserted else { continue }
            out.append(Hit(path: file.path, op: op, credential: credential))
        }
        return out
    }

    /// Concrete files polled even when rules.json has no protect rules.
    /// This does not see a one-off `/tmp/.env` the agent opened and closed;
    /// that depends on the vnode sample.
    public static func builtinCredentialFiles(home: String) -> [String] {
        let root = (home as NSString).expandingTildeInPath
        let names = [
            ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config", ".ssh/known_hosts",
            ".aws/credentials", ".aws/config",
            ".config/gcloud/application_default_credentials.json",
            ".config/gcloud/credentials.db",
            ".netrc", ".npmrc", ".pypirc",
            ".config/gh/hosts.yml",
            "Library/Keychains/login.keychain-db",
        ]
        return names.map { (root as NSString).appendingPathComponent($0) }
    }

    public static func isDotEnvName(_ name: String) -> Bool {
        let base = (name as NSString).lastPathComponent
        if base == ".env" || base.hasPrefix(".env.") { return true }
        return base.range(of: #"(?i)\.env(?:\.|$)"#, options: .regularExpression) != nil
    }

    /// Bounded credential set. `directoryNames` is a one-level listing the caller
    /// already made. No full-disk walk happens here.
    public static func watchFiles(home: String, workspaces: [String], directoryNames: [String: [String]]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        func add(_ path: String) {
            guard out.count < watchCap else { return }
            let cleaned = (path as NSString).standardizingPath
            guard !cleaned.isEmpty, seen.insert(cleaned).inserted else { return }
            out.append(cleaned)
        }
        for path in builtinCredentialFiles(home: home) { add(path) }
        let root = (home as NSString).expandingTildeInPath
        let credentialDirs = [
            (root as NSString).appendingPathComponent(".ssh"),
            (root as NSString).appendingPathComponent(".aws"),
            (root as NSString).appendingPathComponent(".config/gcloud"),
            (root as NSString).appendingPathComponent("Library/Keychains"),
        ]
        for dir in credentialDirs {
            for name in directoryNames[dir] ?? [] {
                let base = (name as NSString).lastPathComponent
                guard base != ".", base != "..", !base.isEmpty else { continue }
                add((dir as NSString).appendingPathComponent(base))
            }
        }
        var envDirs = workspaces
        envDirs.append("/tmp")
        envDirs.append("/private/tmp")
        for dir in envDirs {
            let key = (dir as NSString).standardizingPath
            for name in directoryNames[key] ?? directoryNames[dir] ?? [] where isDotEnvName(name) {
                add((key as NSString).appendingPathComponent((name as NSString).lastPathComponent))
            }
        }
        return out
    }

    /// Shell redirects and absolute credential paths inside a tool command.
    /// Relative paths are left to the existing workspace resolver.
    public static func commandTargets(_ command: String) -> [Hit] {
        var out: [Hit] = []
        var seen = Set<String>()
        func add(_ op: String, _ path: String) {
            let cleaned = path.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            guard cleaned.hasPrefix("/"), !cleaned.contains("$"), !isNoisePath(cleaned) else { return }
            let credential = isCredentialPath(cleaned)
            guard credential || op == "modify" else { return }
            let key = "\(op)|\(cleaned)"
            guard seen.insert(key).inserted else { return }
            out.append(Hit(path: cleaned, op: credential && op != "modify" ? "read" : op, credential: credential))
        }
        if let regex = try? NSRegularExpression(pattern: #"(?i)(?:^|[\n;&|])\s*(?:[^\s;&|]{1,80}\s+){0,8}>>?\s*(/[^\s;&|]+)"#, options: []) {
            for match in regex.matches(in: command, range: NSRange(command.startIndex..., in: command)) {
                guard match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: command) else { continue }
                add("modify", String(command[range]))
            }
        }
        if let regex = try? NSRegularExpression(pattern: #"(?i)(?:^|\s)(/(?:private/)?tmp/[^\s\"';|&]*\.env[^\s\"';|&]*|/[^\s\"';|&]*\.ssh/[^\s\"';|&]+|/[^\s\"';|&]*\.aws/[^\s\"';|&]+|/[^\s\"';|&]+\.pem\b|/[^\s\"';|&]*keychain[^\s\"';|&]*)"#, options: []) {
            for match in regex.matches(in: command, range: NSRange(command.startIndex..., in: command)) {
                guard match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: command) else { continue }
                add("read", String(command[range]))
            }
        }
        return out
    }

    /// Basename / bundle path only. A project directory named Cursor is not an agent.
    public static func agentOwner(path: String) -> String? {
        let base = (path as NSString).lastPathComponent.lowercased()
        if base == "cursor-agent" || path.contains("/Cursor.app/") { return "cursor" }
        if base == "claude" { return "claude" }
        if base == "codex" || base.hasPrefix("codex-") || path.contains("/Codex.app/") { return "codex" }
        if base == "workbuddy" || base == "codebuddy" || path.contains("/WorkBuddy.app/") || path.contains("/CodeBuddy.app/") {
            return "workbuddy"
        }
        return nil
    }
}
