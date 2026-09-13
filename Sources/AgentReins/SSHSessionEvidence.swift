import Foundation

struct SSHTransferEvidence: Equatable, Sendable {
    let direction: String
    let localPaths: [String]
    let remotePath: String?
    let tool: String
}

struct SSHSessionEvidence: Identifiable, Sendable {
    let id: String
    let agent: String
    let host: String
    let port: Int
    let username: String?
    let startedAt: Date
    let lastObservedAt: Date
    let authentication: String
    let credentialEntered: Bool
    let hostKeyPolicy: String
    let transfers: [SSHTransferEvidence]
    let remoteCommandCount: Int
    let socketObserved: Bool
    let sourceEvent: GuardEvent

    var risk: String {
        if username == "root" || credentialEntered || hostKeyPolicy.contains("accept-new") { return "review required" }
        return socketObserved ? "observed" : "unverified"
    }

    var findings: [String] {
        var rows: [String] = []
        if username == "root" { rows.append("Privileged root login was used") }
        if credentialEntered { rows.append("Interactive credential material entered through the Agent tool") }
        if hostKeyPolicy.contains("accept-new") { rows.append("A previously unseen host key may be accepted automatically") }
        if !socketObserved { rows.append("No PID-owned SSH socket was captured") }
        return rows
    }

    static func build(events: [GuardEvent]) -> [SSHSessionEvidence] {
        let ordered = events.sorted { $0.ts < $1.ts }
        let intents = ordered.filter { event in
            guard event.kind == "network", event.remotePort == 22 else { return false }
            return event.source == "tool-intent" || event.command?.range(of: #"\b(?:ssh|scp|rsync)\b"#, options: .regularExpression) != nil
        }
        let grouped = Dictionary(grouping: intents) { event in
            "\(event.agent ?? "agent")|\(event.turnId ?? event.sessionId ?? "session")|\((event.remoteDomain ?? event.remoteHost ?? "unknown").lowercased())|\(event.remotePort ?? 22)"
        }
        return grouped.compactMap { key, rows in
            guard let first = rows.min(by: { $0.ts < $1.ts }),
                  let host = first.remoteDomain ?? first.remoteHost else { return nil }
            let turnRows = ordered.filter {
                ($0.agent ?? "agent") == (first.agent ?? "agent") &&
                ($0.turnId ?? $0.sessionId) == (first.turnId ?? first.sessionId)
            }
            let commands = turnRows.compactMap(\.command)
            let relevant = commands.filter { $0.range(of: #"\b(?:ssh|scp|rsync|write_stdin)\b"#, options: .regularExpression) != nil }
            let joined = relevant.joined(separator: "\n")
            let username = capture(#"(?:ssh\b[^\n]*?\s|(?:scp|rsync)\b[^\n]*?\s)([A-Za-z0-9._-]+)@"#, in: joined)
            let auth = joined.contains(" -i ") ? "Private key path observed" :
                (joined.contains("SSH_AUTH_SOCK") ? "SSH Agent" : (interactiveCredential(in: relevant) ? "Interactive credential" : "Not proven"))
            let policy = joined.contains("StrictHostKeyChecking=accept-new") ? "accept-new" :
                (joined.contains("StrictHostKeyChecking=no") ? "host verification disabled" : "default / not proven")
            let transfers = relevant.compactMap(transfer)
            let sockets = turnRows.contains { $0.kind == "network" && $0.source == "lsof-network" &&
                ($0.remoteHost == host || $0.remoteDomain == host) && $0.remotePort == (first.remotePort ?? 22) }
            let remoteCommands = relevant.filter { $0.contains("write_stdin") && looksLikeRemoteCommand($0) }.count
            return SSHSessionEvidence(id: key, agent: first.agent ?? "Unknown", host: host,
                port: first.remotePort ?? 22, username: username, startedAt: first.startedAt ?? first.ts,
                lastObservedAt: rows.map(\.endedAt).compactMap { $0 }.max() ?? rows.map(\.ts).max() ?? first.ts,
                authentication: auth, credentialEntered: interactiveCredential(in: relevant),
                hostKeyPolicy: policy, transfers: transfers, remoteCommandCount: remoteCommands,
                socketObserved: sockets, sourceEvent: first)
        }.sorted { $0.lastObservedAt > $1.lastObservedAt }
    }

    private static func interactiveCredential(in commands: [String]) -> Bool {
        commands.contains { command in
            guard command.contains("write_stdin"), let value = capture(#"\"chars\"\s*:\s*\"([^\"]*)"#, in: command) else { return false }
            let clean = value.replacingOccurrences(of: #"\n"#, with: "").trimmingCharacters(in: .whitespaces)
            return !clean.isEmpty && clean != "yes" && !looksLikeShell(clean)
        }
    }

    private static func looksLikeRemoteCommand(_ value: String) -> Bool {
        guard let chars = capture(#"\"chars\"\s*:\s*\"([^\"]*)"#, in: value) else { return false }
        return looksLikeShell(chars)
    }

    private static func looksLikeShell(_ value: String) -> Bool {
        [";", "\n", "systemctl", "nginx", "docker", "curl ", "ls ", "cp ", "mv ", "install ", "tar "]
            .contains(where: value.contains)
    }

    private static func transfer(_ command: String) -> SSHTransferEvidence? {
        guard command.range(of: #"\b(?:scp|rsync)\b"#, options: .regularExpression) != nil,
              let remote = capture(#"(?:[^\s@:/]+@)?[A-Za-z0-9._-]+:([^\s\"']+)"#, in: command) else { return nil }
        let tool = command.range(of: #"\brsync\b"#, options: .regularExpression) == nil ? "SCP" : "rsync"
        let prefix = command.components(separatedBy: tool.lowercased()).dropFirst().joined(separator: tool.lowercased())
        let tokens = prefix.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        let locals = tokens.filter { !$0.hasPrefix("-") && !$0.contains("@") && !$0.contains(":") && !$0.hasPrefix("{") }
        return SSHTransferEvidence(direction: "Upload", localPaths: Array(locals.prefix(8)), remotePath: remote, tool: tool)
    }

    private static func capture(_ pattern: String, in value: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
              let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
              match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: value) else { return nil }
        return String(value[range])
    }
}
