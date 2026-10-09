import Combine
import CryptoKit
import Foundation

/// Projects durable network and file intent from native Agent tool calls.
/// This closes the short-lived activity gap left by periodic socket/file snapshots.
@MainActor
final class ToolActivityEvidenceProjector: ObservableObject {
    private struct Descriptor {
        enum Payload {
            case network(domain: String, port: Int, url: String?, basis: String)
            case file(op: String, path: String, relatedPath: String?)
        }
        let id: UUID
        let payload: Payload
        let call: GuardEvent
        let workspace: String
        let executionDerived: Bool
    }

    private struct CommandInput {
        let command: String
        let workspace: String
    }

    private struct NetworkTarget {
        let domain: String
        let port: Int
        let url: String?
        let basis: String
    }

    private var pending: [String: [Descriptor]] = [:]

    func project(_ events: [GuardEvent]) -> [GuardEvent] {
        var output: [GuardEvent] = []
        for event in events.sorted(by: { $0.ts < $1.ts }) where event.kind == "tool" {
            guard let key = callKey(event) else { continue }
            if event.op == "call" || event.op == "exec_start" {
                let descriptors = Self.descriptors(for: event)
                pending[key] = descriptors
                output += descriptors.map { projected($0, result: nil) }
            } else if event.op == "result" {
                if let descriptors = pending.removeValue(forKey: key) {
                    output += descriptors.map { projected($0, result: event) }
                } else if event.toolName == "CommandExecution", event.command != nil {
                    // Some rollouts contain only item_completed. Its command is
                    // execution evidence, not proof of a socket or HTTP request.
                    output += Self.descriptors(for: event, executionDerived: true)
                        .map { projected($0, result: event) }
                }
            }
        }
        if pending.count > 500 { pending.removeAll(keepingCapacity: true) }
        return output
    }

    private func projected(_ descriptor: Descriptor, result: GuardEvent?) -> GuardEvent {
        let call = descriptor.call
        let end = result?.ts
        let action = result.map { Self.resultAction($0) } ?? "requested"
        let common = (session: call.sessionId, trace: call.traceId, turn: call.turnId,
                      toolCall: call.toolCallId, tool: call.toolName)
        switch descriptor.payload {
        case let .network(domain, port, url, basis):
            // Severity follows the destination classification so that
            // untrusted content boundaries surface on the dashboard instead
            // of being filtered out as routine info-level activity.
            let destination = NetworkDestinationAssessment.assess(domain: domain, host: domain)
            let severity: String
            switch destination.kind {
            case .externalContent, .unknown, .modelRelay:
                severity = "high"
            case .developerService:
                severity = "medium"
            case .modelProvider, .telemetry, .localInfrastructure:
                severity = "info"
            }
            var metadata: [String: Any] = ["originalCommand": call.command ?? "", "cwd": descriptor.workspace,
                "destinationBasis": basis, "wireObserved": false,
                "evidenceType": descriptor.executionDerived ? "execution_derived_target" : "requested_target"]
            if let url { metadata["requestedURL"] = url }
            let command = (try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys, .withoutEscapingSlashes]))
                .flatMap { String(data: $0, encoding: .utf8) }
            return GuardEvent(id: descriptor.id, kind: "network", ruleId: "tool_network_intent",
                path: descriptor.workspace, command: command, agent: call.agent, op: "connect",
                severity: severity, ts: call.ts, action: action, sessionId: common.session,
                traceId: common.trace, turnId: common.turn, toolCallId: common.toolCall,
                userIntent: call.userIntent, modelDecision: call.modelDecision,
                toolName: common.tool, model: call.model, source: "tool-intent",
                attributionConfidence: .confirmed,
                attributionMethod: descriptor.executionDerived
                    ? "native CommandExecution completed record; destination derived from executed command; no socket or HTTP request observed"
                    : "native Agent tool arguments; requested destination only; no socket or HTTP request observed",
                remoteHost: domain, remotePort: port, remoteDomain: domain,
                startedAt: call.startedAt ?? call.ts, endedAt: end,
                durationMS: descriptor.executionDerived ? call.durationMS : end.map { max(0, $0.timeIntervalSince(call.ts) * 1_000) })
        case let .file(op, path, relatedPath):
            return GuardEvent(id: descriptor.id, kind: "file", ruleId: "tool_file_intent",
                path: path, command: call.command, agent: call.agent, op: op,
                severity: "info", ts: call.ts, action: action, sessionId: common.session,
                traceId: common.trace, turnId: common.turn, toolCallId: common.toolCall,
                userIntent: call.userIntent, modelDecision: call.modelDecision,
                toolName: common.tool, model: call.model, source: "tool-intent",
                attributionConfidence: .confirmed,
                attributionMethod: "native Agent tool arguments",
                startedAt: call.ts, endedAt: end,
                durationMS: end.map { max(0, $0.timeIntervalSince(call.ts) * 1_000) },
                relatedPath: relatedPath)
        }
    }

    private func callKey(_ event: GuardEvent) -> String? {
        guard let call = event.toolCallId else { return nil }
        return "\(event.agent ?? "agent")|\(event.sessionId ?? "session")|\(event.turnId ?? "turn")|\(call)"
    }

    private static func descriptors(for event: GuardEvent, executionDerived: Bool = false) -> [Descriptor] {
        guard let command = event.command, !command.isEmpty else { return [] }
        var result: [Descriptor] = []
        for input in commandInputs(command, fallbackWorkspace: event.path) {
            var payloads: [Descriptor.Payload] = []
            if let destination = networkDestination(command: input.command, workspace: input.workspace) {
                payloads.append(.network(domain: destination.domain, port: destination.port,
                    url: destination.url, basis: destination.basis))
            }
            if !executionDerived {
                payloads += fileOperations(command: input.command, workspace: input.workspace, toolName: event.toolName)
            }
            for payload in payloads {
                result.append(Descriptor(id: stableUUID("\(event.id.uuidString)|activity|\(result.count)"),
                    payload: payload, call: event, workspace: input.workspace, executionDerived: executionDerived))
            }
        }
        return result
    }

    /// Read actual argument fields, never cwd-looking text in stdout or justification.
    private static func commandInputs(_ value: String, fallbackWorkspace: String) -> [CommandInput] {
        let fallback = normalizedDirectory(fallbackWorkspace, relativeTo: nil) ?? fallbackWorkspace
        if let data = value.data(using: .utf8), let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let workspace = ["cwd", "workdir", "working_directory"].compactMap { object[$0] as? String }.first
                .flatMap { normalizedDirectory($0, relativeTo: fallback) } ?? fallback
            let raw = object["cmd"] ?? object["command"] ?? object["shell_command"]
            if let raw = raw as? String { return [CommandInput(command: raw, workspace: workspace)] }
            if let argv = raw as? [String] {
                let shell = ["sh", "bash", "zsh", "fish"].contains(((argv.first ?? "") as NSString).lastPathComponent)
                if shell, let flag = argv.firstIndex(where: { ["-c", "-lc", "-ic"].contains($0) }), argv.indices.contains(flag + 1) {
                    return [CommandInput(command: argv[flag + 1], workspace: workspace)]
                }
                return [CommandInput(command: argv.map(shellQuoted).joined(separator: " "), workspace: workspace)]
            }
            if raw != nil { return [] }
            return [CommandInput(command: value, workspace: workspace)]
        }
        // functions.exec carries literal JS wrappers. Parse only actual executor
        // argument objects; do not evaluate JS or search unrelated strings.
        if value.range(of: #"\btools\.exec_command\s*\(\s*\{"#, options: .regularExpression) != nil {
            return executorArguments(in: value).compactMap { object in
                guard let command = object["cmd"] ?? object["command"] ?? object["shell_command"] else { return nil }
                let workspace = (object["cwd"] ?? object["workdir"] ?? object["working_directory"])
                    .flatMap { normalizedDirectory($0, relativeTo: fallback) } ?? fallback
                return CommandInput(command: command, workspace: workspace)
            }
        }
        return [CommandInput(command: value, workspace: fallback)]
    }

    private static func networkDestination(command: String, workspace: String) -> NetworkTarget? {
        if let invocation = gitInvocation(command, workspace: workspace) {
            guard !invocation.operation.isEmpty else { return nil }
            guard let remote = invocation.remote else { return nil }
            if let direct = target(remote, basis: "explicit Git repository argument") { return direct }
            guard invocation.operation != "clone", let config = gitConfig(workspace: invocation.workspace),
                  invocation.explicitRemote || canAssumeOrigin(config, push: invocation.operation == "push"),
                  let url = remoteURL(config, remote: remote, push: invocation.operation == "push") else { return nil }
            return target(url, basis: "Git remote \(remote) in \(invocation.workspace)")
        }
        let lower = command.lowercased()
        guard ["http://", "https://", "ssh ", "scp ", "rsync ", "curl ", "wget "]
            .contains(where: lower.contains) else { return nil }
        if let url = firstMatch(#"(https?://[^\s\\\"'<>)}\]]+)"#, in: command), let result = target(url, basis: "explicit URL in native tool arguments") {
            return result
        }
        if lower.contains("scp ") || lower.contains("rsync "),
           let host = firstMatch(#"(?:^|\s)(?:[^\s@:/]+@)?([A-Za-z0-9._-]+):[^\s]+"#, in: command) {
            let port = firstMatch(#"(?:^|\s)-P\s*(\d+)"#, in: command).flatMap(Int.init)
                ?? firstMatch(#"(?:^|\s)-p\s*(\d+)"#, in: command).flatMap(Int.init) ?? 22
            return NetworkTarget(domain: host.lowercased(), port: port, url: nil, basis: "explicit remote transfer argument")
        }
        if lower.contains("ssh "),
           let host = firstMatch(#"\bssh\b(?:\s+-[^\s]+(?:\s+[^\s-][^\s]*)?)*\s+(?:[^\s@]+@)?([A-Za-z0-9._-]+)"#, in: command) {
            let port = firstMatch(#"(?:^|\s)-p\s*(\d+)"#, in: command).flatMap(Int.init) ?? 22
            return NetworkTarget(domain: host.lowercased(), port: port, url: nil, basis: "explicit SSH argument")
        }
        return nil
    }

    private static func target(_ value: String, basis: String) -> NetworkTarget? {
        if var components = URLComponents(string: value), let scheme = components.scheme?.lowercased(),
           let host = components.host, ["http", "https", "ssh", "git"].contains(scheme) {
            components.password = nil
            if scheme == "http" || scheme == "https" { components.user = nil }
            return NetworkTarget(domain: host.lowercased(), port: components.port ?? (scheme == "http" ? 80 : scheme == "git" ? 9418 : scheme == "ssh" ? 22 : 443),
                url: components.string, basis: basis)
        }
        if let host = firstMatch(#"^(?:[^\s@/:]+@)?([A-Za-z0-9._-]+):[^\s]+$"#, in: value), !value.hasPrefix("/") {
            return NetworkTarget(domain: host.lowercased(), port: 22, url: value, basis: basis)
        }
        return nil
    }

    private static func gitInvocation(_ command: String, workspace: String) -> (operation: String, remote: String?, workspace: String, explicitRemote: Bool)? {
        for words in shellCommands(command) {
            var index = 0
            while index < words.count && (words[index] == "env" || words[index].range(of: #"^[A-Za-z_][A-Za-z0-9_]*="#, options: .regularExpression) != nil) { index += 1 }
            guard index < words.count, (words[index] as NSString).lastPathComponent == "git" else { continue }
            index += 1
            var directory = workspace
            while index < words.count {
                let word = words[index]
                if word == "-C" {
                    guard index + 1 < words.count, let changed = normalizedDirectory(words[index + 1], relativeTo: directory) else { return ("", nil, directory, false) }
                    directory = changed; index += 2
                } else if word.hasPrefix("-C"), word.count > 2 {
                    guard let changed = normalizedDirectory(String(word.dropFirst(2)), relativeTo: directory) else { return ("", nil, directory, false) }
                    directory = changed; index += 1
                } else if word == "-c" || word.hasPrefix("-c") {
                    // Runtime config can alter remote URLs, push destinations,
                    // rewrites and defaults. Disk config cannot prove its target.
                    return ("", nil, directory, false)
                } else if word.hasPrefix("-") { return ("", nil, directory, false) }
                else { break }
            }
            guard index < words.count, ["push", "fetch", "pull", "clone"].contains(words[index]) else { continue }
            let operation = words[index]; index += 1
            let valuedOptions = ["--repo", "--receive-pack", "--upload-pack", "--exec", "--depth", "--shallow-since", "--shallow-exclude", "--filter", "--refmap", "--push-option", "-o", "--branch", "-b", "--origin", "--config"]
            while index < words.count {
                let word = words[index]
                if word == "--" { index += 1; break }
                if operation == "fetch", word == "--all" { return ("", nil, directory, false) }
                if word.hasPrefix("--repo=") { return (operation, String(word.dropFirst(7)), directory, true) }
                if word == "--repo", index + 1 < words.count { return (operation, words[index + 1], directory, true) }
                if valuedOptions.contains(word) { index += 2 }
                else if word.hasPrefix("-") { index += 1 }
                else { break }
            }
            let explicit = index < words.count
            let remote = explicit ? words[index] : "origin"
            guard !remote.contains("$") && !remote.contains("`") else { return (operation, nil, directory, explicit) }
            return (operation, remote, directory, explicit)
        }
        return nil
    }

    private static func gitConfig(workspace: String) -> String? {
        guard workspace.hasPrefix("/") else { return nil }
        var directory = URL(fileURLWithPath: workspace)
        for _ in 0..<32 {
            let marker = directory.appendingPathComponent(".git")
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: marker.path, isDirectory: &isDirectory) {
                var gitDirectory = marker
                if !isDirectory.boolValue {
                    guard let text = try? String(contentsOf: marker, encoding: .utf8),
                          let relative = firstMatch(#"^gitdir:\s*(.+)$"#, in: text),
                          let path = normalizedDirectory(relative, relativeTo: directory.path) else { return nil }
                    gitDirectory = URL(fileURLWithPath: path)
                }
                var common = gitDirectory
                if let path = try? String(contentsOf: gitDirectory.appendingPathComponent("commondir"), encoding: .utf8),
                   let resolved = normalizedDirectory(path.trimmingCharacters(in: .whitespacesAndNewlines), relativeTo: gitDirectory.path) {
                    common = URL(fileURLWithPath: resolved)
                }
                // The nearest repository owns the command; never borrow a
                // remote from an unrelated parent repository.
                return try? String(contentsOf: common.appendingPathComponent("config"), encoding: .utf8)
            }
            let parent = directory.deletingLastPathComponent()
            if parent.path == directory.path { break }
            directory = parent
        }
        return nil
    }

    private static func remoteURL(_ config: String, remote: String, push: Bool) -> String? {
        var section: String?, urls: [String] = [], pushURLs: [String] = []
        for raw in config.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("[") { section = firstMatch(#"^\[remote\s+\"([^\"]+)\"\]$"#, in: line); continue }
            guard section == remote, let split = line.firstIndex(of: "=") else { continue }
            let key = line[..<split].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: split)...].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            if key == "url" { urls.append(value) }
            if key == "pushurl" { pushURLs.append(value) }
        }
        let values = push && !pushURLs.isEmpty ? pushURLs : urls
        // Multiple push destinations require separate evidence; do not select
        // an arbitrary first endpoint and claim it is the sole target.
        guard values.count == 1 else { return nil }
        return values.first
    }

    private static func canAssumeOrigin(_ config: String, push: Bool) -> Bool {
        var section = ""
        for raw in config.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("[") { section = line.lowercased(); continue }
            guard let split = line.firstIndex(of: "=") else { continue }
            let key = line[..<split].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: split)...].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            let branchDefault = section.hasPrefix("[branch ") && (key == "remote" || push && key == "pushremote")
            let pushDefault = push && section == "[remote]" && key == "pushdefault"
            // Without a branch/config evaluation, a non-origin default means
            // the implicit repository is unresolved, not automatically origin.
            if (branchDefault || pushDefault), value != "origin" { return false }
        }
        return true
    }

    private static func normalizedDirectory(_ raw: String, relativeTo base: String?) -> String? {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: value), url.isFileURL { return url.standardizedFileURL.path }
        guard !value.isEmpty, !value.contains("$"), !value.contains("`"), !value.contains("\n") else { return nil }
        if value.hasPrefix("/") { return URL(fileURLWithPath: value).standardizedFileURL.path }
        guard let base, base.hasPrefix("/") else { return nil }
        return URL(fileURLWithPath: base).appendingPathComponent(value).standardizedFileURL.path
    }

    private static func shellQuoted(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    private static func shellCommands(_ value: String) -> [[String]] {
        var commands: [[String]] = [], words: [String] = [], word = "", quote: Character?, escaped = false
        func finishWord() { if !word.isEmpty { words.append(word); word = "" } }
        for character in value {
            if escaped { word.append(character); escaped = false; continue }
            if character == "\\", quote != "'" { escaped = true; continue }
            if let current = quote { if character == current { quote = nil } else { word.append(character) }; continue }
            if character == "\"" || character == "'" { quote = character; continue }
            if ";&|\n".contains(character) { finishWord(); if !words.isEmpty { commands.append(words); words = [] } }
            else if character.isWhitespace { finishWord() }
            else { word.append(character) }
        }
        guard quote == nil, !escaped else { return [] }
        finishWord(); if !words.isEmpty { commands.append(words) }
        return commands
    }

    private static func executorArguments(in value: String) -> [[String: String]] {
        guard let regex = try? NSRegularExpression(pattern: #"\btools\.exec_command\s*\(\s*\{"#) else { return [] }
        let matches = regex.matches(in: value, range: NSRange(value.startIndex..., in: value))
        return matches.compactMap { match in
            guard let range = Range(match.range, in: value), isCodePosition(range.lowerBound, in: value) else { return nil }
            var index = range.upperBound, fields: [String: String] = [:], depth = 1, unresolvedArgument = false
            while index < value.endIndex, depth > 0 {
                skipTrivia(value, index: &index)
                guard index < value.endIndex else { break }
                let character = value[index]
                if character == "\"" || character == "'" {
                    let key = quotedLiteral(value, index: &index)
                    skipTrivia(value, index: &index)
                    if depth == 1, let key, ["cmd", "command", "shell_command", "cwd", "workdir", "working_directory"].contains(key),
                       index < value.endIndex, value[index] == ":" {
                        index = value.index(after: index)
                        skipTrivia(value, index: &index)
                        if let literal = quotedLiteral(value, index: &index) {
                            skipTrivia(value, index: &index)
                            if index < value.endIndex, value[index] == "," || value[index] == "}" { fields[key] = literal }
                            else { unresolvedArgument = true }
                        } else { unresolvedArgument = true }
                    }
                    continue
                }
                if character == "{" { depth += 1 }
                if character == "}" { depth -= 1; if depth == 0 { break } }
                if depth == 1, character.isLetter || character == "_" {
                    let start = index
                    while index < value.endIndex, value[index].isLetter || value[index].isNumber || value[index] == "_" { index = value.index(after: index) }
                    let key = String(value[start..<index])
                    skipTrivia(value, index: &index)
                    if index < value.endIndex, value[index] == ":" {
                        index = value.index(after: index)
                        skipTrivia(value, index: &index)
                        if ["cmd", "command", "shell_command", "cwd", "workdir", "working_directory"].contains(key) {
                            if let literal = quotedLiteral(value, index: &index) {
                                skipTrivia(value, index: &index)
                                if index < value.endIndex, value[index] == "," || value[index] == "}" { fields[key] = literal }
                                else { unresolvedArgument = true }
                            } else { unresolvedArgument = true }
                        }
                    }
                    continue
                }
                index = value.index(after: index)
            }
            return unresolvedArgument ? [:] : fields
        }
    }

    private static func isCodePosition(_ target: String.Index, in value: String) -> Bool {
        var index = value.startIndex
        while index < target {
            let character = value[index]
            if character == "\"" || character == "'" || character == "`" {
                let quote = character
                index = value.index(after: index)
                var escaped = false
                while index < value.endIndex {
                    let next = value[index]; index = value.index(after: index)
                    if escaped { escaped = false; continue }
                    if next == "\\" { escaped = true; continue }
                    if next == quote { break }
                }
                if index > target { return false }
            } else {
                let before = index
                skipTrivia(value, index: &index)
                if index > target { return false }
                if index == before { index = value.index(after: index) }
            }
        }
        return index == target
    }

    private static func skipTrivia(_ value: String, index: inout String.Index) {
        while index < value.endIndex {
            if value[index].isWhitespace { index = value.index(after: index); continue }
            let next = value.index(after: index)
            guard value[index] == "/", next < value.endIndex else { return }
            if value[next] == "/" {
                index = value.index(after: next)
                while index < value.endIndex, value[index] != "\n" { index = value.index(after: index) }
            } else if value[next] == "*" {
                index = value.index(after: next)
                while index < value.endIndex {
                    let following = value.index(after: index)
                    if value[index] == "*", following < value.endIndex, value[following] == "/" {
                        index = value.index(after: following); break
                    }
                    index = following
                }
            } else { return }
        }
    }

    private static func quotedLiteral(_ value: String, index: inout String.Index) -> String? {
        guard index < value.endIndex, value[index] == "\"" || value[index] == "'" else { return nil }
        let start = index, quote = value[index]; index = value.index(after: index)
        var escaped = false, result = ""
        while index < value.endIndex {
            let character = value[index]; index = value.index(after: index)
            if escaped {
                if quote == "'" { result.append(character == "n" ? "\n" : character == "r" ? "\r" : character == "t" ? "\t" : character) }
                escaped = false; continue
            }
            if character == "\\" { escaped = true; continue }
            if character == quote {
                if quote == "\"" { return (try? JSONSerialization.jsonObject(with: Data(value[start..<index].utf8), options: [.fragmentsAllowed])) as? String }
                return result
            }
            if quote == "'" { result.append(character) }
        }
        return nil
    }

    private static func fileOperations(command: String, workspace: String, toolName: String?) -> [Descriptor.Payload] {
        var result: [Descriptor.Payload] = []
        let patterns: [(String, String)] = [
            (#"\*\*\* Add File:\s*([^\r\n]+)"#, "create"),
            (#"\*\*\* Update File:\s*([^\r\n]+)"#, "update"),
            (#"\*\*\* Delete File:\s*([^\r\n]+)"#, "delete")
        ]
        for (pattern, op) in patterns {
            for path in matches(pattern, in: command) {
                let resolved = absolute(path, workspace: workspace)
                if !resolved.isEmpty { result.append(.file(op: op, path: resolved, relatedPath: nil)) }
            }
        }
        let name = toolName?.lowercased() ?? ""
        if result.isEmpty,
           let rawPath = firstMatch(#"\"(?:file_?path|path)\"\s*:\s*\"([^\"]+)\""#, in: command) {
            let path = absolute(rawPath, workspace: workspace)
            guard !path.isEmpty else { return result }
            let op: String
            if ["read", "get", "open"].contains(where: name.contains) { op = "read" }
            else if ["delete", "remove"].contains(where: name.contains) { op = "delete" }
            else if ["write", "create"].contains(where: name.contains) {
                op = FileManager.default.fileExists(atPath: path) ? "update" : "create"
            } else if ["edit", "patch", "replace"].contains(where: name.contains) { op = "update" }
            else { op = "" }
            if !op.isEmpty { result.append(.file(op: op, path: path, relatedPath: nil)) }
        }
        if let pair = firstTwoMatches(#"(?:^|[;&|]\s*)mv\s+(?:-[^\s]+\s+)*(\S+)\s+(\S+)"#, in: command) {
            let source = absolute(pair.0, workspace: workspace)
            let destination = absolute(pair.1, workspace: workspace)
            if !source.isEmpty && !destination.isEmpty {
                result.append(.file(op: "rename", path: source, relatedPath: destination))
            }
        }
        if result.isEmpty, let path = firstMatch(#"(?:^|[;&|]\s*)(?:touch|mkdir)\s+(?:-[^\s]+\s+)*(\S+)"#, in: command) {
            let resolved = absolute(path, workspace: workspace)
            if !resolved.isEmpty { result.append(.file(op: "create", path: resolved, relatedPath: nil)) }
        }
        if result.isEmpty, let path = firstMatch(#"(?:^|[;&|]\s*)rm\s+(?:-[^\s]+\s+)*(\S+)"#, in: command) {
            let resolved = absolute(path, workspace: workspace)
            if !resolved.isEmpty { result.append(.file(op: "delete", path: resolved, relatedPath: nil)) }
        }
        if result.isEmpty, let path = firstMatch(#"(?:^|[;&|]\s*)(?:cat|head|tail|less|more)\s+(?:-[^\s]+\s+)*(\S+)"#, in: command) {
            let resolved = absolute(path, workspace: workspace)
            if !resolved.isEmpty { result.append(.file(op: "read", path: resolved, relatedPath: nil)) }
        }
        return result
    }

    private static func absolute(_ raw: String, workspace: String) -> String {
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if cleaned.contains("$") || cleaned.contains("\\") || cleaned.contains("{") || cleaned.contains("*") {
            return ""
        }
        if cleaned.hasPrefix("/") { return cleaned }
        guard workspace.hasPrefix("/") else { return cleaned }
        return URL(fileURLWithPath: workspace).appendingPathComponent(cleaned).standardizedFileURL.path
    }

    private static func resultAction(_ event: GuardEvent) -> String {
        if ["failed", "denied", "cancelled", "canceled"].contains(event.action.lowercased()) { return "failed" }
        if let raw = event.modelResponse?.data(using: .utf8),
           let body = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] {
            if let status = body["status"] as? String, ["failed", "cancelled", "canceled"].contains(status.lowercased()) { return "failed" }
            if let code = body["exit_code"] as? Int { return code == 0 ? "completed" : "failed" }
        }
        let value = "\(event.action) \(event.modelResponse ?? "")".lowercased()
        if ["fail", "error", "denied", "cancel", "timed out", "timeout", "exit code 1", "exit_code\":1"]
            .contains(where: value.contains) { return "failed" }
        if ["script running", "still running", "cell id", "session_id"].contains(where: value.contains) { return "running" }
        let tool = event.toolName?.lowercased() ?? ""
        if ["exec", "shell", "terminal", "bash"].contains(where: tool.contains) {
            return ["script completed", "process exited with code 0", "exit code: 0", "exit_code\":0"]
                .contains(where: value.contains) ? "completed" : "unverified"
        }
        return event.action.lowercased() == "completed" ? "completed" : "unverified"
    }

    private static func firstMatch(_ pattern: String, in text: String) -> String? { matches(pattern, in: text).first }

    private static func matches(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .anchorsMatchLines]) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: text) else { return nil }
            return String(text[range])
        }
    }

    private static func firstTwoMatches(_ pattern: String, in text: String) -> (String, String)? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .anchorsMatchLines]),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              match.numberOfRanges > 2,
              let first = Range(match.range(at: 1), in: text), let second = Range(match.range(at: 2), in: text) else { return nil }
        return (String(text[first]), String(text[second]))
    }

    private static func stableUUID(_ value: String) -> UUID {
        var bytes = Array(SHA256.hash(data: Data(value.utf8)).prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | 0x50
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
