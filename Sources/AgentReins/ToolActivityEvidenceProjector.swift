import Combine
import CryptoKit
import Foundation

/// Projects durable network and file intent from native Agent tool calls.
/// This closes the short-lived activity gap left by periodic socket/file snapshots.
@MainActor
final class ToolActivityEvidenceProjector: ObservableObject {
    private struct Descriptor {
        enum Payload {
            case network(domain: String, port: Int)
            case file(op: String, path: String, relatedPath: String?)
        }
        let id: UUID
        let payload: Payload
        let call: GuardEvent
    }

    private var pending: [String: [Descriptor]] = [:]

    func project(_ events: [GuardEvent]) -> [GuardEvent] {
        var output: [GuardEvent] = []
        for event in events.sorted(by: { $0.ts < $1.ts }) where event.kind == "tool" {
            guard let key = callKey(event) else { continue }
            if event.op == "call" {
                let descriptors = Self.descriptors(for: event)
                pending[key] = descriptors
                output += descriptors.map { projected($0, result: nil) }
            } else if event.op == "result", let descriptors = pending.removeValue(forKey: key) {
                output += descriptors.map { projected($0, result: event) }
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
        case let .network(domain, port):
            return GuardEvent(id: descriptor.id, kind: "network", ruleId: "tool_network_intent",
                path: call.path, command: call.command, agent: call.agent, op: "connect",
                severity: "info", ts: call.ts, action: action, sessionId: common.session,
                traceId: common.trace, turnId: common.turn, toolCallId: common.toolCall,
                userIntent: call.userIntent, modelDecision: call.modelDecision,
                toolName: common.tool, model: call.model, source: "tool-intent",
                attributionConfidence: .confirmed,
                attributionMethod: "native Agent tool arguments",
                remoteHost: domain, remotePort: port, remoteDomain: domain,
                startedAt: call.ts, endedAt: end,
                durationMS: end.map { max(0, $0.timeIntervalSince(call.ts) * 1_000) })
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
        return "\(event.agent ?? "agent")|\(event.sessionId ?? "session")|\(call)"
    }

    private static func descriptors(for event: GuardEvent) -> [Descriptor] {
        guard let command = event.command, !command.isEmpty else { return [] }
        var payloads: [Descriptor.Payload] = []
        if let destination = networkDestination(command: command, workspace: event.path) {
            payloads.append(.network(domain: destination.domain, port: destination.port))
        }
        payloads += fileOperations(command: command, workspace: event.path, toolName: event.toolName)
        return payloads.enumerated().map { index, payload in
            Descriptor(id: stableUUID("\(event.id.uuidString)|activity|\(index)"), payload: payload, call: event)
        }
    }

    private static func networkDestination(command: String, workspace: String) -> (domain: String, port: Int)? {
        let lower = command.lowercased()
        guard ["http://", "https://", "git push", "git fetch", "git pull", "git clone", "ssh ", "scp ", "rsync ", "curl ", "wget "]
            .contains(where: lower.contains) else { return nil }
        if let domain = ExternalURLEvidence.firstDomain(in: command) {
            return (domain, lower.contains("http://") ? 80 : 443)
        }
        if ["ssh ", "scp ", "rsync "].contains(where: lower.contains),
           let host = firstMatch(#"(?:ssh|scp|rsync)(?:\s+-[A-Za-z]+(?:\s+\S+)?)?\s+(?:[^\s@]+@)?([A-Za-z0-9._-]+)"#, in: command) {
            let port = firstMatch(#"(?:^|\s)-p\s*(\d+)"#, in: command).flatMap(Int.init) ?? 22
            return (host.lowercased(), port)
        }
        if lower.contains("git "), let remote = gitRemote(workspace: workspace) {
            return remote
        }
        return nil
    }

    private static func gitRemote(workspace: String) -> (domain: String, port: Int)? {
        guard workspace.hasPrefix("/") else { return nil }
        var directory = URL(fileURLWithPath: workspace)
        if directory.pathExtension != "" { directory.deleteLastPathComponent() }
        for _ in 0..<8 {
            let config = directory.appendingPathComponent(".git/config")
            if let text = try? String(contentsOf: config, encoding: .utf8),
               let url = firstMatch(#"url\s*=\s*([^\s]+)"#, in: text) {
                if let domain = ExternalURLEvidence.firstDomain(in: url) {
                    return (domain, url.lowercased().hasPrefix("http://") ? 80 : 443)
                }
                if let sshHost = firstMatch(#"@([^:/]+)[:/]"#, in: url) { return (sshHost.lowercased(), 22) }
            }
            let parent = directory.deletingLastPathComponent()
            if parent.path == directory.path { break }
            directory = parent
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
