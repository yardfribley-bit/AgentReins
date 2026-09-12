import Foundation

/// Conservative, evidence-based task completion checks. This does not ask a
/// model whether its own answer is correct; it compares explicit requirements
/// with captured tool results and independently observed artifacts.
enum RequirementCompletionAnalyzer {
    struct Check: Codable, Equatable {
        let requirement: String
        let state: String
        let evidence: String
    }

    nonisolated static func cursorAssessments(composerId: String, workspace: String,
                                              events: [GuardEvent]) -> [GuardEvent] {
        let prompts = events.filter { $0.kind == "model" && $0.op == "prompt" && $0.turnId != nil }
        return prompts.compactMap { prompt in
            guard let turn = prompt.turnId, let intent = prompt.userIntent else { return nil }
            let turnEvents = events.filter { $0.turnId == turn }
            let checks = assess(intent: intent, workspace: workspace, events: turnEvents)
            guard !checks.isEmpty else { return nil }
            let states = Set(checks.map(\.state))
            let action: String
            if states == ["completed"] { action = "completed" }
            else if states.contains("completed") || states.contains("unverified") { action = "partial" }
            else { action = "failed" }
            let payload: [String: Any] = [
                "state": action,
                "completed": checks.filter { $0.state == "completed" }.count,
                "total": checks.count,
                "checks": checks.map { ["requirement": $0.requirement, "state": $0.state, "evidence": $0.evidence] }
            ]
            return GuardEvent(id: stableUUID("\(composerId):\(turn):requirements"),
                kind: "verification", ruleId: "cursor_requirement_completion", path: workspace,
                command: nil, agent: "cursor", op: "requirement_completion", severity: "info",
                ts: turnEvents.map(\.ts).max() ?? prompt.ts, action: action,
                sessionId: composerId, turnId: turn, userIntent: intent,
                modelResponse: json(payload), source: "agentsight:cursor-state-v3",
                attributionConfidence: .inferred,
                attributionMethod: "Explicit requirement checks against captured tool results and observed workspace artifacts")
        }
    }

    nonisolated static func assess(intent: String, workspace: String, events: [GuardEvent]) -> [Check] {
        let lines = intent.components(separatedBy: .newlines)
        let numbered = lines.compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.range(of: #"^\d+[\.、\)]\s*"#, options: .regularExpression) != nil else { return nil }
            return trimmed.replacingOccurrences(of: #"^\d+[\.、\)]\s*"#, with: "", options: .regularExpression)
        }
        let requirements = numbered.isEmpty ? [intent] : numbered
        let artifactRoot = requestedDirectory(in: intent).map {
            URL(fileURLWithPath: workspace).appendingPathComponent($0).standardizedFileURL.path
        } ?? workspace
        let toolCalls = events.filter { $0.kind == "tool" && $0.op == "call" }
        let toolResults = events.filter { $0.kind == "tool" && $0.op == "result" }
        let observedFiles = events.filter { $0.kind == "file" && $0.afterContent != nil }
        let finalResponses = events.compactMap(\.modelResponse).joined(separator: "\n")

        return requirements.map { requirement in
            let lower = requirement.lowercased()
            let fileNames = matches(#"[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,10}"#, in: requirement)
                .filter { !$0.lowercased().hasPrefix("example.com") }
            if !fileNames.isEmpty {
                let found = fileNames.filter { name in
                    observedFiles.contains { URL(fileURLWithPath: $0.path).lastPathComponent.caseInsensitiveCompare(name) == .orderedSame } ||
                    FileManager.default.fileExists(atPath: URL(fileURLWithPath: artifactRoot).appendingPathComponent(name).path)
                }
                return Check(requirement: requirement, state: found.count == fileNames.count ? "completed" : "failed",
                    evidence: found.isEmpty ? "Requested file was not observed." : "Observed: \(found.joined(separator: ", ")).")
            }
            if lower.contains("http://") || lower.contains("https://") {
                let requested = ExternalURLEvidence.firstDomain(in: requirement)
                let matched = events.contains { ($0.remoteDomain ?? $0.remoteHost) == requested && $0.kind == "network" } ||
                    toolResults.contains { ($0.modelResponse ?? "").localizedCaseInsensitiveContains(requested ?? "__missing__") }
                return Check(requirement: requirement, state: matched ? "completed" : "failed",
                    evidence: matched ? "A matching network/result record was captured." : "No matching domain or successful webpage result was captured.")
            }
            if lower.contains("运行") || lower.contains("execute") || lower.contains("run ") || lower.contains("git status") {
                let relevant = toolCalls.filter { call in
                    let command = call.command?.lowercased() ?? ""
                    return lower.contains("git status") ? command.contains("git") && command.contains("status") :
                        command.contains("python") || command.contains("swift run") || command.contains("npm")
                }
                let completed = relevant.contains { call in
                    toolResults.contains { $0.toolCallId == call.toolCallId && ["completed", "success", "ok"].contains($0.action.lowercased()) && $0.modelResponse != nil }
                }
                return Check(requirement: requirement, state: completed ? "completed" : (!relevant.isEmpty ? "unverified" : "failed"),
                    evidence: completed ? "A completed Tool Result was captured." : (!relevant.isEmpty ? "The command was requested, but its completed result is unavailable." : "No matching command was captured."))
            }
            if lower.contains("告诉") || lower.contains("report") || lower.contains("汇报") ||
                lower.contains("tell me") || lower.contains("tool results") {
                let reported = !finalResponses.isEmpty && toolCalls.contains { finalResponses.localizedCaseInsensitiveContains($0.toolName ?? "__missing__") }
                return Check(requirement: requirement, state: reported ? "completed" : "failed",
                    evidence: reported ? "The final response names captured tools." : "The final response did not provide the requested tool/result report.")
            }
            return Check(requirement: requirement, state: "unverified", evidence: "No deterministic verifier is available for this requirement yet.")
        }
    }

    private nonisolated static func matches(_ pattern: String, in value: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(value.startIndex..., in: value)
        return regex.matches(in: value, range: range).compactMap { Range($0.range, in: value).map { String(value[$0]) } }
    }

    private nonisolated static func requestedDirectory(in value: String) -> String? {
        let patterns = [#"创建\s*(?:一个\s*)?([A-Za-z0-9_.-]+)\s*目录"#,
                        #"(?i)create\s+(?:an?\s+)?([A-Za-z0-9_.-]+)\s+directory"#]
        for pattern in patterns {
            guard let regex = try? NSRegularExpression(pattern: pattern),
                  let match = regex.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)),
                  match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: value) else { continue }
            return String(value[range])
        }
        return nil
    }

    private nonisolated static func json(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private nonisolated static func stableUUID(_ value: String) -> UUID {
        var hash: UInt64 = 14_695_981_039_346_656_037
        for byte in value.utf8 { hash = (hash ^ UInt64(byte)) &* 1_099_511_628_211 }
        let hex = String(format: "%016llx%016llx", hash, hash ^ 0x9e3779b97f4a7c15)
        let text = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-5\(hex.dropFirst(13).prefix(3))-a\(hex.dropFirst(17).prefix(3))-\(hex.dropFirst(20).prefix(12))"
        return UUID(uuidString: text) ?? UUID()
    }
}
