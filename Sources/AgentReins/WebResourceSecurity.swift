import Foundation

enum WebResourceRelation: String, Codable {
    case recommendedByModel
    case requestedByTool
    case contactedByProcess
}

struct WebResourceEvidence: Identifiable {
    let id: String
    let url: String?
    let domain: String
    let relation: WebResourceRelation
    let eventId: UUID
    let timestamp: Date
    let toolName: String?
    let confidence: EvidenceConfidence

    var isGitHubRepository: Bool {
        guard domain == "github.com", let url = URL(string: url ?? "") else { return false }
        return url.pathComponents.filter { $0 != "/" }.count >= 2
    }
}

struct WebResourceChain: Identifiable {
    let id: String
    let sessionId: String
    let turnId: String
    let agent: String?
    let resources: [WebResourceEvidence]
    let contentFindings: [InjectionFinding]
    let codeFindings: [CodeFinding]
    let changedFiles: [String]
    let executedCommands: [String]

    var githubRepositories: [WebResourceEvidence] { resources.filter(\.isGitHubRepository) }

    var risk: String {
        let severities = contentFindings.map(\.severity) + codeFindings.map(\.severity)
        if severities.contains("critical") { return "critical" }
        if severities.contains("high") { return "high" }
        if !githubRepositories.isEmpty && !executedCommands.isEmpty { return "high" }
        if severities.contains("medium") || !githubRepositories.isEmpty { return "medium" }
        return "info"
    }

    var summary: String {
        let sites = Set(resources.map(\.domain)).count
        return "\(agent?.capitalized ?? "Agent") used \(sites) external destination(s), changed \(changedFiles.count) file(s), and produced \(contentFindings.count + codeFindings.count) security finding(s)."
    }
}

/// Builds one external-resource-to-local-consequence chain from exact turn evidence.
/// Events without both session and turn identifiers remain unassociated rather than
/// being attached by timestamp alone.
enum WebResourceSecurity {
    static func build(events: [GuardEvent]) -> [WebResourceChain] {
        let attributable = events.filter { $0.sessionId != nil && $0.turnId != nil }
        let groups = Dictionary(grouping: attributable) { "\($0.sessionId!):\($0.turnId!)" }
        return groups.compactMap { key, events in
            let ordered = events.sorted { $0.ts < $1.ts }
            let resources = resourceEvidence(events: ordered)
            let content = ordered.flatMap { event -> [InjectionFinding] in
                guard let value = event.modelResponse, !value.isEmpty else { return [] }
                return ExternalContentSecurity.scan(value)
            }
            let code = ordered.flatMap { $0.codeFindings ?? [] }
            let files = unique(ordered.filter { $0.kind == "file" && $0.op != "read" }.map(\.path))
            let commands = unique(ordered.filter(isExecution).compactMap(\.command))
            guard !resources.isEmpty || !content.isEmpty || !code.isEmpty else { return nil }
            return WebResourceChain(id: key, sessionId: ordered[0].sessionId!, turnId: ordered[0].turnId!,
                agent: ordered.compactMap(\.agent).first, resources: resources,
                contentFindings: uniqueFindings(content), codeFindings: uniqueCodeFindings(code),
                changedFiles: files, executedCommands: commands)
        }.sorted { lhs, rhs in
            severityRank(lhs.risk) > severityRank(rhs.risk)
        }
    }

    private static func resourceEvidence(events: [GuardEvent]) -> [WebResourceEvidence] {
        var result: [WebResourceEvidence] = []
        for event in events {
            if let response = event.modelResponse {
                for url in URLs(in: response) {
                    guard let domain = URL(string: url)?.host?.lowercased() else { continue }
                    result.append(evidence(event, url: url, domain: domain, relation: .recommendedByModel,
                                           confidence: .confirmed))
                }
            }
            if let command = event.command {
                for url in URLs(in: command) {
                    guard let domain = URL(string: url)?.host?.lowercased() else { continue }
                    result.append(evidence(event, url: url, domain: domain, relation: .requestedByTool,
                                           confidence: event.attributionConfidence ?? .confirmed))
                }
            }
            if event.kind == "network", let domain = event.remoteDomain ?? event.remoteHost {
                result.append(evidence(event, url: nil, domain: domain.lowercased(), relation: .contactedByProcess,
                                       confidence: event.attributionConfidence ?? .inferred))
            }
        }
        var seen = Set<String>()
        return result.filter { seen.insert("\($0.relation.rawValue):\($0.url ?? $0.domain)").inserted }
    }

    private static func evidence(_ event: GuardEvent, url: String?, domain: String,
                                 relation: WebResourceRelation, confidence: EvidenceConfidence) -> WebResourceEvidence {
        WebResourceEvidence(id: "\(event.id.uuidString):\(relation.rawValue):\(url ?? domain)", url: url,
            domain: domain, relation: relation, eventId: event.id, timestamp: event.ts,
            toolName: event.toolName, confidence: confidence)
    }

    private static func URLs(in text: String) -> [String] {
        let pattern = #"https?://[^\s\"'<>\]\[()]+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..., in: text)
        return regex.matches(in: text, range: range).compactMap { match in
            guard let range = Range(match.range, in: text) else { return nil }
            return String(text[range]).trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?"))
        }
    }

    private static func isExecution(_ event: GuardEvent) -> Bool {
        guard let command = event.command?.lowercased() else { return false }
        if event.kind == "cmd" && event.op == "exec" { return true }
        let tool = event.toolName?.lowercased() ?? ""
        return ["bash", "shell", "terminal", "powershell"].contains(where: tool.contains) &&
            ["git clone", "curl ", "wget ", "npm install", "pnpm install", "pip install", "brew install"]
                .contains(where: command.contains)
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>(); return values.filter { seen.insert($0).inserted }
    }
    private static func uniqueFindings(_ values: [InjectionFinding]) -> [InjectionFinding] {
        var seen = Set<String>(); return values.filter { seen.insert($0.id).inserted }
    }
    private static func uniqueCodeFindings(_ values: [CodeFinding]) -> [CodeFinding] {
        var seen = Set<String>(); return values.filter { seen.insert($0.id).inserted }
    }
    private static func severityRank(_ value: String) -> Int {
        ["info": 0, "medium": 1, "high": 2, "critical": 3][value] ?? 0
    }
}
