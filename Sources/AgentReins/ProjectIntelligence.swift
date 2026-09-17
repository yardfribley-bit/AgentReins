import Foundation

enum ProjectKnowledgeConfidence: String {
    case observed = "Observed"
    case declared = "Declared"
    case inferred = "Inferred"
}

struct ProjectCapability: Identifiable {
    let id: String
    let name: String
    let explanation: String
    let files: [String]
    let confidence: ProjectKnowledgeConfidence
}

struct ProjectArchitectureArea: Identifiable {
    let id: String
    let name: String
    let responsibility: String
    let files: [String]
}

struct ProjectKnowledgeItem: Identifiable {
    let id: String
    let text: String
    let source: String
    let confidence: ProjectKnowledgeConfidence
}

enum ProjectDriftSeverity: String {
    case aligned = "Aligned"
    case review = "Review"
    case conflict = "Conflict"
}

struct ProjectDriftFinding: Identifiable {
    let id: String
    let severity: ProjectDriftSeverity
    let title: String
    let detail: String
}

struct ProjectIntelligenceSnapshot {
    let purpose: ProjectKnowledgeItem
    let currentGoal: ProjectKnowledgeItem?
    let capabilities: [ProjectCapability]
    let architecture: [ProjectArchitectureArea]
    let constraints: [ProjectKnowledgeItem]
    let decisions: [ProjectKnowledgeItem]
    let openQuestions: [ProjectKnowledgeItem]
    let memoryReads: Int
    let memoryWrites: Int
    let drift: [ProjectDriftFinding]
    let observedFileCount: Int
    let lastVerifiedAt: Date?
}

enum ProjectIntelligence {
    static func build(projectPath: String, sessions: [AgentSessionSnapshot],
                      evolution: ProjectEvolutionSnapshot?, index: ProjectIndexSnapshot? = nil) -> ProjectIntelligenceSnapshot {
        let orderedSessions = sessions.sorted { $0.startedAt < $1.startedAt }
        let changes = evolution?.changeSets ?? []
        let allEvents = sessions.flatMap(\.events)
        let intents = sessions.flatMap { session in
            session.turns.compactMap(\.userInput) + session.exchanges.compactMap(\.userIntent)
        }.map(clean).filter(isUsefulText)
        let latestIntent = orderedSessions.last?.turns.last?.userInput.map(clean)
            ?? orderedSessions.last?.latestIntent.map(clean)
        let purposeText = index?.purpose ?? intents.first ?? "Purpose has not been declared in captured Agent activity."
        let purpose = ProjectKnowledgeItem(id: "purpose", text: purposeText,
            source: index?.purpose != nil ? "README · local project index" : (intents.isEmpty ? "No captured requirement" : "Earliest captured requirement"),
            confidence: index?.purpose != nil ? .observed : (intents.isEmpty ? .inferred : .declared))

        let changedFiles = Array(Set(changes.flatMap { $0.createdFiles + $0.modifiedFiles + $0.deletedFiles })).sorted()
        let readFiles = Array(Set(changes.flatMap(\.readFiles))).sorted()
        let indexedFiles = index?.files.map { URL(fileURLWithPath: projectPath).appendingPathComponent($0).path } ?? []
        let files = Array(Set(changedFiles + readFiles + indexedFiles + allEvents.filter { $0.kind == "file" && $0.path != "-" }.map(\.path))).sorted()

        let constraints = extractConstraints(from: sessions)
        let decisions = changes.filter { $0.verification == .verified || $0.verification == .agentReported }
            .prefix(5).map { change in
                ProjectKnowledgeItem(id: "decision:\(change.id)", text: clean(change.requirement),
                    source: "\(formattedAgentName(change.agent)) · \(change.verification.rawValue)",
                    confidence: change.verification == .verified ? .observed : .declared)
            }
        let questions = changes.filter { $0.verification == .failed || $0.verification == .pending }
            .prefix(4).map { change in
                ProjectKnowledgeItem(id: "question:\(change.id)", text: clean(change.requirement),
                    source: change.verification.rawValue, confidence: .observed)
            }

        let verifiedEvents = allEvents.filter {
            $0.kind == "verification" && ["passed", "verified", "success"].contains($0.action.lowercased())
        }
        return ProjectIntelligenceSnapshot(
            purpose: purpose,
            currentGoal: latestIntent.map { ProjectKnowledgeItem(id: "goal", text: $0,
                source: "Latest captured user request", confidence: .declared) },
            capabilities: capabilities(files: files, intents: intents, declaredFeatures: index?.featureNames ?? []),
            architecture: architecture(files: files, projectPath: projectPath, index: index),
            constraints: constraints,
            decisions: Array(decisions),
            openQuestions: Array(questions),
            memoryReads: changes.reduce(0) { $0 + $1.memoryReads },
            memoryWrites: changes.reduce(0) { $0 + $1.memoryWrites },
            drift: driftFindings(changes: changes, sessions: sessions, constraints: constraints),
            observedFileCount: files.count,
            lastVerifiedAt: verifiedEvents.map(\.ts).max())
    }

    private static func capabilities(files: [String], intents: [String], declaredFeatures: [String]) -> [ProjectCapability] {
        struct Rule { let name: String; let explanation: String; let tokens: [String] }
        let rules = [
            Rule(name: "User Experience", explanation: "Application views and interaction surfaces", tokens: ["view", "ui", "screen", "dashboard", "content"]),
            Rule(name: "Agent Runtime", explanation: "Agent discovery, attribution and process behavior", tokens: ["agent", "runtime", "process", "session", "discovery"]),
            Rule(name: "Context & Memory", explanation: "Model context, persistent memory and project understanding", tokens: ["memory", "context", "prompt", "knowledge"]),
            Rule(name: "Network Security", explanation: "External connections, model relays, SSH and destinations", tokens: ["network", "ssh", "proxy", "destination", "relay", "ipgeo"]),
            Rule(name: "Code & File Safety", explanation: "File mutations, generated code and independent verification", tokens: ["file", "code", "scanner", "verification", "requirement"]),
            Rule(name: "Evidence Store", explanation: "Durable raw evidence and activity history", tokens: ["database", "store", "evidence", "journal", "history"]),
            Rule(name: "Web Agent Protection", explanation: "Browser Agent activity and untrusted external content", tokens: ["web", "browser", "externalcontent"])
        ]
        let lowerIntents = intents.joined(separator: " ").lowercased()
        let inferred = rules.compactMap { rule -> ProjectCapability? in
            let matched = files.filter { path in rule.tokens.contains { path.lowercased().contains($0) } }
            guard !matched.isEmpty || rule.tokens.contains(where: lowerIntents.contains) else { return nil }
            return ProjectCapability(id: rule.name, name: rule.name, explanation: rule.explanation,
                files: Array(matched.prefix(8)), confidence: matched.isEmpty ? .inferred : .observed)
        }
        let declared = declaredFeatures.map { name in
            ProjectCapability(id: "readme:\(name)", name: name,
                explanation: "Capability declared in the project README", files: [], confidence: .declared)
        }
        return Array((declared + inferred).prefix(10))
    }

    private static func architecture(files: [String], projectPath: String,
                                     index: ProjectIndexSnapshot?) -> [ProjectArchitectureArea] {
        if let index, !index.areas.isEmpty {
            return index.areas.prefix(7).map { area in
                ProjectArchitectureArea(id: area.name, name: area.name,
                    responsibility: responsibility(for: area.name, files: area.files), files: area.files)
            }
        }
        let relative = files.map { path -> String in
            path.hasPrefix(projectPath) ? String(path.dropFirst(projectPath.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/")) : path
        }
        let grouped = Dictionary(grouping: relative) { path -> String in
            let parts = path.split(separator: "/")
            if let source = parts.firstIndex(where: { ["sources", "src", "app", "packages"].contains($0.lowercased()) }), parts.count > source + 1 {
                return String(parts[source + 1])
            }
            return parts.count > 1 ? String(parts[0]) : "Project Root"
        }
        return grouped.map { name, rows in
            ProjectArchitectureArea(id: name, name: name,
                responsibility: responsibility(for: name, files: rows), files: Array(rows.sorted().prefix(12)))
        }.sorted { $0.files.count > $1.files.count }.prefix(7).map { $0 }
    }

    private static func responsibility(for name: String, files: [String]) -> String {
        let text = "\(name) \(files.joined(separator: " "))".lowercased()
        if text.contains("test") { return "Automated verification" }
        if text.contains("view") || text.contains("ui") { return "User-facing product experience" }
        if text.contains("collector") || text.contains("sight") { return "Runtime evidence collection" }
        if text.contains("model") || text.contains("analysis") { return "Analysis and project interpretation" }
        if text.contains("database") || text.contains("store") { return "Evidence persistence" }
        return "Project implementation area"
    }

    private static func extractConstraints(from sessions: [AgentSessionSnapshot]) -> [ProjectKnowledgeItem] {
        let text = sessions.flatMap { session in
            // Project cards are recomputed by SwiftUI. Never walk the full model
            // context here: prompts can be tens of thousands of tokens and remain
            // available in the evidence inspector when the user asks for them.
            session.turns.compactMap(\.userInput) + session.exchanges.compactMap(\.userIntent)
        }.joined(separator: "\n")
        let markers = ["must", "should", "only", "do not", "don't", "必须", "需要", "不要", "只要", "只能"]
        var seen = Set<String>()
        return text.components(separatedBy: .newlines).map(clean).filter { line in
            line.count >= 12 && line.count <= 240 && markers.contains { line.lowercased().contains($0) }
        }.filter { seen.insert($0.lowercased()).inserted }.prefix(6).enumerated().map { index, line in
            ProjectKnowledgeItem(id: "constraint:\(index)", text: line,
                source: "Captured user requirement", confidence: .declared)
        }
    }

    private static func driftFindings(changes: [ProjectChangeSet], sessions: [AgentSessionSnapshot],
                                      constraints: [ProjectKnowledgeItem]) -> [ProjectDriftFinding] {
        var findings: [ProjectDriftFinding] = []
        for change in changes.prefix(12) where change.verification == .agentReported {
            findings.append(ProjectDriftFinding(id: "unverified:\(change.id)", severity: .review,
                title: "Agent completion is not independently verified",
                detail: "\(formattedAgentName(change.agent)) reported this task complete, but no passing verification evidence was captured."))
        }
        for change in changes.prefix(12) where change.verification == .failed {
            findings.append(ProjectDriftFinding(id: "failed:\(change.id)", severity: .conflict,
                title: "Reported work conflicts with verification",
                detail: "The observed verification failed for: \(clean(change.requirement))"))
        }
        if constraints.isEmpty && !sessions.isEmpty {
            findings.append(ProjectDriftFinding(id: "constraints", severity: .review,
                title: "Project constraints are not explicit",
                detail: "AgentReins captured activity, but could not identify a stable set of project constraints in the recent context."))
        }
        if findings.isEmpty {
            findings.append(ProjectDriftFinding(id: "aligned", severity: .aligned,
                title: "No contradiction observed in the recent window",
                detail: "This means no conflict was found in captured evidence; it is not a guarantee of correctness."))
        }
        return Array(findings.prefix(5))
    }

    private static func clean(_ value: String) -> String {
        value.replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "  ", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func isUsefulText(_ value: String) -> Bool {
        value.count >= 8 && !value.hasPrefix("<system-reminder")
    }
}
