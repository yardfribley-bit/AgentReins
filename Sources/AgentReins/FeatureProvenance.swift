import Foundation

struct FeatureProvenanceTool: Codable, Sendable, Equatable {
    let name: String
    let server: String?
    let arguments: String?
    let state: ToolCallState
    let resultPreview: String?
}

struct FeatureProvenanceRecord: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let sessionID: String
    let turnID: String?
    let agentID: String
    let userPrompt: String?
    let model: String?
    let provider: String?
    let tools: [FeatureProvenanceTool]
    let files: [String]
    let commits: [String]
    let verification: [VerificationEvidence]
    let startedAt: Date
    let lastEventAt: Date
    let relevance: Double
    let matchedEvidenceIDs: [String]

    var evidenceAvailable: Bool { !matchedEvidenceIDs.isEmpty }
}

/// Evidence-only feature history lookup. It ranks recorded turns and never
/// asks a model to invent a prompt, tool call, or relationship that was not
/// captured by an adapter or independently observed.
enum FeatureProvenanceIndex {
    static func search(query: String, projectID: String,
                       events: [AgentEventEnvelope], additionalTerms: [String] = [],
                       limit: Int = 20) -> [FeatureProvenanceRecord] {
        let terms = Array(Set(queryTerms(query) + additionalTerms.flatMap(queryTerms))).sorted()
        guard !terms.isEmpty else { return [] }
        let scoped = events.filter { $0.projectID == projectID }
        let groups = Dictionary(grouping: scoped) { event in
            "\(event.sessionID)\u{0}\(event.turnID ?? "unattributed")"
        }
        return groups.compactMap { key, rows -> FeatureProvenanceRecord? in
            let ordered = rows.sorted {
                if $0.occurredAt == $1.occurredAt { return $0.sequence < $1.sequence }
                return $0.occurredAt < $1.occurredAt
            }
            guard let first = ordered.first, let last = ordered.last else { return nil }
            var weightedTexts: [(String, Double, String)] = []
            var prompt: String?
            var model: String?
            var provider: String?
            var calls: [String: ToolCallLifecycleEvidence] = [:]
            var outputs: [String: ToolOutputEvidence] = [:]
            var files = Set<String>()
            var commits = Set<String>()
            var verification: [VerificationEvidence] = []

            for event in ordered {
                switch event.payload {
                case .userPrompt(let value):
                    if prompt == nil { prompt = value.rawText }
                    weightedTexts.append((value.rawText, 6, event.id))
                case .contextPrepared(let value):
                    model = value.model ?? model; provider = value.provider ?? provider
                    for layer in value.layers { weightedTexts.append((layer.summary, 1, event.id)) }
                case .modelMessage(let value):
                    model = value.model ?? model; provider = value.provider ?? provider
                    weightedTexts.append((value.text, 2, event.id))
                case .plan(let value):
                    weightedTexts.append((([value.title].compactMap { $0 } + value.steps).joined(separator: " "), 3, event.id))
                case .toolCall(let value):
                    calls[value.callID] = value
                    weightedTexts.append(("\(value.toolName) \(value.arguments ?? "")", 3, event.id))
                case .toolOutput(let value):
                    outputs[value.callID] = value
                    if let output = value.output { weightedTexts.append((output, 1, event.id)) }
                case .fileActivity(let value):
                    files.insert(value.path)
                    weightedTexts.append(("\(value.path) \(value.patch ?? "")", 4, event.id))
                case .memoryActivity(let value):
                    weightedTexts.append(("\(value.key ?? "") \(value.storageLocator ?? "") \(value.summary)", 2, event.id))
                case .checkpoint(let value):
                    commits.insert(value.commitHash)
                    files.formUnion(value.touchedPaths)
                    weightedTexts.append((value.touchedPaths.joined(separator: " "), 4, event.id))
                case .verification(let value):
                    verification.append(value)
                    weightedTexts.append((value.summary, 2, event.id))
                case .prediction(let value): weightedTexts.append((value.summary, 1, event.id))
                case .networkActivity(let value): weightedTexts.append((value.destination, 1, event.id))
                case .turnState, .contextUsage: break
                }
            }

            var score = 0.0
            var matched = Set<String>()
            for (text, weight, evidenceID) in weightedTexts {
                let normalized = normalize(text)
                let hits = terms.filter { normalized.contains($0) }.count
                if hits > 0 {
                    score += weight * Double(hits) / Double(terms.count)
                    matched.insert(evidenceID)
                }
            }
            guard score > 0 else { return nil }
            let tools = calls.values.sorted { ($0.startedAt ?? first.occurredAt) < ($1.startedAt ?? first.occurredAt) }
                .map { call in
                    FeatureProvenanceTool(name: call.toolName, server: call.serverName,
                                          arguments: call.arguments, state: call.state,
                                          resultPreview: outputs[call.callID]?.output.map { String($0.prefix(500)) })
                }
            return FeatureProvenanceRecord(
                id: key, projectID: projectID, sessionID: first.sessionID,
                turnID: first.turnID, agentID: first.agentID, userPrompt: prompt,
                model: model, provider: provider, tools: tools,
                files: files.sorted(), commits: commits.sorted(), verification: verification,
                startedAt: first.occurredAt, lastEventAt: last.occurredAt,
                relevance: score, matchedEvidenceIDs: matched.sorted())
        }
        .sorted {
            if $0.relevance == $1.relevance { return $0.lastEventAt > $1.lastEventAt }
            return $0.relevance > $1.relevance
        }
        .prefix(max(1, min(limit, 100)))
        .map { $0 }
    }

    private static func queryTerms(_ query: String) -> [String] {
        let normalized = normalize(query)
        let stopWords: Set<String> = ["的", "了", "是", "用", "功能", "哪个", "什么", "当初",
                                      "a", "an", "the", "feature", "which", "what", "used"]
        let latin = normalized.split { !$0.isLetter && !$0.isNumber }.map(String.init)
            .filter { $0.count > 1 && !stopWords.contains($0) }
        let han = normalized.unicodeScalars.filter { scalar in
            (0x4E00...0x9FFF).contains(Int(scalar.value))
        }.map(String.init).filter { !stopWords.contains($0) }
        return Array(Set(latin + han)).sorted()
    }

    private static func normalize(_ value: String) -> String {
        value.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            .lowercased()
    }
}
