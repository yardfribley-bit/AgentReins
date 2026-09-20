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
    let memoryReads: Int
    let memoryWrites: Int
    let memoryLocators: [String]
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
        let anchorTerms = terms.filter { $0.unicodeScalars.contains { $0.isASCII && ($0.properties.isAlphabetic || CharacterSet.decimalDigits.contains($0)) } }
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
            // Required query anchors must come from evidence owned by this
            // turn. Injected conversation history and tool output may quote
            // unrelated work from an older turn.
            var anchorTexts: [String] = []
            var prompt: String?
            var model: String?
            var provider: String?
            var calls: [String: ToolCallLifecycleEvidence] = [:]
            var outputs: [String: ToolOutputEvidence] = [:]
            var files = Set<String>()
            var memoryReads = 0
            var memoryWrites = 0
            var memoryLocators = Set<String>()
            var commits = Set<String>()
            var verification: [VerificationEvidence] = []

            for event in ordered {
                switch event.payload {
                case .userPrompt(let value):
                    if prompt == nil { prompt = value.rawText }
                    weightedTexts.append((value.rawText, 6, event.id))
                    anchorTexts.append(value.rawText)
                case .contextPrepared(let value):
                    model = value.model ?? model; provider = value.provider ?? provider
                    for layer in value.layers { weightedTexts.append((layer.summary, 1, event.id)) }
                case .modelMessage(let value):
                    model = value.model ?? model; provider = value.provider ?? provider
                    weightedTexts.append((value.text, 2, event.id))
                case .plan(let value):
                    let planText = ([value.title].compactMap { $0 } + value.steps).joined(separator: " ")
                    weightedTexts.append((planText, 3, event.id))
                    anchorTexts.append(planText)
                case .toolCall(let value):
                    if let existing = calls[value.callID], isUnknownTool(value.toolName), !isUnknownTool(existing.toolName) {
                        // Incremental transcript reads may see an output without
                        // replaying the original call. Never let that placeholder
                        // erase a tool name already captured for the same call ID.
                        calls[value.callID] = ToolCallLifecycleEvidence(
                            callID: value.callID, toolName: existing.toolName,
                            serverName: existing.serverName ?? value.serverName,
                            arguments: existing.arguments ?? value.arguments,
                            argumentsDigest: existing.argumentsDigest ?? value.argumentsDigest,
                            state: value.state, startedAt: existing.startedAt ?? value.startedAt,
                            completedAt: value.completedAt ?? existing.completedAt,
                            exitCode: value.exitCode ?? existing.exitCode,
                            evidenceIDs: Array(Set(existing.evidenceIDs + value.evidenceIDs)).sorted())
                    } else {
                        calls[value.callID] = value
                    }
                    weightedTexts.append(("\(value.toolName) \(value.arguments ?? "")", 3, event.id))
                    anchorTexts.append("\(value.toolName) \(value.arguments ?? "")")
                case .toolOutput(let value):
                    outputs[value.callID] = value
                    if let output = value.output { weightedTexts.append((output, 1, event.id)) }
                case .fileActivity(let value):
                    if plausibleProjectPath(value.path) { files.insert(value.path) }
                    weightedTexts.append(("\(value.path) \(value.patch ?? "")", 4, event.id))
                    if plausibleProjectPath(value.path) { anchorTexts.append(value.path) }
                case .memoryActivity(let value):
                    if value.operation == .retrieve { memoryReads += 1 } else { memoryWrites += 1 }
                    if let locator = value.storageLocator, plausibleProjectPath(locator) {
                        memoryLocators.insert(locator)
                    }
                    weightedTexts.append(("\(value.key ?? "") \(value.storageLocator ?? "") \(value.summary)", 2, event.id))
                case .checkpoint(let value):
                    commits.insert(value.commitHash)
                    let validPaths = value.touchedPaths.filter(plausibleProjectPath)
                    files.formUnion(validPaths)
                    weightedTexts.append((value.touchedPaths.joined(separator: " "), 4, event.id))
                    anchorTexts.append(contentsOf: validPaths)
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
            let normalizedAnchors = normalize(anchorTexts.joined(separator: " "))
            let matchedAnchors = Set(anchorTerms.filter { normalizedAnchors.contains($0) })
            guard score > 0, anchorTerms.isEmpty || !matchedAnchors.isEmpty else { return nil }
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
                files: files.sorted(), memoryReads: memoryReads, memoryWrites: memoryWrites,
                memoryLocators: memoryLocators.sorted(), commits: commits.sorted(), verification: verification,
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

    private static func isUnknownTool(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized.isEmpty || normalized == "unknown" || normalized == "unknown_tool" || normalized == "tool"
    }

    private static func plausibleProjectPath(_ value: String) -> Bool {
        let path = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, path.count <= 512 else { return false }
        guard !path.contains("\"") && !path.contains("{") && !path.contains("}")
                && !path.contains("yield_time") && !path.contains("max_output") else { return false }
        guard !path.contains(";") && !path.contains(",") && !path.contains("\n") else { return false }
        guard !path.contains(" ") else { return false }
        let leaf = URL(fileURLWithPath: path).lastPathComponent
        guard !leaf.isEmpty, leaf != ".", leaf != ".." else { return false }
        return path.hasPrefix("/") || path.hasPrefix("./") || path.contains("/") || leaf.contains(".")
    }
}
