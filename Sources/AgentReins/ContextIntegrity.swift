import Foundation

enum ContextEvidenceLevel: String {
    case exact = "Exact"
    case partial = "Partial"
    case inferred = "Inferred"
    case unavailable = "Unavailable"
}

enum ContextHealth: String {
    case healthy = "Healthy"
    case growing = "Growing"
    case memoryAtRisk = "Memory at risk"
}

struct ContextIntegrityAssessment: Equatable {
    let health: ContextHealth
    let evidence: ContextEvidenceLevel
    let requirementRetentionPercent: Int?
    let duplicatePayloadPercent: Int
    let toolNoisePercent: Int
    let findings: [String]

    static func assess(userInput: String?, capturedPrompt: String?, response: String?,
                       toolCalls: [AgentToolCall], growth: ContextGrowthMetrics?) -> ContextIntegrityAssessment {
        let payloads = toolCalls.compactMap { call -> String? in
            let value = [call.arguments, call.result].compactMap { $0 }.joined(separator: "\n")
            return value.isEmpty ? nil : value
        }
        let promptBytes = capturedPrompt?.utf8.count ?? 0
        let responseBytes = response?.utf8.count ?? 0
        let payloadBytes = payloads.reduce(0) { $0 + $1.utf8.count }
        let recordedBytes = max(1, promptBytes + responseBytes + payloadBytes)
        let toolNoise = Int((Double(payloadBytes) / Double(recordedBytes) * 100).rounded())

        var seen = Set<String>()
        var duplicateBytes = 0
        for payload in payloads {
            let normalized = normalize(payload)
            if !normalized.isEmpty && !seen.insert(normalized).inserted { duplicateBytes += payload.utf8.count }
        }
        let duplicatePercent = payloadBytes == 0 ? 0 : Int((Double(duplicateBytes) / Double(payloadBytes) * 100).rounded())

        let requirements = meaningfulTerms(userInput ?? "")
        let downstream = normalize(([response] + toolCalls.flatMap { [$0.arguments, $0.result] })
            .compactMap { $0 }.joined(separator: " "))
        let retained = requirements.isEmpty ? nil : Int((Double(requirements.filter { downstream.contains($0) }.count) /
            Double(requirements.count) * 100).rounded())

        let evidence: ContextEvidenceLevel = capturedPrompt == nil ? .inferred : .partial
        var findings: [String] = []
        if let growth, growth.growthPercent >= 25 {
            findings.append("Input grew \(Int(growth.growthPercent.rounded()))% across \(growth.requestCount) model requests.")
        }
        if duplicatePercent >= 15 { findings.append("\(duplicatePercent)% of recorded tool payload bytes were exact repeats.") }
        if toolNoise >= 50 { findings.append("Tool arguments and results occupy \(toolNoise)% of recorded content.") }
        if let retained, retained < 50 {
            findings.append("Only \(retained)% of identifiable requirement terms appear in downstream evidence.")
        }
        if evidence != .exact {
            findings.append("The agent did not expose every provider request body, so requirement loss is inferred rather than proven.")
        }

        let memoryRisk = duplicatePercent >= 30 || toolNoise >= 70 || (retained.map { $0 < 35 } ?? false)
        let growing = growth?.needsAttention == true || duplicatePercent >= 15 || toolNoise >= 50
        return ContextIntegrityAssessment(health: memoryRisk ? .memoryAtRisk : (growing ? .growing : .healthy),
            evidence: evidence, requirementRetentionPercent: retained,
            duplicatePayloadPercent: duplicatePercent, toolNoisePercent: toolNoise, findings: findings)
    }

    private static func normalize(_ text: String) -> String {
        text.lowercased().split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    private static func meaningfulTerms(_ text: String) -> Set<String> {
        let stop = Set(["the", "and", "that", "this", "with", "from", "into", "for", "are", "was", "you", "your", "please", "then"])
        return Set(text.lowercased().components(separatedBy: CharacterSet.alphanumerics.inverted)
            .filter { $0.count >= 4 && !stop.contains($0) })
    }
}

extension AgentTurn {
    var contextIntegrity: ContextIntegrityAssessment {
        ContextIntegrityAssessment.assess(userInput: userInput, capturedPrompt: fullPrompt,
            response: finalResponse, toolCalls: toolCalls, growth: contextGrowth)
    }
}
