import Foundation

enum ExternalSourceKind: String {
    case web = "Web"
    case mcp = "MCP"
    case skill = "Skill"
    case localFile = "Local file"
    case terminal = "Terminal"
    case memory = "Memory"
    case unknown = "Unknown"
}

enum ContentTrust: String {
    case untrusted = "Untrusted"
    case localUnknown = "Local / unverified"
    case unknown = "Unknown"
}

enum InjectionCategory: String {
    case instructionOverride = "Instruction override"
    case secretExfiltration = "Secret exfiltration"
    case unsafeExecution = "Unsafe execution"
    case safeguardBypass = "Safeguard bypass"
    case memoryPoisoning = "Memory poisoning"
    case authorityImpersonation = "Authority impersonation"
    case obfuscation = "Obfuscation"
}

struct InjectionFinding: Identifiable, Equatable {
    let id: String
    let category: InjectionCategory
    let severity: String
    let confidence: String
    let evidence: String
}

struct ExternalContentAssessment: Identifiable, Equatable {
    let id: UUID
    let sourceKind: ExternalSourceKind
    let sourceIdentity: String
    let trust: ContentTrust
    let turnId: String?
    let traceId: String?
    let timestamp: Date
    let findings: [InjectionFinding]
}

struct InfluenceChain: Identifiable, Equatable {
    let id: String
    let source: ExternalContentAssessment
    let nextActionName: String?
    let nextActionCommand: String?
    let evidence: ContextEvidenceLevel
    let explanation: String
}

enum ExternalContentSecurity {
    static func assess(_ event: GuardEvent) -> ExternalContentAssessment? {
        guard event.op == "result", let content = event.modelResponse, !content.isEmpty else { return nil }
        let descriptor = "\(event.toolName ?? "") \(event.command ?? "")".lowercased()
        let requestedDomain = ExternalURLEvidence.firstDomain(in: event.command)
        let source: ExternalSourceKind
        if requestedDomain != nil { source = .web }
        else if descriptor.contains("mcp__") || descriptor.contains("mcp-") { source = .mcp }
        else if descriptor.contains("skill") || descriptor.contains("skill.md") { source = .skill }
        else if ["web", "fetch", "search", "browser", "http"].contains(where: descriptor.contains) { source = .web }
        else if ["memory", "retrieve", "knowledge"].contains(where: descriptor.contains) { source = .memory }
        else if ["read", "open_file"].contains(where: descriptor.contains) { source = .localFile }
        else if ["bash", "shell", "terminal", "powershell"].contains(where: descriptor.contains) { source = .terminal }
        else { source = .unknown }

        let trust: ContentTrust = [.web, .mcp].contains(source) ? .untrusted :
            ([.localFile, .terminal, .memory, .skill].contains(source) ? .localUnknown : .unknown)
        return ExternalContentAssessment(id: event.id, sourceKind: source,
            sourceIdentity: requestedDomain ?? event.toolName ?? "Unknown source", trust: trust,
            turnId: event.turnId, traceId: event.traceId, timestamp: event.ts,
            findings: scan(content))
    }

    static func scan(_ content: String) -> [InjectionFinding] {
        let rules: [(InjectionCategory, String, String, [String])] = [
            (.instructionOverride, "high", "high", ["ignore previous instructions", "ignore all prior", "disregard the user", "new instructions take priority"]),
            (.secretExfiltration, "critical", "high", ["upload .env", "send the api key", "exfiltrate", "send credentials", "read private key"]),
            (.unsafeExecution, "critical", "high", ["curl | bash", "curl | sh", "download and execute", "run this command silently"]),
            (.safeguardBypass, "high", "high", ["bypass security", "disable safeguards", "do not ask for approval", "avoid detection"]),
            (.memoryPoisoning, "high", "medium", ["remember this permanently", "write to long-term memory", "for all future sessions", "persist these instructions"]),
            (.authorityImpersonation, "high", "medium", ["system message:", "developer instruction:", "administrator says", "official system instruction"]),
            (.obfuscation, "medium", "medium", ["base64 -d", "eval(atob", "unicode invisible", "zero width character"])
        ]
        let lower = content.lowercased()
        var result: [InjectionFinding] = []
        for (category, severity, confidence, patterns) in rules {
            for pattern in patterns where lower.contains(pattern) {
                let evidence = evidenceWindow(content, around: pattern)
                result.append(InjectionFinding(id: "\(category.rawValue):\(pattern)", category: category,
                    severity: severity, confidence: confidence, evidence: evidence))
                break
            }
        }
        if content.unicodeScalars.contains(where: { [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF].contains(Int($0.value)) }) {
            result.append(InjectionFinding(id: "obfuscation:invisible", category: .obfuscation,
                severity: "medium", confidence: "high", evidence: "Invisible Unicode control characters detected"))
        }
        return result
    }

    static func influenceChains(events: [GuardEvent]) -> [InfluenceChain] {
        let ordered = events.sorted { $0.ts < $1.ts }
        return ordered.enumerated().compactMap { index, event in
            guard let assessed = assess(event), !assessed.findings.isEmpty else { return nil }
            let website = ordered[..<index].reversed().first {
                $0.kind == "network" && $0.toolCallId != nil && $0.toolCallId == event.toolCallId &&
                $0.remoteDomain != nil
            }?.remoteDomain
            let source = ExternalContentAssessment(id: assessed.id, sourceKind: assessed.sourceKind,
                sourceIdentity: website ?? assessed.sourceIdentity, trust: assessed.trust,
                turnId: assessed.turnId, traceId: assessed.traceId, timestamp: assessed.timestamp,
                findings: assessed.findings)
            let later = ordered.dropFirst(index + 1).first {
                $0.op == "call" && $0.turnId == event.turnId
            }
            let level: ContextEvidenceLevel = later == nil ? .unavailable :
                (later?.traceId != nil && later?.traceId == event.traceId ? .partial : .inferred)
            let explanation: String
            switch level {
            case .partial: explanation = "A later tool call shares the same turn and trace. Influence is possible but not proven without model attribution."
            case .inferred: explanation = "A later tool call occurred in the same turn. This is temporal correlation, not proof of causation."
            case .unavailable: explanation = "No later tool call was recorded in this turn."
            case .exact: explanation = "The agent explicitly attributed the action to this content."
            }
            return InfluenceChain(id: "\(source.id.uuidString):\(later?.id.uuidString ?? "none")",
                source: source, nextActionName: later?.toolName,
                nextActionCommand: later?.command, evidence: level, explanation: explanation)
        }
    }

    private static func evidenceWindow(_ content: String, around pattern: String) -> String {
        let lower = content.lowercased()
        guard let range = lower.range(of: pattern) else { return String(content.prefix(220)) }
        let offset = lower.distance(from: lower.startIndex, to: range.lowerBound)
        let start = content.index(content.startIndex, offsetBy: max(0, offset - 70))
        let end = content.index(content.startIndex, offsetBy: min(content.count, offset + pattern.count + 100))
        return String(content[start..<end]).replacingOccurrences(of: "\n", with: " ")
    }
}

extension AgentTurn {
    var externalContentAssessments: [ExternalContentAssessment] {
        toolCalls.compactMap { call in
            guard let result = call.result else { return nil }
            let event = GuardEvent(kind: "tool", ruleId: "derived", path: "-", command: call.arguments,
                agent: nil, op: "result", severity: "info", ts: call.completedAt ?? call.startedAt,
                action: call.status, turnId: id, toolCallId: call.id, modelResponse: result, toolName: call.name)
            return ExternalContentSecurity.assess(event)
        }
    }
}
