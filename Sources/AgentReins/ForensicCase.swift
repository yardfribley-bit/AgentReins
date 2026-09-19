import Foundation

/// An investigation-ready projection built from one admitted security incident.
/// It stays read-only: raw evidence remains in EvidenceDatabase.
struct ForensicCase: Identifiable, Sendable {
    enum Confidence: String, Sendable, CaseIterable {
        case confirmed
        case correlated
        case inferred
        case unverified
    }

    struct Finding: Identifiable, Sendable {
        let id: String
        let title: String
        let detail: String
        let confidence: Confidence
        let evidenceIDs: [UUID]
    }

    struct Coverage: Identifiable, Sendable {
        let id: String
        let capability: String
        let available: Bool
        let detail: String
    }

    struct TimelineEntry: Identifiable, Sendable {
        let id: UUID
        let event: GuardEvent
        let relation: String
        let summary: String
    }

    let id: UUID
    let incident: SecurityIncident
    let title: String
    let agent: String
    let sessionID: String?
    let turnID: String?
    let startedAt: Date
    let endedAt: Date
    let intent: String?
    let findings: [Finding]
    let coverage: [Coverage]
    let timeline: [TimelineEntry]
    let collectorWarnings: [String]

    var coveragePercent: Int {
        guard !coverage.isEmpty else { return 0 }
        return Int((Double(coverage.filter(\.available).count) / Double(coverage.count) * 100).rounded())
    }

    var confirmedCount: Int { findings.filter { $0.confidence == .confirmed }.count }
    var openQuestionCount: Int { findings.filter { $0.confidence == .unverified }.count }

    static func build(incident: SecurityIncident, allEvents: [GuardEvent],
                      health: [CollectorHealthRecord]) -> ForensicCase {
        let session = incident.events.compactMap(\.sessionId).first
        let turn = incident.events.compactMap(\.turnId).first
        let incidentIDs = Set(incident.events.map(\.id))
        let lowerBound = incident.ts.addingTimeInterval(-30)
        let upperBound = incident.lastTs.addingTimeInterval(120)

        let related = allEvents.filter { event in
            if incidentIDs.contains(event.id) { return true }
            if let session, event.sessionId == session {
                if let turn, event.turnId == turn { return true }
                return event.ts >= lowerBound && event.ts <= upperBound
            }
            if let trace = incident.events.compactMap(\.traceId).first, event.traceId == trace { return true }
            return false
        }
        let evidence = deduplicated(incident.events + related).sorted { $0.ts < $1.ts }
        let presentation = SecurityIncidentPresentation.make(incident, chinese: false)
        let intent = evidence.compactMap(\.userIntent).first
        let findings = buildFindings(incident: incident, evidence: evidence)
        let coverage = buildCoverage(evidence)
        let timeline = evidence.map { event in
            TimelineEntry(id: event.id, event: event,
                          relation: relation(for: event, incidentIDs: incidentIDs),
                          summary: summary(for: event))
        }
        let warnings = health.filter { $0.state != .healthy }.map { item in
            let lag = item.lagSeconds.map { " · lag \(Int($0))s" } ?? ""
            return "\(item.source): \(item.state.rawValue)\(lag)\(item.detail.map { " · \($0)" } ?? "")"
        }
        return ForensicCase(id: incident.id, incident: incident, title: presentation.title,
                            agent: incident.agent ?? "Unknown agent", sessionID: session, turnID: turn,
                            startedAt: evidence.first?.ts ?? incident.ts,
                            endedAt: evidence.last?.ts ?? incident.lastTs, intent: intent,
                            findings: findings, coverage: coverage, timeline: timeline,
                            collectorWarnings: warnings)
    }

    private static func buildFindings(incident: SecurityIncident, evidence: [GuardEvent]) -> [Finding] {
        var result: [Finding] = []
        let incidentIDs = incident.events.map(\.id)
        let paths = evidence.filter { $0.kind == "file" }.map(\.path).filter { $0 != "-" }
        let endpoints = evidence.compactMap { $0.remoteDomain ?? $0.remoteHost }
        let tools = evidence.compactMap(\.toolName)
        let hasSensitiveRule = incident.ruleIDs.contains {
            $0.contains("credential") || $0.contains("sensitive") || $0.contains("secret")
        }

        if hasSensitiveRule || paths.contains(where: sensitivePath) {
            let asset = paths.first(where: sensitivePath) ?? paths.first ?? "a credential-like value"
            result.append(Finding(id: "sensitive-access", title: "Sensitive data access observed",
                                  detail: asset, confidence: .confirmed, evidenceIDs: incidentIDs))
        }
        if !tools.isEmpty {
            result.append(Finding(id: "tools", title: "Agent invoked tools",
                                  detail: Array(Set(tools)).sorted().joined(separator: ", "),
                                  confidence: .confirmed,
                                  evidenceIDs: evidence.filter { $0.kind == "tool" }.map(\.id)))
        }
        if !endpoints.isEmpty {
            result.append(Finding(id: "network", title: "External destinations observed",
                                  detail: Array(Set(endpoints)).sorted().joined(separator: ", "),
                                  confidence: .confirmed,
                                  evidenceIDs: evidence.filter { $0.kind == "network" }.map(\.id)))
        }
        if (hasSensitiveRule || paths.contains(where: sensitivePath)) && !endpoints.isEmpty {
            result.append(Finding(id: "same-task", title: "Sensitive access and network activity share this task",
                                  detail: "The events are correlated by session/turn or trace. This does not prove content transmission.",
                                  confidence: .correlated, evidenceIDs: evidence.map(\.id)))
            result.append(Finding(id: "exfiltration", title: "Sensitive content was transmitted externally",
                                  detail: "Not proven: no complete request body or matching sensitive-data fingerprint is available.",
                                  confidence: .unverified, evidenceIDs: []))
        }
        if evidence.contains(where: { $0.kind == "model" && $0.op == "prompt" }) {
            result.append(Finding(id: "model-request", title: "A model request occurred in this task",
                                  detail: evidence.compactMap(\.model).first ?? "Model identity was not captured",
                                  confidence: .confirmed,
                                  evidenceIDs: evidence.filter { $0.kind == "model" && $0.op == "prompt" }.map(\.id)))
        }
        if result.isEmpty {
            result.append(Finding(id: "admitted", title: "Policy finding admitted for investigation",
                                  detail: incident.summary, confidence: .confirmed, evidenceIDs: incidentIDs))
        }
        return result
    }

    private static func buildCoverage(_ evidence: [GuardEvent]) -> [Coverage] {
        let promptRows = evidence.filter { $0.kind == "model" && $0.op == "prompt" }
        let hasPromptBody = promptRows.contains { !($0.modelPrompt ?? "").isEmpty }
        let hasNetwork = evidence.contains { $0.kind == "network" && ($0.remoteDomain != nil || $0.remoteHost != nil) }
        let upstreamVerified = evidence.contains {
            $0.ruleId.contains("provider_verified") || $0.attributionMethod?.localizedCaseInsensitiveContains("verified upstream") == true
        }
        return [
            Coverage(id: "intent", capability: "User intent", available: evidence.contains { $0.userIntent != nil },
                     detail: "Correlated local agent conversation"),
            Coverage(id: "prompt-meta", capability: "Model request metadata", available: !promptRows.isEmpty,
                     detail: "Request timing, model label and token metadata"),
            Coverage(id: "prompt-body", capability: "Complete model request body", available: hasPromptBody,
                     detail: hasPromptBody ? "Captured by the agent adapter" : "Unavailable; TLS payload was not captured"),
            Coverage(id: "tools", capability: "Tool calls and results", available: evidence.contains { $0.kind == "tool" },
                     detail: "Tool lifecycle evidence"),
            Coverage(id: "files", capability: "File activity", available: evidence.contains { $0.kind == "file" },
                     detail: "Observed or derived file operations"),
            Coverage(id: "network", capability: "Network destination", available: hasNetwork,
                     detail: hasNetwork ? "Domain/IP destination observed" : "No linked destination"),
            Coverage(id: "payload", capability: "Network request payload", available: false,
                     detail: "Encrypted payload not captured"),
            Coverage(id: "upstream", capability: "Verified upstream model", available: upstreamVerified,
                     detail: upstreamVerified ? "Provider identity independently verified" : "Relay claim is not independent proof")
        ]
    }

    private static func relation(for event: GuardEvent, incidentIDs: Set<UUID>) -> String {
        if incidentIDs.contains(event.id) { return "TRIGGERED_CASE" }
        switch event.kind {
        case "model": return event.op == "prompt" ? "INCLUDED_IN_REQUEST" : "RETURNED_BY_MODEL"
        case "tool": return event.op == "call" ? "INVOKED_TOOL" : "RETURNED_BY_TOOL"
        case "file": return event.op == "read" ? "READ_FROM" : "CHANGED_FILE"
        case "network": return "CONNECTED_TO"
        case "memory": return "PERSISTED_AS_MEMORY"
        default: return "FOLLOWED_BY"
        }
    }

    private static func summary(for event: GuardEvent) -> String {
        if event.kind == "network" {
            return "\(event.remoteDomain ?? event.remoteHost ?? "Unknown destination"):\(event.remotePort.map(String.init) ?? "?")"
        }
        if event.kind == "file" { return "\(event.op.capitalized) \(event.path)" }
        if let tool = event.toolName { return "\(event.op.capitalized) \(tool)" }
        if let value = event.command ?? event.modelResponse ?? event.modelPrompt {
            return String(ProcessArgumentRedactor.redact(value).prefix(240))
        }
        return "\(event.kind) · \(event.op)"
    }

    private static func sensitivePath(_ path: String) -> Bool {
        let value = path.lowercased()
        return value.contains("credential") || value.contains("secret") || value.contains("password") ||
            value.contains("token") || value.contains("/.ssh/") || value.hasSuffix(".pem") ||
            value.hasSuffix(".key") || value.hasSuffix("/.env")
    }

    private static func deduplicated(_ events: [GuardEvent]) -> [GuardEvent] {
        Array(Dictionary(events.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first }).values)
    }
}
