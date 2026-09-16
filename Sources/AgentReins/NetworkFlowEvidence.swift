import Foundation

enum NetworkTrafficCategory: String, CaseIterable, Sendable {
    case model = "MODEL TRAFFIC"
    case web = "AGENT WEB & APIS"
    case remote = "REMOTE OPERATIONS"
    case infrastructure = "AGENT INFRASTRUCTURE"
    case unknown = "UNKNOWN / NEEDS ATTRIBUTION"
}

enum NetworkEvidenceGrade: String, Sendable {
    case observed = "Observed"
    case correlated = "Correlated"
    case inferred = "Inferred"
    case unknown = "Unknown"
}

/// A user-facing projection of raw network evidence. It preserves the observed
/// endpoint and keeps purpose/turn attribution separate so a socket is never
/// presented as proof of encrypted payload contents.
struct NetworkFlowEvidence: Identifiable {
    let id: String
    let category: NetworkTrafficCategory
    let domain: String?
    let ip: String?
    let port: Int?
    let agent: String
    let purpose: String
    let grade: NetworkEvidenceGrade
    let reason: String
    let firstObservedAt: Date
    let lastObservedAt: Date
    let connectionCount: Int
    let sourceEvent: GuardEvent

    var destination: String { domain ?? ip ?? "Unknown destination" }

    static func build(events: [GuardEvent]) -> [NetworkFlowEvidence] {
        let modelTurns = Set(events.compactMap { event -> String? in
            guard event.kind == "model", let session = event.sessionId, let turn = event.turnId else { return nil }
            return "\(session)|\(turn)"
        })
        let webToolCalls = Set(events.compactMap { event -> String? in
            guard event.kind == "tool", let call = event.toolCallId else { return nil }
            let value = "\(event.toolName ?? "") \(event.command ?? "")".lowercased()
            return value.range(of: #"web|fetch|browser|http|url|search|git"#, options: .regularExpression) == nil ? nil : call
        })
        let network = events.filter { event in
            event.kind == "network" || event.remoteDomain != nil || event.remoteHost != nil
        }
        let grouped = Dictionary(grouping: network) { event in
            let category = category(for: event, modelTurns: modelTurns, webToolCalls: webToolCalls)
            let destination = (event.remoteDomain ?? event.remoteHost ?? "unknown").lowercased()
            return "\(category.rawValue)|\(destination)|\(event.remotePort ?? 0)|\(event.agent ?? "unknown")"
        }
        return grouped.compactMap { key, rows in
            guard let latest = rows.max(by: { $0.ts < $1.ts }) else { return nil }
            let category = category(for: latest, modelTurns: modelTurns, webToolCalls: webToolCalls)
            let domain = latest.remoteDomain.flatMap { IPGeolocationStore.isPublicIPAddress($0) ? nil : $0 }
            let rawHost = latest.remoteHost
            let ip = rawHost.flatMap { IPGeolocationStore.isPublicIPAddress($0) ? $0 : nil }
            let grade = evidenceGrade(for: latest)
            return NetworkFlowEvidence(id: key, category: category, domain: domain,
                ip: ip, port: latest.remotePort, agent: latest.agent ?? "Unknown agent",
                purpose: purpose(for: latest, category: category), grade: grade,
                reason: reason(for: latest, grade: grade),
                firstObservedAt: rows.map { $0.startedAt ?? $0.ts }.min() ?? latest.ts,
                lastObservedAt: rows.map { $0.endedAt ?? $0.ts }.max() ?? latest.ts,
                connectionCount: rows.count, sourceEvent: latest)
        }.sorted {
            let order = Dictionary(uniqueKeysWithValues: NetworkTrafficCategory.allCases.enumerated().map { ($1, $0) })
            let lhs = order[$0.category] ?? 99, rhs = order[$1.category] ?? 99
            return lhs == rhs ? $0.lastObservedAt > $1.lastObservedAt : lhs < rhs
        }
    }

    private static func category(for event: GuardEvent, modelTurns: Set<String>,
                                 webToolCalls: Set<String>) -> NetworkTrafficCategory {
        let command = event.command?.lowercased() ?? ""
        if event.remotePort == 22 || command.range(of: #"\b(?:ssh|scp|sftp|rsync)\b"#, options: .regularExpression) != nil {
            return .remote
        }
        let assessment = NetworkDestinationAssessment.assess(domain: event.remoteDomain,
                                                              host: event.remoteHost)
        if event.kind == "model" || assessment.kind == .modelProvider || assessment.kind == .modelRelay {
            return .model
        }
        if let session = event.sessionId, let turn = event.turnId,
           modelTurns.contains("\(session)|\(turn)") {
            return .model
        }
        if let call = event.toolCallId, webToolCalls.contains(call) { return .web }
        if assessment.kind == .developerService || assessment.kind == .externalContent {
            return .web
        }
        if assessment.kind == .telemetry || assessment.kind == .localInfrastructure {
            return .infrastructure
        }
        return .unknown
    }

    private static func evidenceGrade(for event: GuardEvent) -> NetworkEvidenceGrade {
        let socketObserved = event.source == "lsof-network"
        let purposeLinked = event.turnId != nil || event.toolCallId != nil || event.toolName != nil || event.command != nil
        if socketObserved && purposeLinked { return .correlated }
        if socketObserved { return .observed }
        if purposeLinked || event.attributionConfidence == .inferred { return .inferred }
        return .unknown
    }

    private static func purpose(for event: GuardEvent, category: NetworkTrafficCategory) -> String {
        switch category {
        case .model:
            let model = event.model.map { " · \($0)" } ?? ""
            return NetworkDestinationAssessment.assess(domain: event.remoteDomain, host: event.remoteHost).kind == .modelRelay
                ? "Model request through relay\(model)" : "Model provider request\(model)"
        case .remote:
            if event.command?.lowercased().contains("scp") == true || event.command?.lowercased().contains("rsync") == true {
                return "Remote file transfer"
            }
            return "SSH remote operation"
        case .web:
            if let tool = event.toolName { return "Agent tool access · \(tool)" }
            if event.command?.lowercased().contains("git ") == true { return "Source control access · Git" }
            return "External content or developer service"
        case .infrastructure:
            return "Agent support, telemetry, or local service"
        case .unknown:
            return "Connection observed; business purpose not proven"
        }
    }

    private static func reason(for event: GuardEvent, grade: NetworkEvidenceGrade) -> String {
        switch grade {
        case .correlated:
            return "PID-owned socket plus local turn/tool evidence"
        case .observed:
            return "PID-owned socket observed inside the Agent process tree"
        case .inferred:
            return event.attributionMethod ?? "Destination inferred from local Agent/tool evidence"
        case .unknown:
            return "No reliable process-to-turn attribution is available"
        }
    }
}
