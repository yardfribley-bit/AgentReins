import Foundation
import SwiftUI

enum AlertDetector: String, Codable, CaseIterable, Identifiable, Sendable {
    case crossProjectSensitiveFileRead = "cross_project_sensitive_file_read"
    case crossProjectFileRead = "cross_project_file_read"
    case credentialInToolResult = "credential_in_tool_result"
    case credentialInToolArguments = "credential_in_tool_arguments"
    case sensitiveDataInModelRequest = "sensitive_data_in_model_request"
    case crossApplicationSensitiveRead = "cross_application_sensitive_read"

    var id: String { rawValue }
    var title: String {
        switch self {
        case .crossProjectSensitiveFileRead: return "Sensitive file outside project"
        case .crossProjectFileRead: return "File read outside project"
        case .credentialInToolResult: return "Credential in tool result"
        case .credentialInToolArguments: return "Credential in tool arguments"
        case .sensitiveDataInModelRequest: return "Sensitive data sent in model request"
        case .crossApplicationSensitiveRead: return "Sensitive data read from another application"
        }
    }
}

struct AlertPolicy: Identifiable, Codable, Hashable, Sendable {
    let id: String
    var name: String
    var explanation: String
    var enabled: Bool
    var severity: String
    var notify: Bool
    var agentNames: [String]
    var projectPaths: [String]
    var excludedPaths: [String]
    /// Stable executable detector. Custom policy IDs no longer have to equal
    /// an internal detector ID.
    var detector: AlertDetector? = nil
    /// built_in | user | ai_proposed
    var origin: String? = nil
    /// observe records findings without notifying; active follows `notify`.
    var mode: String? = nil

    var effectiveDetector: AlertDetector? { detector ?? AlertDetector(rawValue: id) }
    var effectiveOrigin: String { origin ?? (AlertDetector(rawValue: id) == nil ? "user" : "built_in") }
    var effectiveMode: String { mode ?? "active" }

    func applies(to event: GuardEvent, workspace: String?) -> Bool {
        guard enabled else { return false }
        if !agentNames.isEmpty {
            guard let agent = event.agent?.lowercased(),
                  agentNames.contains(where: { agent.contains($0.lowercased()) }) else { return false }
        }
        if !projectPaths.isEmpty {
            guard let workspace else { return false }
            let root = URL(fileURLWithPath: workspace).standardizedFileURL.path
            guard projectPaths.contains(where: { root == $0 || root.hasPrefix($0 + "/") }) else { return false }
        }
        let target = URL(fileURLWithPath: event.path).standardizedFileURL.path
        return !excludedPaths.contains(where: { target == $0 || target.hasPrefix($0 + "/") })
    }

    static let defaults = [
        AlertPolicy(id: "cross_project_sensitive_file_read", name: "Sensitive file outside project",
            explanation: "Alert when an Agent reads credentials or sensitive configuration outside its active project.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .crossProjectSensitiveFileRead, origin: "built_in", mode: "active"),
        AlertPolicy(id: "cross_project_file_read", name: "File read outside project",
            explanation: "Alert when an Agent reads a file outside its active project boundary.",
            enabled: true, severity: "high", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .crossProjectFileRead, origin: "built_in", mode: "active"),
        AlertPolicy(id: "credential_in_tool_result", name: "Credential in tool result",
            explanation: "Alert when tool output returned to an Agent contains credential-like material.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .credentialInToolResult, origin: "built_in", mode: "active"),
        AlertPolicy(id: "credential_in_tool_arguments", name: "Credential in tool arguments",
            explanation: "Alert when an Agent places a password, token, or private key in a tool call or shell command.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .credentialInToolArguments, origin: "built_in", mode: "active"),
        AlertPolicy(id: "sensitive_data_in_model_request", name: "Sensitive data sent to model",
            explanation: "Alert when a captured model request body contains a credential, password, private key, or regulated identifier.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .sensitiveDataInModelRequest, origin: "built_in", mode: "active"),
        AlertPolicy(id: "cross_application_sensitive_read", name: "Sensitive data from another application",
            explanation: "Alert when an Agent reads credential material or sensitive configuration owned by another application.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [],
            detector: .crossApplicationSensitiveRead, origin: "built_in", mode: "active")
    ]
}

enum AlertPolicyPersistence {
    static let key = "agentreins.alert-policies.v1"

    static func load() -> [AlertPolicy] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let saved = try? JSONDecoder().decode([AlertPolicy].self, from: data) else { return AlertPolicy.defaults }
        let savedByID = Dictionary(saved.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
        let defaultIDs = Set(AlertPolicy.defaults.map(\.id))
        let builtIns = AlertPolicy.defaults.map { savedByID[$0.id] ?? $0 }
        let custom = saved.filter { !defaultIDs.contains($0.id) }
        return builtIns + custom
    }

    static func save(_ policies: [AlertPolicy]) {
        guard let data = try? JSONEncoder().encode(policies) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}

struct AIRuleCandidate: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let name: String
    let condition: String
    let severity: String
    let detector: AlertDetector?
    let verdict: String
    let confidence: Double
    let evidenceSufficient: Bool
    let falsePositiveRisk: String
    let rationale: String
    let historicalMatches: Int
    var historicalSampleCount: Int? = nil
    let generatedAt: String?
}

@MainActor
final class AlertPolicyStore: ObservableObject {
    @Published var policies: [AlertPolicy] { didSet { AlertPolicyPersistence.save(policies) } }
    @Published private(set) var aiCandidates: [AIRuleCandidate] { didSet { saveCandidates() } }
    static let candidateKey = "agentreins.ai-rule-candidates.v1"

    init() {
        policies = AlertPolicyPersistence.load()
        if let data = UserDefaults.standard.data(forKey: Self.candidateKey),
           let saved = try? JSONDecoder().decode([AIRuleCandidate].self, from: data) {
            aiCandidates = saved
        } else {
            aiCandidates = []
        }
    }
    func reset() { policies = AlertPolicy.defaults }
    func add(_ policy: AlertPolicy) {
        policies.removeAll { $0.id == policy.id }
        policies.append(policy)
    }
    func remove(_ policy: AlertPolicy) {
        guard policy.effectiveOrigin != "built_in" else { return }
        policies.removeAll { $0.id == policy.id }
    }

    func ingestAIProposals(_ analysis: HistoricalSecurityAnalysis, events: [GuardEvent]?) {
        let proposals = analysis.rules.filter { $0.origin == "ai_proposed" }.map { rule -> AIRuleCandidate in
            let detector = Self.detector(for: rule)
            let matches: Int
            if let detector, let events {
                let probe = AlertPolicy(id: "candidate_\(rule.id)", name: rule.name,
                    explanation: rule.condition, enabled: true, severity: rule.severity, notify: false,
                    agentNames: [], projectPaths: [], excludedPaths: [], detector: detector,
                    origin: "ai_proposed", mode: "observe")
                matches = AgentPolicyAlertEngine.findings(events: events, policies: [probe]).count
            } else {
                matches = 0
            }
            var candidate = AIRuleCandidate(id: rule.id, name: rule.name, condition: rule.condition,
                severity: rule.severity, detector: detector,
                verdict: rule.llmSelfExamine.verdict,
                confidence: rule.llmSelfExamine.confidence,
                evidenceSufficient: rule.llmSelfExamine.evidenceSufficient,
                falsePositiveRisk: rule.llmSelfExamine.falsePositiveRisk,
                rationale: rule.llmSelfExamine.rationale,
                historicalMatches: matches, generatedAt: analysis.generatedAt)
            candidate.historicalSampleCount = events?.count
            return candidate
        }
        let activeCandidateIDs = Set(proposals.map(\.id))
        aiCandidates.removeAll { activeCandidateIDs.contains($0.id) }
        aiCandidates.append(contentsOf: proposals)
    }

    func approve(_ candidate: AIRuleCandidate) {
        guard let detector = candidate.detector,
              candidate.verdict != "rejected",
              candidate.evidenceSufficient else { return }
        add(AlertPolicy(id: "ai_\(candidate.id)", name: candidate.name,
            explanation: candidate.condition, enabled: true, severity: candidate.severity,
            notify: false, agentNames: [], projectPaths: [], excludedPaths: [], detector: detector,
            origin: "ai_proposed", mode: "observe"))
        aiCandidates.removeAll { $0.id == candidate.id }
    }

    func dismiss(_ candidate: AIRuleCandidate) {
        aiCandidates.removeAll { $0.id == candidate.id }
    }

    private func saveCandidates() {
        guard let data = try? JSONEncoder().encode(aiCandidates) else { return }
        UserDefaults.standard.set(data, forKey: Self.candidateKey)
    }

    private static func detector(for rule: AIRuleExamination) -> AlertDetector? {
        if let exact = AlertDetector(rawValue: rule.id) { return exact }
        let text = "\(rule.name) \(rule.condition)".lowercased()
        if text.contains("credential") || text.contains("secret") || text.contains("token") || text.contains("password") {
            if text.contains("model request") || text.contains("model context") || text.contains("prompt") {
                return .sensitiveDataInModelRequest
            }
            if text.contains("tool result") || text.contains("tool output") { return .credentialInToolResult }
            if text.contains("argument") || text.contains("command") { return .credentialInToolArguments }
            if text.contains("outside") && text.contains("project") { return .crossProjectSensitiveFileRead }
        }
        if text.contains("file") && text.contains("outside") && text.contains("project") {
            return .crossProjectFileRead
        }
        if text.contains("another application") || text.contains("cross-application") {
            return .crossApplicationSensitiveRead
        }
        return nil
    }
}
