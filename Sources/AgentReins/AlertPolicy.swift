import Foundation
import SwiftUI

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
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: []),
        AlertPolicy(id: "cross_project_file_read", name: "File read outside project",
            explanation: "Alert when an Agent reads a file outside its active project boundary.",
            enabled: true, severity: "high", notify: true, agentNames: [], projectPaths: [], excludedPaths: []),
        AlertPolicy(id: "credential_in_tool_result", name: "Credential in tool result",
            explanation: "Alert when tool output returned to an Agent contains credential-like material.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: []),
        AlertPolicy(id: "credential_in_tool_arguments", name: "Credential in tool arguments",
            explanation: "Alert when an Agent places a password, token, or private key in a tool call or shell command.",
            enabled: true, severity: "critical", notify: true, agentNames: [], projectPaths: [], excludedPaths: [])
    ]
}

enum AlertPolicyPersistence {
    static let key = "agentreins.alert-policies.v1"

    static func load() -> [AlertPolicy] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let saved = try? JSONDecoder().decode([AlertPolicy].self, from: data) else { return AlertPolicy.defaults }
        let custom = Dictionary(uniqueKeysWithValues: saved.map { ($0.id, $0) })
        return AlertPolicy.defaults.map { custom[$0.id] ?? $0 }
    }

    static func save(_ policies: [AlertPolicy]) {
        guard let data = try? JSONEncoder().encode(policies) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}

@MainActor
final class AlertPolicyStore: ObservableObject {
    @Published var policies: [AlertPolicy] { didSet { AlertPolicyPersistence.save(policies) } }
    init() { policies = AlertPolicyPersistence.load() }
    func reset() { policies = AlertPolicy.defaults }
}
