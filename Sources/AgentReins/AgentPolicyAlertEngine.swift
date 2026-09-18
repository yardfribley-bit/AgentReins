import CryptoKit
import Foundation

/// Evidence-only policy rules for the global Agent console. Findings never
/// claim that content left the machine unless a later request proves it.
enum AgentPolicyAlertEngine {
    static func findings(events: [GuardEvent], policies: [AlertPolicy] = AlertPolicyPersistence.load()) -> [GuardEvent] {
        let ordered = events.sorted { $0.ts < $1.ts }
        let configured = Dictionary(uniqueKeysWithValues: policies.map { ($0.id, $0) })
        let calls = Dictionary(uniqueKeysWithValues: ordered.compactMap { event -> (String, GuardEvent)? in
            guard event.kind == "tool", event.op == "call", let key = key(event) else { return nil }
            return (key, event)
        })
        var output: [GuardEvent] = []

        for call in ordered where call.kind == "tool" && call.op == "call" {
            guard let arguments = call.command, !arguments.isEmpty,
                  !SensitiveContextExposure.scan(text: arguments, source: "tool arguments").isEmpty,
                  let policy = configured["credential_in_tool_arguments"],
                  policy.applies(to: call, workspace: call.path) else { continue }
            output.append(alert(rule: policy.id, severity: policy.severity, notify: policy.notify,
                                event: call, workspace: call.path,
                                detail: "Credential-like material appeared in Agent tool arguments"))
        }

        for event in ordered where event.kind == "file" && event.op == "read" {
            guard let callKey = key(event), let call = calls[callKey],
                  isOutside(path: event.path, workspace: call.path) else { continue }
            let sensitive = sensitivePath(event.path)
            let ruleID = sensitive ? "cross_project_sensitive_file_read" : "cross_project_file_read"
            guard let policy = configured[ruleID], policy.applies(to: event, workspace: call.path) else { continue }
            output.append(alert(rule: ruleID,
                severity: policy.severity, notify: policy.notify, event: event, workspace: call.path,
                detail: sensitive
                    ? "Agent read a sensitive file outside the active project"
                    : "Agent read a file outside the active project"))
        }

        for result in ordered where result.kind == "tool" && result.op == "result" {
            guard let content = result.modelResponse, !content.isEmpty,
                  !SensitiveContextExposure.scan(text: content, source: "tool result").isEmpty else { continue }
            let workspace = calls[key(result) ?? ""]?.path
            guard let policy = configured["credential_in_tool_result"],
                  policy.applies(to: result, workspace: workspace) else { continue }
            output.append(alert(rule: policy.id, severity: policy.severity, notify: policy.notify, event: result,
                                workspace: workspace,
                                detail: "Sensitive credential material appeared in an Agent tool result"))
        }
        return deduplicate(output)
    }

    private static func key(_ event: GuardEvent) -> String? {
        guard let call = event.toolCallId else { return nil }
        return "\(event.sessionId ?? "")|\(call)"
    }

    private static func isOutside(path: String, workspace: String) -> Bool {
        guard path.hasPrefix("/"), workspace.hasPrefix("/") else { return false }
        let target = URL(fileURLWithPath: path).standardizedFileURL.path
        let root = URL(fileURLWithPath: workspace).standardizedFileURL.path
        return target != root && !target.hasPrefix(root + "/")
    }

    private static func sensitivePath(_ path: String) -> Bool {
        let lower = path.lowercased()
        let name = URL(fileURLWithPath: lower).lastPathComponent
        return [".env", ".pem", ".key", "id_rsa", "id_ed25519", "credentials", "servers.yaml",
                "servers.yml", "secrets.yaml", "secrets.yml", "config.toml", ".zshrc"]
            .contains(where: { name == $0 || lower.contains("/.ssh/") || lower.contains("token") || lower.contains("password") })
    }

    private static func alert(rule: String, severity: String, notify: Bool, event: GuardEvent,
                              workspace: String?, detail: String) -> GuardEvent {
        let identity = "\(rule)|\(event.sessionId ?? "")|\(event.turnId ?? "")|\(event.toolCallId ?? "")|\(event.path)"
        let digest = SHA256.hash(data: Data(identity.utf8))
        let bytes = Array(digest.prefix(16))
        let id = UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
        return GuardEvent(id: id, kind: "alert", ruleId: rule, path: event.path,
            command: detail, agent: event.agent, op: "policy", severity: severity, ts: event.ts,
            action: notify ? "needs_review" : "recorded", sessionId: event.sessionId, traceId: event.traceId,
            turnId: event.turnId, toolCallId: event.toolCallId, userIntent: event.userIntent,
            modelDecision: event.modelDecision, toolName: event.toolName, model: event.model,
            source: "policy-engine", attributionConfidence: event.attributionConfidence ?? .inferred,
            attributionMethod: "project boundary + sensitive asset policy" , relatedPath: workspace)
    }

    private static func deduplicate(_ events: [GuardEvent]) -> [GuardEvent] {
        Array(Dictionary(events.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first }).values)
            .sorted { $0.ts > $1.ts }
    }
}
