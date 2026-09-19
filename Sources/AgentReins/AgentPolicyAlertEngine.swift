import CryptoKit
import Foundation

/// Evidence-only policy rules for the global Agent console. Findings never
/// claim that content left the machine unless a later request proves it.
enum AgentPolicyAlertEngine {
    static func findings(events: [GuardEvent], policies: [AlertPolicy] = AlertPolicyPersistence.load()) -> [GuardEvent] {
        let ordered = events.sorted { $0.ts < $1.ts }
        let configured = Dictionary(grouping: policies.filter(\.enabled), by: \.effectiveDetector)
        let calls = Dictionary(uniqueKeysWithValues: ordered.compactMap { event -> (String, GuardEvent)? in
            guard event.kind == "tool", event.op == "call", let key = key(event) else { return nil }
            return (key, event)
        })
        var output: [GuardEvent] = []

        for request in ordered where request.kind == "model" && request.op == "prompt" {
            guard let body = request.modelPrompt, !body.isEmpty,
                  !SensitiveContextExposure.scan(text: body, source: "model request").isEmpty,
                  let candidates = configured[.some(.sensitiveDataInModelRequest)] else { continue }
            for policy in candidates where policy.applies(to: request, workspace: request.path) {
                output.append(alert(rule: policy.id, severity: policy.severity,
                                    notify: policy.effectiveMode == "active" && policy.notify,
                                    event: request, workspace: request.path,
                                    detail: "Sensitive data appeared in a captured model request body"))
            }
        }

        for call in ordered where call.kind == "tool" && call.op == "call" {
            guard let arguments = call.command, !arguments.isEmpty,
                  !SensitiveContextExposure.scan(text: arguments, source: "tool arguments").isEmpty,
                  let candidates = configured[.some(.credentialInToolArguments)] else { continue }
            for policy in candidates where policy.applies(to: call, workspace: call.path) {
                output.append(alert(rule: policy.id, severity: policy.severity,
                                    notify: policy.effectiveMode == "active" && policy.notify,
                                    event: call, workspace: call.path,
                                    detail: "Credential-like material appeared in Agent tool arguments"))
            }
        }

        for event in ordered where event.kind == "file" && event.op == "read" {
            guard let callKey = key(event), let call = calls[callKey],
                  isOutside(path: event.path, workspace: call.path) else { continue }
            let sensitive = sensitivePath(event.path)
            let detector: AlertDetector = sensitive ? .crossProjectSensitiveFileRead : .crossProjectFileRead
            guard let candidates = configured[.some(detector)] else { continue }
            for policy in candidates where policy.applies(to: event, workspace: call.path) {
                output.append(alert(rule: policy.id, severity: policy.severity,
                    notify: policy.effectiveMode == "active" && policy.notify, event: event, workspace: call.path,
                    detail: sensitive
                        ? "Agent read a sensitive file outside the active project"
                        : "Agent read a file outside the active project"))
            }
        }

        for event in ordered where event.kind == "file" && event.op == "read" {
            guard let agent = event.agent, !agent.isEmpty,
                  belongsToAnotherApplication(path: event.path, agent: agent),
                  isSensitiveRead(event),
                  let candidates = configured[.some(.crossApplicationSensitiveRead)] else { continue }
            let workspace = event.relatedPath ?? calls[key(event) ?? ""]?.path
            for policy in candidates where policy.applies(to: event, workspace: workspace) {
                output.append(alert(rule: policy.id, severity: policy.severity,
                    notify: policy.effectiveMode == "active" && policy.notify,
                    event: event, workspace: workspace,
                    detail: "Agent read sensitive data owned by another application"))
            }
        }

        for result in ordered where result.kind == "tool" && result.op == "result" {
            guard let content = result.modelResponse, !content.isEmpty,
                  !SensitiveContextExposure.scan(text: content, source: "tool result").isEmpty else { continue }
            let workspace = calls[key(result) ?? ""]?.path
            guard let candidates = configured[.some(.credentialInToolResult)] else { continue }
            for policy in candidates where policy.applies(to: result, workspace: workspace) {
                output.append(alert(rule: policy.id, severity: policy.severity,
                                    notify: policy.effectiveMode == "active" && policy.notify, event: result,
                                    workspace: workspace,
                                    detail: "Sensitive credential material appeared in an Agent tool result"))
            }
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

    private static func isSensitiveRead(_ event: GuardEvent) -> Bool {
        if sensitivePath(event.path) { return true }
        let captured = [event.beforeContent, event.afterContent, event.modelResponse]
            .compactMap { $0 }.joined(separator: "\n")
        return !captured.isEmpty && !SensitiveContextExposure.scan(text: captured, source: "file read").isEmpty
    }

    private static func belongsToAnotherApplication(path: String, agent: String) -> Bool {
        let lower = path.lowercased()
        let ownerBoundary = lower.contains("/library/containers/")
            || lower.contains("/library/application support/")
            || lower.contains("/.config/")
        guard ownerBoundary else { return false }
        let normalizedAgent = agent.lowercased().replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
        let normalizedPath = lower.replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: " ", with: "")
        return normalizedAgent.isEmpty || !normalizedPath.contains(normalizedAgent)
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
