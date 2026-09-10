import Foundation

enum NetworkDestinationKind: String {
    case modelProvider = "Model provider"
    case externalContent = "External content"
    case developerService = "Developer service"
    case telemetry = "Telemetry"
    case localInfrastructure = "Local infrastructure"
    case unknown = "Unknown"
}

struct NetworkDestinationAssessment: Equatable {
    let kind: NetworkDestinationKind
    let needsAttention: Bool
    let reason: String

    static func assess(domain: String?, host: String?) -> NetworkDestinationAssessment {
        let value = (domain ?? host ?? "").lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else {
            return NetworkDestinationAssessment(kind: .unknown, needsAttention: true,
                reason: "The destination domain is unknown, so its content trust cannot be evaluated.")
        }
        if value == "localhost" || value == "::1" || value.hasPrefix("127.") {
            return NetworkDestinationAssessment(kind: .localInfrastructure, needsAttention: false,
                reason: "This is a loopback endpoint, not the final external destination.")
        }
        if matches(value, suffixes: ["chatgpt.com", "openai.com", "openrouter.ai", "anthropic.com",
                                     "mistral.ai", "groq.com", "together.ai", "cohere.com"]) {
            return NetworkDestinationAssessment(kind: .modelProvider, needsAttention: false,
                reason: "Recognized model-service infrastructure; still monitored, but not treated as external content by default.")
        }
        if matches(value, suffixes: ["github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
                                     "npmjs.org", "npmjs.com", "pypi.org", "crates.io", "stackoverflow.com"]) {
            return NetworkDestinationAssessment(kind: .developerService, needsAttention: true,
                reason: "Developer-hosted content can contain poisoned issues, READMEs, packages, or instructions that influence an agent.")
        }
        if matches(value, suffixes: ["sentry.io", "segment.io", "datadoghq.com", "cline.bot"]) {
            return NetworkDestinationAssessment(kind: .telemetry, needsAttention: false,
                reason: "Recognized telemetry destination; review data disclosure separately from prompt-injection risk.")
        }
        if isIPAddress(value) {
            return NetworkDestinationAssessment(kind: .unknown, needsAttention: true,
                reason: "Only an IP address was observed. The final content source remains unidentified.")
        }
        return NetworkDestinationAssessment(kind: .externalContent, needsAttention: true,
            reason: "This non-model website is an untrusted content boundary and may expose the agent to prompt injection.")
    }

    private static func matches(_ domain: String, suffixes: [String]) -> Bool {
        suffixes.contains { domain == $0 || domain.hasSuffix("." + $0) }
    }

    private static func isIPAddress(_ value: String) -> Bool {
        value.allSatisfy { $0.isNumber || $0 == "." } || value.contains(":")
    }
}
