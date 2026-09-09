import Foundation

enum AgentCapabilityKind: String {
    case tool = "Tool"
    case mcp = "MCP"
    case skill = "Skill"
}

enum CapabilityRisk: String {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case unknown = "Unknown"
}

struct ToolSecurityAssessment: Equatable {
    let kind: AgentCapabilityKind
    let risk: CapabilityRisk
    let capability: String
    let reason: String

    static func assess(name: String?, command: String?) -> ToolSecurityAssessment {
        let name = name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let evidence = "\(name) \(command ?? "")".lowercased()
        let kind: AgentCapabilityKind
        if evidence.contains("mcp__") || evidence.contains("mcp-") || evidence.contains("mcp server") {
            kind = .mcp
        } else if evidence.contains("skill") || evidence.contains("skill.md") {
            kind = .skill
        } else {
            kind = .tool
        }

        if ["bash", "shell", "terminal", "exec", "powershell", "cmd.exe"].contains(where: evidence.contains) {
            return ToolSecurityAssessment(kind: kind, risk: .high, capability: "Arbitrary command execution",
                reason: "Can execute local programs, modify files, access credentials, or open network connections.")
        }
        if ["delete", "remove", "write", "edit", "patch", "move", "rename"].contains(where: evidence.contains) {
            return ToolSecurityAssessment(kind: kind, risk: .high, capability: "Filesystem mutation",
                reason: "Can create, overwrite, move, or delete user and project data.")
        }
        if kind == .mcp {
            return ToolSecurityAssessment(kind: kind, risk: .medium, capability: "External integration",
                reason: "Crosses an MCP trust boundary; permissions, destination, and returned content require verification.")
        }
        if kind == .skill {
            return ToolSecurityAssessment(kind: kind, risk: .medium, capability: "Instruction extension",
                reason: "A skill can add instructions and scripts that influence later agent decisions and tool use.")
        }
        if ["fetch", "web", "http", "browser", "search"].contains(where: evidence.contains) {
            return ToolSecurityAssessment(kind: kind, risk: .medium, capability: "Network access",
                reason: "Can send queries or data to an external destination and ingest untrusted content.")
        }
        if ["read", "open", "memory", "retrieve", "load"].contains(where: evidence.contains) {
            return ToolSecurityAssessment(kind: kind, risk: .medium, capability: "Local data access",
                reason: "Can expose source code, local files, memories, or secrets to the agent context.")
        }
        if name.isEmpty || name == "unknown_tool" {
            return ToolSecurityAssessment(kind: kind, risk: .unknown, capability: "Unidentified capability",
                reason: "The source did not provide enough identity or permission evidence to assess this call.")
        }
        return ToolSecurityAssessment(kind: kind, risk: .low, capability: "Limited observed action",
            reason: "No high-impact capability was inferred from the recorded name and arguments; this is not a trust guarantee.")
    }
}
