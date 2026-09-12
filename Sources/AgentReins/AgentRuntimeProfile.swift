import Foundation

/// Stable product vocabulary. Agent-specific process names are projected into
/// these capabilities without changing the underlying PID/PPID evidence.
enum RuntimeCapability: String, CaseIterable, Codable, Sendable {
    case agentCore = "Agent Core"
    case context = "Context Engine"
    case memory = "Memory System"
    case modelConnection = "Model Connection"
    case toolRuntime = "Tool Runtime"
    case mcp = "MCP Boundary"
    case sandbox = "Sandbox"
    case storage = "Local Storage"
    case network = "Network Service"
    case sourceControl = "Source Control"
    case interface = "Interface Service"
    case unknown = "Unclassified Component"
}

struct RuntimeComponentClassification: Equatable, Sendable {
    let componentId: String
    let profileId: String
    let profileVersion: Int
    let displayName: String
    let capability: RuntimeCapability
    let responsibility: String
    let icon: String
    let confidence: EvidenceConfidence
    let matchedEvidence: [String]
    let securitySurface: [String]
}

struct RuntimeComponentRule: Sendable {
    let id: String
    let any: [String]
    let all: [String]
    let name: String
    let capability: RuntimeCapability
    let responsibility: String
    let icon: String
    let securitySurface: [String]
    let executableNames: [String]

    func matches(_ command: String) -> Bool {
        let text = command.lowercased()
        let executable = command.split(separator: " ").first.map(String.init) ?? command
        let executableName = URL(fileURLWithPath: executable).lastPathComponent.lowercased()
        return (executableNames.isEmpty || executableNames.contains(executableName)) &&
            (any.isEmpty || any.contains(where: text.contains)) && all.allSatisfy(text.contains)
    }

    func evidence(in command: String) -> [String] {
        let text = command.lowercased()
        return Array((any + all).filter(text.contains).prefix(4)).map { "command contains ‘\($0)’" }
    }
}

struct AgentRuntimeProfile: Sendable {
    let id: String
    let agent: String
    let version: Int
    let aliases: [String]
    let rules: [RuntimeComponentRule]
}

enum AgentRuntimeProfileRegistry {
    static let profiles: [AgentRuntimeProfile] = [workBuddy, codex, cursor]

    static func classify(_ process: ProcessSnapshotRecord, agentHint: String? = nil)
        -> RuntimeComponentClassification {
        let profile = profile(agentHint: agentHint, command: process.command)
        if let profile, let rule = profile.rules.first(where: { $0.matches(process.command) }) {
            return classification(rule, profile: profile, command: process.command)
        }
        if let rule = commonRules.first(where: { $0.matches(process.command) }) {
            return classification(rule, profile: profile, command: process.command)
        }
        let executable = process.command.split(separator: " ").first.map(String.init) ?? process.command
        return RuntimeComponentClassification(
            componentId: "unknown", profileId: profile?.id ?? "generic-runtime",
            profileVersion: profile?.version ?? 1,
            displayName: URL(fileURLWithPath: executable).lastPathComponent,
            capability: .unknown,
            responsibility: "Its responsibility has not been identified by this Runtime Profile.",
            icon: "questionmark.square.dashed", confidence: .unknown,
            matchedEvidence: ["observed PID \(process.pid) with parent PID \(process.ppid)"],
            securitySurface: ["Process behavior requires classification"])
    }

    static func profile(agentHint: String?, command: String) -> AgentRuntimeProfile? {
        let hint = agentHint?.lowercased() ?? ""
        if let direct = profiles.first(where: {
            hint == $0.agent.lowercased() || hint.contains($0.agent.lowercased())
        }) { return direct }
        let text = command.lowercased()
        return profiles.first { $0.aliases.contains(where: text.contains) }
    }

    private static func classification(_ rule: RuntimeComponentRule, profile: AgentRuntimeProfile?,
                                       command: String) -> RuntimeComponentClassification {
        RuntimeComponentClassification(
            componentId: rule.id, profileId: profile?.id ?? "generic-runtime",
            profileVersion: profile?.version ?? 1, displayName: rule.name,
            capability: rule.capability, responsibility: rule.responsibility,
            icon: rule.icon, confidence: .inferred,
            matchedEvidence: rule.evidence(in: command), securitySurface: rule.securitySurface)
    }

    private static let workBuddy = AgentRuntimeProfile(
        id: "workbuddy-macos", agent: "WorkBuddy", version: 1,
        aliases: ["workbuddy.app", "/.workbuddy/"],
        rules: [
            rule("workbuddy-host", ["workbuddy.app/contents/macos/electron"], "WorkBuddy Desktop Host", .interface,
                 "Hosts the WorkBuddy interface and launches its native agent services.",
                 "macwindow", ["Agent lifecycle", "User interaction", "Runtime launch"]),
            rule("workbuddy-codebuddy", ["cli/bin/codebuddy"], "WorkBuddy Agent Core", .agentCore,
                 "Orchestrates the active coding session, model requests, tools, and child processes.",
                 "brain.head.profile", ["Prompt assembly", "Tool dispatch", "MCP authority", "Session state"]),
            rule("memory-storage", ["storage service", "storage-service"], "Memory & State Storage", .memory,
                 "Persists conversation state, indexes, cache, and potential long-term memory artifacts.",
                 "externaldrive.badge.timemachine", ["Memory retrieval", "Memory commits", "Conversation retention", "Sensitive local data"]),
            rule("sandbox", ["sandbox-center", "sandbox center"], "Sandbox Center", .sandbox,
                 "Creates an isolated execution boundary for agent-generated commands and artifacts.",
                 "shippingbox.and.arrow.backward", ["Downloaded artifact execution", "Filesystem mounts", "Network access", "Sandbox escape"]),
            rule("node-peer", ["nodepeer", "node-peer"], "NodePeer", .agentCore,
                 "Coordinates WorkBuddy runtime messages and supporting services.",
                 "point.3.connected.trianglepath.dotted", ["Cross-component messages", "Tool dispatch", "Context propagation"]),
            rootRule("workbuddy-core", "workbuddy", "WorkBuddy Core", .agentCore,
                 "Owns the WorkBuddy agent instance and its child-process lifecycle.",
                 "brain.head.profile", ["Task orchestration", "Child process authority", "Session lifecycle"])
        ])

    private static let codex = AgentRuntimeProfile(
        id: "codex-macos", agent: "Codex", version: 1,
        aliases: ["/resources/codex", "codex app-server", "openai.chatgpt-", "chatgpt.app"],
        rules: [
            rule("codex-app-server", ["codex app-server", "/resources/codex"], "Codex App Server", .agentCore,
                 "Orchestrates Codex sessions, model interactions, tool calls, and task state.",
                 "brain.head.profile", ["Prompt assembly", "Tool authorization", "Task state", "Model response handling"]),
            rule("codex-extension", ["openai.chatgpt-"], "Codex Editor Extension", .context,
                 "Bridges editor context, selections, workspace state, and Codex runtime requests.",
                 "puzzlepiece.extension", ["Workspace context exposure", "Editor data", "Permission propagation"]),
            rootRule("chatgpt-shell", "chatgpt", "Codex Desktop Host", .interface,
                 "Hosts the desktop interface and the Codex runtime process tree.",
                 "macwindow", ["Agent lifecycle", "User interaction", "Runtime launch"])
        ])

    private static let cursor = AgentRuntimeProfile(
        id: "cursor-macos", agent: "Cursor", version: 1,
        aliases: ["cursor.app", "/.cursor/"],
        rules: [
            rule("cursor-extension-host", ["extension-host", "extensionhost"], "Extension Host", .context,
                 "Runs editor extensions that can read workspace context and invoke agent integrations.",
                 "puzzlepiece.extension", ["Extension supply chain", "Workspace context", "Credentials available to extensions"]),
            rule("cursor-pty-host", ["pty-host", "ptyhost"], "Terminal Host", .toolRuntime,
                 "Creates terminal sessions used by agent-generated shell commands.",
                 "terminal", ["Command execution", "Environment variables", "Filesystem and network access"]),
            rule("cursor-file-watcher", ["filewatcher", "file-watcher"], "Workspace File Watcher", .storage,
                 "Observes workspace changes used to refresh editor and agent context.",
                 "doc.badge.ellipsis", ["Source-code observation", "Context expansion", "Generated-file detection"]),
            rootRule("cursor-core", "cursor", "Cursor Core", .agentCore,
                 "Owns the Cursor editor instance and coordinates its supporting process tree.",
                 "brain.head.profile", ["Agent lifecycle", "Editor authority", "Child process creation"])
        ])

    private static let commonRules: [RuntimeComponentRule] = [
        rule("network-service", ["network.mojom.networkservice", "networkservice"], "Network Service", .network,
             "Owns network sockets used by the Agent interface or runtime.", "network",
             ["Model endpoints", "Relay ownership", "External websites", "Data exfiltration"]),
        rule("mcp-server", ["mcp-process", "mcp-server"], "MCP Server", .mcp,
             "Loads tools and external capabilities across an MCP trust boundary.", "shippingbox",
             ["Tool supply chain", "MCP arguments", "MCP results", "External access"]),
        rule("conversation-search", ["conversation-search"], "Conversation Search", .memory,
             "Indexes and retrieves local conversation records for reuse.", "text.magnifyingglass",
             ["Memory retrieval", "Historical prompt exposure", "Sensitive conversation search"]),
        rule("storage-service", ["storage", "sqlite"], "Storage Service", .storage,
             "Reads and writes local application state, databases, cache, or conversation artifacts.", "internaldrive",
             ["Persistent state", "Memory candidates", "Local privacy data"]),
        rule("shell", ["/bin/zsh", "/bin/bash", "/bin/sh"], "Shell", .toolRuntime,
             "Executes commands requested through the agent tool path.", "terminal",
             ["Command execution", "Filesystem mutation", "Network tools", "Credential access"]),
        rule("git-worker", ["gitworker", "/git ", " git "], "Git Worker", .sourceControl,
             "Reads repository state or performs source-control operations.", "arrow.triangle.branch",
             ["Repository mutation", "Remote supply chain", "Commit and push authority"]),
        rule("renderer", ["renderer"], "Renderer", .interface,
             "Displays the Agent or editor user interface.", "macwindow",
             ["Displayed external content", "Webview isolation"]),
        rule("gpu", ["gpu-process"], "GPU Process", .interface,
             "Renders accelerated interface content.", "square.3.layers.3d", ["Rendered untrusted content"]),
        rule("node-helper", ["node ", "helper"], "Runtime Helper", .toolRuntime,
             "Hosts a runtime helper or child service used by the Agent.", "cpu",
             ["Child process authority", "Package supply chain", "Tool execution"]),
        rule("python", ["python"], "Python Runtime", .toolRuntime,
             "Executes Python tooling or language-intelligence workloads.", "chevron.left.forwardslash.chevron.right",
             ["Code execution", "Package imports", "Filesystem and network access"])
    ]

    private static func rule(_ id: String, _ any: [String], _ name: String,
                             _ capability: RuntimeCapability, _ responsibility: String,
                             _ icon: String, _ securitySurface: [String]) -> RuntimeComponentRule {
        RuntimeComponentRule(id: id, any: any, all: [], name: name, capability: capability,
            responsibility: responsibility, icon: icon, securitySurface: securitySurface,
            executableNames: [])
    }

    private static func rootRule(_ id: String, _ executableName: String, _ name: String,
                                 _ capability: RuntimeCapability, _ responsibility: String,
                                 _ icon: String, _ securitySurface: [String]) -> RuntimeComponentRule {
        RuntimeComponentRule(id: id, any: [], all: [], name: name, capability: capability,
            responsibility: responsibility, icon: icon, securitySurface: securitySurface,
            executableNames: [executableName])
    }
}
