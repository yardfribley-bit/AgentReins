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
    static let profiles: [AgentRuntimeProfile] = [workBuddy, codex, claude, cursor]

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
        id: "workbuddy-macos", agent: "WorkBuddy", version: 2,
        aliases: ["workbuddy.app", "/.workbuddy/"],
        rules: [
            rule("workbuddy-active-agent", ["cli/bin/codebuddy --serve"], "Active Agent Runtime", .agentCore,
                 "Runs the active coding-agent service created by WorkBuddy's sidecar broker.",
                 "brain.head.profile", ["Prompt assembly", "Tool dispatch", "MCP authority", "Session state"]),
            rule("workbuddy-prewarm-pool", ["cli/bin/codebuddy --prewarm"], "Prewarm Agent Pool", .agentCore,
                 "Keeps a reusable coding-agent runtime ready and owns its configured MCP children.",
                 "bolt.horizontal.circle", ["Dormant agent authority", "MCP lifecycle", "Plugin loading"]),
            rule("workbuddy-sidecar", ["main/sidecar-entry.js"], "Sidecar Broker", .agentCore,
                 "Controls a headless WorkBuddy agent service outside the visible desktop process tree.",
                 "point.3.connected.trianglepath.dotted", ["Agent launch token", "Control pipe", "Runtime authority"]),
            rule("workbuddy-daemon", ["main/daemon-app-server-entry.js"], "Desktop Agent Server", .agentCore,
                 "Bridges the WorkBuddy desktop interface to agent, editor-context, and integration services.",
                 "server.rack", ["Task dispatch", "Editor context", "Integration lifecycle"]),
            rule("workbuddy-mcp-weixin", ["weixinpay", "mcp-server.mjs"], "Weixin Pay MCP Server", .mcp,
                 "Exposes the installed Weixin Pay plugin across WorkBuddy's MCP trust boundary.",
                 "shippingbox", ["MCP supply chain", "Tool arguments", "External service access"]),
            rule("workbuddy-mcp-sheet", ["sheetagent", "/mcp/start.mjs"], "Sheet Agent MCP Server", .mcp,
                 "Exposes spreadsheet capabilities through WorkBuddy's MCP trust boundary.",
                 "shippingbox", ["MCP supply chain", "Document access", "Tool results"]),
            rule("workbuddy-editor-sdk", ["tencent-docs-ai-engine", "editor_sdk"], "Editor Context Engine", .context,
                 "Collects and serves editor context to the WorkBuddy desktop agent over a local port.",
                 "doc.text.magnifyingglass", ["Workspace context", "Local API", "Prompt expansion"]),
            rule("workbuddy-edge-sync", ["edge-sync/server/index.cjs"], "Edge Sync Service", .storage,
                 "Synchronizes WorkBuddy integration state for the desktop agent runtime.",
                 "arrow.triangle.2.circlepath", ["Persistent state", "Remote synchronization", "Account context"]),
            rule("workbuddy-network", ["network.mojom.networkservice"], "WorkBuddy Network Service", .network,
                 "Owns WorkBuddy desktop network sockets and external service connections.",
                 "network", ["Model endpoints", "Relay ownership", "External websites", "Data exfiltration"]),
            rule("workbuddy-host", ["workbuddy.app/contents/macos/electron"], "WorkBuddy Desktop Host", .interface,
                 "Hosts the WorkBuddy interface and launches its native agent services.",
                 "macwindow", ["Agent lifecycle", "User interaction", "Runtime launch"]),
            rule("memory-storage", ["storage service", "storage-service"], "Memory & State Storage", .memory,
                 "Persists conversation state, indexes, cache, and potential long-term memory artifacts.",
                 "externaldrive.badge.timemachine", ["Memory retrieval", "Memory commits", "Conversation retention", "Sensitive local data"]),
            rule("sandbox", ["sandbox-center", "sandbox center"], "Sandbox Center", .sandbox,
                 "Runs as an independently launched isolation boundary for agent-generated commands and artifacts.",
                 "shippingbox.and.arrow.backward", ["Downloaded artifact execution", "Filesystem mounts", "Network access", "Sandbox escape"]),
            rule("node-peer", ["nodepeer", "node-peer"], "NodePeer", .agentCore,
                 "Coordinates WorkBuddy runtime messages and supporting services.",
                 "point.3.connected.trianglepath.dotted", ["Cross-component messages", "Tool dispatch", "Context propagation"])
        ])

    private static let codex = AgentRuntimeProfile(
        id: "codex-macos", agent: "Codex", version: 1,
        aliases: ["/resources/codex", "codex app-server", "openai.chatgpt-", "chatgpt.app"],
        rules: [
            rule("codex-computer-use-runtime", ["unified-computer-use", "/scripts/launch.mjs"], "Computer Use Runtime", .toolRuntime,
                 "Hosts the computer-use tool runtime and its isolated Node REPL child.",
                 "macwindow.on.rectangle", ["Computer control", "Tool execution", "Screen and input access", "External content"]),
            rule("codex-mcp-tool-server", [" ./server.mjs"], "MCP Tool Server", .mcp,
                 "Hosts tools exposed to Codex through its configured MCP trust boundary.",
                 "shippingbox", ["Tool supply chain", "MCP arguments", "MCP results", "External access"]),
            rule("codex-node-repl", ["node_repl"], "Node REPL", .sandbox,
                 "Provides the isolated JavaScript execution boundary used by an active Codex tool session.",
                 "terminal", ["Untrusted code execution", "Sandbox escape", "Filesystem access", "Network access"]),
            rule("codex-code-mode-host", ["codex-code-mode-host"], "Code Execution Host", .toolRuntime,
                 "Runs the isolated execution bridge used by Codex code-mode tools.",
                 "chevron.left.forwardslash.chevron.right", ["Command execution", "Tool input", "Filesystem mutation", "Process creation"]),
            rule("codex-app-server", [" app-server"], "Codex App Server", .agentCore,
                 "Orchestrates Codex sessions, model interactions, tool calls, and task state.",
                 "brain.head.profile", ["Prompt assembly", "Tool authorization", "Task state", "Model response handling"]),
            rule("codex-extension", ["openai.chatgpt-"], "Codex Editor Extension", .context,
                 "Bridges editor context, selections, workspace state, and Codex runtime requests.",
                 "puzzlepiece.extension", ["Workspace context exposure", "Editor data", "Permission propagation"]),
            rootRule("chatgpt-shell", "chatgpt", "Codex Desktop Host", .interface,
                 "Hosts the desktop interface and the Codex runtime process tree.",
                 "macwindow", ["Agent lifecycle", "User interaction", "Runtime launch"])
        ])

    private static let claude = AgentRuntimeProfile(
        id: "claude-macos", agent: "Claude", version: 1,
        aliases: ["claude-code", "/claude.app/", "/usr/local/bin/claude"],
        rules: [
            rule("claude-code-cli", ["claude-code/bin/claude", "/usr/local/bin/claude"], "Claude Code Agent", .agentCore,
                 "Runs the Claude Code session, prepares model context, and dispatches tools from the terminal.",
                 "brain.head.profile", ["Prompt assembly", "Tool authorization", "Session state", "Model interaction"]),
            rule("claude-desktop-network", ["network.mojom.networkservice"], "Claude Network Service", .network,
                 "Owns Claude Desktop network sockets; it is not a Claude Code CLI process.",
                 "network", ["Anthropic endpoints", "External websites", "Uploaded context"]),
            rule("claude-desktop-renderer", ["claude helper (renderer)"], "Claude Desktop Renderer", .interface,
                 "Renders Claude Desktop and Cowork content; it does not prove Claude Code tool execution.",
                 "macwindow", ["Rendered external content", "Desktop webview isolation"]),
            rule("claude-desktop-updater", ["claudefordesktop.shipit"], "Claude Desktop Updater", .unknown,
                 "Updates the Claude Desktop application and is unrelated to an active coding task.",
                 "arrow.down.app", ["Application update supply chain"]),
            rootRule("claude-desktop-host", "claude", "Claude Desktop Host", .interface,
                 "Hosts Claude Desktop and Cowork. Claude Code CLI sessions are represented separately.",
                 "macwindow", ["Desktop session lifecycle", "User interaction"])
        ])

    private static let cursor = AgentRuntimeProfile(
        id: "cursor-macos", agent: "Cursor", version: 2,
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
            rule("cursor-mcp-gateway", ["mcp-process"], "Cursor MCP Gateway", .mcp,
                 "Hosts Cursor's MCP boundary and brokers configured tool-server connections.",
                 "shippingbox", ["MCP server lifecycle", "Tool arguments", "Tool results", "External service authority"]),
            rule("cursor-git-worker", ["extensions/cursor-always-local/dist/gitworker.js", "gitworker.js"], "Git Worker", .sourceControl,
                 "Reads repository state and performs source-control operations for the Cursor workspace.",
                 "arrow.triangle.branch", ["Repository contents", "Commit metadata", "Remote supply chain", "Push authority"]),
            rule("cursor-network", ["network.mojom.networkservice"], "Cursor Network Service", .network,
                 "Owns Cursor network sockets, including model, relay, extension, and external website connections.",
                 "network", ["Model endpoints", "Relay ownership", "External websites", "Data exfiltration"]),
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
