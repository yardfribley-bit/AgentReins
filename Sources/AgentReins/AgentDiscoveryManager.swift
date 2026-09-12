import Foundation
import SwiftUI

enum AgentPresence: String, Codable { case installed, running }
enum AgentConnectionState: String, Codable {
    case native, partial, processOnly, browser, installed, unavailable
}
enum AgentCoverage: String, Codable, Hashable {
    case process, session, prompt, response, tools, network, files, browserContent
}

struct DiscoveredAgent: Identifiable, Codable, Equatable {
    let id: String
    let product: String
    let presence: AgentPresence
    let instances: [String]
    let processIds: [Int32]
    let confidence: EvidenceConfidence
    let identificationEvidence: [String]
    let connection: AgentConnectionState
    let coverage: Set<AgentCoverage>
    let adapter: String?
    let missing: [String]
    let lastSeen: Date
}

/// Low-frequency, read-only inventory of AI agents and the best available
/// evidence adapter. Discovery never installs hooks or grants browser access.
@MainActor
final class AgentDiscoveryManager: ObservableObject {
    @Published private(set) var agents: [DiscoveredAgent] = []
    @Published private(set) var scanning = false
    @Published private(set) var lastScan: Date?

    private let provider: any ProcessSnapshotting
    private let queue = DispatchQueue(label: "com.agentspec.discovery", qos: .utility)
    private var timer: Timer?
    private var adapterHealth: [String: Bool] = [:]

    init(provider: (any ProcessSnapshotting)? = nil) {
        self.provider = provider ?? ResilientProcessSnapshotProvider(agentMarkers:
            ["codex", "chatgpt", "workbuddy", "qoder", "claude", "cursor", "kiro", "windsurf", "trae"])
    }

    func start() {
        guard timer == nil else { return }
        scan()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.scan() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func scan() {
        guard !scanning else { return }
        scanning = true
        let provider = provider
        queue.async { [weak self] in
            let processes = provider.snapshot()
            let paths = AgentDiscoveryEngine.knownPaths.filter(FileManager.default.fileExists(atPath:))
            let webActive = AgentDiscoveryEngine.grokEvidenceIsActive()
            let result = AgentDiscoveryEngine.discover(processes: processes,
                                                       existingPaths: Set(paths), webEvidenceActive: webActive)
            DispatchQueue.main.async {
                self?.agents = result
                if let self {
                    for (id, connected) in self.adapterHealth {
                        self.applyAdapterState(id, connected: connected)
                    }
                }
                self?.lastScan = Date()
                self?.scanning = false
            }
        }
    }

    func setAdapterConnected(_ id: String, connected: Bool) {
        adapterHealth[id] = connected
        applyAdapterState(id, connected: connected)
    }

    private func applyAdapterState(_ id: String, connected: Bool) {
        guard let index = agents.firstIndex(where: { $0.id == id }) else { return }
        let item = agents[index]
        let expected: AgentConnectionState = id == "grok-web" ? .browser : .native
        let fallback: AgentConnectionState = item.presence == .running ?
            (item.adapter == nil ? .processOnly : .partial) : .installed
        let next = connected ? expected : fallback
        guard item.connection != next else { return }
        agents[index] = DiscoveredAgent(id: item.id, product: item.product, presence: item.presence,
            instances: item.instances, processIds: item.processIds, confidence: item.confidence,
            identificationEvidence: item.identificationEvidence, connection: next,
            coverage: item.coverage, adapter: item.adapter, missing: item.missing, lastSeen: item.lastSeen)
    }
}

enum AgentDiscoveryEngine {
    struct Signature {
        let id: String
        let product: String
        let appPaths: [String]
        let markers: [String]
        let dataPath: String?
        let adapter: String?
    }

    static let home = FileManager.default.homeDirectoryForCurrentUser.path
    static let signatures: [Signature] = [
        Signature(id: "codex", product: "Codex",
            appPaths: ["/Applications/ChatGPT.app"],
            markers: ["/chatgpt.app/", "/resources/codex", "/openai.chatgpt-"],
            dataPath: "\(home)/.codex/sessions", adapter: "codex-local-compat"),
        Signature(id: "workbuddy", product: "WorkBuddy",
            appPaths: ["/Applications/WorkBuddy.app"], markers: ["/workbuddy.app/", "/.workbuddy/"],
            dataPath: "\(home)/.workbuddy/projects", adapter: "workbuddy-native"),
        Signature(id: "qoder", product: "Qoder",
            appPaths: ["/Applications/Qoder.app"], markers: ["/qoder.app/", "/.qoder/"],
            dataPath: "\(home)/.qoder/projects", adapter: "qoder-native"),
        Signature(id: "claude", product: "Claude",
            appPaths: ["/Applications/Claude.app", "\(home)/Applications/Claude Code URL Handler.app"],
            markers: ["/claude.app/", "/claude-code", "/claude "], dataPath: "\(home)/.claude", adapter: nil),
        Signature(id: "cursor", product: "Cursor", appPaths: ["/Applications/Cursor.app"],
            markers: ["/cursor.app/", "/.cursor/"],
            dataPath: "\(home)/Library/Application Support/Cursor/User/globalStorage/state.vscdb",
            adapter: "cursor-composer-v3"),
        Signature(id: "kiro", product: "Kiro", appPaths: ["/Applications/Kiro.app"],
            markers: ["/kiro.app/", "/.kiro/"], dataPath: "\(home)/.kiro", adapter: nil),
        Signature(id: "trae", product: "TRAE", appPaths: ["/Applications/TRAE SOLO CN.app"],
            markers: ["/trae solo cn.app/", "/.trae/"], dataPath: "\(home)/.trae", adapter: nil),
        Signature(id: "windsurf", product: "Windsurf", appPaths: ["/Applications/Windsurf.app"],
            markers: ["/windsurf.app/", "/.windsurf/", "/.codeium/"], dataPath: "\(home)/.codeium", adapter: nil)
    ]

    static var knownPaths: [String] {
        signatures.flatMap(\.appPaths) + signatures.compactMap(\.dataPath)
    }

    static func discover(processes: [ProcessSnapshotRecord], existingPaths: Set<String>,
                         webEvidenceActive: Bool, now: Date = Date()) -> [DiscoveredAgent] {
        var result = signatures.compactMap { signature -> DiscoveredAgent? in
            let matches = processes.filter { process in
                let command = process.command.lowercased()
                return signature.markers.contains(where: command.contains)
            }
            let installed = signature.appPaths.contains(where: existingPaths.contains) ||
                signature.dataPath.map(existingPaths.contains) == true
            guard installed || !matches.isEmpty else { return nil }
            let running = !matches.isEmpty
            let hasNativeData = signature.dataPath.map(existingPaths.contains) == true && signature.adapter != nil
            var coverage: Set<AgentCoverage> = running ? [.process, .network] : []
            if hasNativeData { coverage.formUnion([.session, .prompt, .response, .tools]) }
            // A directory proves adapter availability, not a healthy connection.
            // The running adapter upgrades this to `.native` after its own read succeeds.
            let connection: AgentConnectionState = !running ? .installed :
                (hasNativeData ? .partial : (signature.adapter == nil ? .processOnly : .partial))
            let instances = instanceNames(for: signature.id, processes: matches)
            var evidence = signature.appPaths.filter(existingPaths.contains).map { "installed app: \($0)" }
            if hasNativeData, let dataPath = signature.dataPath { evidence.append("local evidence: \(dataPath)") }
            if running { evidence.append("matched \(matches.count) process(es)") }
            return DiscoveredAgent(id: signature.id, product: signature.product,
                presence: running ? .running : .installed, instances: instances,
                processIds: matches.compactMap { Int32($0.pid) }.sorted(), confidence: .confirmed,
                identificationEvidence: evidence, connection: connection, coverage: coverage,
                adapter: signature.adapter,
                missing: missingCapabilities(coverage: coverage, running: running), lastSeen: now)
        }
        if webEvidenceActive {
            result.append(DiscoveredAgent(id: "grok-web", product: "Grok Web", presence: .running,
                instances: ["Chrome browser session"], processIds: [], confidence: .confirmed,
                identificationEvidence: ["recent authenticated Native Messaging evidence from grok.com"],
                connection: .browser, coverage: [.session, .prompt, .response, .browserContent],
                adapter: "grok-browser-native", missing: ["tool process attribution", "complete network body"],
                lastSeen: now))
        }
        return result.sorted { lhs, rhs in
            if lhs.presence != rhs.presence { return lhs.presence == .running }
            return lhs.product.localizedCaseInsensitiveCompare(rhs.product) == .orderedAscending
        }
    }

    static func grokEvidenceIsActive(now: Date = Date()) -> Bool {
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentGuard/web-agent-events.jsonl")
        guard let modified = try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate else {
            return false
        }
        return now.timeIntervalSince(modified) < 90
    }

    private static func instanceNames(for product: String, processes: [ProcessSnapshotRecord]) -> [String] {
        var values = Set<String>()
        for process in processes {
            let command = process.command.lowercased()
            if product == "codex" && command.contains("/.vscode/extensions/openai.chatgpt-") { values.insert("VS Code") }
            else if product == "codex" && command.contains("/chatgpt.app/") { values.insert("Desktop") }
            else if command.contains(".app/") { values.insert("Desktop") }
            else { values.insert("CLI / background service") }
        }
        return values.sorted()
    }

    private static func missingCapabilities(coverage: Set<AgentCoverage>, running: Bool) -> [String] {
        guard running else { return ["agent is not running"] }
        var missing: [String] = []
        if !coverage.contains(.session) { missing.append("session and turn context") }
        if !coverage.contains(.tools) { missing.append("tool and MCP results") }
        if !coverage.contains(.files) { missing.append("confirmed turn-level file attribution") }
        return missing
    }
}
