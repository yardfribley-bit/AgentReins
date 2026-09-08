import Foundation

/// 所有安全信号的统一、本地事件仓库。事件跨 App 重启保留，不上传网络。
@MainActor
final class EventStore: ObservableObject {
    @Published private(set) var events: [GuardEvent] = []
    @Published private(set) var incidents: [SecurityIncident] = []
    @Published private(set) var sessions: [AgentSessionSnapshot] = []

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let maximumEvents = 5_000

    init(fileURL: URL = EventStore.defaultURL()) {
        self.fileURL = fileURL
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        load()
        rebuildAgentSightIndexOnce()
        importLegacyLogsOnce()
    }

    nonisolated static func defaultURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let directory = base.appendingPathComponent("AgentGuard", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("events.json")
    }

    func record(_ event: GuardEvent) {
        guard !events.contains(where: { $0.id == event.id }) else { return }
        events.insert(event, at: 0)
        trimAndSave()
    }

    func record(_ incoming: [GuardEvent]) {
        guard !incoming.isEmpty else { return }
        var indexes = Dictionary(uniqueKeysWithValues: events.enumerated().map { ($0.element.id, $0.offset) })
        var changed = false
        for event in incoming {
            if let index = indexes[event.id] {
                // 原生会话源可能后来补齐模型响应/上下文字段，允许富化已有事件。
                events[index] = event
                changed = true
            } else {
                indexes[event.id] = events.count
                events.append(event)
                changed = true
            }
        }
        guard changed else { return }
        trimAndSave()
    }

    func events(on date: Date, calendar: Calendar = .current) -> [GuardEvent] {
        events.filter { calendar.isDate($0.ts, inSameDayAs: date) }
    }

    func recordMemoryFindings(_ findings: [MemoryFinding], scannedAt: Date) {
        guard !findings.isEmpty else { return }
        for finding in findings {
            events.append(GuardEvent(kind: "memory", ruleId: finding.ruleId,
                path: finding.src, command: nil, agent: nil, op: "scan",
                severity: finding.severity, ts: scannedAt, action: "seen"))
        }
        trimAndSave()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let saved = try? decoder.decode([GuardEvent].self, from: data) else { return }
        events = saved.sorted { $0.ts > $1.ts }
        rebuildViews()
    }

    private func trimAndSave() {
        events.sort { $0.ts > $1.ts }
        if events.count > maximumEvents { events.removeLast(events.count - maximumEvents) }
        rebuildViews()
        guard let data = try? encoder.encode(events) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    private func rebuildViews() {
        // 首页/时间线只物化最近窗口，完整原始记录仍保留在本地事件库。
        incidents = SecurityIncident.correlate(Array(events.prefix(1_200)))
        sessions = AgentSessionSnapshot.build(from: events)
    }

    /// Parser v2 fixes user-query extraction and WorkBuddy's reused tool row IDs.
    /// Native AgentSight events are reproducible from JSONL, so discard only the
    /// old projection and let WorkBuddySight rebuild it on startup.
    private func rebuildAgentSightIndexOnce() {
        let key = "agr_agentsight_projection_v2"
        guard !UserDefaults.standard.bool(forKey: key) else { return }
        events.removeAll { $0.source?.hasPrefix("agentsight:") == true }
        trimAndSave()
        UserDefaults.standard.set(true, forKey: key)
    }

    /// 开发版兼容：首次启动把旧监测、拦截与记忆扫描 JSONL 合并进统一仓库。
    private func importLegacyLogsOnce() {
        let defaultsKey = "agr_legacyEventsImported_v1"
        guard !UserDefaults.standard.bool(forKey: defaultsKey) else { return }

        var roots = [URL(fileURLWithPath: FileManager.default.currentDirectoryPath)]
        roots.append(URL(fileURLWithPath: "/Users/jatsmith/AgentSpec"))
        var imported: [GuardEvent] = []
        for root in roots {
            imported += parseJSONL(root.appendingPathComponent("agentguard/agentguard_audit.jsonl"), source: "monitor")
            imported += parseJSONL(root.appendingPathComponent("agentguard-block/agentguard_block_audit.jsonl"), source: "block")
            imported += parseJSONL(root.appendingPathComponent("agentguard/agentguard_memory_scan.jsonl"), source: "memory")
        }

        var fingerprints = Set(events.map(fingerprint))
        for event in imported where fingerprints.insert(fingerprint(event)).inserted {
            events.append(event)
        }
        trimAndSave()
        UserDefaults.standard.set(true, forKey: defaultsKey)
    }

    private func parseJSONL(_ url: URL, source: String) -> [GuardEvent] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(whereSeparator: \.isNewline).compactMap { line in
            guard let data = String(line).data(using: .utf8),
                  let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
            let ts = parseDate(value["ts"] as? String) ?? Date()
            switch source {
            case "memory":
                return GuardEvent(kind: "memory", ruleId: value["rule_id"] as? String ?? "memory_sensitive",
                    path: value["src"] as? String ?? "-", command: nil, agent: nil, op: "scan",
                    severity: value["severity"] as? String ?? "high", ts: ts, action: "seen")
            case "block":
                let command = [value["cmd"] as? String, value["args"] as? String].compactMap { $0 }.joined(separator: " ")
                return GuardEvent(kind: "cmd", ruleId: value["rule"] as? String ?? "legacy_block",
                    path: "-", command: command, agent: nil, op: "exec",
                    severity: (value["decision"] as? String) == "block" ? "critical" : "high",
                    ts: ts, action: value["decision"] as? String ?? "seen")
            default:
                return GuardEvent(kind: "cmd", ruleId: value["rule"] as? String ?? "legacy_monitor",
                    path: "-", command: value["detail"] as? String, agent: value["agent"] as? String,
                    op: "exec", severity: value["severity"] as? String ?? "high", ts: ts,
                    action: value["action"] as? String ?? "seen")
            }
        }
    }

    private func parseDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        let iso = ISO8601DateFormatter()
        if let date = iso.date(from: value) { return date }
        let local = DateFormatter()
        local.locale = Locale(identifier: "en_US_POSIX")
        local.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return local.date(from: value)
    }

    private func fingerprint(_ event: GuardEvent) -> String {
        "\(event.kind)|\(event.ruleId)|\(event.path)|\(event.command ?? "")|\(event.ts.timeIntervalSince1970)|\(event.action)"
    }
}
