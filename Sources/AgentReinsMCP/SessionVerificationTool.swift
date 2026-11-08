import AgentReinsCore
import AgentReinsVerify
import Foundation

/// Read-only session verification. Parses local logs on demand and joins transport
/// records already on disk. It does not write evidence and does not copy log bodies.
enum SessionVerificationTool {
    static func list(_ records: [[String: Any]], args: [String: Any], offset: Int, limit: Int?) -> [String: Any] {
        let document = make(records)
        var cards = document.cards
        if let agent = str(args["agent"]), !agent.isEmpty, agent != "all" {
            cards = cards.filter { $0.agent.localizedCaseInsensitiveContains(agent) }
        }
        if let session = str(args["session_id"]), !session.isEmpty {
            cards = cards.filter { $0.sessionId == session }
        }
        let encoded = jsonArray(cards)
        let page = ListPage.slice(encoded, offset: offset, limit: limit)
        return [
            "cards": page.items,
            "sources": jsonArray(document.sources),
            "fileObservation": document.fileObservation,
            "networkObservation": document.networkObservation,
            "unclaimedCount": document.unclaimed.count,
            "total": page.total,
            "offset": page.offset,
            "limit": page.limit,
            "truncated": page.truncated || document.truncated,
            "nextCursor": page.nextCursor,
            "note": "卡片来自本机 Claude Code / Codex 日志的摘录，加上已有运输记录。日志原文不写入证据库。",
        ]
    }

    static func session(_ records: [[String: Any]], sessionID: String) -> [String: Any] {
        let document = make(records)
        let cards = document.cards.filter { $0.sessionId == sessionID }
        let unclaimed = document.unclaimed.filter { $0.sessionId == nil || $0.sessionId == sessionID }
        let checklists = document.checklists.filter { $0.sessionId == sessionID }
        var result: [String: Any] = [
            "sessionId": sessionID,
            "sources": jsonArray(document.sources),
            "fileObservation": document.fileObservation,
            "networkObservation": document.networkObservation,
            "cards": jsonArray(cards),
            "unclaimed": jsonArray(unclaimed),
            "checklists": jsonArray(checklists),
            "truncated": document.truncated,
        ]
        if cards.isEmpty {
            result["note"] = "这份会话日志里没有这个 session，或日志目录不在。"
        } else {
            result["note"] = "只读核对。文件 diff 不在运输审计里时，fileObservation 会写 absent，不把空窗说成没改。"
        }
        return result
    }

    private static func make(_ records: [[String: Any]]) -> SessionVerificationDocument {
        let roots = logRoots()
        let logs = SessionVerification.load(claudeRoot: roots.claude, codexRoot: roots.codex)
        let effects = hostEffects(records)
        var document = SessionVerification.verify(
            calls: logs.calls, effects: effects, completions: logs.completions,
            fileChannel: effects.contains { $0.kind == "file" },
            networkChannel: effects.contains { $0.kind == "network" })
        document.sources = logs.sources
        return document
    }

    private static func logRoots() -> (claude: String, codex: String) {
        let env = ProcessInfo.processInfo.environment
        let home = NSHomeDirectory()
        let claude = env["AGENTREINS_CLAUDE_PROJECTS"] ?? (home as NSString).appendingPathComponent(".claude/projects")
        let codex = env["AGENTREINS_CODEX_SESSIONS"] ?? (home as NSString).appendingPathComponent(".codex/sessions")
        return (claude, codex)
    }

    private static func hostEffects(_ records: [[String: Any]]) -> [HostEffect] {
        var effects: [HostEffect] = []
        for (index, record) in records.enumerated() {
            guard let stamp = Clock.parse(record["startedAt"]) else { continue }
            let timestamp = Date(timeIntervalSince1970: stamp)
            let pid = intValue(record["pid"]).map { Int32($0) }
            let session = str(record["session"])
            let call = str(record["call"]) ?? str(record["runID"])
            let tool = str(record["tool"]) ?? ""
            let args = commandText(record["args"])
            let destination = destinationHost(record)
            if let destination, !destination.isEmpty {
                effects.append(HostEffect(
                    id: "transport-net-\(index)", kind: "network", timestamp: timestamp, pid: pid,
                    command: args, remote: destination, sessionId: session, toolCallId: call, source: "transport"))
            }
            if !tool.isEmpty || !args.isEmpty {
                effects.append(HostEffect(
                    id: "transport-proc-\(index)", kind: "process", timestamp: timestamp, pid: pid,
                    command: [tool, args].filter { !$0.isEmpty }.joined(separator: " "),
                    sessionId: session, toolCallId: call,
                    credential: SessionVerification.isCredential(args), source: "transport"))
            }
        }
        return effects
    }

    private static func destinationHost(_ record: [String: Any]) -> String? {
        if let audit = record["securityAudit"] as? [String: Any], let host = str(audit["destinationHost"]) { return host }
        return str(record["destinationHost"]) ?? str(record["remoteHost"])
    }

    private static func commandText(_ value: Any?) -> String {
        if let text = value as? String { return text }
        if let list = value as? [String] { return list.joined(separator: " ") }
        if let list = value as? [Any] { return list.map { String(describing: $0) }.joined(separator: " ") }
        return ""
    }

    private static func jsonArray<T: Encodable>(_ value: [T]) -> [[String: Any]] {
        guard let data = try? encoder.encode(value),
              let object = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        return object
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()
}
