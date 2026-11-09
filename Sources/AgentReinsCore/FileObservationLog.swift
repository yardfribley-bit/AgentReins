import Foundation

/// Thin file-change rows for session verification. Path and time only.
/// File bytes are not stored.
public enum FileObservationLog {
    public struct Row: Equatable, Sendable {
        public var path: String
        public var at: String
        public var agent: String
        public var op: String

        public init(path: String, at: String, agent: String, op: String) {
            self.path = path
            self.at = at
            self.agent = agent
            self.op = op
        }
    }

    public static func defaultURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_FILE_OBSERVATIONS"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentReins/file-observations.jsonl")
    }

    public static func append(_ row: Row, to url: URL, maxLines: Int = 200) {
        var rows = recent(from: url, limit: maxLines)
        if rows.contains(where: { $0.path == row.path && $0.at == row.at && $0.op == row.op }) { return }
        rows.append(row)
        if rows.count > maxLines { rows.removeFirst(rows.count - maxLines) }
        let text = rows.map(encode).filter { !$0.isEmpty }.joined(separator: "\n")
        let body = text.isEmpty ? "" : text + "\n"
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(body.utf8).write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public static func recent(from url: URL, limit: Int) -> [Row] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let parsed = text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line -> Row? in
            guard let data = String(line).data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let path = obj["path"] as? String, !path.isEmpty else { return nil }
            return Row(path: path, at: obj["at"] as? String ?? "", agent: obj["agent"] as? String ?? "", op: obj["op"] as? String ?? "modify")
        }
        if parsed.count <= limit { return parsed }
        return Array(parsed.suffix(limit))
    }

    private static func encode(_ row: Row) -> String {
        let payload: [String: Any] = ["path": row.path, "at": row.at, "agent": row.agent, "op": row.op]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let text = String(data: data, encoding: .utf8) else { return "" }
        return text
    }
}
