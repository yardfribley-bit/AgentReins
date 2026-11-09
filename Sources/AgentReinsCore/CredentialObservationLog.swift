import Foundation

/// Small sidecar for credential reads the PATH wrappers never see.
/// `list_alerts` reads this file. It does not open the evidence database.
public enum CredentialObservationLog {
    public struct Row: Equatable, Sendable {
        public var path: String
        public var grade: String
        public var agent: String
        public var at: String
        public var source: String
        public var blocked: Bool

        public init(path: String, grade: String, agent: String, at: String, source: String, blocked: Bool) {
            self.path = path
            self.grade = grade
            self.agent = agent
            self.at = at
            self.source = source
            self.blocked = blocked
        }
    }

    public static func defaultURL() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentReins/credential-observations.jsonl")
    }

    public static func append(_ row: Row, to url: URL, maxLines: Int = 200) {
        var rows = recent(from: url, limit: maxLines)
        let bucket = String(row.at.prefix(13))
        if rows.contains(where: { $0.path == row.path && $0.grade == row.grade && String($0.at.prefix(13)) == bucket }) {
            return
        }
        rows.append(row)
        if rows.count > maxLines { rows.removeFirst(rows.count - maxLines) }
        let text = rows.map(encode).joined(separator: "\n") + (rows.isEmpty ? "" : "\n")
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(text.utf8).write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public static func recent(from url: URL, limit: Int) -> [Row] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let parsed = text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line -> Row? in
            guard let data = String(line).data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let path = obj["path"] as? String, !path.isEmpty else { return nil }
            let grade = (obj["grade"] as? String) == "confirmed" ? "confirmed" : "possible"
            return Row(
                path: path,
                grade: grade,
                agent: obj["agent"] as? String ?? "",
                at: obj["at"] as? String ?? "",
                source: obj["source"] as? String ?? "",
                blocked: (obj["blocked"] as? Bool) == true
            )
        }
        if parsed.count <= limit { return parsed }
        return Array(parsed.suffix(limit))
    }

    private static func encode(_ row: Row) -> String {
        let payload: [String: Any] = [
            "path": row.path,
            "grade": row.grade,
            "agent": row.agent,
            "at": row.at,
            "source": row.source,
            "blocked": row.blocked,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let text = String(data: data, encoding: .utf8) else { return "" }
        return text
    }
}
