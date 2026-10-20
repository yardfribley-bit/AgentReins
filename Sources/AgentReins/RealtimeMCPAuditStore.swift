import Foundation

/// Append-only supervisor MCP read log written by tools/agentreins-mcp/server.py.
/// The realtime UI only displays entries; it never mutates the log from WebKit.
enum RealtimeMCPAuditStore {
    static var url: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentGuard/mcp-supervisor-audit.jsonl")
    }

    static func recent(limit: Int = 40) -> [[String: Any]] {
        guard limit > 0,
              let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        guard let data = try? handle.readToEnd(), !data.isEmpty,
              let text = String(data: data, encoding: .utf8) else { return [] }
        let lines = text.split(whereSeparator: \.isNewline).suffix(limit)
        var rows: [[String: Any]] = []
        for line in lines {
            guard let payload = line.data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { continue }
            var safe: [String: Any] = [:]
            for key in ["at", "actor", "tool", "argsDigest", "prevHash", "hash"] {
                if let value = object[key] as? String { safe[key] = String(value.prefix(200)) }
            }
            rows.append(safe)
        }
        return rows
    }
}
