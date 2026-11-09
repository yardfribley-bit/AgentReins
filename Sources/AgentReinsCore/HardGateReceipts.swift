import Foundation

/// Tail of the hard-gate audit. Blocked commands never create a transport.json
/// row, so list_alerts and list_network read this file instead. Only the tail
/// is read. The rows are keep-tier and are not deleted here.
public enum HardGateReceipts {
    public struct Row: Equatable, Sendable {
        public var at: String
        public var action: String
        public var kind: String
        public var subject: String
        public var enforced: Bool
        public var mechanism: String
        public var detail: String

        public init(at: String, action: String, kind: String, subject: String, enforced: Bool, mechanism: String, detail: String) {
            self.at = at
            self.action = action
            self.kind = kind
            self.subject = subject
            self.enforced = enforced
            self.mechanism = mechanism
            self.detail = detail
        }
    }

    public static func defaultURL() -> URL {
        if let env = ProcessInfo.processInfo.environment["AGENTREINS_HARDGATE_ROOT"], !env.isEmpty {
            return URL(fileURLWithPath: env).appendingPathComponent("audit.jsonl")
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentReins/hardgate/audit.jsonl")
    }

    public static func isTelemetrySubject(_ subject: String) -> Bool {
        let host = subject.lowercased().hasPrefix("host:") ? String(subject.dropFirst(5)) : subject.lowercased()
        return host.contains("telemetry")
    }

    /// Enforced denies, newest last in the file, capped. A review-only row
    /// (enforced false) is not "已阻断".
    public static func enforcedDenies(from url: URL, limit: Int = 80) -> [Row] {
        guard let text = tail(url, maxBytes: 256 * 1024) else { return [] }
        var rows: [Row] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let data = String(line).data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            guard (obj["action"] as? String) == "deny" else { continue }
            let enforced = (obj["enforced"] as? Bool) == true || (obj["enforced"] as? NSNumber)?.boolValue == true
            guard enforced else { continue }
            let subject = obj["subject"] as? String ?? ""
            guard !subject.isEmpty else { continue }
            rows.append(Row(
                at: obj["at"] as? String ?? "",
                action: "deny",
                kind: obj["kind"] as? String ?? "",
                subject: subject,
                enforced: true,
                mechanism: obj["mechanism"] as? String ?? "",
                detail: obj["detail"] as? String ?? ""
            ))
        }
        if rows.count <= limit { return rows }
        return Array(rows.suffix(limit))
    }

    private static func tail(_ url: URL, maxBytes: Int) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let budget = UInt64(max(1024, maxBytes))
        if size > budget {
            try? handle.seek(toOffset: size - budget)
        } else {
            try? handle.seek(toOffset: 0)
        }
        guard var data = try? handle.readToEnd() else { return nil }
        if size > budget, let newline = data.firstIndex(of: 0x0A) {
            data = Data(data[data.index(after: newline)...])
        }
        return String(data: data, encoding: .utf8)
    }
}
