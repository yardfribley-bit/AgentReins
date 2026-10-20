import CryptoKit
import Foundation

/// Durable human dispositions for realtime risk alerts.
/// Kept outside WKWebView's non-persistent websiteDataStore so decisions survive relaunch.
enum RealtimeReviewStore {
    struct Decision: Codable, Equatable {
        var id: String
        var state: String
        var note: String?
        var decidedAt: String
        var evidenceHash: String?
        var evidenceCount: Int?
    }

    private static let fileName = "realtime-review-decisions-v1.json"

    static var url: URL {
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentGuard", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root.appendingPathComponent(fileName)
    }

    static func load() -> [Decision] {
        guard let data = try? Data(contentsOf: url), !data.isEmpty else { return [] }
        return (try? JSONDecoder().decode([Decision].self, from: data)) ?? []
    }

    @discardableResult
    static func save(_ decision: Decision) -> [Decision] {
        var all = Dictionary(uniqueKeysWithValues: load().map { ($0.id, $0) })
        all[decision.id] = decision
        let ordered = all.values.sorted { $0.decidedAt > $1.decidedAt }
        if let data = try? JSONEncoder().encode(ordered) {
            try? data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        return ordered
    }

    static func evidenceHash(for text: String) -> String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static func packJSON(
        alertID: String,
        title: String,
        summary: String,
        rule: String,
        agent: String,
        session: String,
        call: String?,
        decidedAt: String?,
        state: String?,
        note: String?,
        evidenceText: String
    ) -> Data {
        let hash = evidenceHash(for: evidenceText)
        let body: [String: Any] = [
            "schema": 1,
            "kind": "agentreins-risk-evidence-pack",
            "exportedAt": ISO8601DateFormatter().string(from: Date()),
            "alert": [
                "id": alertID,
                "title": title,
                "summary": summary,
                "rule": rule,
                "agent": agent,
                "session": session,
                "call": call as Any,
            ],
            "decision": [
                "state": state as Any,
                "note": note as Any,
                "decidedAt": decidedAt as Any,
            ],
            "evidence": [
                "sha256": hash,
                "bytes": evidenceText.utf8.count,
                "text": evidenceText,
            ],
        ]
        return (try? JSONSerialization.data(withJSONObject: body, options: [.prettyPrinted, .sortedKeys])) ?? Data("{}".utf8)
    }
}
