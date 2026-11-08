import CryptoKit
import Foundation

/// Durable local reviews: alert ack / confirm / allowlist, gateway demo marks, and task acceptance.
/// Kept outside WKWebView's non-persistent websiteDataStore so they survive relaunch.
/// Storage path is injectable so XCTest never writes into Application Support.
enum RealtimeReviewStore {
    struct Decision: Codable, Equatable {
        var id: String
        var state: String
        var note: String?
        var decidedAt: String
        var evidenceHash: String?
        var evidenceCount: Int?
        var subject: String? = nil
        var rule: String? = nil
        var effect: String? = nil
    }

    /// Returns the state to store, or nil when the action is not a known review.
    static func normalize(state: String, note: String?, subject: String?) -> (state: String, effect: String)? {
        switch state {
        case "acked", "acknowledged", "known":
            return ("acked", "persisted")
        case "confirmed":
            return ("confirmed", "persisted")
        case "released", "blocked", "escalated":
            return (state, "persisted")
        case "gateway_allow":
            return ("released", "persisted")
        case "gateway_block":
            return ("blocked", "persisted")
        case "allowlisted":
            guard let subject, !subject.isEmpty, subject.count <= 300 else { return nil }
            return ("allowlisted", "persisted")
        case "accept", "needs_evidence":
            return (state, "persisted")
        case "return":
            guard let note, !note.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
            return ("return", "persisted")
        default:
            return nil
        }
    }

    private static let fileName = "realtime-review-decisions-v1.json"
    private static let lock = NSLock()
    private static var overrideDirectory: URL?

    /// Production Application Support root (never used by XCTest).
    static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("AgentGuard", isDirectory: true)
    }

    /// Inject a temporary directory for tests. Pass `nil` to restore the default.
    static func useDirectory(_ directory: URL?) {
        lock.lock()
        defer { lock.unlock() }
        overrideDirectory = directory
        if let directory {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    static var url: URL {
        lock.lock()
        let root = overrideDirectory ?? defaultDirectory
        lock.unlock()
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

    @discardableResult
    static func remove(id: String) -> [Decision] {
        let kept = load().filter { $0.id != id }
        if let data = try? JSONEncoder().encode(kept) {
            try? data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        return kept
    }

    /// Drop seed / fixture acknowledgements from the production store.
    @discardableResult
    static func clearSeedAndTestDecisions() -> [Decision] {
        let kept = load().filter { decision in
            let id = decision.id.lowercased()
            let note = (decision.note ?? "").lowercased()
            if id.contains("seed") || note.contains("seed") { return false }
            if id.contains("fixture") || note.contains("fixture") { return false }
            if note.contains("packaged-app persistence probe") { return false }
            return true
        }
        if let data = try? JSONEncoder().encode(kept) {
            try? data.write(to: url, options: [.atomic])
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        return kept
    }

    static func evidenceHash(for text: String) -> String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Writes one evidence pack under the review directory. Tests inject that directory.
    static func writeExport(name: String, json: String) throws -> URL {
        let root = url.deletingLastPathComponent().appendingPathComponent("exports", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cleaned = String(name.unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) || $0 == "-" }.prefix(40))
        let stem = cleaned.isEmpty ? "task" : cleaned
        let file = root.appendingPathComponent("\(stem)-\(UUID().uuidString.prefix(8)).json")
        try Data(json.utf8).write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        return file
    }
}
