import CryptoKit
import Foundation

/// Durable style-only acknowledgements for realtime risk alerts ("已知悉").
/// Kept outside WKWebView's non-persistent websiteDataStore so acks survive relaunch.
/// Storage path is injectable so XCTest never writes into Application Support.
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
}
