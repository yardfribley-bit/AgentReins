import Foundation

/// A bounded restart checkpoint for active runs and unread terminal tasks.
/// Only already-observed live records are stored; no history query is performed.
struct RealtimeActiveCheckpoint: Codable {
    let version: Int
    let savedAt: Date
    let events: [GuardEvent]
    let readTaskIDs: [String]
    static let maximumBytes = 16 * 1024 * 1024
    static func load(_ url: URL) throws -> RealtimeActiveCheckpoint? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= maximumBytes else { throw CocoaError(.fileReadTooLarge) }
        let value = try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
        guard value.version == 1 else { throw CocoaError(.coderReadCorrupt) }
        return value
    }
    func save(_ url: URL) throws {
        let data = try JSONEncoder().encode(self)
        guard data.count <= Self.maximumBytes else { throw NSError(domain: "AgentReins.RealtimeCheckpoint", code: 1, userInfo: [NSLocalizedDescriptionKey: "实时恢复数据超过16 MiB上限；本次保存未覆盖已有恢复文件"]) }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
