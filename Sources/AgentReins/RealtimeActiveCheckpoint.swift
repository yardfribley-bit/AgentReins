import Foundation

/// A bounded checkpoint of already observed ACTIVE runs. This is not a history
/// query: completed runs and unrelated old evidence are never loaded here.
struct RealtimeActiveCheckpoint: Codable {
    let version: Int
    let savedAt: Date
    let events: [GuardEvent]
    let readTaskIDs: [String]
    static let maximumBytes = 8 * 1024 * 1024
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
        guard data.count <= Self.maximumBytes else { throw CocoaError(.fileWriteOutOfSpace) }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
