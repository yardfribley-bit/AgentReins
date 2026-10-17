import Compression
import CryptoKit
import Darwin
import Foundation

/// Restart state for already-observed active runs and unread terminal tasks.
/// The manifest is bounded; immutable, lossless event bodies live beside it.
/// This storage is never populated by a history query.
struct RealtimeActiveCheckpoint: Codable {
    let version: Int
    let savedAt: Date
    let events: [GuardEvent]
    let readTaskIDs: [String]
    var coverageTruncated: Bool = false

    /// This bound applies to the index, not to all captured command output.
    static let maximumBytes = 16 * 1024 * 1024
    private static let maximumEventBytes = 256 * 1024 * 1024

    init(version: Int, savedAt: Date, events: [GuardEvent], readTaskIDs: [String], coverageTruncated: Bool = false) {
        self.version = version; self.savedAt = savedAt; self.events = events
        self.readTaskIDs = readTaskIDs; self.coverageTruncated = coverageTruncated
    }

    private enum CodingKeys: String, CodingKey {
        case version, savedAt, events, readTaskIDs, coverageTruncated
    }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        savedAt = try values.decode(Date.self, forKey: .savedAt)
        events = try values.decode([GuardEvent].self, forKey: .events)
        readTaskIDs = try values.decode([String].self, forKey: .readTaskIDs)
        coverageTruncated = try values.decodeIfPresent(Bool.self, forKey: .coverageTruncated) ?? false
    }

    private struct FormatHeader: Decodable { let version: Int }
    private struct BodyReference: Codable {
        let eventID: UUID
        let encoding: String
        let sha256: String
        let bytes: Int
        let compressedSHA256: String
        let compressedBytes: Int
    }
    private struct Manifest: Codable {
        let version: Int
        let checkpointVersion: Int
        let savedAt: Date
        let bodies: [BodyReference]
        let readTaskIDs: [String]
        let coverageTruncated: Bool
    }

    /// One writer per recovery file. Its cache contains only immutable body
    /// references, never a second copy of captured command output. The lock
    /// serializes background saves and a final synchronous shutdown save.
    final class Writer: @unchecked Sendable {
        struct SaveMetrics: Equatable {
            var serializedEvents = 0
            var reusedEvents = 0
            var revalidatedBodies = 0
        }
        private struct CachedBody {
            let revision: UUID
            let reference: BodyReference
            let stamp: FileStamp
        }
        private struct FileStamp: Equatable {
            let device: UInt64, inode: UInt64
            let size: Int64
            let modifiedSeconds: Int64, modifiedNanos: Int64
            let changedSeconds: Int64, changedNanos: Int64

            init(_ url: URL) throws {
                var value = Darwin.stat()
                guard Darwin.lstat(url.path, &value) == 0 else {
                    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno),
                        userInfo: [NSLocalizedDescriptionKey: "实时恢复正文缺失或无法读取；旧检查点保留"])
                }
                guard value.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) else {
                    throw RealtimeActiveCheckpoint.failure("实时恢复正文不是常规文件；旧检查点保留")
                }
                device = UInt64(truncatingIfNeeded: value.st_dev); inode = UInt64(value.st_ino)
                size = Int64(value.st_size)
                modifiedSeconds = Int64(value.st_mtimespec.tv_sec); modifiedNanos = Int64(value.st_mtimespec.tv_nsec)
                changedSeconds = Int64(value.st_ctimespec.tv_sec); changedNanos = Int64(value.st_ctimespec.tv_nsec)
            }
        }
        private let url: URL
        private let lock = NSLock()
        private var cached: [UUID: CachedBody] = [:]

        private let useDatabase: Bool
        private var database: RealtimeCheckpointDatabase?
        init(url: URL, useDatabase: Bool = false) { self.url = url; self.useDatabase = useDatabase }

        /// Only changed revisions read their live body. Unchanged references
        /// are checked against filesystem identity/size/nanosecond timestamps;
        /// a changed file must pass a fresh digest check before it can be reused.
        /// Missing or damaged blobs fail the save instead of silently committing
        /// an unreadable manifest. Old manifests/bodies are never deleted here.
        @discardableResult
        func save(records: [RealtimeLiveEvidenceBuffer.Record], readTaskIDs: [String],
                  coverageTruncated: Bool, savedAt: Date = Date()) throws -> SaveMetrics {
            lock.lock(); defer { lock.unlock() }
            if useDatabase {
                if database == nil { database = try RealtimeCheckpointDatabase(url: RealtimeCheckpointDatabase.location(for: url)) }
                return try database!.save(records: records, readTaskIDs: readTaskIDs, coverageTruncated: coverageTruncated, savedAt: savedAt)
            }
            guard Set(records.map(\.id)).count == records.count else {
                throw RealtimeActiveCheckpoint.failure("实时恢复快照含重复事件身份；旧检查点保留")
            }
            let manager = FileManager.default
            let directory = RealtimeActiveCheckpoint.bodyDirectory(for: url)
            try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            var next: [UUID: CachedBody] = [:]
            var references: [BodyReference] = []
            references.reserveCapacity(records.count)
            var metrics = SaveMetrics()
            for record in records {
                if let old = cached[record.id], old.revision == record.revision {
                    let bodyURL = directory.appendingPathComponent(old.reference.sha256 + ".lzfse")
                    let stamp = try FileStamp(bodyURL)
                    guard stamp.size == old.reference.compressedBytes else {
                        throw RealtimeActiveCheckpoint.failure("实时恢复正文长度不匹配；旧检查点保留")
                    }
                    if stamp != old.stamp {
                        let bytes = try Data(contentsOf: bodyURL)
                        guard bytes.count == old.reference.compressedBytes,
                              RealtimeActiveCheckpoint.digest(bytes) == old.reference.compressedSHA256,
                              try FileStamp(bodyURL) == stamp else {
                            throw RealtimeActiveCheckpoint.failure("实时恢复正文校验失败；旧检查点保留")
                        }
                        metrics.revalidatedBodies += 1
                    }
                    next[record.id] = CachedBody(revision: record.revision, reference: old.reference, stamp: stamp)
                    references.append(old.reference); metrics.reusedEvents += 1
                    continue
                }
                // Read/encode one changed event at a time. There is no full
                // decompressed events array and no task projection in this path.
                let event = try record.read()
                guard event.id == record.id else {
                    throw RealtimeActiveCheckpoint.failure("实时恢复事件身份不匹配；旧检查点保留")
                }
                let data = try encoder.encode(event)
                guard data.count <= RealtimeActiveCheckpoint.maximumEventBytes else {
                    throw RealtimeActiveCheckpoint.failure("单条实时恢复正文超过256 MiB安全读取上限；旧检查点保留")
                }
                let compressed = try RealtimeActiveCheckpoint.compress(data)
                let reference = BodyReference(eventID: event.id, encoding: "lzfse-json-event-v1",
                    sha256: RealtimeActiveCheckpoint.digest(data), bytes: data.count,
                    compressedSHA256: RealtimeActiveCheckpoint.digest(compressed), compressedBytes: compressed.count)
                let bodyURL = directory.appendingPathComponent(reference.sha256 + ".lzfse")
                if manager.fileExists(atPath: bodyURL.path) {
                    let before = try FileStamp(bodyURL)
                    guard before.size == compressed.count,
                          try Data(contentsOf: bodyURL) == compressed,
                          try FileStamp(bodyURL) == before else {
                        throw RealtimeActiveCheckpoint.failure("已有实时恢复正文校验失败；旧检查点保留")
                    }
                } else { try RealtimeActiveCheckpoint.atomicPrivateWrite(compressed, to: bodyURL) }
                next[record.id] = CachedBody(revision: record.revision, reference: reference, stamp: try FileStamp(bodyURL))
                references.append(reference); metrics.serializedEvents += 1
            }
            let manifest = Manifest(version: 2, checkpointVersion: 1, savedAt: savedAt, bodies: references,
                                    readTaskIDs: readTaskIDs, coverageTruncated: coverageTruncated)
            let data = try encoder.encode(manifest)
            guard data.count <= RealtimeActiveCheckpoint.maximumBytes else {
                throw RealtimeActiveCheckpoint.failure("实时恢复索引超过16 MiB上限；旧检查点保留")
            }
            try RealtimeActiveCheckpoint.atomicPrivateWrite(data, to: url)
            cached = next
            return metrics
        }
    }

    static func load(_ url: URL, maximumRawBytes: Int = 32 * 1024 * 1024) throws -> RealtimeActiveCheckpoint? {
        let databaseURL = RealtimeCheckpointDatabase.location(for: url)
        if FileManager.default.fileExists(atPath: databaseURL.path),
           let checkpoint = try RealtimeCheckpointDatabase(url: databaseURL).load(maximumRawBytes: maximumRawBytes) { return checkpoint }

        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= maximumBytes else { throw failure("实时恢复索引超过16 MiB上限") }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumBytes else { throw failure("实时恢复索引超过16 MiB上限") }
        let decoder = JSONDecoder()
        switch try decoder.decode(FormatHeader.self, from: data).version {
        case 1:
            // Existing inline checkpoints remain readable and migrate on save.
            return try decoder.decode(Self.self, from: data)
        case 2:
            let manifest = try decoder.decode(Manifest.self, from: data)
            guard manifest.checkpointVersion == 1 else { throw failure("不支持的实时恢复数据版本") }
            let root = bodyDirectory(for: url)
            let events = try manifest.bodies.map { reference -> GuardEvent in
                try validate(reference)
                let bodyURL = root.appendingPathComponent(reference.sha256 + ".lzfse")
                let fileSize = try bodyURL.resourceValues(forKeys: [.fileSizeKey]).fileSize
                guard fileSize == reference.compressedBytes else { throw failure("实时恢复正文缺失或长度不匹配") }
                let compressed = try Data(contentsOf: bodyURL)
                guard compressed.count == reference.compressedBytes, digest(compressed) == reference.compressedSHA256 else {
                    throw failure("实时恢复正文校验失败")
                }
                let body = try decompress(compressed, expectedBytes: reference.bytes)
                guard digest(body) == reference.sha256 else { throw failure("实时恢复原文校验失败") }
                let event = try decoder.decode(GuardEvent.self, from: body)
                guard event.id == reference.eventID else { throw failure("实时恢复事件身份不匹配") }
                return event
            }
            return Self(version: manifest.checkpointVersion, savedAt: manifest.savedAt, events: events,
                        readTaskIDs: manifest.readTaskIDs, coverageTruncated: manifest.coverageTruncated)
        default:
            throw failure("不支持的实时恢复索引版本")
        }
    }

    func save(_ url: URL) throws {
        guard version == 1 else { throw Self.failure("不支持的实时恢复数据版本") }
        let manager = FileManager.default
        let directory = Self.bodyDirectory(for: url)
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        // Stable encoding makes unchanged events share the same immutable file.
        encoder.outputFormatting = [.sortedKeys]
        var references: [BodyReference] = []
        references.reserveCapacity(events.count)
        for event in events {
            let data = try encoder.encode(event)
            guard data.count <= Self.maximumEventBytes else { throw Self.failure("单条实时恢复正文超过256 MiB安全读取上限；旧检查点保留") }
            let compressed = try Self.compress(data)
            let reference = BodyReference(eventID: event.id, encoding: "lzfse-json-event-v1", sha256: Self.digest(data),
                                          bytes: data.count, compressedSHA256: Self.digest(compressed), compressedBytes: compressed.count)
            let bodyURL = directory.appendingPathComponent(reference.sha256 + ".lzfse")
            if manager.fileExists(atPath: bodyURL.path) {
                // Never trust an existing file merely because its name matches.
                let existing = try Data(contentsOf: bodyURL)
                guard existing == compressed else { throw Self.failure("已有实时恢复正文校验失败；旧检查点保留") }
            } else {
                try Self.atomicPrivateWrite(compressed, to: bodyURL)
            }
            references.append(reference)
        }
        let manifest = Manifest(version: 2, checkpointVersion: version, savedAt: savedAt, bodies: references,
                                readTaskIDs: readTaskIDs, coverageTruncated: coverageTruncated)
        let data = try encoder.encode(manifest)
        guard data.count <= Self.maximumBytes else { throw Self.failure("实时恢复索引超过16 MiB上限；旧检查点保留") }
        // Commit last. Failed body or manifest writes leave the old snapshot usable.
        try Self.atomicPrivateWrite(data, to: url)
        // Do not delete old bodies here: a concurrent reader may hold the previous
        // manifest. Cleanup needs a separate quiescent lifecycle, not save-time GC.
    }

    static func bodyDirectory(for url: URL) -> URL { url.appendingPathExtension("bodies") }
    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func validate(_ value: BodyReference) throws {
        guard value.encoding == "lzfse-json-event-v1", isDigest(value.sha256), isDigest(value.compressedSHA256),
              value.bytes > 0, value.bytes <= maximumEventBytes,
              value.compressedBytes > 0, value.compressedBytes <= maximumEventBytes + 1024 * 1024 else {
            throw failure("实时恢复正文引用无效")
        }
    }
    private static func compress(_ data: Data) throws -> Data {
        // NSData's streaming implementation handles incompressible data without
        // assuming that compressed output must be smaller than its input.
        try (data as NSData).compressed(using: .lzfse) as Data
    }
    private static func decompress(_ data: Data, expectedBytes: Int) throws -> Data {
        // An extra byte lets us reject a stream that expands beyond its declared
        // size. The validated reference bounds allocation before decompression.
        var output = Data(count: expectedBytes + 1)
        let capacity = output.count
        let written = output.withUnsafeMutableBytes { destination in
            data.withUnsafeBytes { source in
                compression_decode_buffer(destination.bindMemory(to: UInt8.self).baseAddress!, capacity,
                                          source.bindMemory(to: UInt8.self).baseAddress!, data.count, nil, COMPRESSION_LZFSE)
            }
        }
        guard written == expectedBytes else { throw failure("实时恢复正文解压长度不匹配") }
        output.removeLast()
        return output
    }
    private static func atomicPrivateWrite(_ data: Data, to url: URL) throws {
        let manager = FileManager.default
        let parent = url.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temporary = parent.appendingPathComponent(".checkpoint-" + UUID().uuidString + ".tmp")
        guard manager.createFile(atPath: temporary.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw failure("无法创建实时恢复临时文件；旧检查点保留")
        }
        defer { try? manager.removeItem(at: temporary) }
        let handle = try FileHandle(forWritingTo: temporary)
        do {
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            throw error
        }
        guard Darwin.rename(temporary.path, url.path) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno), userInfo: [NSLocalizedDescriptionKey: "实时恢复文件原子替换失败；旧检查点保留"])
        }
        // Persist the rename where supported. Some filesystems reject directory
        // fsync; the file itself was synchronized before the atomic replacement.
        let descriptor = Darwin.open(parent.path, O_RDONLY)
        if descriptor >= 0 { _ = Darwin.fsync(descriptor); _ = Darwin.close(descriptor) }
    }
    private static func failure(_ message: String) -> NSError {
        NSError(domain: "AgentReins.RealtimeCheckpoint", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
