import Foundation
import CryptoKit

/// Content-addressed JSON tree: unchanged values retain their hashes across revisions.
enum AuditBlockProtocol {
    static let blockBytes = 256 * 1024
    struct Prepared: Codable {
        let root: String
        let hashes: [String]
        let sequence: Int
        let generation: Int
        let identity: AuditDeviceIdentity
    }
    static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    static func prepare(_ snapshot: AgentTaskSnapshot, directory: URL, sequence: Int, generation: Int) throws -> Prepared {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let object = try JSONSerialization.jsonObject(with: encoder.encode(snapshot))
        var hashes = Set<String>()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let root = try encode(object, directory: directory, hashes: &hashes)
        return Prepared(root: root, hashes: hashes.sorted(), sequence: sequence, generation: generation, identity: AuditDeviceIdentity.capture())
    }
    static func encode(_ value: Any, directory: URL, hashes: inout Set<String>) throws -> String {
        func node(_ object: [String: Any]) throws -> String {
            try store(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .fragmentsAllowed]), directory: directory, hashes: &hashes)
        }
        let compact = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed])
        if compact.count <= 16 * 1024 { return try node(["t": "j", "v": value]) }
        if let object = value as? [String: Any] {
            var children: [String: String] = [:]
            for (key, child) in object { children[key] = try encode(child, directory: directory, hashes: &hashes) }
            return try node(["t": "o", "v": children])
        }
        if let array = value as? [Any] {
            var children: [String] = []
            for child in array { children.append(try encode(child, directory: directory, hashes: &hashes)) }
            if children.count <= 1024 { return try node(["t": "a", "v": children]) }
            var pages: [String] = []
            for offset in stride(from: 0, to: children.count, by: 1024) {
                pages.append(try node(["t": "a", "v": Array(children[offset..<min(offset + 1024, children.count)])]))
            }
            return try node(["t": "l", "v": pages])
        }
        if let string = value as? String, string.utf8.count > 32 * 1024 {
            let data = Data(string.utf8)
            var parts: [String] = []
            for offset in stride(from: 0, to: data.count, by: blockBytes) {
                parts.append(try store(data.subdata(in: offset..<min(offset + blockBytes, data.count)), directory: directory, hashes: &hashes))
            }
            return try node(["t": "s", "parts": parts])
        }
        return try node(["t": "v", "v": value])
    }
    private static func store(_ data: Data, directory: URL, hashes: inout Set<String>) throws -> String {
        guard data.count <= blockBytes else { throw CocoaError(.fileWriteOutOfSpace) }
        let digest = hash(data), url = directory.appendingPathComponent(digest)
        if !FileManager.default.fileExists(atPath: url.path) {
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        hashes.insert(digest)
        return digest
    }
}
