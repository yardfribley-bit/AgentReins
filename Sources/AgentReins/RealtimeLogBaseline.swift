import Foundation

/// Records file lengths only, never reads old log bodies. Existing files begin at EOF.
enum RealtimeLogBaseline {
    static func offsets(root: URL) -> [String: UInt64] {
        guard let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.fileSizeKey], options: [.skipsHiddenFiles]) else { return [:] }
        var result: [String: UInt64] = [:]
        for case let url as URL in files where url.pathExtension == "jsonl" {
            if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize { result[url.path] = UInt64(size) }
        }
        return result
    }
}
