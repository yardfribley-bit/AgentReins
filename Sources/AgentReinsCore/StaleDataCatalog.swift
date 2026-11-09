import Foundation

/// Files that are safe to offer for deletion. The live evidence database,
/// its WAL, and the search index are never suggestions. Nothing here deletes.
public enum StaleDataCatalog {
    public struct Item: Equatable, Sendable {
        public var id: String
        public var name: String
        public var path: String
        public var bytes: Int64
        public var reason: String

        public init(id: String, name: String, path: String, bytes: Int64, reason: String) {
            self.id = id
            self.name = name
            self.path = path
            self.bytes = bytes
            self.reason = reason
        }
    }

    public static func isStaleName(_ name: String) -> String? {
        if name == "evidence.sqlite3" || name == "evidence.sqlite3-wal" || name == "evidence.sqlite3-shm" {
            return nil
        }
        if name == "evidence.search.sqlite3" || name == "evidence.search.sqlite3-wal" || name == "evidence.search.sqlite3-shm" {
            return nil
        }
        if name == "rules.json" || name == "realtime-review-decisions-v1.json" || name == "mcp-http.token" {
            return nil
        }
        if name == "evidence.sqlite3.backup" || name.hasSuffix(".sqlite3.backup") {
            return "旧的证据库备份。正在用的 evidence.sqlite3 不会动。"
        }
        if name.hasPrefix("evidence-before-") {
            return "更早一次重建留下的证据库副本。正在用的库不会动。"
        }
        if name.contains(".corrupt-") {
            return "校验失败后隔离的副本。正在用的库不会动。"
        }
        if name.hasSuffix(".previous") || name.hasPrefix("evidence.sqlite3.previous") {
            return "压缩替换后留下的旧库。正在用的库不会动。"
        }
        return nil
    }

    public static func suggestions(directory: URL, cloudAuditBytes: Int64 = 0) -> [Item] {
        let root = directory.standardizedFileURL
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.path)) ?? []
        var items: [Item] = []
        for name in names.sorted() {
            guard let reason = isStaleName(name) else { continue }
            let url = root.appendingPathComponent(name)
            let bytes = fileBytes(url)
            guard bytes > 0 else { continue }
            items.append(Item(id: name, name: name, path: url.path, bytes: bytes, reason: reason))
        }
        if cloudAuditBytes > 0 {
            let url = root.appendingPathComponent("CloudAudit", isDirectory: true)
            items.append(Item(
                id: "CloudAudit",
                name: "CloudAudit",
                path: url.path,
                bytes: cloudAuditBytes,
                reason: "云审计暂存目录。确认后才删除，不会动 evidence.sqlite3。"
            ))
        }
        return items
    }

    /// True only for a path this catalog just offered, inside `directory`.
    public static func canDelete(id: String, directory: URL) -> URL? {
        let root = directory.standardizedFileURL.resolvingSymlinksInPath()
        if id == "CloudAudit" {
            let url = root.appendingPathComponent("CloudAudit", isDirectory: true)
            guard url.resolvingSymlinksInPath().path.hasPrefix(root.path + "/") else { return nil }
            return url
        }
        guard isStaleName(id) != nil, !id.contains("/"), !id.contains("..") else { return nil }
        let url = root.appendingPathComponent(id)
        let resolved = url.resolvingSymlinksInPath()
        guard resolved.path.hasPrefix(root.path + "/") || resolved.path == root.path else { return nil }
        guard resolved.lastPathComponent == id else { return nil }
        return resolved
    }

    public static func fileBytes(_ url: URL) -> Int64 {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else { return 0 }
        if !isDir.boolValue {
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            return (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        }
        guard let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) else {
            return 0
        }
        var total: Int64 = 0
        var seen = 0
        for case let item as URL in enumerator {
            seen += 1
            if seen > 20_000 { break }
            let values = try? item.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
            if values?.isRegularFile == true { total += Int64(values?.fileSize ?? 0) }
        }
        return total
    }
}
