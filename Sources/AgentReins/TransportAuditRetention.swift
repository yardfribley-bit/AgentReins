import Foundation

/// transport-audit grew to thousands of run directories and several gigabytes of
/// pack/trace sidecars. `transport.json` is the summary list_alerts reads.
/// Raw sidecars are removed after `maxAge`. The signed summary files stay.
enum TransportAuditRetention {
    static let summaryNames: Set<String> = [
        "transport.json", "transport.json.mac", "manifest.json", "manifest.json.mac",
    ]

    struct Result: Equatable {
        var runsVisited: Int
        var filesRemoved: Int
        var bytesRemoved: Int64
    }

    static func prune(root: URL, now: Date = Date(), maxAge: TimeInterval = EvidenceValue.bulkMaxAge, maxRuns: Int = 40) -> Result {
        let fm = FileManager.default
        guard let dirs = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey, .isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return Result(runsVisited: 0, filesRemoved: 0, bytesRemoved: 0)
        }
        let cutoff = now.addingTimeInterval(-maxAge)
        var visited = 0
        var removed = 0
        var bytes: Int64 = 0
        let ranked = dirs.sorted { lhs, rhs in
            let left = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantFuture
            let right = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantFuture
            return left < right
        }
        for dir in ranked {
            if visited >= maxRuns { break }
            let values = try? dir.resourceValues(forKeys: [.isDirectoryKey, .contentModificationDateKey])
            guard values?.isDirectory != false else { continue }
            let when = values?.contentModificationDate ?? .distantFuture
            guard when < cutoff else { continue }
            let summary = dir.appendingPathComponent("transport.json")
            guard fm.fileExists(atPath: summary.path) else { continue }
            guard let children = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) else { continue }
            visited += 1
            for child in children where !summaryNames.contains(child.lastPathComponent) {
                let size = (try? child.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
                do {
                    try fm.removeItem(at: child)
                    removed += 1
                    bytes += size
                } catch {
                    continue
                }
            }
        }
        return Result(runsVisited: visited, filesRemoved: removed, bytesRemoved: bytes)
    }
}
