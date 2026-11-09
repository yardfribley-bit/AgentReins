import Foundation

/// Bounded look at a session-log tree. A tick either continues a paused
/// directory walk (a fixed entry budget, heavy folders skipped) or stats the
/// jsonl files already found. It does not re-read log bodies and does not
/// start a fresh full scan on every poll.
public final class JSONLTreeCursor {
    public struct Listed: Equatable, Sendable {
        public var path: String
        public var modified: Date
        public var size: UInt64
        public init(path: String, modified: Date, size: UInt64) {
            self.path = path
            self.modified = modified
            self.size = size
        }
    }

    public struct Refresh: Equatable, Sendable {
        public var listed: [Listed]
        public var walked: Bool
        public var entriesVisited: Int
        public var discoveryFinished: Bool
    }

    public struct Partition: Equatable, Sendable {
        /// Files that already existed and were not in the caller's size map.
        /// Record the size and do not parse the historical body.
        public var baseline: [String: UInt64]
        /// Files whose size changed, or that were created after the live boundary.
        public var readable: [Listed]
    }

    public static let skippedDirectoryNames: Set<String> = [
        "node_modules", ".git", ".build", "DerivedData", "dist", ".next",
        "Pods", "Carthage", ".swiftpm", ".cache", "vendor", "__pycache__",
    ]

    public static func shouldSkip(_ name: String) -> Bool {
        skippedDirectoryNames.contains(name)
    }

    private var root = ""
    private var pending: [String] = []
    private var leftover: [URL] = []
    private var known: [String: Listed] = [:]
    private var lastFinished = Date.distantPast
    public private(set) var discoveryFinished = false
    public private(set) var lastEntriesVisited = 0
    public private(set) var lastWasFullWalk = false

    public init() {}

    public var sizes: [String: UInt64] {
        known.mapValues(\.size)
    }

    /// `fullInterval` of 0 walks until discovery finishes and does not schedule another pass.
    @discardableResult
    public func refresh(root rootPath: String, now: Date = Date(), fullInterval: TimeInterval = 30, entryBudget: Int = 800) -> Refresh {
        let expanded = (rootPath as NSString).expandingTildeInPath
        if expanded != root {
            root = expanded
            pending = [expanded]
            leftover = []
            known.removeAll()
            discoveryFinished = false
            lastFinished = .distantPast
        }
        let restart = discoveryFinished && fullInterval > 0 && now.timeIntervalSince(lastFinished) >= fullInterval
        if restart {
            pending = [root]
            leftover = []
            discoveryFinished = false
        }
        var walked = false
        var visited = 0
        if !discoveryFinished {
            walked = true
            let budget = max(1, entryBudget)
            if pending.isEmpty && leftover.isEmpty { pending = [root] }
            let keys: Set<URLResourceKey> = [.contentModificationDateKey, .fileSizeKey, .isSymbolicLinkKey, .isDirectoryKey]
            while visited < budget {
                if leftover.isEmpty {
                    guard let dir = pending.popLast() else { break }
                    let url = URL(fileURLWithPath: dir, isDirectory: true)
                    guard let items = try? FileManager.default.contentsOfDirectory(
                        at: url, includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]
                    ) else { continue }
                    visited += 1
                    leftover = items
                }
                while visited < budget, !leftover.isEmpty {
                    let item = leftover.removeLast()
                    visited += 1
                    let name = item.lastPathComponent
                    let values = try? item.resourceValues(forKeys: keys)
                    if values?.isSymbolicLink == true { continue }
                    if values?.isDirectory == true {
                        if Self.shouldSkip(name) { continue }
                        pending.append(item.path)
                        continue
                    }
                    guard item.pathExtension == "jsonl" else { continue }
                    let size = UInt64(values?.fileSize ?? 0)
                    let modified = values?.contentModificationDate ?? .distantPast
                    known[item.path] = Listed(path: item.path, modified: modified, size: size)
                }
            }
            if pending.isEmpty && leftover.isEmpty {
                discoveryFinished = true
                lastFinished = now
            }
        } else {
            for path in Array(known.keys) {
                visited += 1
                let url = URL(fileURLWithPath: path)
                guard let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey]),
                      values.isRegularFile != false else {
                    known.removeValue(forKey: path)
                    continue
                }
                known[path] = Listed(path: path, modified: values.contentModificationDate ?? .distantPast, size: UInt64(values.fileSize ?? 0))
            }
        }
        lastEntriesVisited = visited
        lastWasFullWalk = walked
        MainProcessMeter.addDirectoryEntries(visited, fullWalk: walked)
        return Refresh(listed: Array(known.values), walked: walked, entriesVisited: visited, discoveryFinished: discoveryFinished)
    }

    /// Old files missing from `knownSizes` become a baseline (no body read).
    /// A file modified after `acceptNewSince` is readable so a session that
    /// started this launch is not dropped. A known size that moved is readable.
    public static func partition(listed: [Listed], knownSizes: [String: UInt64], acceptNewSince: Date?) -> Partition {
        var baseline: [String: UInt64] = [:]
        var readable: [Listed] = []
        for file in listed {
            if let previous = knownSizes[file.path] {
                if previous != file.size { readable.append(file) }
                continue
            }
            let fresh = acceptNewSince.map { file.modified >= $0.addingTimeInterval(-2) } ?? true
            if fresh { readable.append(file) }
            else { baseline[file.path] = file.size }
        }
        return Partition(baseline: baseline, readable: readable)
    }
}

/// Cheap counters for the main-process hot path. Tests assert a tick stays bounded.
public enum MainProcessMeter {
    private static let lock = NSLock()
    private static var directoryEntries = 0
    private static var fullWalks = 0
    private static var processScans = 0
    private static var skips = 0

    public static func reset() {
        lock.lock()
        directoryEntries = 0
        fullWalks = 0
        processScans = 0
        skips = 0
        lock.unlock()
    }

    public static func addDirectoryEntries(_ count: Int, fullWalk: Bool) {
        lock.lock()
        directoryEntries += count
        if fullWalk { fullWalks += 1 }
        lock.unlock()
    }

    public static func noteProcessTableScan() {
        lock.lock(); processScans += 1; lock.unlock()
    }

    public static func noteSkip() {
        lock.lock(); skips += 1; lock.unlock()
    }

    public static var directoryEntriesVisited: Int { lock.lock(); defer { lock.unlock() }; return directoryEntries }
    public static var fullTreeWalks: Int { lock.lock(); defer { lock.unlock() }; return fullWalks }
    public static var processTableScans: Int { lock.lock(); defer { lock.unlock() }; return processScans }
    public static var mainLoopsSkipped: Int { lock.lock(); defer { lock.unlock() }; return skips }
}
