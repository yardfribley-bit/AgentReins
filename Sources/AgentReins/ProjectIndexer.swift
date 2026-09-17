import Foundation

struct ProjectIndexSnapshot: Sendable {
    let projectPath: String
    let indexedAt: Date
    let purpose: String?
    let featureNames: [String]
    let files: [String]
    let areas: [ProjectIndexArea]
    let technologies: [String]
    let complete: Bool
}

struct ProjectIndexArea: Sendable {
    let name: String
    let files: [String]
}

@MainActor
final class ProjectIndexStore: ObservableObject {
    @Published private(set) var snapshots: [String: ProjectIndexSnapshot] = [:]
    @Published private(set) var indexing: Set<String> = []
    @Published private(set) var progress: [String: ProjectIndexProgress] = [:]
    @Published private(set) var paused: Set<String> = []

    private var lastRequested: [String: Date] = [:]
    private var tasks: [String: Task<Void, Never>] = [:]
    private let minimumRefreshInterval: TimeInterval = 20

    func snapshot(for path: String) -> ProjectIndexSnapshot? { snapshots[path] }
    func progress(for path: String) -> ProjectIndexProgress? { progress[path] }

    func refresh(paths: [String], force: Bool = false) {
        let now = Date()
        for path in Set(paths) where path.hasPrefix("/") {
            if indexing.contains(path) { continue }
            if !force, let last = lastRequested[path], now.timeIntervalSince(last) < minimumRefreshInterval { continue }
            lastRequested[path] = now
            indexing.insert(path)
            paused.remove(path)
            tasks[path] = Task { [weak self] in
                let updates = ProjectIndexer.updates(path: path)
                for await update in updates {
                    guard !Task.isCancelled, let self else { return }
                    switch update {
                    case .partial(let snapshot): self.snapshots[path] = snapshot
                    case .progress(let value): self.progress[path] = value
                    case .complete(let snapshot): self.snapshots[path] = snapshot
                    }
                }
                guard let self else { return }
                self.indexing.remove(path)
                self.tasks[path] = nil
            }
        }
    }

    func pause(path: String) {
        tasks[path]?.cancel()
        tasks[path] = nil
        indexing.remove(path)
        paused.insert(path)
        if let current = progress[path] {
            progress[path] = ProjectIndexProgress(scannedFiles: current.scannedFiles,
                currentPath: current.currentPath, phase: .paused)
        }
    }

    func resume(path: String) {
        paused.remove(path)
        refresh(paths: [path], force: true)
    }
}

struct ProjectIndexProgress: Sendable {
    enum Phase: String, Sendable { case discovering, indexing, paused, complete }
    let scannedFiles: Int
    let currentPath: String?
    let phase: Phase
}

fileprivate enum ProjectIndexUpdate: Sendable {
    case partial(ProjectIndexSnapshot)
    case progress(ProjectIndexProgress)
    case complete(ProjectIndexSnapshot)
}

enum ProjectIndexer {
    private static let batchSize = 75
    private static let batchDelay = Duration.milliseconds(120)
    private static let ignoredDirectories: Set<String> = [
        ".git", ".build", "build", "dist", "deriveddata", "node_modules", "pods",
        ".next", ".cache", "coverage", "vendor", "target"
    ]

    fileprivate static func updates(path: String) -> AsyncStream<ProjectIndexUpdate> {
        AsyncStream { continuation in
            let worker = Task.detached(priority: .utility) {
                let root = URL(fileURLWithPath: path).standardized
                var isDirectory: ObjCBool = false
                guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
                    continuation.finish(); return
                }
                let keys: Set<URLResourceKey> = [.isRegularFileKey, .isDirectoryKey, .fileSizeKey]
                guard let enumerator = FileManager.default.enumerator(at: root,
                    includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles, .skipsPackageDescendants]) else {
                    continuation.finish(); return
                }
                var files: [String] = []
                var readme: String?
                continuation.yield(.progress(ProjectIndexProgress(scannedFiles: 0, currentPath: nil, phase: .discovering)))
                while !Task.isCancelled, let url = enumerator.nextObject() as? URL {
                    let values = try? url.resourceValues(forKeys: keys)
                    if values?.isDirectory == true {
                        if ignoredDirectories.contains(url.lastPathComponent.lowercased()) { enumerator.skipDescendants() }
                        continue
                    }
                    guard values?.isRegularFile == true else { continue }
                    let relative = relativePath(url.path, root: root.path)
                    guard !relative.isEmpty else { continue }
                    files.append(relative)
                    if readme == nil, ["readme.md", "readme", "readme.txt"].contains(url.lastPathComponent.lowercased()) {
                        readme = readText(url)
                    }
                    if files.count == 250 {
                        continuation.yield(.partial(snapshot(root: root, files: files, readme: readme, complete: false)))
                    }
                    if files.count.isMultiple(of: batchSize) {
                        continuation.yield(.progress(ProjectIndexProgress(scannedFiles: files.count,
                            currentPath: relative, phase: .indexing)))
                        try? await Task.sleep(for: batchDelay)
                    }
                }
                guard !Task.isCancelled else { continuation.finish(); return }
                files.sort()
                let result = snapshot(root: root, files: files, readme: readme, complete: true)
                continuation.yield(.complete(result))
                continuation.yield(.progress(ProjectIndexProgress(scannedFiles: files.count,
                    currentPath: nil, phase: .complete)))
                continuation.finish()
            }
            continuation.onTermination = { _ in worker.cancel() }
        }
    }

    private static func snapshot(root: URL, files: [String], readme: String?, complete: Bool) -> ProjectIndexSnapshot {
        ProjectIndexSnapshot(projectPath: root.path, indexedAt: Date(),
            purpose: readme.flatMap(readmePurpose), featureNames: readme.map(readmeFeatures) ?? [],
            files: files, areas: architectureAreas(files), technologies: technologies(files), complete: complete)
    }

    private static func readText(_ url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: 128_000) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func readmePurpose(_ text: String) -> String? {
        var paragraph: [String] = []
        var passedTitle = false
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("#") { passedTitle = true; if !paragraph.isEmpty { break }; continue }
            if line.hasPrefix("[") || line.hasPrefix("!") || line.hasPrefix("<") { continue }
            if line.isEmpty {
                if passedTitle && !paragraph.isEmpty { break }
                continue
            }
            if passedTitle { paragraph.append(line) }
            if paragraph.joined(separator: " ").count > 300 { break }
        }
        let result = paragraph.joined(separator: " ")
        return result.count >= 20 ? String(result.prefix(420)) : nil
    }

    private static func readmeFeatures(_ text: String) -> [String] {
        let ignored = ["install", "installation", "usage", "quick start", "getting started", "license",
                       "contributing", "requirements", "build", "development", "roadmap", "contents"]
        var seen = Set<String>()
        return text.components(separatedBy: .newlines).compactMap { raw -> String? in
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.hasPrefix("##") else { return nil }
            let title = line.trimmingCharacters(in: CharacterSet(charactersIn: "# "))
            guard title.count >= 3, title.count <= 64, !ignored.contains(where: title.lowercased().contains) else { return nil }
            return seen.insert(title.lowercased()).inserted ? title : nil
        }.prefix(8).map { $0 }
    }

    private static func architectureAreas(_ files: [String]) -> [ProjectIndexArea] {
        let grouped = Dictionary(grouping: files) { file -> String in
            let parts = file.split(separator: "/")
            if let source = parts.firstIndex(where: { ["sources", "src", "app", "packages"].contains($0.lowercased()) }), parts.count > source + 1 {
                return String(parts[source + 1])
            }
            return parts.count > 1 ? String(parts[0]) : "Project Root"
        }
        return grouped.map { ProjectIndexArea(name: $0.key, files: Array($0.value.prefix(20))) }
            .sorted { $0.files.count > $1.files.count }.prefix(10).map { $0 }
    }

    private static func technologies(_ files: [String]) -> [String] {
        let mapping: [(String, String)] = [
            (".swift", "Swift"), (".xcodeproj", "Xcode"), ("package.swift", "Swift Package Manager"),
            (".ts", "TypeScript"), (".tsx", "React / TypeScript"), ("package.json", "Node.js"),
            (".py", "Python"), ("pyproject.toml", "Python"), (".go", "Go"), ("go.mod", "Go"),
            (".rs", "Rust"), ("cargo.toml", "Rust"), (".java", "Java"), ("pom.xml", "Maven"),
            ("dockerfile", "Docker"), (".sql", "SQL")
        ]
        let lower = files.map { $0.lowercased() }
        return Array(Set(mapping.compactMap { suffix, technology in
            lower.contains(where: { $0.hasSuffix(suffix) }) ? technology : nil
        })).sorted()
    }

    private static func relativePath(_ path: String, root: String) -> String {
        guard path.hasPrefix(root) else { return path }
        return String(path.dropFirst(root.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
}
