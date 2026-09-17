import Foundation

struct ProjectIndexSnapshot: Sendable {
    let projectPath: String
    let indexedAt: Date
    let purpose: String?
    let featureNames: [String]
    let files: [String]
    let areas: [ProjectIndexArea]
    let technologies: [String]
    let truncated: Bool
}

struct ProjectIndexArea: Sendable {
    let name: String
    let files: [String]
}

@MainActor
final class ProjectIndexStore: ObservableObject {
    @Published private(set) var snapshots: [String: ProjectIndexSnapshot] = [:]
    @Published private(set) var indexing: Set<String> = []

    private var lastRequested: [String: Date] = [:]
    private let minimumRefreshInterval: TimeInterval = 20

    func snapshot(for path: String) -> ProjectIndexSnapshot? { snapshots[path] }

    func refresh(paths: [String], force: Bool = false) {
        let now = Date()
        for path in Set(paths) where path.hasPrefix("/") {
            if indexing.contains(path) { continue }
            if !force, let last = lastRequested[path], now.timeIntervalSince(last) < minimumRefreshInterval { continue }
            lastRequested[path] = now
            indexing.insert(path)
            Task { [weak self] in
                let result = await Task.detached(priority: .utility) {
                    ProjectIndexer.index(path: path)
                }.value
                guard let self else { return }
                self.indexing.remove(path)
                if let result { self.snapshots[path] = result }
            }
        }
    }
}

enum ProjectIndexer {
    private static let maximumFiles = 2_500
    private static let ignoredDirectories: Set<String> = [
        ".git", ".build", "build", "dist", "deriveddata", "node_modules", "pods",
        ".next", ".cache", "coverage", "vendor", "target"
    ]

    static func index(path: String) -> ProjectIndexSnapshot? {
        let root = URL(fileURLWithPath: path).standardized
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else { return nil }

        let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .fileSizeKey]
        guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]) else { return nil }

        var files: [String] = []
        var truncated = false
        while let url = enumerator.nextObject() as? URL {
            if (try? url.resourceValues(forKeys: Set(keys)))?.isDirectory == true {
                if ignoredDirectories.contains(url.lastPathComponent.lowercased()) { enumerator.skipDescendants() }
                continue
            }
            guard (try? url.resourceValues(forKeys: Set(keys)))?.isRegularFile == true else { continue }
            let relative = relativePath(url.path, root: root.path)
            guard !relative.isEmpty else { continue }
            files.append(relative)
            if files.count >= maximumFiles { truncated = true; break }
        }
        files.sort()

        let readmeURL = files.first(where: { file in
            let name = URL(fileURLWithPath: file).lastPathComponent.lowercased()
            return name == "readme.md" || name == "readme" || name == "readme.txt"
        }).map { root.appendingPathComponent($0) }
        let readme = readmeURL.flatMap(readText)
        return ProjectIndexSnapshot(projectPath: root.path, indexedAt: Date(),
            purpose: readme.flatMap(readmePurpose), featureNames: readme.map(readmeFeatures) ?? [],
            files: files, areas: architectureAreas(files), technologies: technologies(files), truncated: truncated)
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
