import Foundation

struct ProjectIndexSnapshot: Sendable {
    let projectPath: String
    let indexedAt: Date
    let purpose: String?
    let featureNames: [String]
    let files: [String]
    let areas: [ProjectIndexArea]
    let technologies: [String]
    let documents: [ProjectCodeDocument]
    let engine: ProjectIndexEngine
    let atlasEvents: [AtlasProjectEvent]
    let complete: Bool
}

struct AtlasProjectEvent: Codable, Hashable, Sendable {
    let source: String
    let kind: String
    let summary: String
    let timestamp: String
    let status: String?
    let agent: String?
}

enum ProjectIndexEngine: String, Sendable {
    case structural = "AgentReins Structural Index"
    case atlasImport = "Atlas Code Index"
}

struct ProjectCodeSymbol: Codable, Hashable, Sendable {
    let name: String
    let kind: String
    let line: Int
}

/// AgentReins' versioned form of Atlas' `CodebaseDoc`.  Keeping this boundary
/// independent from the UI lets us consume a native atlas-codeindex sidecar or
/// an existing `.atlas/codebase-index/docs.json` without changing the product.
struct ProjectCodeDocument: Codable, Hashable, Sendable {
    let rel: String
    let language: String
    let imports: [String]
    let symbols: [ProjectCodeSymbol]
    let hash: String
    let summary: String
    let importRank: Int
}

struct ProjectIndexArea: Sendable {
    let name: String
    let files: [String]
}

enum ProjectIndexError: LocalizedError {
    case invalidPath(String)
    case gitUnavailable(String)
    case gitFailed(path: String, status: Int32, detail: String)
    case invalidGitOutput(String)

    var errorDescription: String? {
        switch self {
        case .invalidPath(let path):
            return "项目路径不可用：\(path)"
        case .gitUnavailable(let path):
            return "无法读取项目 Git 索引：\(path)"
        case .gitFailed(let path, let status, let detail):
            return "Git 索引失败：\(path)，退出码 \(status)，\(detail)"
        case .invalidGitOutput(let path):
            return "Git 返回了无法解析的文件列表：\(path)"
        }
    }
}

@MainActor
final class ProjectIndexStore: ObservableObject {
    @Published private(set) var snapshots: [String: ProjectIndexSnapshot] = [:]
    @Published private(set) var indexing: Set<String> = []
    @Published private(set) var errors: [String: String] = [:]

    private var tasks: [String: Task<Void, Never>] = [:]
    private let maximumFiles = 2_500

    func snapshot(for path: String) -> ProjectIndexSnapshot? { snapshots[path] }
    func error(for path: String) -> String? { errors[path] }
    func isIndexing(_ path: String) -> Bool { indexing.contains(path) }

    func request(path: String) {
        guard snapshots[path] == nil, errors[path] == nil else { return }
        start(path: path)
    }

    func refresh(path: String) {
        start(path: path)
    }

    func cancel(path: String) {
        tasks[path]?.cancel()
        tasks[path] = nil
        indexing.remove(path)
    }

    private func start(path: String) {
        guard path.hasPrefix("/"), !indexing.contains(path) else { return }
        indexing.insert(path)
        errors[path] = nil
        let maximumFiles = maximumFiles
        tasks[path] = Task { [weak self] in
            let worker = Task.detached(priority: .utility) {
                try ProjectIndexer.index(path: path, maximumFiles: maximumFiles)
            }
            let result = await withTaskCancellationHandler {
                await worker.result
            } onCancel: {
                worker.cancel()
            }
            guard !Task.isCancelled, let self else { return }
            switch result {
            case .success(let snapshot):
                self.snapshots[path] = snapshot
            case .failure(let error):
                self.errors[path] = error.localizedDescription
            }
            self.indexing.remove(path)
            self.tasks[path] = nil
        }
    }
}

enum ProjectIndexer {
    static func index(path: String, maximumFiles: Int) throws -> ProjectIndexSnapshot {
        let root = URL(fileURLWithPath: path).standardized
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ProjectIndexError.invalidPath(path)
        }
        let allFiles = try gitTrackedFiles(root: root)
        guard !Task.isCancelled else { throw CancellationError() }
        let files = Array(allFiles.prefix(maximumFiles)).sorted()
        let readmeURL = files.first { file in
            ["readme.md", "readme", "readme.txt"].contains(URL(fileURLWithPath: file).lastPathComponent.lowercased())
        }.map { root.appendingPathComponent($0) }
        let readme = readmeURL.flatMap(readText)
        if let atlasDocuments = loadAtlasDocuments(root: root), !atlasDocuments.isEmpty {
            return snapshot(root: root, files: files, readme: readme, documents: atlasDocuments,
                            engine: .atlasImport, atlasEvents: atlasEvents(root: root),
                            complete: allFiles.count <= maximumFiles)
        }
        let documents = ProjectStructuralIndexer.scan(root: root, files: files)
        return snapshot(root: root, files: files, readme: readme, documents: documents,
                        engine: .structural, atlasEvents: atlasEvents(root: root),
                        complete: allFiles.count <= maximumFiles)
    }

    private static func gitTrackedFiles(root: URL) throws -> [String] {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["-C", root.path, "ls-files", "-z"]
        process.standardOutput = output
        process.standardError = error
        do {
            try process.run()
        } catch {
            throw ProjectIndexError.gitUnavailable(root.path)
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let detail = String(data: errorData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                ?? "Git 未返回错误详情"
            throw ProjectIndexError.gitFailed(path: root.path, status: process.terminationStatus, detail: detail)
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ProjectIndexError.invalidGitOutput(root.path)
        }
        return text.split(separator: "\0").map(String.init)
    }

    private static func snapshot(root: URL, files: [String], readme: String?,
                                 documents: [ProjectCodeDocument], engine: ProjectIndexEngine,
                                 atlasEvents: [AtlasProjectEvent],
                                 complete: Bool) -> ProjectIndexSnapshot {
        ProjectIndexSnapshot(projectPath: root.path, indexedAt: Date(),
            purpose: readme.flatMap(readmePurpose), featureNames: readme.map(readmeFeatures) ?? [],
            files: files, areas: architectureAreas(files, documents: documents),
            technologies: technologies(files), documents: documents, engine: engine,
            atlasEvents: atlasEvents, complete: complete)
    }

    private static func atlasEvents(root: URL) -> [AtlasProjectEvent] {
        let url = root.appendingPathComponent(".atlas/logs.jsonl")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        struct Raw: Decodable {
            let source: String?
            let kind: String?
            let summary: String?
            let timestamp: String?
            let payload: Payload?
            struct Payload: Decodable {
                let status: String?
                let agent: String?
                let kind: String?
            }
        }
        return text.split(separator: "\n").compactMap { line in
            guard let data = line.data(using: .utf8), let raw = try? JSONDecoder().decode(Raw.self, from: data),
                  let source = raw.source, let kind = raw.kind, let summary = raw.summary else { return nil }
            return AtlasProjectEvent(source: source, kind: raw.payload?.kind ?? kind,
                summary: summary, timestamp: raw.timestamp ?? "", status: raw.payload?.status,
                agent: raw.payload?.agent)
        }
        .suffix(100)
        .reversed()
        .map { $0 }
    }

    private struct AtlasIndex: Decodable { let docs: [AtlasDocument] }
    private struct AtlasDocument: Decodable {
        let rel: String
        let language: String
        let imports: [String]
        let symbols: [ProjectCodeSymbol]
        let hash: String
        let summary: String?
        let importRank: Int?
    }

    private static func loadAtlasDocuments(root: URL) -> [ProjectCodeDocument]? {
        let url = root.appendingPathComponent(".atlas/codebase-index/docs.json")
        guard let data = try? Data(contentsOf: url),
              let index = try? JSONDecoder().decode(AtlasIndex.self, from: data) else { return nil }
        return index.docs.map {
            ProjectCodeDocument(rel: $0.rel, language: $0.language, imports: $0.imports,
                symbols: $0.symbols, hash: $0.hash, summary: $0.summary ?? "",
                importRank: $0.importRank ?? 0)
        }
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

    private static func architectureAreas(_ files: [String], documents: [ProjectCodeDocument]) -> [ProjectIndexArea] {
        let grouped = Dictionary(grouping: files) { file -> String in
            let parts = file.split(separator: "/")
            if let source = parts.firstIndex(where: { ["sources", "src", "app", "packages"].contains($0.lowercased()) }), parts.count > source + 1 {
                return String(parts[source + 1])
            }
            return parts.count > 1 ? String(parts[0]) : "Project Root"
        }
        let importance = Dictionary(uniqueKeysWithValues: documents.map { ($0.rel, $0.importRank) })
        return grouped.map { name, paths in
            ProjectIndexArea(name: name, files: Array(paths.sorted {
                importance[$0, default: 0] > importance[$1, default: 0]
            }.prefix(20)))
        }.sorted { $0.files.count > $1.files.count }.prefix(10).map { $0 }
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

}
