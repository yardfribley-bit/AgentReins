import CryptoKit
import Foundation

/// Deterministic, offline structural indexer based on the document model and
/// ranking approach used by pacifio/atlas. Unlike Atlas' current scanner, this
/// implementation includes Swift so AgentReins can understand its own codebase.
enum ProjectStructuralIndexer {
    private static let maximumSourceBytes = 1_000_000

    static func scan(root: URL, files: [String]) -> [ProjectCodeDocument] {
        // Atlas caps structural indexing for large repositories. Keep the same
        // bounded behavior and yield between batches so indexing cannot monopolize
        // an interactive AgentReins session.
        var documents: [ProjectCodeDocument] = []
        for (offset, relativePath) in files.prefix(1_500).enumerated() {
            if Task.isCancelled { break }
            if let document = scanFile(root: root, relativePath: relativePath) { documents.append(document) }
            if offset > 0, offset.isMultiple(of: 25) { Thread.sleep(forTimeInterval: 0.004) }
        }
        let ranks = importRanks(documents)
        documents = documents.map { document in
            ProjectCodeDocument(rel: document.rel, language: document.language,
                imports: document.imports, symbols: document.symbols, hash: document.hash,
                summary: structuralSummary(document), importRank: ranks[document.rel, default: 0])
        }
        return documents.sorted {
            if $0.importRank != $1.importRank { return $0.importRank > $1.importRank }
            return $0.rel < $1.rel
        }
    }

    private static func scanFile(root: URL, relativePath: String) -> ProjectCodeDocument? {
        guard !Task.isCancelled, let language = language(for: relativePath) else { return nil }
        let url = root.appendingPathComponent(relativePath)
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              ((attributes[.size] as? NSNumber)?.intValue ?? (maximumSourceBytes + 1)) <= maximumSourceBytes,
              let data = try? Data(contentsOf: url), let source = String(data: data, encoding: .utf8) else { return nil }
        let imports = parseImports(source, language: language)
        let symbols = parseSymbols(source, language: language)
        guard !imports.isEmpty || !symbols.isEmpty else { return nil }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return ProjectCodeDocument(rel: relativePath, language: language, imports: imports,
            symbols: symbols, hash: digest, summary: "", importRank: 0)
    }

    private static func language(for path: String) -> String? {
        switch URL(fileURLWithPath: path).pathExtension.lowercased() {
        case "swift": return "Swift"
        case "rs": return "Rust"
        case "ts", "tsx": return "TypeScript"
        case "js", "jsx", "mjs", "cjs": return "JavaScript"
        case "py": return "Python"
        case "go": return "Go"
        case "c", "h": return "C"
        case "cc", "cpp", "cxx", "hpp": return "C++"
        case "java", "kt", "kts": return "JVM"
        default: return nil
        }
    }

    private static func parseImports(_ source: String, language: String) -> [String] {
        let patterns: [String]
        switch language {
        case "Swift": patterns = [#"(?m)^\s*(?:@\w+(?:\([^\n]*\))?\s+)*import\s+(?:\w+\s+)?([A-Za-z_][\w.]*)"#]
        case "Rust": patterns = [#"(?m)^\s*(?:use|mod)\s+([^;{]+)"#]
        case "Python": patterns = [#"(?m)^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))"#]
        case "Go": patterns = [#"(?m)^\s*import\s+(?:\w+\s+)?\"([^\"]+)\""#]
        case "C", "C++": patterns = [#"(?m)^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]"#]
        case "JVM": patterns = [#"(?m)^\s*import\s+([A-Za-z_][\w.*]+)"#]
        default: patterns = [#"(?m)(?:import[^\n]*?from\s*|require\s*\()?[\"']([^\"']+)[\"']"#]
        }
        return unique(patterns.flatMap { captures(pattern: $0, in: source).flatMap { $0 } }).prefix(40).map { $0 }
    }

    private static func parseSymbols(_ source: String, language: String) -> [ProjectCodeSymbol] {
        let pattern: String
        switch language {
        case "Swift":
            pattern = #"(?m)^\s*(?:public\s+|internal\s+|private\s+|fileprivate\s+|open\s+|final\s+|static\s+|class\s+|nonisolated\s+|@\w+(?:\([^\n]*\))?\s+)*(actor|class|struct|enum|protocol|extension|func|typealias|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)"#
        case "Rust": pattern = #"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(fn|struct|enum|trait|mod|type|const)\s+([A-Za-z_][A-Za-z0-9_]*)"#
        case "Python": pattern = #"(?m)^\s*(class|def|async\s+def)\s+([A-Za-z_][A-Za-z0-9_]*)"#
        case "Go": pattern = #"(?m)^\s*(func|type|const|var)\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)"#
        case "C", "C++": pattern = #"(?m)^\s*(?:template\s*<[^\n>]+>\s*)?(?:[A-Za-z_][\w:<>,*&\s]+\s+)?(class|struct|enum|typedef|using|function)\s*([A-Za-z_][A-Za-z0-9_]*)"#
        case "JVM": pattern = #"(?m)^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|final\s+|sealed\s+|data\s+)*(class|interface|enum|object|fun)\s+([A-Za-z_][A-Za-z0-9_]*)"#
        default: pattern = #"(?m)^\s*(?:export\s+)?(?:default\s+)?(?:public\s+|private\s+|protected\s+|static\s+)*(class|interface|enum|function|const|let|var|type|struct)\s+([A-Za-z_$][A-Za-z0-9_$]*)"#
        }
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = source as NSString
        let newlineOffsets = source.utf16.enumerated().compactMap { $0.element == 10 ? $0.offset : nil }
        return regex.matches(in: source, range: NSRange(location: 0, length: ns.length)).prefix(200).compactMap { match in
            guard match.numberOfRanges >= 3 else { return nil }
            let kind = ns.substring(with: match.range(at: 1)).replacingOccurrences(of: "async ", with: "")
            let name = ns.substring(with: match.range(at: 2))
            let line = newlineOffsets.partitioningIndex { $0 >= match.range.location } + 1
            return ProjectCodeSymbol(name: name, kind: kind, line: line)
        }
    }

    private static func captures(pattern: String, in source: String) -> [[String]] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = source as NSString
        return regex.matches(in: source, range: NSRange(location: 0, length: ns.length)).map { match in
            (1..<match.numberOfRanges).compactMap { index in
                let range = match.range(at: index)
                return range.location == NSNotFound ? nil : ns.substring(with: range)
            }
        }
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }

    private static func importRanks(_ documents: [ProjectCodeDocument]) -> [String: Int] {
        var ranks: [String: Int] = [:]
        for candidate in documents {
            let stem = URL(fileURLWithPath: candidate.rel).deletingPathExtension().lastPathComponent.lowercased()
            guard !stem.isEmpty else { continue }
            ranks[candidate.rel] = documents.filter { document in
                document.rel != candidate.rel && document.imports.contains { $0.lowercased().contains(stem) }
            }.count
        }
        return ranks
    }

    private static func structuralSummary(_ document: ProjectCodeDocument) -> String {
        let definitions = document.symbols.prefix(8).map { "\($0.kind) \($0.name)" }.joined(separator: ", ")
        let dependencies = document.imports.prefix(6).joined(separator: ", ")
        var parts = ["\(document.rel) is a \(document.language) source file"]
        if !definitions.isEmpty { parts.append("defining \(definitions)") }
        if !dependencies.isEmpty { parts.append("depending on \(dependencies)") }
        return parts.joined(separator: "; ") + "."
    }
}

private extension RandomAccessCollection where Element: Comparable {
    func partitioningIndex(where predicate: (Element) -> Bool) -> Int {
        var lower = startIndex
        var upper = endIndex
        while lower != upper {
            let distance = self.distance(from: lower, to: upper)
            let middle = index(lower, offsetBy: distance / 2)
            if predicate(self[middle]) { upper = middle } else { lower = index(after: middle) }
        }
        return distance(from: startIndex, to: lower)
    }
}
