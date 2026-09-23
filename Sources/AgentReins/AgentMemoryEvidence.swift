import CryptoKit
import Foundation

/// Memory instructions and memory data have different evidentiary meanings.
/// A reminder about MEMORY.md does not prove that the file was read or sent.
struct AgentMemoryEvidenceReport: Codable, Sendable {
    enum Assessment: String, Codable, Sendable {
        case noMemoryEvidence
        case instructionsOnly
        case memoryBlockUnverified
        case memoryContentObservedLocally
        case memoryContentInCompleteRequest
    }

    enum Coverage: String, Codable, Sendable {
        case noRequestContext
        case partialOrUnverifiedContext
        case completeRequestBody
    }

    struct ContextSegment: Codable, Identifiable, Sendable {
        enum Kind: String, Codable, Sendable {
            case usageInstructions
            case memoryContentCandidate
            case memoryFileContent
        }

        let id: String
        let kind: Kind
        let requestEventID: String
        let source: String
        let captureMode: AgentOutboundRequestEvidence.CaptureMode
        let completeness: AgentOutboundRequestEvidence.Completeness
        let content: String
        let contentSHA256: String
        let byteCount: Int
        let sourcePaths: [String]
    }

    struct ContentMatch: Codable, Identifiable, Sendable {
        let id: String
        let memoryEventID: String
        let requestEventID: String
        let contentSHA256: String
        let byteCount: Int
        let captureMode: AgentOutboundRequestEvidence.CaptureMode
        let completeness: AgentOutboundRequestEvidence.Completeness
    }

    let assessment: Assessment
    let coverage: Coverage
    let contextSegments: [ContextSegment]
    let contentMatches: [ContentMatch]
    let memoryActivityEventIDs: [String]

    static func build(events: [GuardEvent], requests: [AgentOutboundRequestEvidence]) -> Self {
        let memoryEvents = events.filter {
            $0.kind == "file" && isKnownMemoryStore($0.relatedPath ?? $0.path)
        }
        var segments: [ContextSegment] = []
        for request in requests {
            for (kind, tag) in [
                (ContextSegment.Kind.usageInstructions, "memory_and_skills_reminder"),
                (.memoryContentCandidate, "memory_context"),
                (.memoryContentCandidate, "memory"),
                (.memoryContentCandidate, "identity_context")
            ] {
                for (index, content) in taggedBlocks(tag, in: request.body).enumerated() {
                    segments.append(ContextSegment(
                        id: "\(request.eventID):\(tag):\(index)", kind: kind,
                        requestEventID: request.eventID, source: request.evidenceSource,
                        captureMode: request.captureMode, completeness: request.completeness,
                        content: content, contentSHA256: digest(content),
                        byteCount: content.utf8.count,
                        sourcePaths: tag == "identity_context" ? identityMemoryPaths(in: content) : []))
                    if tag == "identity_context" {
                        for (fileIndex, file) in identityFileBlocks(in: content).enumerated() {
                            segments.append(ContextSegment(
                                id: "\(request.eventID):identity-file:\(index):\(fileIndex)",
                                kind: .memoryFileContent, requestEventID: request.eventID,
                                source: request.evidenceSource, captureMode: request.captureMode,
                                completeness: request.completeness, content: file.content,
                                contentSHA256: digest(file.content), byteCount: file.content.utf8.count,
                                sourcePaths: [file.path]))
                        }
                    }
                }
            }
        }
        // Match complete observed file content. Short or generic fragments
        // cannot establish that a specific memory file entered a request.
        let matches = memoryEvents.flatMap { event -> [ContentMatch] in
            guard let content = event.afterContent, content.utf8.count >= 32 else { return [] }
            return requests.filter { $0.body.contains(content) }.map { request in
                ContentMatch(id: "\(event.id.uuidString):\(request.eventID)",
                    memoryEventID: event.id.uuidString, requestEventID: request.eventID,
                    contentSHA256: digest(content), byteCount: content.utf8.count,
                    captureMode: request.captureMode, completeness: request.completeness)
            }
        }
        let assessment: Assessment
        if matches.contains(where: { $0.completeness == .complete &&
            [.completeHTTPSRequestBody, .preEncryptionRequestBody].contains($0.captureMode) }) {
            assessment = .memoryContentInCompleteRequest
        } else if !matches.isEmpty || segments.contains(where: { $0.kind == .memoryFileContent }) {
            assessment = .memoryContentObservedLocally
        } else if segments.contains(where: { $0.kind == .memoryContentCandidate }) {
            assessment = .memoryBlockUnverified
        } else if segments.contains(where: { $0.kind == .usageInstructions }) {
            assessment = .instructionsOnly
        } else {
            assessment = .noMemoryEvidence
        }
        let coverage: Coverage = requests.contains {
            $0.completeness == .complete &&
                [.completeHTTPSRequestBody, .preEncryptionRequestBody].contains($0.captureMode)
        } ? .completeRequestBody : requests.isEmpty ? .noRequestContext : .partialOrUnverifiedContext
        return Self(assessment: assessment, coverage: coverage, contextSegments: segments,
                    contentMatches: matches,
                    memoryActivityEventIDs: memoryEvents.map { $0.id.uuidString }.sorted())
    }

    static func containsMemoryContentCandidate(_ text: String) -> Bool {
        !taggedBlocks("memory_context", in: text).isEmpty ||
            !taggedBlocks("memory", in: text).isEmpty ||
            taggedBlocks("identity_context", in: text).contains { !identityFileBlocks(in: $0).isEmpty }
    }

    static func isKnownMemoryStore(_ value: String) -> Bool {
        let path = value.lowercased()
        return path.contains("/.workbuddy/memory/") ||
            path.contains("/.kiro/knowledge/memory/") ||
            path.contains("/.kiro/crew/workspace/memory/") ||
            path.contains("/.agent-memory/") ||
            (path.contains("/.workbuddy/") &&
                ["/memory.md", "/user.md", "/identity.md", "/soul.md"].contains(where: path.contains))
    }

    private static func taggedBlocks(_ tag: String, in text: String) -> [String] {
        let escaped = NSRegularExpression.escapedPattern(for: tag)
        guard let regex = try? NSRegularExpression(
            pattern: "<\(escaped)(?:\\s[^>]*)?>[\\s\\S]*?</\(escaped)>",
            options: [.caseInsensitive]) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
            .compactMap { Range($0.range, in: text).map { String(text[$0]) } }
    }

    private static func identityMemoryPaths(in content: String) -> [String] {
        // WorkBuddy trace toolInput is a JSON-escaped request prefix. Convert
        // line escapes only for path recognition; retain the raw source block.
        let lines = content.replacingOccurrences(of: "\\n", with: "\n")
        guard let regex = try? NSRegularExpression(
            pattern: #"(?m)^Path:\s*([^\r\n]+/\.workbuddy/(?:SOUL|IDENTITY|USER)\.md)\s*$"#,
            options: [.caseInsensitive]) else { return [] }
        let paths = regex.matches(in: lines, range: NSRange(lines.startIndex..., in: lines))
            .compactMap { Range($0.range(at: 1), in: lines).map { String(lines[$0]) } }
        return Array(Set(paths)).sorted()
    }

    private static func identityFileBlocks(in content: String) -> [(path: String, content: String)] {
        let text = content.replacingOccurrences(of: "\\n", with: "\n")
        guard let heading = try? NSRegularExpression(
            pattern: #"(?m)^## (?:SOUL|IDENTITY|USER)\.md\s*$"#,
            options: [.caseInsensitive]) else { return [] }
        let matches = heading.matches(in: text, range: NSRange(text.startIndex..., in: text))
        return matches.enumerated().compactMap { index, match in
            let end = index + 1 < matches.count ? matches[index + 1].range.location : (text as NSString).length
            guard let range = Range(NSRange(location: match.range.location,
                                             length: end - match.range.location), in: text) else { return nil }
            let block = String(text[range]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard let path = identityMemoryPaths(in: block).first,
                  let pathLine = block.range(of: "Path: \(path)"),
                  block[pathLine.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines).utf8.count >= 24
            else { return nil }
            return (path, block)
        }
    }

    private static func digest(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
