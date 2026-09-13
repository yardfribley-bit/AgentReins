import CryptoKit
import Foundation

enum MemoryChangeKind: String, Codable, Equatable, Sendable {
    case create, update, delete, toolReported
}

/// A persistent-memory mutation attributed to an agent turn. A commit can be
/// fully observed (file before/after evidence) or tool-reported; confidence
/// makes that distinction explicit.
struct MemoryCommitEvidence: Codable, Equatable, Sendable {
    let commitId: String
    let sessionId: String
    let turnId: String
    let agent: String
    let toolCallId: String?
    let processId: Int32?
    let storagePath: String?
    let changeKind: MemoryChangeKind
    let beforeHash: String?
    let afterHash: String?
    let contentDiff: String?
    let summary: String
    let risk: String
    let riskReasons: [String]
    let confidence: EvidenceConfidence
    let attributionMethod: String
    let observedAt: Date
    let evidenceEventIds: [String]

    static func build(events: [GuardEvent]) -> [MemoryCommitEvidence] {
        let grouped = Dictionary(grouping: events.filter { $0.sessionId != nil && $0.turnId != nil }) {
            "\($0.sessionId!):\($0.turnId!)"
        }
        return grouped.flatMap { _, rows -> [MemoryCommitEvidence] in
            guard let first = rows.first, let session = first.sessionId, let turn = first.turnId else { return [] }
            let candidates = rows.filter(isMemoryMutation)
            return candidates.map { event in
                let path = event.path == "-" ? pathFromTool(event) : event.path
                let kind = changeKind(event)
                let diff = event.fileDiff ?? bounded(event.command)
                let reasons = riskReasons(event: event, rows: rows, diff: diff)
                let confidence = event.beforeContent != nil || event.afterContent != nil
                    ? event.attributionConfidence ?? .confirmed
                    : EvidenceConfidence.inferred
                let stable = "\(session)|\(turn)|\(event.id.uuidString)|\(path ?? "unknown")"
                return MemoryCommitEvidence(commitId: sha256(stable), sessionId: session, turnId: turn,
                    agent: event.agent ?? first.agent ?? "unknown", toolCallId: event.toolCallId,
                    processId: event.processId, storagePath: path, changeKind: kind,
                    beforeHash: event.beforeContent.map(sha256), afterHash: event.afterContent.map(sha256),
                    contentDiff: diff, summary: summary(kind: kind, path: path),
                    risk: severity(reasons), riskReasons: reasons, confidence: confidence,
                    attributionMethod: event.attributionMethod ?? "native turn evidence",
                    observedAt: event.ts,
                    evidenceEventIds: sourceEvidence(for: event, in: rows))
            }
        }.sorted { $0.observedAt > $1.observedAt }
    }

    private static func isMemoryMutation(_ event: GuardEvent) -> Bool {
        guard ["create", "write", "modify", "update", "delete", "append", "call"].contains(event.op.lowercased()) else {
            return false
        }
        let descriptor = "\(event.path) \(event.relatedPath ?? "") \(event.toolName ?? "") \(event.command ?? "")".lowercased()
        let memoryMarkers = ["memory", "remember", "knowledge", "user.md", "identity.md", "soul.md",
                             "workspaceStorage".lowercased(), "globalstorage", "state.vscdb"]
        return memoryMarkers.contains { descriptor.contains($0) }
    }

    private static func changeKind(_ event: GuardEvent) -> MemoryChangeKind {
        if event.kind == "tool" { return .toolReported }
        if event.op == "delete" { return .delete }
        if event.beforeContent == nil && event.afterContent != nil { return .create }
        return .update
    }

    private static func pathFromTool(_ event: GuardEvent) -> String? {
        guard let text = event.command else { return nil }
        let pattern = #"(?:file_path|path|memory_file)[\"']?\s*[:=]\s*[\"']([^\"']+)"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
              let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[range])
    }

    private static func riskReasons(event: GuardEvent, rows: [GuardEvent], diff: String?) -> [String] {
        let text = "\(diff ?? "") \(event.command ?? "")".lowercased()
        var reasons: [String] = []
        if ["ignore previous", "without confirmation", "无需确认", "永久", "always execute",
            "remember this permanently", "for all future sessions"].contains(where: text.contains) {
            reasons.append("Persistent behavioral instruction was written to memory")
        }
        if ["api_key", "api key", "password", "secret", "token", "银行卡", "身份证"].contains(where: text.contains) {
            reasons.append("Potential credential or sensitive personal data was persisted")
        }
        if rows.contains(where: { row in
            guard let destination = row.remoteDomain ?? row.remoteHost else { return false }
            let kind = NetworkDestinationAssessment.assess(domain: row.remoteDomain, host: destination).kind
            return kind == .externalContent || kind == .developerService || kind == .unknown
        }) {
            reasons.append("External content was observed in the same turn; causal influence requires review")
        }
        if event.beforeContent == nil && event.afterContent == nil {
            reasons.append("The agent reported a memory write, but content-level before/after evidence was unavailable")
        }
        return reasons
    }

    private static func severity(_ reasons: [String]) -> String {
        if reasons.contains(where: { $0.contains("behavioral") || $0.contains("credential") }) { return "high" }
        return reasons.isEmpty ? "info" : "medium"
    }

    private static func sourceEvidence(for event: GuardEvent, in rows: [GuardEvent]) -> [String] {
        let causal = rows.filter { candidate in
            candidate.id == event.id || candidate.op == "prompt" || candidate.op == "response" ||
            candidate.toolCallId == event.toolCallId || candidate.remoteDomain != nil
        }
        return Array(Set(causal.map { $0.id.uuidString })).sorted()
    }

    private static func summary(kind: MemoryChangeKind, path: String?) -> String {
        "\(kind.rawValue.capitalized) persistent memory\(path.map { " at \($0)" } ?? "")"
    }

    private static func bounded(_ value: String?) -> String? {
        value.map { String($0.prefix(32_000)) }
    }

    private static func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
