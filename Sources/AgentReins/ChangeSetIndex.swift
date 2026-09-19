import CryptoKit
import Foundation

enum ChangeSetState: String, Codable, Sendable { case active, accepted, verified, failed, cancelled, unknown }
enum RequirementDialogueRole: String, Codable, Sendable {
    case start, refine, correct, continueWork, accept, cancel, newRequirement, unknown
}

struct RequirementDialogueEntry: Codable, Identifiable, Sendable {
    let id: String
    let role: RequirementDialogueRole
    let text: String
    let sessionID: String
    let turnID: String?
    let occurredAt: Date
    let evidenceID: String
    let confidence: AlignmentConfidence
}

struct IndexedChangeSet: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let title: String
    let requirementIDs: [String]
    let dialogue: [RequirementDialogueEntry]
    let agentIDs: [String]
    let sessionIDs: [String]
    let turnIDs: [String]
    let contextCount: Int
    let attemptCount: Int
    let codeChangeIDs: [String]
    let paths: [String]
    let commitHashes: [String]
    let startedAt: Date
    let lastActivityAt: Date
    let state: ChangeSetState
    let groupingConfidence: AlignmentConfidence
    let groupingReasons: [String]
    let evidenceIDs: [String]
}

/// A Change Set is one user request and the dialogue that evolves it. Files,
/// turns, sessions, agents, and commits are contributions—not boundaries.
enum ChangeSetIndexer {
    private struct Draft {
        var idSeed: String
        var dialogue: [RequirementDialogueEntry]
        var requirementIDs: Set<String>
        var changes: [IndexedCodeChange]
    }

    static func build(projectID: String, events: [AgentEventEnvelope],
                      changes: [IndexedCodeChange]) -> [IndexedChangeSet] {
        let candidates = events.compactMap { event -> (AgentEventEnvelope, UserPromptEvidence)? in
            guard event.projectID == projectID, case let .userPrompt(value) = event.payload else { return nil }
            // Codex compaction may replay a transcript bundle as one compatibility
            // message. It is useful context evidence, but it is not a new user ask.
            guard !isTranscriptBundle(value.rawText) else { return nil }
            return (event, value)
        }.sorted { $0.0.occurredAt < $1.0.occurredAt }
        // Re-reading a compatibility stream can produce more than one projection
        // of the same logical prompt. A turn has one user prompt boundary.
        var seenPromptTurns = Set<String>()
        let prompts = candidates.filter { event, _ in
            guard let turnID = event.turnID else { return true }
            return seenPromptTurns.insert(key(event.sessionID, turnID)).inserted
        }
        var drafts: [Draft] = []
        // A session is a hard attribution boundary. Different agent sessions may
        // work on the same project at the same time and must never share an
        // implicit "current requirement".
        var activeIndexBySession: [String: Int] = [:]
        var turnToDraft: [String: Int] = [:]

        for (event, prompt) in prompts {
            let sessionID = event.sessionID
            let activeIndex = activeIndexBySession[sessionID]
            let role = classify(prompt.rawText, hasActive: activeIndex != nil)
            if activeIndex == nil || role == .newRequirement || role == .start {
                drafts.append(Draft(idSeed: event.id, dialogue: [],
                                    requirementIDs: Set(prompt.requirementIDs), changes: []))
                activeIndexBySession[sessionID] = drafts.count - 1
            }
            guard let index = activeIndexBySession[sessionID] else { continue }
            let storedRole: RequirementDialogueRole = drafts[index].dialogue.isEmpty ? .start : role
            drafts[index].dialogue.append(RequirementDialogueEntry(
                id: event.id, role: storedRole, text: prompt.rawText,
                sessionID: event.sessionID, turnID: event.turnID,
                occurredAt: event.occurredAt, evidenceID: event.id,
                confidence: role == .unknown ? .inferred : .observed))
            drafts[index].requirementIDs.formUnion(prompt.requirementIDs)
            turnToDraft[key(event.sessionID, event.turnID)] = index
            // Acknowledgements such as "好" and "行" are part of the same
            // requirement dialogue. Only an explicit cancellation closes it.
            if role == .cancel { activeIndexBySession[sessionID] = nil }
        }

        for change in changes.sorted(by: { $0.startedAt < $1.startedAt }) {
            let exact = turnToDraft[key(change.sessionID, change.turnID)]
            let preceding = drafts.indices.reversed().first { index in
                drafts[index].dialogue.contains { entry in
                    entry.sessionID == change.sessionID && entry.occurredAt <= change.startedAt
                }
            }
            if let index = exact ?? preceding {
                drafts[index].changes.append(change)
            } else {
                let synthetic = RequirementDialogueEntry(
                    id: "unattributed:\(change.id)", role: .unknown,
                    text: change.userPrompt ?? "Code changes without a captured user request",
                    sessionID: change.sessionID, turnID: change.turnID,
                    occurredAt: change.startedAt, evidenceID: change.id, confidence: .unknown)
                drafts.append(Draft(idSeed: synthetic.id, dialogue: [synthetic],
                                    requirementIDs: Set(change.requirementIDs), changes: [change]))
            }
        }

        return drafts.compactMap { draft in
            guard let first = draft.dialogue.first else { return nil }
            let dialogueTurns = Set(draft.dialogue.map { key($0.sessionID, $0.turnID) })
            let contextualEvidence = events.filter { dialogueTurns.contains(key($0.sessionID, $0.turnID)) }.map(\.id)
            let evidence = Set(draft.dialogue.map(\.evidenceID) + contextualEvidence + draft.changes.flatMap(\.evidenceIDs))
            let agents = Set(draft.changes.map(\.agentID))
            let sessions = Set(draft.dialogue.map(\.sessionID) + draft.changes.map(\.sessionID))
            let turns = Set(draft.dialogue.compactMap(\.turnID) + draft.changes.compactMap(\.turnID))
            let checks = draft.changes.flatMap(\.verification)
            let accepted = draft.dialogue.last?.role == .accept
            let cancelled = draft.dialogue.last?.role == .cancel
            let state: ChangeSetState = cancelled ? .cancelled :
                (checks.contains { $0.outcome == .passed } ? .verified :
                 (checks.contains { $0.outcome == .failed } ? .failed : (accepted ? .accepted : .active)))
            let times = draft.dialogue.map(\.occurredAt) + draft.changes.map(\.lastObservedAt)
            return IndexedChangeSet(
                id: digest("\(projectID)\u{0}\(draft.idSeed)"), projectID: projectID,
                title: String(first.text.prefix(240)), requirementIDs: draft.requirementIDs.sorted(),
                dialogue: draft.dialogue, agentIDs: agents.sorted(), sessionIDs: sessions.sorted(),
                turnIDs: turns.sorted(), contextCount: draft.dialogue.count, attemptCount: turns.count,
                codeChangeIDs: draft.changes.map(\.id).sorted(),
                paths: Array(Set(draft.changes.map(\.path))).sorted(),
                commitHashes: Array(Set(draft.changes.flatMap(\.commitHashes))).sorted(),
                startedAt: times.min() ?? first.occurredAt,
                lastActivityAt: times.max() ?? first.occurredAt, state: state,
                groupingConfidence: draft.dialogue.contains { $0.confidence == .inferred } ? .inferred : .observed,
                groupingReasons: ["same_session_requirement_dialogue"], evidenceIDs: evidence.sorted())
        }.sorted { $0.lastActivityAt > $1.lastActivityAt }
    }

    static func classify(_ raw: String, hasActive: Bool) -> RequirementDialogueRole {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !hasActive { return .start }
        if matches(value, ["取消", "不用做", "别做", "cancel", "stop this"]) { return .cancel }
        if matches(value, ["可以了", "这样可以", "完成了", "通过", "looks good", "approved", "done"]) { return .accept }
        if matches(value, ["继续", "接着", "往下", "干", "做", "行", "好", "go on", "continue"]) && value.count <= 40 { return .continueWork }
        if matches(value, ["不应该", "不对", "错了", "修复", "修一下", "重新", "刚才", "bug", "fix", "wrong"]) { return .correct }
        if matches(value, ["我认为", "应该", "再加", "还要", "同时", "改成", "调整", "补充", "优化", "also", "add", "change", "refine"]) { return .refine }
        // Length is not evidence of a new requirement. Require an explicit goal
        // switch so detailed corrections remain attached to their original ask.
        if matches(value, ["新需求", "新的需求", "另一个需求", "另外一个需求", "全新的", "下一个任务",
                           "下面做", "接下来做", "换一个", "做另一个", "new task", "another task",
                           "next task", "new requirement", "switch to"]) { return .newRequirement }
        return .unknown
    }

    private static func matches(_ value: String, _ markers: [String]) -> Bool {
        markers.contains { value.contains($0) }
    }
    static func isTranscriptBundle(_ value: String) -> Bool {
        let pattern = #"(?m)^\s*\[\d+\]\s+(user|assistant|tool|developer):"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return false }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return expression.numberOfMatches(in: value, range: range) >= 2
    }
    private static func key(_ session: String, _ turn: String?) -> String { "\(session)\u{0}\(turn ?? "unattributed")" }
    private static func digest(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
