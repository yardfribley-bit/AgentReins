import Foundation

/// Confined to the serial projection queue. Unchanged sessions retain their
/// projection without reading, decompressing or parsing their evidence again.
final class RealtimeProjectionCache: @unchecked Sendable {
    struct Entry {
        let revisions: [UUID: UUID]
        let contextIDs: Set<String>
        let contextRevisions: [UUID: UUID]
        let tasks: [RealtimeTask]
        let contexts: [RealtimeContextExchange]
        let candidates: [RealtimeArtifactProjector.Candidate]
    }
    private struct TaskEntry {
        let contextIDs: Set<String>
        let revisions: [UUID: UUID]
        let tasks: [RealtimeTask]
        let candidates: [RealtimeArtifactProjector.Candidate]
    }
    private var taskEntries: [String: TaskEntry] = [:]
    private var entries: [String: Entry] = [:]
    private(set) var rebuiltGroups = 0
    func project(_ snapshot: RealtimeLiveEvidenceBuffer.Snapshot,
                 contexts: [RealtimeContextExchange], contextVersions: [UUID: Int] = [:], since: Date) throws
        -> (tasks: [RealtimeTask], contexts: [RealtimeContextExchange], candidates: [RealtimeArtifactProjector.Candidate]) {
        func key(_ agent: String?, _ session: String?) -> String {
            // WorkBuddy's proxy and native evidence can have different sessions;
            // retain their existing exact-input cross-source reconciliation.
            let canonical = RealtimeWorkspaceProjector.canonicalAgent(agent) ?? "unknown"
            return canonical.lowercased() == "workbuddy" ? canonical : canonical + "\u{0}" + (session ?? "")
        }
        let groups = Dictionary(grouping: snapshot.records.filter { $0.session != nil }, by: { key($0.agent, $0.session) })
        let contextGroups = Dictionary(grouping: contexts, by: { key($0.agent, $0.session) })
        var next: [String: Entry] = [:]
        for (group, records) in groups {
            let revisions = Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0.revision) })
            let parsed = contextGroups[group] ?? []
            let ids = Set(parsed.map { exchange in
                exchange.id + ":" + String(UUID(uuidString: exchange.id).flatMap { contextVersions[$0] } ?? 0)
            })
            if let cached = entries[group], cached.revisions == revisions, cached.contextIDs == ids {
                next[group] = cached; continue
            }
            var tasks: [RealtimeTask] = []
            var candidates: [RealtimeArtifactProjector.Candidate] = []
            if records.first.map({ RealtimeWorkspaceProjector.canonicalAgent($0.agent) == "Codex" }) == true {
                var callTurns: [String: Set<String>] = [:]
                for event in records {
                    if let call = event.call, let turn = event.turn { callTurns[call, default: []].insert(turn) }
                }
                let turns = Dictionary(grouping: records) { event -> String in
                    if let turn = event.turn { return turn }
                    if let call = event.call, let matches = callTurns[call], matches.count == 1 { return matches.first! }
                    return ""
                }
                for (turn, values) in turns {
                    let taskKey = group + "\u{0}" + turn
                    let versions = Dictionary(uniqueKeysWithValues: values.map { ($0.id, revisions[$0.id]!) })
                    let turnContextIDs = Set(parsed.filter { $0.turn == turn }.map { exchange in
                        exchange.id + ":" + String(UUID(uuidString: exchange.id).flatMap { contextVersions[$0] } ?? 0)
                    })
                    let entry: TaskEntry
                    if let old = taskEntries[taskKey], old.revisions == versions, old.contextIDs == turnContextIDs { entry = old }
                    else {
                        let events = try values.map { try $0.read() }
                        let projected = RealtimeWorkspaceProjector.tasks(events: events, since: since)
                        entry = TaskEntry(contextIDs: turnContextIDs, revisions: versions, tasks: projected,
                            candidates: RealtimeArtifactProjector.candidates(events: events, tasks: projected))
                        taskEntries[taskKey] = entry
                    }
                    tasks += entry.tasks; candidates += entry.candidates
                }
            } else {
                let events = try records.map { try $0.read() }
                tasks = RealtimeWorkspaceProjector.tasks(events: events, since: since)
                candidates = RealtimeArtifactProjector.candidates(events: events, tasks: tasks)
            }
            let contextRecords = records.filter { $0.kind == "model" || ["result", "hook_tool_finish"].contains($0.op) }
            let contextRevisions = Dictionary(uniqueKeysWithValues: contextRecords.map { ($0.id, $0.revision) })
            let exchanges: [RealtimeContextExchange]
            if parsed.isEmpty { exchanges = [] }
            else if let old = entries[group], old.contextIDs == ids, old.contextRevisions == contextRevisions { exchanges = old.contexts }
            else { exchanges = RealtimeContextProjector.assemble(parsed, events: try contextRecords.map { try $0.read() }) }
            // WorkBuddy keeps a cross-session group for exact native/HTTPS reconciliation.
            // A change in that group must not give every unchanged task a new export
            // revision. Compare the full projected task AND assembled context, so a
            // late response/tool-result or corrected attribution still invalidates it.
            if let old = entries[group] {
                let previousTasks = Dictionary(uniqueKeysWithValues: old.tasks.map { ($0.id, $0) })
                func contextKey(_ agent: String, _ session: String, _ turn: String) -> String {
                    agent + "\u{0}" + session + "\u{0}" + turn
                }
                let oldContexts = Dictionary(grouping: old.contexts) { contextKey($0.agent, $0.session, $0.turn) }
                let newContexts = Dictionary(grouping: exchanges) { contextKey($0.agent, $0.session, $0.turn) }
                tasks = tasks.map { task in
                    guard let previous = previousTasks[task.id] else { return task }
                    var candidate = task
                    candidate.projectionRevision = previous.projectionRevision
                    let context = contextKey(task.agent, task.session, task.turn)
                    guard candidate == previous, (oldContexts[context] ?? []) == (newContexts[context] ?? []) else { return task }
                    return previous
                }
            }
            next[group] = Entry(revisions: revisions, contextIDs: ids, contextRevisions: contextRevisions, tasks: tasks,
                contexts: exchanges,
                candidates: candidates)
            rebuiltGroups += 1
        }
        entries = next
        return (next.values.flatMap(\.tasks).sorted { $0.lastActivity > $1.lastActivity },
                next.values.flatMap(\.contexts).sorted { $0.timestamp < $1.timestamp },
                next.values.flatMap(\.candidates).sorted { $0.id < $1.id })
    }
}
