import Foundation

/// Keeps native Hook identity separate from inferred executor identity.
/// No PID is joined using time proximity alone; raw process samples remain untouched.
final class HookProcessCorrelation {
    private struct Window {
        let hook: GuardEvent
        let command: String?
        let ancestors: [(pid: String, birth: UInt64)]
        var endedAt: Date?
    }
    private var recentCallers: [(Date, [(pid: String, birth: UInt64)])] = []
    private var windows: [String: Window] = [:]
    private var finishes: [String: Date] = [:]
    private var history: [String: ProcessSnapshotRecord] = [:]
    private var signatures: [String: String] = [:]
    private var callerSignatures = Set<String>()

    func observeHook(_ event: GuardEvent, now: Date = Date()) -> [GuardEvent] {
        guard event.source == "workbuddy-hook", let session = event.sessionId else { return [] }
        prune(now)
        let ancestryRecord = event.afterContent.flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        let ancestors = (ancestryRecord["caller_ancestors"] as? [[String: Any]] ?? []).compactMap { row -> (String, UInt64)? in
            guard let pid = row["pid"] as? NSNumber, let birth = row["birth_identity"] as? NSNumber else { return nil }
            return (pid.stringValue, birth.uint64Value)
        }
        let callerEvents = callerEvidence(event, record: ancestryRecord)
        recentCallers.append((now, ancestors))
        if recentCallers.count > 128 { recentCallers.removeFirst(recentCallers.count - 128) }
        if event.op == "hook_turn_stop" {
            for key in Array(windows.keys) where windows[key]?.hook.sessionId == session && windows[key]!.hook.ts <= event.ts {
                let end = windows[key]?.endedAt ?? event.ts
                windows[key]?.endedAt = end
            }
            return callerEvents + evaluate(now)
        }
        guard let call = event.toolCallId else { return callerEvents }
        let key = session + "\u{0}" + call
        if event.op == "hook_tool_start" {
            if windows[key] == nil {
                let record = event.afterContent.flatMap { $0.data(using: .utf8) }
                    .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
                let payload = record["payload"] as? [String: Any] ?? [:]
                let input = payload["tool_input"] as? [String: Any] ?? [:]
                let ancestry = (record["caller_ancestors"] as? [[String: Any]] ?? []).compactMap { row -> (String, UInt64)? in
                    guard let pid = row["pid"] as? NSNumber, let birth = row["birth_identity"] as? NSNumber else { return nil }
                    return (pid.stringValue, birth.uint64Value)
                }
                windows[key] = Window(hook: event, command: input["command"] as? String,
                                      ancestors: ancestry, endedAt: finishes[key])
            }
        } else if event.op == "hook_tool_finish" {
            // Missing/reordered starts never create a synthetic start window.
            finishes[key] = event.ts
            windows[key]?.endedAt = event.ts
        }
        if windows.count > 128 {
            for old in windows.sorted(by: { $0.value.hook.ts < $1.value.hook.ts }).prefix(windows.count - 128) {
                windows.removeValue(forKey: old.key)
            }
        }
        return callerEvents + evaluate(now)
    }

    func observeProcesses(_ records: [ProcessSnapshotRecord], now: Date = Date()) -> [GuardEvent] {
        prune(now)
        for record in records where record.agent?.lowercased() == "workbuddy" && record.birthIdentity != nil {
            history[ProcessObservationCoordinator.identity(record)] = record
        }
        if history.count > 512 {
            for old in history.sorted(by: { ($0.value.birthIdentity ?? 0) < ($1.value.birthIdentity ?? 0) }).prefix(history.count - 512) {
                history.removeValue(forKey: old.key)
            }
        }
        return evaluate(now)
    }

    func reset() { windows.removeAll(); finishes.removeAll(); history.removeAll(); signatures.removeAll(); recentCallers.removeAll(); callerSignatures.removeAll() }

    func samplingTargets(_ records: [ProcessSnapshotRecord], now: Date = Date()) -> [ProcessSnapshotRecord] {
        prune(now)
        let liveIdentities = Set(records.map(ProcessObservationCoordinator.identity))
        let ancestryLists = recentCallers.map { $0.1 } + windows.values.map(\.ancestors)
        var roots: [String: ProcessSnapshotRecord] = [:]
        for ancestors in ancestryLists {
            for ancestor in ancestors {
                let key = "\(ancestor.pid):\(ancestor.birth)"
                guard liveIdentities.contains(key), let root = history[key] else { continue }
                let name = URL(fileURLWithPath: root.executablePath ?? "").lastPathComponent
                guard !["sh", "bash", "zsh", "fish", "AgentReinsHook"].contains(name) else { continue }
                // Backends above the SDK may carry the network operation. Observe
                // all validated WorkBuddy ancestors, not only the nearest child.
                guard root.agent?.lowercased() == "workbuddy" else { continue }
                roots[key] = root
            }
        }
        let scoped = records.filter { $0.agent?.lowercased() == "workbuddy" }
        // Caller metadata can be absent (old hooks / inaccessible ancestors).
        // Keep application-scoped observation, without assigning an executor.
        if roots.isEmpty { return scoped }
        return scoped.filter { process in
            roots[ProcessObservationCoordinator.identity(process)] != nil || roots.values.contains { descendant(process, of: $0) }
        }
    }

    private func prune(_ now: Date) {
        recentCallers.removeAll { now.timeIntervalSince($0.0) > 5 }
        finishes = finishes.filter { now.timeIntervalSince($0.value) < 30 }
        if finishes.count > 256 {
            for old in finishes.sorted(by: { $0.value < $1.value }).prefix(finishes.count - 256) { finishes.removeValue(forKey: old.key) }
        }
        windows = windows.filter { _, window in
            window.endedAt.map { now.timeIntervalSince($0) < 30 } ?? (now.timeIntervalSince(window.hook.ts) < 1800)
        }
        // Long-running roots remain necessary to walk parentage. Bound by count;
        // short-lived children can still arrive after their Hook has been ingested.
        if signatures.count > 1024 { signatures.removeAll() }
    }

    private func callerEvidence(_ hook: GuardEvent, record: [String: Any]) -> [GuardEvent] {
        guard !callerSignatures.contains(hook.id.uuidString),
              let ancestors = record["caller_ancestors"] as? [[String: Any]],
              let caller = ancestors.first(where: {
                  let path = $0["executable"] as? String ?? ""
                  return path.contains("/WorkBuddy.app/Contents/")
              }), let pid = caller["pid"] as? NSNumber,
              let birth = caller["birth_identity"] as? NSNumber else { return [] }
        callerSignatures.insert(hook.id.uuidString)
        if callerSignatures.count > 1024 { callerSignatures = [hook.id.uuidString] }
        var data: [String: Any] = ["schemaVersion": 1, "hookEventID": hook.id.uuidString,
            "relation": "hook_caller", "status": "observed",
            "processIdentity": "\(pid):\(birth)", "caller": caller,
            "basis": "libproc ancestor identity captured inside the native Hook",
            "limitation": "identifies the Hook issuer, not the tool executor or network request owner"]
        if let snapshot = record["caller_snapshot"] { data["sample"] = snapshot }
        let encoded = (try? JSONSerialization.data(withJSONObject: data, options: [.sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) }
        return [GuardEvent(kind: "activity", ruleId: "process_observation", path: "-", command: nil,
            agent: "workbuddy", op: "hook_caller_observation", severity: "info", ts: hook.ts,
            action: "observed", sessionId: hook.sessionId, toolCallId: hook.toolCallId, toolName: hook.toolName,
            afterContent: encoded, source: "hook-process-correlation", attributionConfidence: .confirmed,
            attributionMethod: "native Hook issuer PID + birth identity; not executor attribution",
            processId: pid.int32Value, parentProcessId: (caller["parent_pid"] as? NSNumber)?.int32Value)]
    }

    private func caller(_ window: Window) -> ProcessSnapshotRecord? {
        for ancestor in window.ancestors {
            guard let process = history["\(ancestor.pid):\(ancestor.birth)"] else { continue }
            let name = URL(fileURLWithPath: process.executablePath ?? "").lastPathComponent
            guard !["sh", "bash", "zsh", "fish", "AgentReinsHook"].contains(name) else { continue }
            return process
        }
        return nil
    }

    private func descendant(_ child: ProcessSnapshotRecord, of root: ProcessSnapshotRecord) -> Bool {
        var cursor = child
        var seen = Set<String>()
        for _ in 0..<32 {
            if cursor.ppid == root.pid, let birth = cursor.birthIdentity,
               let actualParent = history.values.filter({ $0.pid == cursor.ppid && ($0.birthIdentity ?? UInt64.max) <= birth })
                .max(by: { ($0.birthIdentity ?? 0) < ($1.birthIdentity ?? 0) }),
               actualParent.birthIdentity == root.birthIdentity { return true }
            guard seen.insert(ProcessObservationCoordinator.identity(cursor)).inserted,
                  let birth = cursor.birthIdentity,
                  let parent = history.values.filter({ $0.pid == cursor.ppid && ($0.birthIdentity ?? UInt64.max) <= birth })
                    .max(by: { ($0.birthIdentity ?? 0) < ($1.birthIdentity ?? 0) }) else { return false }
            cursor = parent
        }
        return false
    }

    private func commandMatches(_ observed: String, _ requested: String?) -> Bool {
        guard let requested = requested?.trimmingCharacters(in: .whitespacesAndNewlines), !requested.isEmpty else { return false }
        // Preserve internal quoting/whitespace; a fuzzy substring is insufficient.
        return observed == requested || observed.hasSuffix(" -c " + requested) || observed.hasSuffix(" -lc " + requested)
    }

    private func evaluate(_ now: Date) -> [GuardEvent] {
        var matches: [(String, Window, ProcessSnapshotRecord)] = []
        for (key, window) in windows {
            guard let root = caller(window) else { continue }
            for process in history.values {
                guard let birth = process.birthIdentity else { continue }
                let start = Date(timeIntervalSince1970: Double(birth) / 1_000_000)
                guard start >= window.hook.ts, start <= (window.endedAt ?? now),
                      commandMatches(process.command, window.command), descendant(process, of: root) else { continue }
                matches.append((key, window, process))
            }
        }
        var result: [GuardEvent] = []
        for (key, window, process) in matches {
            let identity = ProcessObservationCoordinator.identity(process)
            let peers = matches.filter { ProcessObservationCoordinator.identity($0.2) == identity }.map(\.0).sorted()
            let signature = peers.joined(separator: "|")
            let edge = key + "\u{0}" + identity
            guard signatures[edge] != signature else { continue }
            signatures[edge] = signature
            guard let issuer = caller(window) else { continue }
            let payload: [String: Any] = ["schemaVersion": 1, "processIdentity": identity,
                "callerProcessIdentity": ProcessObservationCoordinator.identity(issuer),
                "hookEventID": window.hook.id.uuidString, "relation": "possible_tool_executor",
                "status": peers.count > 1 ? "ambiguous" : "candidate",
                "basis": ["native Hook caller ancestry", "PID + birth identity", "command text match", "tool observation window"],
                "competingCalls": peers.map { $0.replacingOccurrences(of: "\u{0}", with: "/") },
                "limitation": "no direct tool executor PID; not confirmed execution"]
            let encoded = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
                .flatMap { String(data: $0, encoding: .utf8) }
            result.append(GuardEvent(kind: "activity", ruleId: "process_observation", path: "-",
                command: nil, agent: "workbuddy", op: "hook_process_candidate", severity: "info", ts: now,
                action: "correlated", sessionId: window.hook.sessionId, toolCallId: window.hook.toolCallId,
                toolName: window.hook.toolName, afterContent: encoded, source: "hook-process-correlation",
                attributionConfidence: peers.count > 1 ? .unknown : .inferred,
                attributionMethod: "caller branch + command + birth/time; executor remains candidate",
                processId: Int32(process.pid), parentProcessId: Int32(process.ppid)))
        }
        return result
    }
}
