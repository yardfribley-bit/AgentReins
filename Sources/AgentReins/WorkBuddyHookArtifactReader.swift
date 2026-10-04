import Foundation
import CryptoKit

/// Evidence adapter for the installed LoongSuite Pilot WorkBuddy hook writer.
/// This reads its outputs, never executes the script or assumes generic Node behaviour.
struct WorkBuddyHookArtifactReader {
    let root: URL
    init(root: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".loongsuite-pilot/state/workbuddy/hook-events")) {
        self.root = root
    }

    func events(for process: ProcessSnapshotRecord, now: Date) -> [GuardEvent] {
        guard process.command.contains("/.loongsuite-pilot/hooks/workbuddy-hook-event-writer.mjs"),
              let birth = process.birthIdentity, Int32(process.pid) != nil else { return [] }
        let started = Double(birth) / 1_000_000
        let manager = FileManager.default
        let keys: Set<URLResourceKey> = [.contentModificationDateKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey]
        guard let directories = try? manager.contentsOfDirectory(at: root,
            includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]) else { return [] }
        let candidates = directories.compactMap { url -> (URL, Date)? in
            guard let values = try? url.resourceValues(forKeys: keys),
                  values.isDirectory == true, values.isSymbolicLink != true,
                  let date = values.contentModificationDate, date.timeIntervalSince1970 >= started - 2 else { return nil }
            return (url, date)
        }.sorted { $0.1 > $1.1 }.prefix(32)
        var events: [GuardEvent] = []
        for (directory, _) in candidates {
            guard let files = try? manager.contentsOfDirectory(at: directory,
                includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]) else { continue }
            // Filename embeds writer PID. Timestamp also guards against stale PID reuse.
            for file in files.filter({ $0.pathExtension == "json" && $0.lastPathComponent.contains("-\(process.pid)-") }).prefix(32) {
                let parts = file.lastPathComponent.split(separator: "-", maxSplits: 2)
                guard parts.count == 3, parts[1] == Substring(process.pid), let timestamp = Double(parts[0]),
                      timestamp / 1000 >= started, timestamp / 1000 <= now.timeIntervalSince1970,
                      let values = try? file.resourceValues(forKeys: keys), values.isSymbolicLink != true,
                      let size = values.fileSize, size <= 65_536,
                      let bytes = try? Data(contentsOf: file), bytes.count <= 65_536,
                      let record = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                      let observed = record["observed_at_ms"] as? NSNumber, observed.doubleValue == timestamp,
                      let session = record["session_id"] as? String, !session.isEmpty,
                      let hook = record["hook_event_name"] as? String else { continue }
                let payload: [String: Any] = ["schemaVersion": 1,
                    "processIdentity": ProcessObservationCoordinator.identity(process),
                    "artifactPath": file.path, "sha256": SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
                    "record": record, "correlation": "writer filename PID + birth/time + artifact session",
                    "scope": "installed hook output; not a complete file syscall trace"]
                let encoded = (try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
                    .flatMap { String(data: $0, encoding: .utf8) }
                events.append(GuardEvent(kind: "activity", ruleId: "process_observation", path: file.path,
                    command: nil, agent: process.agent, op: "process_hook_artifact", severity: "info", ts: now,
                    action: "observed", sessionId: session, toolCallId: record["tool_call_id"] as? String,
                    afterContent: encoded, source: "workbuddy-hook-artifact",
                    attributionConfidence: .inferred, attributionMethod: "artifact filename PID/birth/time; \(hook)",
                    processId: Int32(process.pid), parentProcessId: Int32(process.ppid)))
            }
        }
        return events
    }
}
