import Foundation
import CryptoKit

struct WorkBuddyHookEnvelope {
    let file: URL
    let raw: RawEvidenceRecord
    let event: GuardEvent
    let transcript: URL?
}

/// Bounded independent spool. Existing LoongSuite files are never consumed here.
enum WorkBuddyHookInbox {
    static let defaultURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/AgentGuard/hook-events/workbuddy")

    static func read(root: URL, projects: URL) -> [WorkBuddyHookEnvelope] {
        let files = (try? FileManager.default.contentsOfDirectory(at: root,
            includingPropertiesForKeys: [.fileSizeKey, .isSymbolicLinkKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles])) ?? []
        return files.filter { $0.pathExtension == "json" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
            .prefix(64).compactMap { decode(file: $0, projects: projects) }
    }

    static func decode(file: URL, projects: URL) -> WorkBuddyHookEnvelope? {
        guard let values = try? file.resourceValues(forKeys: [.fileSizeKey, .isSymbolicLinkKey]),
              values.isSymbolicLink != true, let size = values.fileSize, size <= 17_000_000,
              let bytes = try? Data(contentsOf: file), bytes.count <= 17_000_000,
              let record = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let eventID = record["event_id"] as? String, let id = UUID(uuidString: eventID),
              let payload = record["payload"] as? [String: Any],
              let session = payload["session_id"] as? String, !session.isEmpty,
              let hook = record["hook_event_name"] as? String,
              let timestamp = record["observed_at_ms"] as? NSNumber else { return nil }
        let operations = ["SessionStart": "hook_session_start", "UserPromptSubmit": "hook_user_prompt",
            "PreToolUse": "hook_tool_start", "PostToolUse": "hook_tool_finish", "Stop": "hook_turn_stop",
            "CaptureGap": "hook_capture_gap"]
        guard let operation = operations[hook] else { return nil }
        let canonicalRoot = projects.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        let transcript = (payload["transcript_path"] as? String).flatMap { path -> URL? in
            let url = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL
            guard url.path.hasPrefix(canonicalRoot), url.pathExtension == "jsonl",
                  url.deletingPathExtension().lastPathComponent == session else { return nil }
            return url
        }
        let date = Date(timeIntervalSince1970: timestamp.doubleValue / 1000)
        let raw = RawEvidenceRecord(source: "workbuddy-hook", stream: file.path, offsetStart: 0,
            offsetEnd: Int64(bytes.count), fingerprint: SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined(),
            observedAt: date, payload: bytes)
        let event = GuardEvent(id: id, kind: "activity", ruleId: "workbuddy_hook_native", path: transcript?.path ?? "-",
            command: nil, agent: "workbuddy", op: operation, severity: "info", ts: date, action: "observed",
            sessionId: session, turnId: payload["turn_id"] as? String, toolCallId: (payload["call_id"] ?? payload["tool_use_id"]) as? String,
            userIntent: hook == "UserPromptSubmit" ? payload["prompt"] as? String : nil,
            toolName: payload["tool_name"] as? String, model: payload["model"] as? String,
            afterContent: String(data: bytes, encoding: .utf8), source: "workbuddy-hook",
            attributionConfidence: hook == "CaptureGap" ? .unknown : .confirmed,
            attributionMethod: hook == "CaptureGap" ? "Hook payload unavailable; session attribution unknown"
                : "native Hook session/tool IDs; writer PID is not tool process PID")
        return WorkBuddyHookEnvelope(file: file, raw: raw, event: event, transcript: transcript)
    }
}
