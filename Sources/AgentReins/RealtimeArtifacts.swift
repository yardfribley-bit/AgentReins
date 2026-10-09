import AppKit
import CryptoKit
import Foundation

struct RealtimeArtifact: Encodable, Identifiable {
    let id: String, taskID: String, name: String, path: String, kind: String
    let exists: Bool, preview: String?, previewTruncated: Bool, sizeBytes: Int?
    let source: String, eventIDs: [String], basis: String, openable: Bool, status: String
}

/// Only successful, explicit output evidence creates candidates. File reads,
/// incidental open handles and arbitrary paths in a final answer do not.
enum RealtimeArtifactProjector {
    struct Candidate: Equatable {
        let id: String, taskID: String, path: String, source: String, eventIDs: [String], basis: String
    }
    static func candidates(events: [GuardEvent], tasks: [RealtimeTask]) -> [Candidate] {
        var output: [String: Candidate] = [:]
        let byTask = Dictionary(uniqueKeysWithValues: tasks.map { ($0.agent + "\u{0}" + $0.session + "\u{0}" + $0.turn, $0.id) })
        func taskID(_ event: GuardEvent) -> String? {
            guard let agent = RealtimeWorkspaceProjector.canonicalAgent(event.agent), let session = event.sessionId, let turn = event.turnId else { return nil }
            return byTask[agent + "\u{0}" + session + "\u{0}" + turn]
        }
        func add(_ path: String, event: GuardEvent, task: String, basis: String, ids: [String]? = nil) {
            guard path.hasPrefix("/"), !path.contains("\u{0}") else { return }
            let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
            let identity = task + "\u{0}" + normalized
            let id = SHA256.hash(data: Data(identity.utf8)).map { String(format: "%02x", $0) }.joined()
            output[identity] = Candidate(id: id, taskID: task, path: normalized, source: event.source ?? "来源未标明", eventIDs: ids ?? [event.id.uuidString], basis: basis)
        }
        let ordered = events.sorted { $0.ts < $1.ts }
        for event in ordered {
            guard let task = taskID(event), !RealtimeWorkspaceProjector.isFailure(event, result: event.modelResponse),
                  !["requested", "planned", "queued", "running", "unverified", "cancelled", "canceled"].contains(event.action.lowercased()) else { continue }
            if event.kind == "file", ["create", "write", "update", "modify"].contains(event.op),
               event.source != "tool-intent" || event.action == "completed" {
                add(event.path, event: event, task: task, basis: "当前任务明确写入/创建记录；文件存在与内容另行核对")
            }
            if event.kind == "tool", event.op == "result", let result = object(event.modelResponse) {
                let keys = ["output_files", "artifacts"] + (event.toolName == "present_files" && result["type"] as? String == "present_files_result" ? ["files"] : [])
                for key in keys {
                    for value in result[key] as? [Any] ?? [] {
                        if let path = value as? String { add(path, event: event, task: task, basis: "工具实际返回的产物路径") }
                        else if let row = value as? [String: Any], let path = row["path"] as? String { add(path, event: event, task: task, basis: "工具实际返回的产物路径") }
                    }
                }
            }
        }
        // WorkBuddy Hook bodies retain native tool_input/tool_response even
        // when the compatibility tool-intent projector cannot parse them.
        for task in tasks {
            for card in task.cards where card.call != nil && card.status == "returned" && card.tag != "执行失败" {
                let starts = ordered.filter { card.eventIDs.contains($0.id.uuidString) && ["call", "hook_tool_start"].contains($0.op) }
                guard let start = starts.first, ["write", "write_file", "create_file"].contains((start.toolName ?? "").lowercased()) else { continue }
                let envelope = object(start.afterContent)?["payload"] as? [String: Any]
                let input = envelope?["tool_input"] as? [String: Any] ?? object(start.command)
                guard let rawPath = input?["file_path"] as? String ?? input?["path"] as? String else { continue }
                let absolute: String
                if rawPath.hasPrefix("/") { absolute = rawPath }
                else if start.path.hasPrefix("/"), start.source != "workbuddy-hook" { absolute = URL(fileURLWithPath: start.path).appendingPathComponent(rawPath).path }
                else { continue }
                add(absolute, event: start, task: task.id, basis: "同一任务/调用的原生写入参数及成功返回", ids: card.eventIDs)
            }
        }
        return output.values.sorted { $0.path < $1.path }
    }
    static func probe(_ candidates: [Candidate]) -> [RealtimeArtifact] {
        candidates.map { candidate in
            let url = URL(fileURLWithPath: candidate.path)
            let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey])
            let exists = values?.isRegularFile == true && values?.isSymbolicLink != true
            let ext = url.pathExtension.lowercased()
            let text = ["txt", "md", "markdown", "json", "csv", "tsv", "log", "yaml", "yml", "swift", "py", "js", "css", "html", "xml"].contains(ext)
            let image = ["png", "jpg", "jpeg", "gif", "webp", "heic"].contains(ext)
            let document = ["pdf", "docx", "xlsx", "pptx"].contains(ext)
            var preview: String?, truncated = false
            if exists && text, let handle = try? FileHandle(forReadingFrom: url) {
                defer { try? handle.close() }
                if let data = try? handle.read(upToCount: 65_537) {
                    truncated = data.count > 65_536 || (values?.fileSize ?? 0) > 65_536
                    // UTF-8 boundary truncation remains an explicit preview.
                    preview = String(decoding: data.prefix(65_536), as: UTF8.self)
                }
            }
            let allowed = text && ext != "html" && !["js", "py", "swift"].contains(ext) || image || document
            return RealtimeArtifact(id: candidate.id, taskID: candidate.taskID, name: url.lastPathComponent, path: candidate.path,
                kind: text ? "text" : image ? "image" : document ? "document" : "file", exists: exists,
                preview: preview, previewTruncated: truncated, sizeBytes: values?.fileSize,
                source: candidate.source, eventIDs: candidate.eventIDs, basis: candidate.basis, openable: exists && allowed,
                status: !exists ? "文件不存在、不是普通文件或为符号链接" : preview != nil ? "文件存在 · 可预览" : "文件存在 · 已取得路径与元数据")
        }
    }
    static func open(_ artifact: RealtimeArtifact) -> Bool {
        guard artifact.openable, artifact.exists else { return false }
        let url = URL(fileURLWithPath: artifact.path)
        guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]), values.isRegularFile == true, values.isSymbolicLink != true else { return false }
        return NSWorkspace.shared.open(url)
    }
    private static func object(_ text: String?) -> [String: Any]? {
        guard let text, text.utf8.count <= 2_000_000, let data = text.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }
}
