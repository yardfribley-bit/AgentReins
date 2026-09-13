import Combine
import Foundation

/// Lightweight live watcher for explicitly known persistent-memory stores.
/// Startup establishes a baseline only; it never emits historical files as new
/// commits. Polling is scoped to small memory directories and performs content
/// reads only after metadata changes.
final class LiveMemoryMonitor: ObservableObject {
    var onEvents: (([GuardEvent]) -> Void)?
    private let queue = DispatchQueue(label: "com.agentreins.memory-live", qos: .utility)
    private var timer: Timer?
    private var baseline: [String: FileState] = [:]

    private struct FileState {
        let modifiedAt: Date
        let size: Int
        let content: String?
    }

    func start() {
        guard timer == nil else { return }
        queue.async { [weak self] in self?.establishBaseline() }
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.queue.async { [weak self] in self?.poll() }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func roots() -> [(agent: String, url: URL)] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [("workbuddy", home.appendingPathComponent(".workbuddy/memory", isDirectory: true))]
    }

    private func establishBaseline() {
        baseline = snapshot()
    }

    private func poll() {
        let current = snapshot()
        let timestamp = Date()
        var events: [GuardEvent] = []
        for (path, state) in current {
            guard let previous = baseline[path] else {
                events.append(event(path: path, op: "create", before: nil, after: state.content, at: timestamp))
                continue
            }
            guard previous.modifiedAt != state.modifiedAt || previous.size != state.size else { continue }
            events.append(event(path: path, op: "modify", before: previous.content, after: state.content, at: timestamp))
        }
        for (path, previous) in baseline where current[path] == nil {
            events.append(event(path: path, op: "delete", before: previous.content, after: nil, at: timestamp))
        }
        baseline = current
        guard !events.isEmpty else { return }
        DispatchQueue.main.async { [weak self] in self?.onEvents?(events) }
    }

    private func snapshot() -> [String: FileState] {
        let manager = FileManager.default
        var result: [String: FileState] = [:]
        for (_, root) in roots() {
            guard let files = try? manager.contentsOfDirectory(at: root,
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey],
                options: [.skipsHiddenFiles]) else { continue }
            for file in files where file.pathExtension.lowercased() != "bak" {
                guard let values = try? file.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey, .isRegularFileKey]),
                      values.isRegularFile == true else { continue }
                let size = values.fileSize ?? 0
                let content: String?
                if size <= 512_000, let data = try? Data(contentsOf: file) {
                    content = String(data: data, encoding: .utf8)
                } else { content = nil }
                result[file.path] = FileState(modifiedAt: values.contentModificationDate ?? .distantPast,
                                              size: size, content: content)
            }
        }
        return result
    }

    private func event(path: String, op: String, before: String?, after: String?, at timestamp: Date) -> GuardEvent {
        GuardEvent(kind: "file", ruleId: "live-memory-commit", path: path, command: nil,
            agent: "workbuddy", op: op, severity: "info", ts: timestamp, action: "observed",
            beforeContent: before, afterContent: after, fileDiff: diff(before: before, after: after),
            source: "memory-live:workbuddy", attributionConfidence: .unknown,
            attributionMethod: "confirmed WorkBuddy memory path; writer process and turn awaiting correlation")
    }

    private func diff(before: String?, after: String?) -> String? {
        guard before != after else { return nil }
        let old = (before ?? "").components(separatedBy: .newlines)
        let new = (after ?? "").components(separatedBy: .newlines)
        var output = ["--- before", "+++ after"]
        for index in 0..<max(old.count, new.count) {
            let left = index < old.count ? old[index] : nil
            let right = index < new.count ? new[index] : nil
            guard left != right else { continue }
            if let left { output.append("-\(left)") }
            if let right { output.append("+\(right)") }
            if output.count >= 2_000 { output.append("… diff truncated …"); break }
        }
        return output.joined(separator: "\n")
    }
}
