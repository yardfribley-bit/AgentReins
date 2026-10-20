import Foundation

/// Reads only evidence produced by the explicit live command collector, on demand.
/// No shell execution or history discovery is performed by the UI bridge.
enum NativeTransportAudit {
    static func records(root: URL = URL(fileURLWithPath: "/private/tmp/agentreins-transport-audit")) -> [[String: Any]] {
        let fm = FileManager.default
        let canonical = root.resolvingSymlinksInPath().path + "/"
        let directories = (try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        let files = directories.map { $0.appendingPathComponent("transport.json") }.filter {
            $0.resolvingSymlinksInPath().path.hasPrefix(canonical)
        }.sorted {
            ((try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast) >
            ((try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast)
        }.prefix(50)
        var records: [[String: Any]] = []
        for file in files {
            guard let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 4_000_000,
                  let data = try? Data(contentsOf: file),
                  let item = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let invocation = item["invocation"] as? [String: Any],
                  invocation["captureMode"] as? String == "agent-path" else { continue }
            var row: [String: Any] = ["runID": file.deletingLastPathComponent().lastPathComponent]
            for key in ["agent", "tool", "args", "task", "call", "startedAt", "pid", "exitCode", "captureMode", "gap", "auditBypass", "codexThreadID", "session"] {
                row[key] = invocation[key] ?? NSNull()
            }
            for key in ["connections", "children", "blocks", "helpers", "packFiles"] { row[key] = item[key] as? [Any] ?? [] }
            for key in ["fileResult", "repoResult", "gitOperation"] { row[key] = item[key] ?? NSNull() }
            row["outboundFiles"] = item["outboundFiles"] as? [Any] ?? []
            row["downloads"] = item["downloads"] as? [Any] ?? []
            row["formulas"] = item["formulas"] as? [Any] ?? []
            if let audit = item["securityAudit"] as? [String: Any] { row["securityAudit"] = audit }
            row["limitations"] = invocation["tool"] as? String == "git" ? ["只有独立 helper 日志并经 Trace2 核对的记录可确认子进程；同一 helper 的并发连接编号仍未提供。", "Git 文本追踪不能还原完整二进制正文；单独保存的对象包仅覆盖 clone/fetch 接收的 PACK 数据，不代表整个协议或 push 正文。"] : []
            records.append(row)
        }
        return records.sorted { ($0["startedAt"] as? String ?? "") > ($1["startedAt"] as? String ?? "") }
    }
}
