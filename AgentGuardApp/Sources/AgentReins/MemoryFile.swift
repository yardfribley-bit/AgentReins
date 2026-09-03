import Foundation
import SwiftUI

/// 记忆体文件节点：扫描脚本 inventory 输出的单文件元数据 + 命中列表。
/// 用于记忆体 Inspector 的左栏结构树与中栏内容展示。
struct MemoryFile: Identifiable {
    let id = UUID()
    let agent: String
    let path: String
    let rel: String
    let size: Int
    let kind: String            // md / jsonl / sqlite / text
    var sensitiveCount: Int
    var sensitiveTypes: [String]
    var hits: [MemoryFinding]
    var content: String?        // 选中后懒加载

    /// 该文件是否可文本编辑（sqlite 二进制库不可内联打码/删行）。
    var isTextEditable: Bool { kind != "sqlite" }

    /// 命中行集合（1-based），中栏高亮用。
    var hitLines: Set<Int> {
        Set(hits.compactMap { $0.line > 0 ? $0.line : nil })
    }

    static func groupByAgent(_ files: [MemoryFile]) -> [(agent: String, files: [MemoryFile])] {
        let grouped = Dictionary(grouping: files) { $0.agent }
        return grouped.map { (agent: $0.key, files: $0.value.sorted { $0.rel < $1.rel }) }
                      .sorted { $0.agent < $1.agent }
    }
}
