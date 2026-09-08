import SwiftUI

/// 严重级 → 颜色（统一全 App 配色，避免散落三处不一致）。
extension Color {
    static func agrSeverity(_ s: String) -> Color {
        switch s {
        case "critical": return .red
        case "high":     return .orange
        case "medium":   return .yellow
        case "info":     return .blue
        default:         return .secondary
        }
    }
}

/// 处置动作 → 中文短标签（用于时间线与规则面板）。
extension String {
    var agrActionLabel: String {
        switch self {
        case "restored": return "已还原"
        case "alert":    return "已告警"
        case "seen":     return "已监测"
        case "block":    return "已拦截"
        case "protect":  return "保护中"
        default:         return self
        }
    }
}

/// Rule 的人类可读描述，给「拦截规则」面板与状态栏复用。
extension Rule {
    /// 触发条件摘要：文件类显示受保护路径，命令类显示正则。
    var triggerSummary: String {
        if kind == "file" {
            let ws = (watch ?? []).map { ($0 as NSString).expandingTildeInPath }
            return ws.isEmpty ? "（未指定路径）" : ws.joined(separator: "、")
        } else if kind == "cmd" {
            return pattern ?? "（未指定正则）"
        }
        return ""
    }

    /// 处置方式摘要：文件类显示 还原/保护/拦截/告警 + 动作；命令类显示「监测」。
    var enforceSummary: String {
        if kind == "file" {
            let ops = (ops ?? []).joined(separator: "/")
            switch action {
            case "protect" where restore == true: return "命中即还原（\(ops)）"
            case "protect":                       return "保护（\(ops)）"
            case "block":                         return "拦截（\(ops)）"
            case "alert":                         return "仅告警（\(ops)）"
            default:                              return action
            }
        }
        return "实时监测（可视化）"
    }

    /// 类型中文标签。
    var kindLabel: String {
        kind == "file" ? "文件" : (kind == "cmd" ? "命令" : kind)
    }
}
