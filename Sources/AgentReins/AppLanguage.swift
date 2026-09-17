import Foundation
import SwiftUI

enum AppLanguage: String, CaseIterable, Identifiable {
    case english = "en"
    case simplifiedChinese = "zh-Hans"
    var id: String { rawValue }
    var displayName: String { self == .english ? "English" : "中文" }
    var locale: Locale { Locale(identifier: rawValue) }
}

@MainActor
final class AppLanguageStore: ObservableObject {
    private static let preferenceKey = "AgentReins.AppLanguage"
    @Published var language: AppLanguage {
        didSet { UserDefaults.standard.set(language.rawValue, forKey: Self.preferenceKey) }
    }

    init() {
        language = AppLanguage(rawValue: UserDefaults.standard.string(forKey: Self.preferenceKey) ?? "en") ?? .english
    }

    func toggle() {
        language = language == .english ? .simplifiedChinese : .english
    }

    func text(_ english: String) -> String {
        guard language == .simplifiedChinese else { return english }
        return Self.zh[english] ?? english
    }

    private static let zh: [String: String] = [
        "All agents": "全部智能体", "Projects": "项目", "Agents": "智能体", "Security": "安全",
        "Overview": "概览", "Processes": "进程", "Network": "网络", "Files": "文件",
        "Memory": "记忆", "Generated Code": "生成代码", "Tool Calls": "工具调用", "Timeline": "时间线",
        "Capabilities": "功能", "Architecture": "架构", "Evolution": "演进", "Understanding": "项目理解",
        "AI AGENT FLEET": "AI 智能体集群", "Project mission control": "项目任务控制中心",
        "Running": "运行中", "Idle": "空闲", "Monitoring runtime": "正在监控运行时",
        "Running a terminal command": "正在执行终端命令", "Reading project context": "正在读取项目上下文",
        "Editing project files": "正在修改项目文件", "Processing the current task": "正在处理当前任务",
        "LIVE MISSION CONTROL": "实时任务控制中心",
        "Track every project, task and safety decision across your AI agents.": "跟踪所有 AI 智能体的项目、任务与安全决策。",
        "PROJECTS": "项目", "ACTIVE TASKS": "活动任务", "REVIEW": "待审查", "EVIDENCE": "证据",
        "REAL-TIME · RECENT ACTIVITY ONLY": "实时 · 仅近期活动",
        "Monitoring for new Agent activity": "正在等待新的智能体活动", "Monitoring is paused": "监控已暂停",
        "PROJECT BRIEF": "项目简介", "CURRENT GOAL": "当前目标", "CAPABILITIES": "功能",
        "FILES SEEN": "已发现文件", "DRIFT": "认知偏差", "WHAT THIS PROJECT DOES": "这个项目能做什么",
        "HOW THE PROJECT IS ORGANIZED": "项目如何组织", "WHY THE PROJECT CHANGED": "项目为什么发生变化",
        "AGENT'S PROJECT MODEL": "智能体的项目认知", "UNRESOLVED & UNVERIFIED": "未解决与未验证",
        "REALITY VS AGENT UNDERSTANDING": "项目现实与智能体理解", "LIVE AGENT WORK": "智能体实时工作",
        "Observed": "已观察", "Declared": "已声明", "Inferred": "推断",
        "OBSERVED": "已观察", "DECLARED": "已声明", "INFERRED": "推断",
        "MONITORING": "监控中", "REVIEW REQUIRED": "需要审查", "CHANGED": "已变更",
        "No capabilities can be grounded in recent evidence yet": "近期证据尚不足以确认项目功能",
        "No grounded knowledge captured yet": "尚未采集到有证据支撑的项目认知",
        "No project evolution has been attributed yet": "尚未关联到项目演进记录",
        "Agent completion is not independently verified": "智能体声称完成，但尚未独立验证",
        "Reported work conflicts with verification": "智能体报告与验证结果冲突",
        "Project constraints are not explicit": "项目约束尚不明确",
        "No contradiction observed in the recent window": "近期证据中未发现冲突",
        "Search…": "搜索…", "MONITORING LIVE": "实时监控", "PAUSED": "已暂停",
        "HISTORY": "历史", "ANALYSIS READY": "分析已就绪", "ANALYSIS MODEL": "分析模型",
        "WEB PROTECTED": "网页已保护", "PROTECT WEB AI": "保护网页 AI",
        "NODE STATUS": "节点状态", "Confirmed": "已确认", "Unknown": "未知",
        "Open session…": "打开会话…", "Done": "完成", "Not captured": "未采集",
        "Open AgentReins": "打开 AgentReins", "Pause protection": "暂停保护", "Resume protection": "恢复保护",
        "Quit AgentReins": "退出 AgentReins", "AgentReins is protecting you": "AgentReins 正在保护你",
        "AgentReins is paused": "AgentReins 已暂停"
    ]
}
