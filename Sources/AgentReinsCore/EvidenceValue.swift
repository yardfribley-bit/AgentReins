import Foundation

/// What AgentReins keeps so a person can see host behavior, stop it, and account for it.
/// Noise and bulk copies are what fill the disk. A byte cap applies only after those
/// tiers, and it never deletes a keep-tier row on its own.
public enum EvidenceTier: String, Equatable, Sendable {
    case keep
    case noise
    case bulk
}

public struct EvidenceValueFields: Equatable, Sendable {
    public var kind: String
    public var op: String
    public var ruleId: String
    public var action: String
    public var severity: String
    public var source: String
    public var userIntent: String
    public var command: String
    public var path: String
    public var toolName: String
    public var toolCallId: String
    public var modelText: String
    public var processId: Int?
    public var payloadBytes: Int

    public init(kind: String = "", op: String = "", ruleId: String = "", action: String = "",
                severity: String = "", source: String = "", userIntent: String = "", command: String = "",
                path: String = "", toolName: String = "", toolCallId: String = "", modelText: String = "",
                processId: Int? = nil, payloadBytes: Int = 0) {
        self.kind = kind
        self.op = op
        self.ruleId = ruleId
        self.action = action
        self.severity = severity
        self.source = source
        self.userIntent = userIntent
        self.command = command
        self.path = path
        self.toolName = toolName
        self.toolCallId = toolCallId
        self.modelText = modelText
        self.processId = processId
        self.payloadBytes = payloadBytes
    }
}

public enum EvidenceValue {
    public static let excerptLimit = 480
    public static let keepFieldCap = 8_192
    /// Heartbeats and missing-prompt rows are not kept forever.
    public static let noiseMaxAge: TimeInterval = 24 * 60 * 60
    /// Raw dumps and session copies, after a summary or excerpt exists.
    public static let bulkMaxAge: TimeInterval = 3 * 24 * 60 * 60
    /// Safety backstop for noise and bulk only. Keep-tier rows are not auto-dropped to meet it.
    public static let backstopBytes: Int64 = 2 * 1024 * 1024 * 1024
    public static let batchRows = 200
    public static let maxBatchesPerPass = 4

    public static let policySummary = "留下能看见、能拦住、能核清的记录：外联、凭据、策略命中、处置决定；对得上工具或没人认领的文件改动；待我处理的决定和理由；说了没做、做了没说、做的比说的多所需的短摘录；工具名、路径、时间和 pid。心跳、没采到用户原话、重复采样、整段会话副本，以及已经有摘要的大块原文会清掉。容量只在这些低价值数据清完之后作为保险，不会为了凑容量丢掉高价值记录。"

    public static let keepTopics = [
        "egress, credential reads, policy hits, dispositions",
        "file changes tied to a tool call, or unclaimed file changes",
        "review decisions and reasons",
        "mismatch excerpts",
        "compact join keys (tool, path, time, pid)",
    ]
    public static let dropTopics = [
        "heartbeats, automation tags, missing user prompt",
        "raw transport blobs once a hash summary exists",
        "duplicate sampler ticks",
        "full session transcripts (index the agent file on demand)",
    ]

    public static func tier(_ fields: EvidenceValueFields) -> EvidenceTier {
        if isNoise(fields) && !isSecurity(fields) && !isFileChange(fields) && !isReviewAction(fields) {
            return .noise
        }
        if isSecurity(fields) || isFileChange(fields) || isReviewAction(fields) || isMismatch(fields) {
            return .keep
        }
        // Sampler and process-observation ticks carry a pid, which would otherwise
        // look like a join key and be kept forever. They are the rows that filled the disk.
        if isSamplerTick(fields) || isTranscriptOp(fields.op) {
            return .bulk
        }
        if isJoinKey(fields) && fields.payloadBytes <= 4_096 && fields.modelText.count <= excerptLimit {
            return .keep
        }
        if isRealShortRequest(fields) { return .keep }
        return .bulk
    }

    /// Window around a mismatch phrase, so a long transcript is not what we retain.
    public static func mismatchWindow(_ text: String, limit: Int = excerptLimit) -> String? {
        guard let range = text.range(of: mismatchPattern, options: .regularExpression) else { return nil }
        let start = text.index(range.lowerBound, offsetBy: -min(80, text.distance(from: text.startIndex, to: range.lowerBound)), limitedBy: text.startIndex) ?? text.startIndex
        let end = text.index(start, offsetBy: limit, limitedBy: text.endIndex) ?? text.endIndex
        return String(text[start..<end])
    }

    private static let mismatchPattern = "不联网|不会外联|不外联|只读取|只读|不上传"
    private static let noisePattern = "<\\s*/?\\s*(heartbeat|automation_id|automation)\\b|用户需求未采集|轮次尚未关联|没有采到这次任务的用户原话|机器标记，没有用户原话"
    private static let securityRule = "(?i)\\bS0[1-9]\\b|S10|credential|egress|policy|bypass|disposition"
    private static let reviewActions: Set<String> = [
        "allowlisted", "blocked", "released", "confirmed", "acked", "escalated",
        "accept", "return", "needs_evidence", "whitelist", "allow", "block",
    ]
    private static let networkOps: Set<String> = ["network", "egress", "download", "connect", "socket", "dns"]
    private static let fileKinds: Set<String> = ["file", "files", "skill"]
    private static let fileOps: Set<String> = ["write", "edit", "modify", "delete", "create"]
    private static let transcriptOps: Set<String> = ["recovered_transcript", "runtime_user_context", "output", "streaming"]

    private static func isNoise(_ fields: EvidenceValueFields) -> Bool {
        let op = fields.op.lowercased()
        if op == "heartbeat" || op == "automation" { return true }
        let blob = [fields.userIntent, fields.command, fields.modelText, fields.source, fields.op].joined(separator: "\n")
        return blob.range(of: noisePattern, options: .regularExpression) != nil
    }

    private static func isSecurity(_ fields: EvidenceValueFields) -> Bool {
        let severity = fields.severity.lowercased()
        if severity == "critical" || severity == "high" { return true }
        if fields.ruleId.range(of: securityRule, options: .regularExpression) != nil { return true }
        if reviewActions.contains(fields.action.lowercased()) { return true }
        let kind = fields.kind.lowercased()
        let op = fields.op.lowercased()
        if kind == "network" || networkOps.contains(op) || networkOps.contains(kind) { return true }
        if fields.source.lowercased().contains("content-audit") || fields.source.lowercased().contains("credential") {
            return true
        }
        return false
    }

    private static func isReviewAction(_ fields: EvidenceValueFields) -> Bool {
        reviewActions.contains(fields.action.lowercased())
    }

    private static func isFileChange(_ fields: EvidenceValueFields) -> Bool {
        let kind = fields.kind.lowercased()
        let op = fields.op.lowercased()
        let file = fileKinds.contains(kind) || fileOps.contains(op)
        guard file else { return false }
        if !fields.toolCallId.isEmpty || !fields.toolName.isEmpty { return true }
        let path = fields.path.trimmingCharacters(in: .whitespacesAndNewlines)
        return !path.isEmpty && path != "-"
    }

    private static func isMismatch(_ fields: EvidenceValueFields) -> Bool {
        guard fields.modelText.range(of: mismatchPattern, options: .regularExpression) != nil else { return false }
        return !fields.command.isEmpty || !fields.toolName.isEmpty || !fields.toolCallId.isEmpty
    }

    private static func isJoinKey(_ fields: EvidenceValueFields) -> Bool {
        if !fields.toolName.isEmpty || !fields.toolCallId.isEmpty || fields.processId != nil { return true }
        let path = fields.path.trimmingCharacters(in: .whitespacesAndNewlines)
        if !path.isEmpty && path != "-" { return true }
        return !fields.command.isEmpty
    }

    private static func isRealShortRequest(_ fields: EvidenceValueFields) -> Bool {
        let text = fields.userIntent.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= excerptLimit, fields.payloadBytes <= 8_192 else { return false }
        return text.range(of: noisePattern, options: .regularExpression) == nil
    }

    static func isTranscriptOp(_ op: String) -> Bool {
        transcriptOps.contains(op.lowercased())
    }

    private static let samplerOps: Set<String> = [
        "process_observation", "process_socket_observation", "process_ipc_observation",
        "process_communication_observation", "process_observation_unavailable",
        "process_watch_attached", "process_watch_detached", "process_identity_changed",
    ]

    private static func isSamplerTick(_ fields: EvidenceValueFields) -> Bool {
        let source = fields.source.lowercased()
        if source.contains("socket-sampler") || source.contains("process-observation") { return true }
        return samplerOps.contains(fields.op.lowercased())
    }
}
