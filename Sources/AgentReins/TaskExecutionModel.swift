import Foundation

enum TaskExecutionState: String, Codable, Sendable {
    case queued, running, blocked, failed, succeeded
}

enum EngineAttemptState: String, Codable, Sendable {
    case preparing, running, blocked, failed, agentReportedComplete, verified, superseded, cancelled

    var isTerminal: Bool {
        switch self {
        case .blocked, .failed, .verified, .superseded, .cancelled: return true
        case .preparing, .running, .agentReportedComplete: return false
        }
    }
}

enum AttemptTrigger: String, Codable, Sendable {
    case initial
    case retryAfterFailure
    case userCorrection
    case modelSwitch
    case recovery
}

enum VerificationVerdict: String, Codable, Sendable {
    case pending, passed, failed, unavailable
}

enum CriterionState: String, Codable, Sendable {
    case pending, passed, failed, unknown
}

enum RetryFailureClass: String, Codable, Sendable {
    case planning, environment, permission, dependency, tool, network, compilation, test, verification, userRejected, unknown
}

enum AttemptDecisionKind: String, Codable, Sendable {
    case continueCurrentAttempt
    case retrySameEngine
    case switchModel
    case requestUserAction
    case stopSucceeded
    case stopFailed
}

struct EvidenceReference: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let eventId: String
    let source: String
    let summary: String
    let observedAt: Date
    let confidence: EvidenceConfidence
}

struct AttemptAcceptanceCriterion: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let statement: String
    var state: CriterionState
    var evidence: [EvidenceReference]
}

struct IndependentVerification: Codable, Hashable, Sendable {
    let verdict: VerificationVerdict
    let method: String
    let summary: String
    let performedAt: Date?
    let evidence: [EvidenceReference]

    static let pending = IndependentVerification(verdict: .pending, method: "Not run",
        summary: "Independent verification has not run", performedAt: nil, evidence: [])
}

struct EngineIdentity: Codable, Hashable, Sendable {
    let agent: String
    let engine: String
    let model: String?
    let provider: String?
    let relay: String?

    var budgetKey: String {
        [agent, engine, model ?? "unknown-model", provider ?? "unknown-provider", relay ?? "direct"]
            .map { $0.lowercased() }.joined(separator: "|")
    }
}

struct AttemptUsage: Codable, Hashable, Sendable {
    var inputTokens: Int
    var outputTokens: Int
    var cachedTokens: Int
    var reasoningTokens: Int
    var costUSD: Double
    var durationMS: Int64

    static let zero = AttemptUsage(inputTokens: 0, outputTokens: 0, cachedTokens: 0,
        reasoningTokens: 0, costUSD: 0, durationMS: 0)
}

struct CorrectiveRetry: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let sequence: Int
    let startedAt: Date
    var endedAt: Date?
    let reason: String
    let failureClass: RetryFailureClass
    let failureSignature: String?
    let changedApproach: String?
    var outcome: VerificationVerdict
    var toolCallIds: [String]
    var evidence: [EvidenceReference]
}

struct AttemptDecision: Codable, Hashable, Sendable {
    let kind: AttemptDecisionKind
    let reason: String
    let decidedAt: Date
    let fromEngine: EngineIdentity?
    let suggestedEngine: EngineIdentity?
}

struct EngineAttempt: Identifiable, Codable, Hashable, Sendable {
    let id: String
    let taskId: String
    let sequence: Int
    let engineAttemptNumber: Int
    let engine: EngineIdentity
    let trigger: AttemptTrigger
    let startedAt: Date
    var endedAt: Date?
    var state: EngineAttemptState
    var planSummary: String?
    var contextHash: String?
    var acceptanceCriteria: [AttemptAcceptanceCriterion]
    var correctiveRetries: [CorrectiveRetry]
    var toolCallIds: [String]
    var changedFiles: [String]
    var networkDestinations: [String]
    var memoryOperationIds: [String]
    var failureSignatures: [String]
    var agentReportedOutcome: String?
    var verification: IndependentVerification
    var usage: AttemptUsage
    var evidence: [EvidenceReference]
    var decision: AttemptDecision?

    var isSuccessful: Bool {
        guard state == .verified, verification.verdict == .passed else { return false }
        return !acceptanceCriteria.contains { criterion in
            criterion.state == .failed || criterion.state == .unknown
        }
    }
}

struct AttemptBudgetPolicy: Codable, Hashable, Sendable {
    /// Advisory threshold for changing models. This never limits evidence collection:
    /// if an engine runs 17 times, all 17 attempts remain recorded.
    let modelSwitchThreshold: Int
    let maximumCorrectiveRetriesPerAttempt: Int?

    static let pairProgramming = AttemptBudgetPolicy(modelSwitchThreshold: 3,
        maximumCorrectiveRetriesPerAttempt: nil)
}

struct TaskExecution: Identifiable, Codable, Hashable, Sendable {
    static let schemaVersion = 1

    let schemaVersion: Int
    let id: String
    let projectId: String?
    let title: String
    let originalRequirement: String
    let createdAt: Date
    var updatedAt: Date
    var state: TaskExecutionState
    var budgetPolicy: AttemptBudgetPolicy
    var attempts: [EngineAttempt]
    var finalVerification: IndependentVerification
    var finalDecision: AttemptDecision?

    init(id: String, projectId: String?, title: String, originalRequirement: String,
         createdAt: Date, updatedAt: Date, state: TaskExecutionState,
         budgetPolicy: AttemptBudgetPolicy = .pairProgramming, attempts: [EngineAttempt] = [],
         finalVerification: IndependentVerification = .pending, finalDecision: AttemptDecision? = nil) {
        self.schemaVersion = Self.schemaVersion
        self.id = id
        self.projectId = projectId
        self.title = title
        self.originalRequirement = originalRequirement
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.state = state
        self.budgetPolicy = budgetPolicy
        self.attempts = attempts
        self.finalVerification = finalVerification
        self.finalDecision = finalDecision
    }

    var latestAttempt: EngineAttempt? { attempts.max { $0.sequence < $1.sequence } }

    func attemptsUsed(for engine: EngineIdentity) -> Int {
        attempts.filter { $0.engine.budgetKey == engine.budgetKey }.count
    }

    func attemptsRemaining(for engine: EngineIdentity) -> Int {
        max(0, budgetPolicy.modelSwitchThreshold - attemptsUsed(for: engine))
    }

    func attemptsBeyondSwitchThreshold(for engine: EngineIdentity) -> Int {
        max(0, attemptsUsed(for: engine) - budgetPolicy.modelSwitchThreshold)
    }

    var requiresModelSwitch: Bool {
        guard state != .succeeded, let latest = latestAttempt, latest.state.isTerminal,
              !latest.isSuccessful else { return false }
        return attemptsUsed(for: latest.engine) >= budgetPolicy.modelSwitchThreshold
    }

    var finalOutcomeIsVerified: Bool {
        state == .succeeded && finalVerification.verdict == .passed && latestAttempt?.isSuccessful == true
    }
}
