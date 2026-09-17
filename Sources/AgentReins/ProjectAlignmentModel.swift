import Foundation

// MARK: - Shared truth semantics

enum AlignmentConfidence: String, Codable, Sendable, CaseIterable {
    case confirmed
    case observed
    case declared
    case inferred
    case unknown
}

enum EvidenceRelation: String, Codable, Sendable {
    case supports
    case contradicts
    case producedBy
    case verifiedBy
    case derivedFrom
}

struct EvidenceLink: Codable, Hashable, Sendable {
    let evidenceID: String
    let relation: EvidenceRelation
    let note: String?
}

struct GroundedStatement: Codable, Identifiable, Sendable {
    let id: String
    var text: String
    var confidence: AlignmentConfidence
    var evidence: [EvidenceLink]
    var createdAt: Date
    var updatedAt: Date
}

// MARK: - Raw and derived evidence

enum ProjectEvidenceKind: String, Codable, Sendable, CaseIterable {
    case userRequest
    case userConfirmation
    case projectDocument
    case sourceCode
    case codeStructure
    case gitCommit
    case gitDiff
    case agentPrompt
    case agentResponse
    case agentPlan
    case toolCall
    case process
    case fileMutation
    case networkConnection
    case memoryRead
    case memoryWrite
    case buildResult
    case testResult
    case securityFinding
}

struct ProjectEvidenceRecord: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let kind: ProjectEvidenceKind
    let capturedAt: Date
    let source: String
    let sourceLocator: String?
    let contentDigest: String?
    let summary: String
    let rawEventIDs: [String]
    let confidence: AlignmentConfidence
    let agentID: String?
    let sessionID: String?
    let turnID: String?
}

// MARK: - What the user wants

enum RequirementOrigin: String, Codable, Sendable {
    case userConfirmed
    case userConversation
    case projectDocument
    case issueTracker
    case agentExtracted
    case systemInferred
}

enum RequirementState: String, Codable, Sendable, CaseIterable {
    case proposed
    case confirmed
    case planned
    case inProgress
    case implemented
    case verified
    case rejected
    case superseded
}

enum RequirementPriority: String, Codable, Sendable { case critical, high, medium, low, unset }

enum AcceptanceState: String, Codable, Sendable {
    case pending
    case observed
    case passed
    case failed
    case notVerifiable
}

struct AcceptanceCriterion: Codable, Identifiable, Sendable {
    let id: String
    var statement: String
    var state: AcceptanceState
    var verificationIDs: [String]
    var evidence: [EvidenceLink]
}

struct RequirementRevision: Codable, Identifiable, Sendable {
    let id: String
    let changedAt: Date
    let changedBy: String
    let previousStatement: String?
    let newStatement: String
    let reason: String?
    let evidence: [EvidenceLink]
}

struct ProjectRequirement: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    var title: String
    var statement: String
    var rationale: String?
    var origin: RequirementOrigin
    var state: RequirementState
    var priority: RequirementPriority
    var createdAt: Date
    var updatedAt: Date
    var acceptanceCriteria: [AcceptanceCriterion]
    var constraints: [GroundedStatement]
    var capabilityIDs: [String]
    var parentRequirementID: String?
    var supersedesRequirementIDs: [String]
    var revisions: [RequirementRevision]
    var evidence: [EvidenceLink]
}

// MARK: - What the code currently is

enum CapabilityState: String, Codable, Sendable {
    case declared
    case partiallyObserved
    case implemented
    case verified
    case degraded
    case unknown
}

struct ProjectCapabilityRecord: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    var name: String
    var purpose: GroundedStatement
    var state: CapabilityState
    var requirementIDs: [String]
    var componentIDs: [String]
    var verificationIDs: [String]
    var evidence: [EvidenceLink]
    var updatedAt: Date
}

enum ProjectComponentKind: String, Codable, Sendable {
    case application
    case service
    case module
    case package
    case dataStore
    case userInterface
    case runtime
    case externalDependency
    case file
    case symbol
}

struct SourceLocation: Codable, Hashable, Sendable {
    let path: String
    let symbol: String?
    let line: Int?
}

struct ProjectComponent: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    var name: String
    var kind: ProjectComponentKind
    var responsibility: GroundedStatement
    var locations: [SourceLocation]
    var dependencyIDs: [String]
    var capabilityIDs: [String]
    var evidence: [EvidenceLink]
}

// MARK: - What an Agent currently believes

enum UnderstandingClaimKind: String, Codable, Sendable {
    case projectPurpose
    case currentGoal
    case capability
    case architecture
    case requirement
    case constraint
    case decision
    case assumption
    case risk
    case openQuestion
}

enum UnderstandingFreshness: String, Codable, Sendable { case current, aging, stale, contradicted, unknown }

struct AgentUnderstandingClaim: Codable, Identifiable, Sendable {
    let id: String
    var kind: UnderstandingClaimKind
    var statement: String
    var freshness: UnderstandingFreshness
    var confidence: AlignmentConfidence
    var requirementIDs: [String]
    var capabilityIDs: [String]
    var componentIDs: [String]
    var memoryItemIDs: [String]
    var evidence: [EvidenceLink]
}

struct AgentProjectUnderstanding: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let agentID: String
    let sessionID: String?
    let capturedAt: Date
    var claims: [AgentUnderstandingClaim]
    var contextEvidenceIDs: [String]
    var memoryItemIDs: [String]
}

// MARK: - What persists between tasks

enum ProjectMemoryScope: String, Codable, Sendable { case user, project, agent, session }
enum ProjectMemoryState: String, Codable, Sendable { case active, stale, contradicted, deleted, unknown }

struct ProjectMemoryRevision: Codable, Identifiable, Sendable {
    let id: String
    let timestamp: Date
    let operation: String
    let previousDigest: String?
    let newDigest: String?
    let actorAgentID: String?
    let evidence: [EvidenceLink]
}

struct ProjectMemoryItem: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    var scope: ProjectMemoryScope
    var ownerAgentID: String?
    var key: String?
    var content: String
    var state: ProjectMemoryState
    var createdAt: Date
    var updatedAt: Date
    var requirementIDs: [String]
    var capabilityIDs: [String]
    var revisions: [ProjectMemoryRevision]
    var evidence: [EvidenceLink]
}

// MARK: - Decisions and independent verification

enum DecisionState: String, Codable, Sendable { case proposed, accepted, rejected, superseded }

struct ProjectDecision: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    var title: String
    var decision: String
    var rationale: String?
    var state: DecisionState
    var decidedAt: Date
    var requirementIDs: [String]
    var componentIDs: [String]
    var evidence: [EvidenceLink]
}

enum VerificationKind: String, Codable, Sendable {
    case build
    case test
    case lint
    case codeSecurity
    case runtime
    case requirementAcceptance
    case humanReview
}

enum VerificationOutcome: String, Codable, Sendable { case passed, failed, partial, unavailable }

struct ProjectVerification: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let kind: VerificationKind
    let startedAt: Date
    let completedAt: Date?
    let outcome: VerificationOutcome
    let independentOfAgentClaim: Bool
    let requirementIDs: [String]
    let capabilityIDs: [String]
    let componentIDs: [String]
    let summary: String
    let evidence: [EvidenceLink]
}

// MARK: - Where the three models disagree

enum AlignmentDimension: String, Codable, Sendable {
    case requirementVersusCode
    case agentVersusRequirement
    case agentVersusCode
    case memoryVersusRequirement
    case memoryVersusCode
}

enum AlignmentSeverity: String, Codable, Sendable { case info, low, medium, high, critical }
enum DriftState: String, Codable, Sendable { case open, acknowledged, resolved, dismissed }

struct ProjectAlignmentDrift: Codable, Identifiable, Sendable {
    let id: String
    let projectID: String
    let dimension: AlignmentDimension
    var severity: AlignmentSeverity
    var state: DriftState
    var title: String
    var explanation: String
    var detectedAt: Date
    var resolvedAt: Date?
    var requirementIDs: [String]
    var capabilityIDs: [String]
    var componentIDs: [String]
    var understandingClaimIDs: [String]
    var memoryItemIDs: [String]
    var evidence: [EvidenceLink]
}

// MARK: - Complete project alignment document

struct ProjectIdentity: Codable, Sendable {
    let id: String
    var name: String
    var rootPath: String
    var purpose: GroundedStatement?
    var repositoryURL: String?
    var firstObservedAt: Date
    var lastIndexedAt: Date?
}

struct ProjectAlignmentDocument: Codable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    var project: ProjectIdentity
    var requirements: [ProjectRequirement]
    var capabilities: [ProjectCapabilityRecord]
    var components: [ProjectComponent]
    var agentUnderstandings: [AgentProjectUnderstanding]
    var memoryItems: [ProjectMemoryItem]
    var decisions: [ProjectDecision]
    var verifications: [ProjectVerification]
    var drifts: [ProjectAlignmentDrift]
    var evidence: [ProjectEvidenceRecord]
    var generatedAt: Date

    init(project: ProjectIdentity, requirements: [ProjectRequirement] = [],
         capabilities: [ProjectCapabilityRecord] = [], components: [ProjectComponent] = [],
         agentUnderstandings: [AgentProjectUnderstanding] = [], memoryItems: [ProjectMemoryItem] = [],
         decisions: [ProjectDecision] = [], verifications: [ProjectVerification] = [],
         drifts: [ProjectAlignmentDrift] = [], evidence: [ProjectEvidenceRecord] = [],
         generatedAt: Date = Date()) {
        schemaVersion = Self.currentSchemaVersion
        self.project = project
        self.requirements = requirements
        self.capabilities = capabilities
        self.components = components
        self.agentUnderstandings = agentUnderstandings
        self.memoryItems = memoryItems
        self.decisions = decisions
        self.verifications = verifications
        self.drifts = drifts
        self.evidence = evidence
        self.generatedAt = generatedAt
    }
}

// MARK: - Referential integrity and derived posture

struct ProjectAlignmentValidationIssue: Equatable, Sendable {
    let entityID: String
    let message: String
}

struct ProjectAlignmentPosture: Equatable, Sendable {
    let confirmedRequirements: Int
    let verifiedRequirements: Int
    let verifiedCapabilities: Int
    let openDrifts: Int
    let criticalDrifts: Int
}

extension ProjectAlignmentDocument {
    var posture: ProjectAlignmentPosture {
        ProjectAlignmentPosture(
            confirmedRequirements: requirements.filter { [.confirmed, .planned, .inProgress, .implemented, .verified].contains($0.state) }.count,
            verifiedRequirements: requirements.filter { $0.state == .verified }.count,
            verifiedCapabilities: capabilities.filter { $0.state == .verified }.count,
            openDrifts: drifts.filter { $0.state == .open }.count,
            criticalDrifts: drifts.filter { $0.state == .open && $0.severity == .critical }.count)
    }

    func validateReferences() -> [ProjectAlignmentValidationIssue] {
        let evidenceIDs = Set(evidence.map(\.id))
        let requirementIDs = Set(requirements.map(\.id))
        let capabilityIDs = Set(capabilities.map(\.id))
        let componentIDs = Set(components.map(\.id))
        let verificationIDs = Set(verifications.map(\.id))
        let memoryIDs = Set(memoryItems.map(\.id))
        let claimIDs = Set(agentUnderstandings.flatMap(\.claims).map(\.id))
        var issues: [ProjectAlignmentValidationIssue] = []

        func check(_ owner: String, _ values: [String], _ available: Set<String>, _ label: String) {
            for value in values where !available.contains(value) {
                issues.append(ProjectAlignmentValidationIssue(entityID: owner, message: "Missing \(label): \(value)"))
            }
        }
        func checkEvidence(_ owner: String, _ links: [EvidenceLink]) {
            check(owner, links.map(\.evidenceID), evidenceIDs, "evidence")
        }

        for requirement in requirements {
            check(requirement.id, requirement.capabilityIDs, capabilityIDs, "capability")
            check(requirement.id, requirement.acceptanceCriteria.flatMap(\.verificationIDs), verificationIDs, "verification")
            checkEvidence(requirement.id, requirement.evidence + requirement.constraints.flatMap(\.evidence))
        }
        for capability in capabilities {
            check(capability.id, capability.requirementIDs, requirementIDs, "requirement")
            check(capability.id, capability.componentIDs, componentIDs, "component")
            check(capability.id, capability.verificationIDs, verificationIDs, "verification")
            checkEvidence(capability.id, capability.evidence + capability.purpose.evidence)
        }
        for component in components {
            check(component.id, component.dependencyIDs, componentIDs, "component")
            check(component.id, component.capabilityIDs, capabilityIDs, "capability")
            checkEvidence(component.id, component.evidence + component.responsibility.evidence)
        }
        for understanding in agentUnderstandings {
            check(understanding.id, understanding.contextEvidenceIDs, evidenceIDs, "evidence")
            check(understanding.id, understanding.memoryItemIDs, memoryIDs, "memory")
            for claim in understanding.claims {
                check(claim.id, claim.requirementIDs, requirementIDs, "requirement")
                check(claim.id, claim.capabilityIDs, capabilityIDs, "capability")
                check(claim.id, claim.componentIDs, componentIDs, "component")
                check(claim.id, claim.memoryItemIDs, memoryIDs, "memory")
                checkEvidence(claim.id, claim.evidence)
            }
        }
        for drift in drifts {
            check(drift.id, drift.requirementIDs, requirementIDs, "requirement")
            check(drift.id, drift.capabilityIDs, capabilityIDs, "capability")
            check(drift.id, drift.componentIDs, componentIDs, "component")
            check(drift.id, drift.understandingClaimIDs, claimIDs, "understanding claim")
            check(drift.id, drift.memoryItemIDs, memoryIDs, "memory")
            checkEvidence(drift.id, drift.evidence)
        }
        for verification in verifications { checkEvidence(verification.id, verification.evidence) }
        for memory in memoryItems { checkEvidence(memory.id, memory.evidence + memory.revisions.flatMap(\.evidence)) }
        for decision in decisions { checkEvidence(decision.id, decision.evidence) }
        return issues
    }
}
