import Foundation
import XCTest
@testable import AgentReins

final class ProjectAlignmentModelTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    func testAlignmentDocumentRoundTripsWithoutLosingProvenance() throws {
        let evidence = ProjectEvidenceRecord(id: "ev-user", projectID: "project", kind: .userConfirmation,
            capturedAt: now, source: "conversation", sourceLocator: "session:s1/turn:t1",
            contentDigest: "sha256:test", summary: "User confirmed relay attribution requirement",
            rawEventIDs: ["raw-1"], confidence: .confirmed, agentID: nil, sessionID: "s1", turnID: "t1")
        let criterion = AcceptanceCriterion(id: "criterion", statement: "Show the relay operator",
            state: .pending, verificationIDs: [], evidence: [EvidenceLink(evidenceID: evidence.id, relation: .derivedFrom, note: nil)])
        let requirement = ProjectRequirement(id: "req", projectID: "project", title: "Relay attribution",
            statement: "Identify the model relay and its operator", rationale: "Users need to know where code is uploaded",
            origin: .userConfirmed, state: .confirmed, priority: .high, createdAt: now, updatedAt: now,
            acceptanceCriteria: [criterion], constraints: [], capabilityIDs: [], parentRequirementID: nil,
            supersedesRequirementIDs: [], revisions: [],
            evidence: [EvidenceLink(evidenceID: evidence.id, relation: .supports, note: "Direct user confirmation")])
        let project = ProjectIdentity(id: "project", name: "AgentReins", rootPath: "/tmp/AgentReins",
            purpose: nil, repositoryURL: nil, firstObservedAt: now, lastIndexedAt: nil)
        let original = ProjectAlignmentDocument(project: project, requirements: [requirement], evidence: [evidence], generatedAt: now)

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ProjectAlignmentDocument.self, from: data)

        XCTAssertEqual(decoded.schemaVersion, ProjectAlignmentDocument.currentSchemaVersion)
        XCTAssertEqual(decoded.requirements.first?.origin, .userConfirmed)
        XCTAssertEqual(decoded.requirements.first?.evidence.first?.evidenceID, evidence.id)
        XCTAssertTrue(decoded.validateReferences().isEmpty)
    }

    func testValidatorRejectsDanglingSemanticReferences() {
        let project = ProjectIdentity(id: "project", name: "Test", rootPath: "/tmp/Test",
            purpose: nil, repositoryURL: nil, firstObservedAt: now, lastIndexedAt: nil)
        let purpose = GroundedStatement(id: "purpose", text: "Missing evidence", confidence: .inferred,
            evidence: [EvidenceLink(evidenceID: "missing-evidence", relation: .supports, note: nil)],
            createdAt: now, updatedAt: now)
        let capability = ProjectCapabilityRecord(id: "cap", projectID: "project", name: "Memory",
            purpose: purpose, state: .declared, requirementIDs: ["missing-requirement"],
            componentIDs: ["missing-component"], verificationIDs: ["missing-verification"],
            evidence: [], updatedAt: now)
        let document = ProjectAlignmentDocument(project: project, capabilities: [capability], generatedAt: now)

        let messages = Set(document.validateReferences().map(\.message))

        XCTAssertTrue(messages.contains("Missing requirement: missing-requirement"))
        XCTAssertTrue(messages.contains("Missing component: missing-component"))
        XCTAssertTrue(messages.contains("Missing verification: missing-verification"))
        XCTAssertTrue(messages.contains("Missing evidence: missing-evidence"))
    }

    func testPostureKeepsVerifiedWorkSeparateFromOpenDrift() {
        let project = ProjectIdentity(id: "project", name: "Test", rootPath: "/tmp/Test",
            purpose: nil, repositoryURL: nil, firstObservedAt: now, lastIndexedAt: nil)
        let requirement = ProjectRequirement(id: "req", projectID: "project", title: "Requirement",
            statement: "Do the work", rationale: nil, origin: .userConfirmed, state: .verified,
            priority: .high, createdAt: now, updatedAt: now, acceptanceCriteria: [], constraints: [],
            capabilityIDs: [], parentRequirementID: nil, supersedesRequirementIDs: [], revisions: [], evidence: [])
        let drift = ProjectAlignmentDrift(id: "drift", projectID: "project", dimension: .agentVersusCode,
            severity: .critical, state: .open, title: "Stale Agent belief", explanation: "Agent claims code exists",
            detectedAt: now, resolvedAt: nil, requirementIDs: [], capabilityIDs: [], componentIDs: [],
            understandingClaimIDs: [], memoryItemIDs: [], evidence: [])
        let document = ProjectAlignmentDocument(project: project, requirements: [requirement], drifts: [drift], generatedAt: now)

        XCTAssertEqual(document.posture.confirmedRequirements, 1)
        XCTAssertEqual(document.posture.verifiedRequirements, 1)
        XCTAssertEqual(document.posture.openDrifts, 1)
        XCTAssertEqual(document.posture.criticalDrifts, 1)
    }
}
