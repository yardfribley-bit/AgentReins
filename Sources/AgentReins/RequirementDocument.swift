import Foundation

struct CitedRequirementStatement: Codable, Sendable, Hashable {
    let text: String
    let evidenceIDs: [String]

    enum CodingKeys: String, CodingKey {
        case text
        case evidenceIDs = "evidence_ids"
    }
}

struct RequirementDocumentDraft: Codable, Sendable {
    let title: String
    let originalRequirement: CitedRequirementStatement
    let finalRequirements: [CitedRequirementStatement]
    let evolution: [CitedRequirementStatement]
    let acceptanceCriteria: [CitedRequirementStatement]
    let implementation: [CitedRequirementStatement]
    let gaps: [CitedRequirementStatement]
    let status: String

    enum CodingKeys: String, CodingKey {
        case title, evolution, implementation, gaps, status
        case originalRequirement = "original_requirement"
        case finalRequirements = "final_requirements"
        case acceptanceCriteria = "acceptance_criteria"
    }
}

struct GeneratedRequirementDocument: Codable, Identifiable, Sendable {
    let id: String
    let changeSetID: String
    let version: Int
    let generatedAt: Date
    let model: String
    let document: RequirementDocumentDraft
    let sourceEvidenceIDs: [String]
}
