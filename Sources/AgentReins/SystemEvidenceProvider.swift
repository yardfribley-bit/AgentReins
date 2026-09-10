import Foundation

enum SystemEvidenceCapability: String, Codable, Sendable, Hashable {
    case processExecution
    case processLineage
    case fileMutation
    case contentDiff
    case networkConnection
}

struct SystemEvidenceSource: Sendable {
    let id: String
    let captureMethod: String
    let capabilities: Set<SystemEvidenceCapability>
    let confidenceCeiling: EvidenceConfidence
    let requiresRestrictedEntitlement: Bool
}

/// Stable boundary between AgentReins and operating-system evidence sources.
/// The current providers need no restricted entitlement; Endpoint Security and
/// Windows ETW providers can be added without changing normalized evidence.
@MainActor
protocol SystemEvidenceProvider: AnyObject {
    var evidenceSource: SystemEvidenceSource { get }
    func start()
    func stop()
}

extension ProcessGuard: SystemEvidenceProvider {
    var evidenceSource: SystemEvidenceSource {
        SystemEvidenceSource(
            id: "process-polling",
            captureMethod: "macOS libproc process identity and parent lineage with ps fallback",
            capabilities: [.processExecution, .processLineage, .networkConnection],
            confidenceCeiling: .inferred,
            requiresRestrictedEntitlement: false)
    }
}

extension FileGuard: SystemEvidenceProvider {
    var evidenceSource: SystemEvidenceSource {
        SystemEvidenceSource(
            id: "file-polling",
            captureMethod: "protected-path metadata and content comparison",
            capabilities: [.fileMutation, .contentDiff],
            confidenceCeiling: .inferred,
            requiresRestrictedEntitlement: false)
    }
}
