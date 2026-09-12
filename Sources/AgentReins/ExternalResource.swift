import CryptoKit
import Foundation

enum ExternalResourceKind: String, Codable, CaseIterable {
    case webPage, githubRepository, remoteFile, localFile, document, dependency, skill, mcp, api, unknown
}

enum ResourceOrigin: String, Codable {
    case userConfigured, userOpened, userSelected, modelRecommended, agentDiscovered, toolReturned, unknown
}

enum ResourceUsage: String, Codable, CaseIterable {
    case mentioned, opened, read, enteredContext, downloaded, uploaded, executed, modifiedWorkspace
}

enum InspectionDepth: String, Codable, Comparable {
    case ignore, observe, inspect, verify, contain
    private var rank: Int { [0, 1, 2, 3, 4][Self.allCases.firstIndex(of: self)!] }
    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

extension InspectionDepth: CaseIterable {}

struct ExternalResource: Identifiable {
    let id: String
    let kind: ExternalResourceKind
    let locator: String
    let domain: String?
    let contentFingerprint: String?
    let origin: ResourceOrigin
    let usages: Set<ResourceUsage>
    let sessionId: String?
    let turnId: String?
    let firstSeen: Date
    let lastSeen: Date
    let evidenceEventIds: [UUID]
    let confidence: EvidenceConfidence

    static func stableID(kind: ExternalResourceKind, locator: String, fingerprint: String? = nil) -> String {
        let canonical = canonicalLocator(locator, kind: kind)
        let material = "\(kind.rawValue)|\(canonical)|\(fingerprint ?? "unversioned")"
        return SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func canonicalLocator(_ locator: String, kind: ExternalResourceKind) -> String {
        guard var parts = URLComponents(string: locator) else { return locator.lowercased() }
        parts.fragment = nil
        parts.host = parts.host?.lowercased()
        if kind == .githubRepository {
            parts.query = nil
            var components = parts.path.split(separator: "/").prefix(2).map(String.init)
            if components.count == 2, components[1].lowercased().hasSuffix(".git") {
                components[1].removeLast(4)
            }
            parts.path = "/\(components.joined(separator: "/").lowercased())"
        }
        return parts.string ?? locator
    }
}

struct ResourceInspectionPolicy {
    let configuredDomains: Set<String>
    let trustedResourceFingerprints: Set<String>

    init(configuredDomains: Set<String> = [], trustedResourceFingerprints: Set<String> = []) {
        self.configuredDomains = Set(configuredDomains.map { $0.lowercased() })
        self.trustedResourceFingerprints = trustedResourceFingerprints
    }

    func depth(for resource: ExternalResource) -> InspectionDepth {
        if let fingerprint = resource.contentFingerprint,
           trustedResourceFingerprints.contains(fingerprint) { return .observe }
        if [.githubRepository, .dependency, .skill, .mcp].contains(resource.kind) { return .verify }
        if resource.usages.contains(.executed) { return .contain }
        if resource.kind == .remoteFile || resource.usages.contains(.downloaded) { return .verify }
        if let domain = resource.domain, configuredDomains.contains(domain.lowercased()) { return .inspect }
        if [.modelRecommended, .agentDiscovered, .toolReturned].contains(resource.origin) { return .inspect }
        return .observe
    }
}

enum ExternalResourceCatalog {
    static func build(events: [GuardEvent]) -> [ExternalResource] {
        struct Accumulator {
            var kind: ExternalResourceKind
            var locator: String
            var domain: String?
            var origin: ResourceOrigin
            var usages: Set<ResourceUsage>
            var sessionId: String?
            var turnId: String?
            var firstSeen: Date
            var lastSeen: Date
            var eventIds: [UUID]
            var confidence: EvidenceConfidence
        }
        var resources: [String: Accumulator] = [:]
        for event in events {
            let candidates = candidates(for: event)
            for candidate in candidates {
                let id = ExternalResource.stableID(kind: candidate.kind, locator: candidate.locator)
                if var existing = resources[id] {
                    existing.usages.formUnion(candidate.usages)
                    existing.firstSeen = min(existing.firstSeen, event.ts)
                    existing.lastSeen = max(existing.lastSeen, event.ts)
                    if !existing.eventIds.contains(event.id) { existing.eventIds.append(event.id) }
                    if originRank(candidate.origin) > originRank(existing.origin) { existing.origin = candidate.origin }
                    resources[id] = existing
                } else {
                    resources[id] = Accumulator(kind: candidate.kind, locator: candidate.locator,
                        domain: candidate.domain, origin: candidate.origin, usages: candidate.usages,
                        sessionId: event.sessionId, turnId: event.turnId, firstSeen: event.ts,
                        lastSeen: event.ts, eventIds: [event.id],
                        confidence: event.attributionConfidence ?? .confirmed)
                }
            }
        }
        return resources.map { id, item in
            ExternalResource(id: id, kind: item.kind, locator: item.locator, domain: item.domain,
                contentFingerprint: nil, origin: item.origin, usages: item.usages,
                sessionId: item.sessionId, turnId: item.turnId, firstSeen: item.firstSeen,
                lastSeen: item.lastSeen, evidenceEventIds: item.eventIds, confidence: item.confidence)
        }.sorted { $0.lastSeen > $1.lastSeen }
    }

    private struct Candidate {
        let kind: ExternalResourceKind
        let locator: String
        let domain: String?
        let origin: ResourceOrigin
        let usages: Set<ResourceUsage>
    }

    private static func candidates(for event: GuardEvent) -> [Candidate] {
        var result: [Candidate] = []
        if let response = event.modelResponse {
            result += URLs(in: response).map { makeURLCandidate($0, origin: .modelRecommended, usage: .mentioned) }
        }
        if let command = event.command {
            let usage: ResourceUsage = command.localizedCaseInsensitiveContains("git clone") ? .downloaded : .opened
            result += URLs(in: command).map { makeURLCandidate($0, origin: .agentDiscovered, usage: usage) }
        }
        if event.kind == "network", let domain = event.remoteDomain ?? event.remoteHost {
            result.append(Candidate(kind: .api, locator: domain.lowercased(), domain: domain.lowercased(),
                                    origin: .agentDiscovered, usages: [.opened]))
        }
        if event.kind == "file", event.path != "-" {
            let usage: ResourceUsage = event.op == "read" ? .read : .modifiedWorkspace
            result.append(Candidate(kind: classifyFile(event.path), locator: event.path, domain: nil,
                                    origin: .userSelected, usages: [usage]))
        }
        return result
    }

    private static func makeURLCandidate(_ value: String, origin: ResourceOrigin, usage: ResourceUsage) -> Candidate {
        let url = URL(string: value)
        let domain = url?.host?.lowercased()
        let components = url?.pathComponents.filter { $0 != "/" } ?? []
        let kind: ExternalResourceKind = domain == "github.com" && components.count >= 2 ? .githubRepository : .webPage
        return Candidate(kind: kind, locator: value, domain: domain, origin: origin, usages: [usage])
    }

    private static func classifyFile(_ path: String) -> ExternalResourceKind {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        if ["pdf", "doc", "docx", "md", "txt"].contains(ext) { return .document }
        return .localFile
    }

    private static func originRank(_ value: ResourceOrigin) -> Int {
        switch value {
        case .userConfigured: return 6
        case .modelRecommended: return 5
        case .agentDiscovered: return 4
        case .toolReturned: return 3
        case .userSelected: return 2
        case .userOpened: return 1
        case .unknown: return 0
        }
    }

    private static func URLs(in text: String) -> [String] {
        let pattern = #"https?://[^\s\"'<>\]\[()]+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap {
            guard let range = Range($0.range, in: text) else { return nil }
            return String(text[range]).trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?"))
        }
    }
}
