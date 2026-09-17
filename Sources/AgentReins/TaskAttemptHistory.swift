import Foundation

enum TaskFamilyConfidence: String, Sendable {
    case confirmed = "Confirmed"
    case inferred = "Inferred"
}

struct TaskAttemptFamily: Identifiable, Sendable {
    let id: String
    let requirement: String
    let attempts: [ProjectChangeSet]
    let confidence: TaskFamilyConfidence

    var firstAttemptAt: Date { attempts.map(\.startedAt).min() ?? .distantPast }
    var lastAttemptAt: Date { attempts.map(\.lastActivityAt).max() ?? .distantPast }
    /// A superseded intermediate success must not turn the whole task green.
    /// The deliverable is successful only when the latest attempt is independently verified.
    var succeeded: Bool { attempts.last?.verification == .verified }
    var hadEarlierVerifiedAttempt: Bool {
        guard attempts.count > 1 else { return false }
        return attempts.dropLast().contains { $0.verification == .verified }
    }
    var agents: [String] { Array(Set(attempts.map { formattedAgentName($0.agent) })).sorted() }
}

/// Read-only projection over immutable task evidence. It never rewrites session or turn identity.
/// Exact normalized requirements are confirmed; fuzzy grouping is deliberately conservative and
/// remains visibly inferred.
enum TaskAttemptHistory {
    static func build(changeSets: [ProjectChangeSet]) -> [TaskAttemptFamily] {
        var families: [TaskAttemptFamily] = []
        for attempt in changeSets.sorted(by: { $0.startedAt < $1.startedAt }) {
            let exactKey = normalizedRequirement(attempt.requirement)
            if let index = families.firstIndex(where: {
                normalizedRequirement($0.requirement) == exactKey && !$0.attempts.isEmpty
            }) {
                let previous = families[index]
                families[index] = TaskAttemptFamily(id: previous.id, requirement: previous.requirement,
                    attempts: previous.attempts + [attempt], confidence: previous.confidence)
                continue
            }

            if let index = families.indices.reversed().first(where: {
                isLikelyRetry(attempt, of: families[$0])
            }) {
                let previous = families[index]
                families[index] = TaskAttemptFamily(id: previous.id, requirement: previous.requirement,
                    attempts: previous.attempts + [attempt], confidence: .inferred)
                continue
            }

            families.append(TaskAttemptFamily(id: "task-family:\(attempt.id)",
                requirement: attempt.requirement, attempts: [attempt], confidence: .confirmed))
        }
        return families.sorted { $0.lastAttemptAt > $1.lastAttemptAt }
    }

    private static func isLikelyRetry(_ attempt: ProjectChangeSet, of family: TaskAttemptFamily) -> Bool {
        guard let previous = family.attempts.last,
              attempt.startedAt.timeIntervalSince(previous.lastActivityAt) <= 24 * 60 * 60 else { return false }
        let similarity = shingleSimilarity(attempt.requirement, family.requirement)
        let sharedFiles = !Set(attempt.createdFiles + attempt.modifiedFiles + attempt.deletedFiles)
            .isDisjoint(with: Set(previous.createdFiles + previous.modifiedFiles + previous.deletedFiles))
        return similarity >= 0.82 || (similarity >= 0.68 && sharedFiles)
    }

    private static func normalizedRequirement(_ value: String) -> String {
        value.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
            .unicodeScalars
            .filter { CharacterSet.alphanumerics.contains($0) }
            .map(String.init)
            .joined()
    }

    private static func shingleSimilarity(_ lhs: String, _ rhs: String) -> Double {
        let left = shingles(normalizedRequirement(lhs))
        let right = shingles(normalizedRequirement(rhs))
        guard !left.isEmpty, !right.isEmpty else { return 0 }
        return Double(left.intersection(right).count) / Double(left.union(right).count)
    }

    private static func shingles(_ value: String) -> Set<String> {
        let characters = Array(value)
        guard characters.count >= 5 else { return [] }
        return Set((0...(characters.count - 3)).map { String(characters[$0...($0 + 2)]) })
    }
}
