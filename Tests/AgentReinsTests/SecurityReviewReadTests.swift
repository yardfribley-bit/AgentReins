import XCTest
@testable import AgentReins

final class SecurityReviewReadTests: XCTestCase {
    @MainActor func testAIProposalWithoutExecutableEvidenceCannotBeApproved() {
        let store = AlertPolicyStore()
        let originalPolicies = store.policies
        for (detector, verdict, sufficient) in [
            (Optional<AlertDetector>.none, "confirmed", true),
            (.credentialInToolArguments, "rejected", true),
            (.credentialInToolArguments, "needs_review", false)
        ] {
            let candidate = AIRuleCandidate(id: UUID().uuidString, name: "test", condition: "test",
                severity: "high", detector: detector, verdict: verdict, confidence: 0.9,
                evidenceSufficient: sufficient, falsePositiveRisk: "unknown", rationale: "fixture",
                historicalMatches: 1, generatedAt: nil)
            store.approve(candidate)
            XCTAssertEqual(store.policies, originalPolicies)
        }
    }

    func testRecentReviewHasHardLimitAndNewestFirst() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = try EvidenceDatabase(url: directory.appendingPathComponent("review.sqlite3"))
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let events = (0..<510).map { index in
            GuardEvent(kind: "alert", ruleId: "fixture", path: "-", command: "event \(index)",
                agent: "workbuddy", op: "call", severity: "high",
                ts: start.addingTimeInterval(Double(index)), action: "observed")
        }
        try database.append(events)
        let page = try database.recentSecurityReviewEvidence(limit: 200)
        XCTAssertEqual(page.count, 200)
        XCTAssertEqual(page.first?.id, events.last?.id)
        XCTAssertEqual(page.last?.id, events[310].id)
        XCTAssertEqual(try database.recentSecurityReviewEvidence(limit: 100_000).count, 500)
        XCTAssertEqual(try database.recentSecurityReviewEvidence(limit: 0).count, 1)
        let exact = try database.securityEvidence(ids: [events[0].id.uuidString.lowercased(), events[0].id.uuidString, "invalid", UUID().uuidString])
        XCTAssertEqual(Set(exact.map(\.id)), [events[0].id])
    }
}
