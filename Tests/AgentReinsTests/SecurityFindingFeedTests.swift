import XCTest
@testable import AgentReins

final class SecurityFindingFeedTests: XCTestCase {
    func testSavedAIFindingsAppearWithoutRuleEvents() {
        let report = Self.report()
        let feed = SecurityFindingItem.merge(incidents: [], analysis: report)
        XCTAssertEqual(feed.count, 1)
        XCTAssertTrue(feed[0].isAI)
        XCTAssertTrue(feed[0].id.hasPrefix("ai:"))
    }

    func testBothSourcesRemainVisibleAndSortBySeverity() {
        let event = GuardEvent(kind: "alert", ruleId: "test", path: "-", command: nil,
            agent: "workbuddy", op: "call", severity: "medium", ts: Date(), action: "observed")
        let feed = SecurityFindingItem.merge(incidents: SecurityIncident.correlate([event]), analysis: Self.report())
        XCTAssertEqual(feed.count, 2)
        XCTAssertTrue(feed[0].isAI)
        XCTAssertFalse(feed[1].isAI)
        XCTAssertEqual(Set(feed.map(\.id)).count, 2)
    }

    static func report() -> HistoricalSecurityAnalysis {
        let finding = AIHistoricalFinding(id: "fixture", title: "模型请求中发现内部地址", severity: "high",
            summary: "测试数据：请求包含内部地址，是否获得授权需要人工确认。", recommendedAction: "核对接收方和业务授权。",
            evidenceEventIds: ["fixture-event"], ruleId: "fixture-rule",
            llmSelfExamine: .init(verdict: "needs_review", confidence: 0.8, evidenceSufficient: true,
                falsePositiveRisk: "可能是合法业务", counterEvidence: "尚未核实授权", rationale: "地址出现不等于违规泄露"))
        return .init(findings: [finding], rules: [], generatedAt: "2026-09-25T00:00:00Z", model: "测试模型", examinationPasses: 2)
    }
}
