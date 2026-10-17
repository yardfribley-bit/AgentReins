import XCTest
@testable import AgentReins
final class SensitiveRuleDraftTests: XCTestCase {
    func testRejectsUnsupportedSemanticAndInvalidRules() {
        for draft in [
            SensitiveRuleDraft(name: "客户", kind: "keyword", value: "客户名单", explanation: "", limitation: "", supported: false),
            SensitiveRuleDraft(name: "正则", kind: "regex", value: ".*secret.*", explanation: "", limitation: "", supported: true),
            SensitiveRuleDraft(name: "空值", kind: "secret", value: "", explanation: "", limitation: "", supported: true)
        ] { XCTAssertThrowsError(try draft.validate()) }
    }
    func testAcceptsLiteralRuleAfterReview() throws {
        try SensitiveRuleDraft(name: "内部标记", kind: "keyword", value: "内部项目代号", explanation: "字面量匹配", limitation: "不理解语义", supported: true).validate()
    }
    func testCompatibleCatalogWithoutDisplayName() throws {
        let data = Data(#"{"data":[{"id":"local-model"}]}"#.utf8)
        XCTAssertEqual(try OpenRouterModelCatalog.decode(data).first?.name, "local-model")
    }
}
