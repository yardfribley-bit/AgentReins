import XCTest
@testable import AgentReins

final class RealtimeReviewStoreTests: XCTestCase {
    func testDecisionSurvivesReloadAndPackIncludesHash() throws {
        let id = "S02:call-fixture:credential-outbound"
        let evidence = "rule=S02\ntitle=fixture\nAuthorization: Bearer sk-test-not-real"
        let decision = RealtimeReviewStore.Decision(
            id: id,
            state: "accepted",
            note: "packaged-app persistence probe",
            decidedAt: "2026-10-21T01:40:00Z",
            evidenceHash: RealtimeReviewStore.evidenceHash(for: evidence),
            evidenceCount: evidence.utf8.count
        )
        let saved = RealtimeReviewStore.save(decision)
        XCTAssertTrue(saved.contains(where: { $0.id == id && $0.state == "accepted" }))
        let loaded = RealtimeReviewStore.load()
        guard let hit = loaded.first(where: { $0.id == id }) else {
            return XCTFail("decision missing after reload")
        }
        XCTAssertEqual(hit.state, "accepted")
        XCTAssertEqual(hit.note, "packaged-app persistence probe")
        XCTAssertEqual(hit.evidenceHash?.count, 64)

        let pack = RealtimeReviewStore.packJSON(
            alertID: id, title: "出站含密钥", summary: "fixture", rule: "S02",
            agent: "Cursor", session: "s1", call: "call-fixture",
            decidedAt: hit.decidedAt, state: hit.state, note: hit.note,
            evidenceText: evidence
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: pack) as? [String: Any])
        let evidenceObj = try XCTUnwrap(object["evidence"] as? [String: Any])
        XCTAssertEqual(evidenceObj["sha256"] as? String, hit.evidenceHash)
        XCTAssertEqual(evidenceObj["bytes"] as? Int, evidence.utf8.count)
    }
}
