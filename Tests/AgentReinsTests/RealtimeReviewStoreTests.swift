import XCTest
@testable import AgentReins

final class RealtimeReviewStoreTests: XCTestCase {
    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("AgentReinsReviewStoreTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        RealtimeReviewStore.useDirectory(tempDir)
    }

    override func tearDownWithError() throws {
        RealtimeReviewStore.useDirectory(nil)
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testDecisionSurvivesReloadInInjectedTempDirectory() throws {
        let id = "S02:call-fixture:credential-outbound"
        let evidence = "rule=S02\ntitle=fixture\nAuthorization: Bearer sk-test-not-real"
        let decision = RealtimeReviewStore.Decision(
            id: id,
            state: "acked",
            note: "style-only ack",
            decidedAt: "2026-10-21T01:40:00Z",
            evidenceHash: RealtimeReviewStore.evidenceHash(for: evidence),
            evidenceCount: evidence.utf8.count
        )
        let saved = RealtimeReviewStore.save(decision)
        XCTAssertTrue(saved.contains(where: { $0.id == id && $0.state == "acked" }))
        let loaded = RealtimeReviewStore.load()
        guard let hit = loaded.first(where: { $0.id == id }) else {
            return XCTFail("decision missing after reload")
        }
        XCTAssertEqual(hit.state, "acked")
        XCTAssertEqual(hit.note, "style-only ack")
        XCTAssertEqual(hit.evidenceHash?.count, 64)
        XCTAssertTrue(RealtimeReviewStore.url.path.hasPrefix(tempDir.path))
    }

    func testDoesNotWriteApplicationSupport() throws {
        let prod = RealtimeReviewStore.defaultDirectory
            .appendingPathComponent("realtime-review-decisions-v1.json")
        let beforeExists = FileManager.default.fileExists(atPath: prod.path)
        let beforeMod = (try? FileManager.default.attributesOfItem(atPath: prod.path)[.modificationDate]) as? Date
        let beforeData = beforeExists ? try? Data(contentsOf: prod) : nil

        let marker = "S07:xctest-must-not-touch-appsupport-\(UUID().uuidString)"
        _ = RealtimeReviewStore.save(RealtimeReviewStore.Decision(
            id: marker, state: "acked", note: "xctest", decidedAt: "2026-10-21T04:00:00Z",
            evidenceHash: RealtimeReviewStore.evidenceHash(for: marker), evidenceCount: 1
        ))

        if beforeExists {
            let afterMod = (try? FileManager.default.attributesOfItem(atPath: prod.path)[.modificationDate]) as? Date
            let afterData = try? Data(contentsOf: prod)
            XCTAssertEqual(beforeMod, afterMod, "Application Support mtime must not change")
            XCTAssertEqual(beforeData, afterData, "Application Support contents must not change")
            if let afterData, let text = String(data: afterData, encoding: .utf8) {
                XCTAssertFalse(text.contains(marker), "XCTest marker must not appear in Application Support")
            }
        } else {
            XCTAssertFalse(FileManager.default.fileExists(atPath: prod.path),
                           "tests must not create Application Support decisions file")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: RealtimeReviewStore.url.path))
    }
}
