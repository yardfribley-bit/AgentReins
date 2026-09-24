import Foundation
import XCTest
import SQLite3
@testable import AgentReins

final class AuditBlockProtocolTests: XCTestCase {
    func testNetworkStagesRetainFailedRequestAndDistinctIdenticalCalls() throws {
        let data = Data(#"{"messages":[{"role":"user","content":"hello"}]}"#.utf8)
        func record(_ flow: String, _ stage: String) -> WorkBuddyNetworkCaptureRecord {
            WorkBuddyNetworkCaptureRecord(observedAt: Date(), host: "copilot.tencent.com", path: "/v1/chat/completions",
                method: "POST", httpVersion: "HTTP/2", contentEncoding: nil, declaredContentLength: data.count,
                capturedWireBodyBytes: data.count, requestBodyBase64: data.base64EncodedString(), requestSHA256: AuditBlockProtocol.hash(data),
                responseStatus: nil, responseComplete: false, responseBodyBase64: nil, flowID: flow,
                captureStage: stage, transportError: stage == "error" ? "timeout" : nil)
        }
        let first = try XCTUnwrap(WorkBuddyNetworkEvidence.project(record("one", "request")).first)
        let repeated = try XCTUnwrap(WorkBuddyNetworkEvidence.project(record("two", "request")).first)
        let failed = try XCTUnwrap(WorkBuddyNetworkEvidence.project(record("one", "error")).first)
        XCTAssertNotEqual(first.id, repeated.id)
        XCTAssertEqual(first.modelPrompt, String(decoding: data, as: UTF8.self))
        XCTAssertEqual(failed.traceId, first.traceId)
        XCTAssertEqual(failed.action, "failed")
        XCTAssertNil(failed.modelPrompt)
    }
    func testPayloadTamperingFailsIntegrityWithoutChangingStoredHashes() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("evidence.sqlite3")
        let db = try EvidenceDatabase(url: url)
        try db.appendRaw([RawEvidenceRecord(source: "test", stream: "test", offsetStart: 0, offsetEnd: 4,
            fingerprint: nil, observedAt: Date(), payload: Data("good".utf8))])
        XCTAssertTrue(try db.verifyIntegrity())
        var handle: OpaquePointer?
        XCTAssertEqual(sqlite3_open(url.path, &handle), SQLITE_OK)
        defer { sqlite3_close(handle) }
        XCTAssertEqual(sqlite3_exec(handle, "UPDATE raw_evidence SET payload=x'62616421'", nil, nil, nil), SQLITE_OK)
        XCTAssertFalse(try db.verifyIntegrity())
    }

    func testWorkBuddyIncrementalParserPersistsTurnAcrossLongStreamAndPartialLine() throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        let user = #"{"id":"turn-one","sessionId":"session","type":"message","role":"user","content":[{"text":"hello"}]}"# + "\n"
        let noise = String(repeating: #"{"id":"noop","padding":""# + String(repeating: "x", count: 1500) + #""}"# + "\n", count: 450)
        try (user + noise).write(to: file, atomically: true, encoding: .utf8)
        var state = WorkBuddySight.ParserState()
        _ = WorkBuddySight.readIncremental(file, state: &state)
        state = try JSONDecoder().decode(WorkBuddySight.ParserState.self, from: JSONEncoder().encode(state))
        let handle = try FileHandle(forWritingTo: file); defer { try? handle.close() }
        try handle.seekToEnd()
        let response = #"{"id":"response","sessionId":"session","type":"message","role":"assistant","content":[{"text":"done"}]}"#
        try handle.write(contentsOf: Data(response.utf8))
        XCTAssertTrue(WorkBuddySight.readIncremental(file, state: &state).isEmpty)
        try handle.write(contentsOf: Data("\n".utf8))
        let events = WorkBuddySight.readIncremental(file, state: &state)
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events.first?.turnId, "turn-one")
        XCTAssertEqual(events.first?.userIntent, "hello")
    }
    func testLargeBodiesUseBoundedReusableBlocks() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var hashes = Set<String>()
        let original: [String: Any] = ["body": String(repeating: "中文-", count: 200_000), "sequence": 1]
        let root = try AuditBlockProtocol.encode(original, directory: dir, hashes: &hashes)
        for hash in hashes {
            let data = try Data(contentsOf: dir.appendingPathComponent(hash))
            XCTAssertLessThanOrEqual(data.count, AuditBlockProtocol.blockBytes)
            XCTAssertEqual(AuditBlockProtocol.hash(data), hash)
        }
        var second = Set<String>()
        var changed = original; changed["sequence"] = 2
        let newRoot = try AuditBlockProtocol.encode(changed, directory: dir, hashes: &second)
        XCTAssertNotEqual(root, newRoot)
        XCTAssertGreaterThan(hashes.intersection(second).count, 0)
        XCTAssertLessThanOrEqual(second.subtracting(hashes).count, 2)
    }

    func testFailedTaskDoesNotBlockNextTaskAndQueueSurvivesRestart() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        var state = AuditUploadWorker.State()
        state.pending["s\u{0}bad"] = .init(sessionID: "s", turnID: "bad", generation: 1, notBefore: .distantPast, retries: 8, followups: 0, rejected: "HTTP 400")
        state.pending["s\u{0}good"] = .init(sessionID: "s", turnID: "good", generation: 1, notBefore: .distantPast, retries: 0, followups: 0)
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(state).write(to: dir.appendingPathComponent("queue-v2.json"))
        let config = AuditUploadClient.Configuration(endpoint: URL(string: "https://example.invalid/api/audit/ingest")!, deviceID: "test", token: "test", enabledAt: .distantPast, uploadEnabled: true)
        let worker = AuditUploadWorker(config: config, directory: dir)
        let selected = await worker.next()
        XCTAssertEqual(selected?.turnID, "good")
        await worker.fail("s\u{0}good", message: "network unavailable")
        let restarted = AuditUploadWorker(config: config, directory: dir)
        let next = await restarted.next()
        XCTAssertNil(next)
    }
}
