import CryptoKit
import Foundation
import XCTest
@testable import AgentReins

final class CapturedNetworkArchiveTests: XCTestCase {
    func testCommandArchiveSurvivesTheLiveDirectory() throws {
        let live = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let archive = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: live); try? FileManager.default.removeItem(at: archive) }
        let folder = live.appendingPathComponent("run-1")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let item: [String: Any] = ["invocation": ["agent": "Cursor", "captureMode": "agent-path", "tool": "gh", "args": ["pr", "list"], "startedAt": "2026-10-17T10:00:00Z"]]
        try JSONSerialization.data(withJSONObject: item).write(to: folder.appendingPathComponent("transport.json"))
        let first = CapturedNetworkArchive.commandRecords(liveRoot: live, archiveRoot: archive)
        XCTAssertEqual(first.first?["runID"] as? String, "run-1")
        try FileManager.default.removeItem(at: live)
        let second = CapturedNetworkArchive.commandRecords(liveRoot: live, archiveRoot: archive)
        XCTAssertEqual(second.first?["runID"] as? String, "run-1")
        XCTAssertEqual(second.first?["tool"] as? String, "gh")
    }

    func testHTTPSTailIncludesEarlierCapturesAndSkipsTelemetry() throws {
        let log = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".jsonl")
        defer { try? FileManager.default.removeItem(at: log) }
        let body = Data("{}".utf8)
        let response = Data("baidu".utf8)
        let visit = WorkBuddyNetworkCaptureRecord(
            observedAt: Date(timeIntervalSince1970: 1_700_000_000), host: "news.baidu.com", path: "/", method: "GET",
            httpVersion: "HTTP/2", contentEncoding: nil, declaredContentLength: body.count, capturedWireBodyBytes: body.count,
            requestBodyBase64: body.base64EncodedString(), requestSHA256: sha256(body), responseStatus: 200,
            responseComplete: true, responseBodyBase64: response.base64EncodedString(), remoteHost: "39.156.68.124",
            remotePort: 443, flowID: "old-baidu", requestComplete: true, responseSHA256: sha256(response), accessHop: "local-target")
        let noise = WorkBuddyNetworkCaptureRecord(
            observedAt: Date(), host: "galileotelemetry.tencent.com", path: "/collect", method: "POST",
            httpVersion: "HTTP/2", contentEncoding: nil, declaredContentLength: body.count, capturedWireBodyBytes: body.count,
            requestBodyBase64: body.base64EncodedString(), requestSHA256: sha256(body), responseStatus: 200,
            responseComplete: true, responseBodyBase64: response.base64EncodedString(), flowID: "telemetry",
            requestComplete: true, responseSHA256: sha256(response), accessHop: "local-target")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let text = try [visit, noise].map { try encoder.encode($0) }.map { String(decoding: $0, as: UTF8.self) }.joined(separator: "\n") + "\n"
        try Data(text.utf8).write(to: log)
        let rows = CapturedNetworkArchive.httpsRecords(jsonl: log)
        XCTAssertTrue(rows.contains { ($0["resource"] as? [String: Any])?["domain"] as? String == "news.baidu.com" })
        XCTAssertFalse(rows.contains { ($0["resource"] as? [String: Any])?["domain"] as? String == "galileotelemetry.tencent.com" })
    }

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
