import CryptoKit
import Foundation
import XCTest
@testable import AgentReins

final class RealtimeCheckpointStorageTests: XCTestCase {
    private func root() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("checkpoint-storage-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory
    }
    private func event(_ output: String, id: UUID = UUID(), op: String = "result") -> GuardEvent {
        GuardEvent(id: id, kind: "tool", ruleId: "storage-fixture", path: "/tmp/checkpoint-fixture", command: #"{"cmd":"fixture-command","workdir":"/tmp"}"#,
                   agent: "codex", op: op, severity: "info", ts: Date(timeIntervalSince1970: 1_800_000_000.125), action: "completed",
                   sessionId: "storage-session", turnId: "storage-turn", toolCallId: id.uuidString,
                   userIntent: "原始需求必须完整保留\n保留状态与执行证据", modelResponse: output,
                   toolName: "CommandExecution", source: "storage-test", endedAt: Date(timeIntervalSince1970: 1_800_000_001.25))
    }
    private func stableData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
    private func object(_ url: URL) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }
    private func bodyURL(_ url: URL, index: Int = 0) throws -> URL {
        let bodies = try XCTUnwrap(try object(url)["bodies"] as? [[String: Any]])
        let digest = try XCTUnwrap(bodies[index]["sha256"] as? String)
        return RealtimeActiveCheckpoint.bodyDirectory(for: url).appendingPathComponent(digest + ".lzfse")
    }
    private func rewriteManifest(_ url: URL, change: (inout [String: Any]) -> Void) throws {
        var value = try object(url); change(&value)
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: url)
    }

    func testLargeCapturedOutputRoundTripsBeyondOldSixteenMiBLimit() throws {
        let url = try root().appendingPathComponent("active.json")
        let text = String(repeating: "stdout 原文 🕸️ \"\\\n", count: 48_000)
        let events = (0..<20).map { event("output-\($0)\n" + text + "\nEND-\($0)") }
        let original = RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: events, readTaskIDs: ["read-task"], coverageTruncated: true)
        XCTAssertGreaterThan(try stableData(original).count, RealtimeActiveCheckpoint.maximumBytes)
        try original.save(url)
        XCTAssertLessThan(try Data(contentsOf: url).count, RealtimeActiveCheckpoint.maximumBytes)
        XCTAssertEqual(try object(url)["version"] as? Int, 2)
        let restored = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(restored.version, 1)
        XCTAssertEqual(restored.savedAt, original.savedAt)
        XCTAssertEqual(restored.readTaskIDs, original.readTaskIDs)
        XCTAssertTrue(restored.coverageTruncated)
        XCTAssertEqual(try stableData(restored.events), try stableData(original.events))
        let manifestMode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber
        let bodyMode = try FileManager.default.attributesOfItem(atPath: bodyURL(url).path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(manifestMode?.intValue, 0o600)
        XCTAssertEqual(bodyMode?.intValue, 0o600)
    }

    func testIncrementalSaveReusesIdenticalBodiesAndDoesNotDeletePreviousSnapshotBodies() throws {
        let url = try root().appendingPathComponent("active.json")
        let first = event("first complete output")
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [first], readTaskIDs: []).save(url)
        let firstURL = try bodyURL(url)
        let previousAttributes = try FileManager.default.attributesOfItem(atPath: firstURL.path)
        let firstBytes = try Data(contentsOf: firstURL)
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [first, event("second complete output")], readTaskIDs: []).save(url)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: RealtimeActiveCheckpoint.bodyDirectory(for: url).path).count, 2)
        let currentAttributes = try FileManager.default.attributesOfItem(atPath: firstURL.path)
        XCTAssertEqual(previousAttributes[.systemFileNumber] as? NSNumber, currentAttributes[.systemFileNumber] as? NSNumber)
        XCTAssertEqual(previousAttributes[.modificationDate] as? Date, currentAttributes[.modificationDate] as? Date)
        XCTAssertEqual(try Data(contentsOf: firstURL), firstBytes)
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [], readTaskIDs: []).save(url)
        XCTAssertTrue(try XCTUnwrap(RealtimeActiveCheckpoint.load(url)).events.isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: firstURL.path), "An old manifest reader must retain its immutable body.")
    }

    func testMissingOrCorruptBodyNeverReturnsPartialRecoveredCheckpoint() throws {
        for corruption in ["missing", "bytes", "digest", "length", "encoding", "identity", "path"] {
            let url = try root().appendingPathComponent("active.json")
            try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [event("valid-original-output")], readTaskIDs: []).save(url)
            if corruption == "missing" {
                try FileManager.default.removeItem(at: bodyURL(url))
            } else if corruption == "bytes" {
                let target = try bodyURL(url)
                var bytes = try Data(contentsOf: target); bytes[bytes.startIndex] ^= 0xFF
                try bytes.write(to: target)
            } else {
                try rewriteManifest(url) { manifest in
                    var bodies = manifest["bodies"] as! [[String: Any]]
                    switch corruption {
                    case "digest": bodies[0]["compressedSHA256"] = String(repeating: "0", count: 64)
                    case "length": bodies[0]["bytes"] = (bodies[0]["bytes"] as! Int) + 1
                    case "encoding": bodies[0]["encoding"] = "unknown-codec"
                    case "identity": bodies[0]["eventID"] = UUID().uuidString
                    case "path": bodies[0]["sha256"] = "../../outside"
                    default: break
                    }
                    manifest["bodies"] = bodies
                }
            }
            XCTAssertThrowsError(try RealtimeActiveCheckpoint.load(url), corruption)
        }
    }

    func testBodyWriteFailurePreservesPreviousManifestAndRecovery() throws {
        let url = try root().appendingPathComponent("active.json")
        let first = event("already safely saved")
        try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [first], readTaskIDs: []).save(url)
        let oldManifest = try Data(contentsOf: url)
        let next = event("new body must fail before commit")
        let hash = SHA256.hash(data: try stableData(next)).map { String(format: "%02x", $0) }.joined()
        // A directory at the next immutable file destination creates a deterministic
        // write failure, without relying on chmod behavior when tests run as root.
        let collision = RealtimeActiveCheckpoint.bodyDirectory(for: url).appendingPathComponent(hash + ".lzfse")
        try FileManager.default.createDirectory(at: collision, withIntermediateDirectories: false)
        XCTAssertThrowsError(try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [first, next], readTaskIDs: []).save(url))
        XCTAssertEqual(try Data(contentsOf: url), oldManifest)
        XCTAssertEqual(try stableData(XCTUnwrap(RealtimeActiveCheckpoint.load(url)).events), try stableData([first]))
    }

    func testLegacyV1LoadsWithoutCoverageFlagAndMigratesLosslessly() throws {
        let url = try root().appendingPathComponent("active.json")
        let original = RealtimeActiveCheckpoint(version: 1, savedAt: Date(timeIntervalSince1970: 1_800_000_000), events: [event("legacy complete output")], readTaskIDs: ["read-task"])
        var legacy = try XCTUnwrap(JSONSerialization.jsonObject(with: stableData(original)) as? [String: Any])
        legacy.removeValue(forKey: "coverageTruncated")
        try JSONSerialization.data(withJSONObject: legacy).write(to: url)
        let loaded = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertFalse(loaded.coverageTruncated)
        XCTAssertEqual(try stableData(loaded.events), try stableData(original.events))
        try loaded.save(url)
        XCTAssertEqual(try object(url)["version"] as? Int, 2)
        XCTAssertEqual(try stableData(XCTUnwrap(RealtimeActiveCheckpoint.load(url))), try stableData(loaded))
    }

    func testUnsupportedManifestAndCheckpointVersionsAreRejected() throws {
        for field in ["version", "checkpointVersion"] {
            let url = try root().appendingPathComponent("active.json")
            try RealtimeActiveCheckpoint(version: 1, savedAt: Date(), events: [event("body")], readTaskIDs: []).save(url)
            try rewriteManifest(url) { $0[field] = 999 }
            XCTAssertThrowsError(try RealtimeActiveCheckpoint.load(url))
        }
    }

    func testWriterSerializesOnlyTheChangedRevisionAndPreservesAllFields() throws {
        let url = try root().appendingPathComponent("active.json")
        let writer = RealtimeActiveCheckpoint.Writer(url: url)
        let first = event("original first output"), second = event("original second output")
        var buffer = RealtimeLiveEvidenceBuffer()
        buffer.insert(first); buffer.insert(second)
        let initial = try writer.save(records: buffer.snapshot().records, readTaskIDs: [], coverageTruncated: false)
        XCTAssertEqual(initial.serializedEvents, 2)
        XCTAssertEqual(initial.reusedEvents, 0)
        let repeatSave = try writer.save(records: buffer.snapshot().records, readTaskIDs: ["read-task"], coverageTruncated: true)
        XCTAssertEqual(repeatSave.serializedEvents, 0)
        XCTAssertEqual(repeatSave.reusedEvents, 2)
        XCTAssertEqual(repeatSave.revalidatedBodies, 0)
        let updated = event("updated first output\n完整原文🙂", id: first.id)
        buffer.insert(updated)
        let changed = try writer.save(records: buffer.snapshot().records, readTaskIDs: ["read-task"], coverageTruncated: true)
        XCTAssertEqual(changed.serializedEvents, 1)
        XCTAssertEqual(changed.reusedEvents, 1)
        let restored = try XCTUnwrap(RealtimeActiveCheckpoint.load(url))
        XCTAssertEqual(restored.events.count, 2)
        XCTAssertEqual(try stableData(XCTUnwrap(restored.events.first { $0.id == first.id })), try stableData(updated))
        XCTAssertEqual(try stableData(XCTUnwrap(restored.events.first { $0.id == second.id })), try stableData(second))
        XCTAssertEqual(restored.readTaskIDs, ["read-task"])
        XCTAssertTrue(restored.coverageTruncated)
    }

    func testWriterReusesVerifiedBlobWithoutReadingUnchangedColdSourceAgain() throws {
        let url = try root().appendingPathComponent("active.json")
        let writer = RealtimeActiveCheckpoint.Writer(url: url)
        var buffer = RealtimeLiveEvidenceBuffer()
        buffer.insert(event("immutable cold output"))
        let plan = buffer.coolingPlan(byteBudget: 0)
        buffer.install(try plan.records.map { try $0.cooled(in: plan.directory) })
        let snapshot = buffer.snapshot()
        try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
        // Recovery now owns a verified immutable copy. Removing the separate
        // working-set body proves a repeated save does not re-read that source.
        try FileManager.default.removeItem(at: plan.directory.url)
        XCTAssertThrowsError(try snapshot.read())
        let metrics = try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
        XCTAssertEqual(metrics.serializedEvents, 0)
        XCTAssertEqual(metrics.reusedEvents, 1)
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events.first?.modelResponse, "immutable cold output")
    }

    func testWriterRejectsMissingOrCorruptCachedBlobWithoutReplacingManifest() throws {
        for damage in ["missing", "same-length-corruption"] {
            let url = try root().appendingPathComponent("active.json")
            let writer = RealtimeActiveCheckpoint.Writer(url: url)
            var buffer = RealtimeLiveEvidenceBuffer()
            buffer.insert(event("verified output"))
            let snapshot = buffer.snapshot()
            try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
            let manifest = try Data(contentsOf: url), target = try bodyURL(url)
            if damage == "missing" {
                try FileManager.default.removeItem(at: target)
            } else {
                let priorAttributes = try FileManager.default.attributesOfItem(atPath: target.path)
                var bytes = try Data(contentsOf: target); bytes[bytes.startIndex] ^= 0xFF
                try bytes.write(to: target, options: [.atomic])
                // Even a restored mtime cannot conceal replacement or ctime.
                if let date = priorAttributes[.modificationDate] {
                    try FileManager.default.setAttributes([.modificationDate: date], ofItemAtPath: target.path)
                }
            }
            XCTAssertThrowsError(try writer.save(records: snapshot.records, readTaskIDs: ["new-read-state"], coverageTruncated: false), damage)
            XCTAssertEqual(try Data(contentsOf: url), manifest)
        }
    }

    func testWriterRevalidatesAnUnchangedBlobWhenFileMetadataChanges() throws {
        let url = try root().appendingPathComponent("active.json")
        let writer = RealtimeActiveCheckpoint.Writer(url: url)
        var buffer = RealtimeLiveEvidenceBuffer()
        buffer.insert(event("still valid output"))
        let snapshot = buffer.snapshot()
        try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1_234)], ofItemAtPath: bodyURL(url).path)
        let first = try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
        XCTAssertEqual(first.serializedEvents, 0)
        XCTAssertEqual(first.revalidatedBodies, 1)
        let second = try writer.save(records: snapshot.records, readTaskIDs: [], coverageTruncated: false)
        XCTAssertEqual(second.revalidatedBodies, 0)
        XCTAssertEqual(try RealtimeActiveCheckpoint.load(url)?.events.first?.modelResponse, "still valid output")
    }
}
