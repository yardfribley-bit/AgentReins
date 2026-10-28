import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// tools/socket-sampler output, checked with the same rules as socket_sampler.verify_snapshot.
public enum SocketLedgerCore {
    public static let fields = ["id", "agent", "pid", "ppid", "processName", "processPath", "processStartAt", "protocol",
        "localAddress", "remoteAddress", "remoteIP", "remotePort", "state", "firstSeen", "lastSeen",
        "sampleCount", "scope", "viaProxy", "transportPeer", "realDestination", "realDestinationPort",
        "destinationSource", "destinationEvidence", "destinationBasis", "forwardConfirmed", "transportCall",
        "proxy", "evidence"]
    public static let sideFields = ["schema", "seq", "prevHash", "fileSha256", "at"]

    public static func sibling(_ u: URL, _ suffix: String) -> URL {
        u.deletingLastPathComponent().appendingPathComponent(u.lastPathComponent + suffix)
    }

    /// Must match socket_sampler.default_seal_path / evidence.socket_ledger_seal_path.
    public static func sealPath(ledger: URL, defaultLedger: URL, integrityDir: URL) -> URL {
        if ledger.resolvingSymlinksInPath().path == defaultLedger.resolvingSymlinksInPath().path {
            return integrityDir.appendingPathComponent("seals").appendingPathComponent("socket-ledger.seal")
        }
        return sibling(ledger, ".seal")
    }

    public static func truthy(_ v: Any?) -> Bool {
        guard let v, !(v is NSNull) else { return false }
        if let b = v as? Bool { return b }
        if let i = v as? Int { return i != 0 }
        if let s = v as? String { return !s.isEmpty }
        return true
    }

    public static func verify(_ data: Data?, _ side: Any?, _ seal: Any?, _ key: Data?, _ crypto: CryptoBox) -> [String: Any] {
        func bad(_ reason: String, _ extra: [String: Any] = [:]) -> [String: Any] {
            var out: [String: Any] = ["state": "tampered", "ok": false, "reason": reason, "confidence": "Unknown"]
            for (k, v) in extra { out[k] = v }
            return out
        }
        let sealD = seal as? [String: Any]
        let sealed = sealD != nil && !truthy(sealD?["unsigned"])
        guard let data else {
            if sealed { return bad("ledger_deleted_after_signed", ["sealSeq": nn(sealD?["seq"])]) }
            return ["state": "missing", "ok": NSNull(), "confidence": "Unknown", "reason": "no ledger"]
        }
        guard let s = side as? [String: Any] else {
            if sealed { return bad("ledger_mac_missing_after_signed", ["sealSeq": nn(sealD?["seq"])]) }
            return ["state": "unsigned", "ok": NSNull(), "confidence": "Unknown",
                    "reason": "no .mac sidecar (sampler older than tamper evidence, or never signed)"]
        }
        if truthy(s["unsigned"]) {
            if sealed { return bad("unsigned_snapshot_after_signed", ["sealSeq": nn(sealD?["seq"])]) }
            let reason = str(s["reason"]).flatMap { $0.isEmpty ? nil : $0 } ?? "integrity key unavailable to the sampler"
            return ["state": "unsigned", "ok": NSNull(), "confidence": "Unknown", "reason": reason]
        }
        guard let key else {
            return ["state": "unverifiable", "ok": NSNull(), "confidence": "Unknown",
                    "reason": "integrity key not available to this reader", "seq": nn(s["seq"])]
        }
        var body: [String: Any] = [:]
        for k in sideFields { if let v = s[k] { body[k] = v } }
        if !constantTimeEqual(str(s["mac"]) ?? "", crypto.entryMac(body, key)) {
            return bad("ledger_mac_mismatch", ["seq": nn(s["seq"])])
        }
        if str(s["fileSha256"]) != crypto.shaHex(data: data) { return bad("ledger_content_modified", ["seq": nn(s["seq"])]) }
        var withMac = body
        withMac["mac"] = nn(s["mac"])
        if str(s["hash"]) != crypto.shaHex(JSON.string(withMac)) {
            return bad("ledger_sidecar_hash_mismatch", ["seq": nn(s["seq"])])
        }
        let seq = intValue(s["seq"]) ?? 0
        if sealed, let sealD {
            var sb: [String: Any] = [:]
            for k in sideFields { if let v = sealD[k] { sb[k] = v } }
            if !constantTimeEqual(str(sealD["mac"]) ?? "", crypto.entryMac(sb, key)) {
                return bad("ledger_seal_mac_mismatch", ["seq": seq])
            }
            let sseq = intValue(sealD["seq"]) ?? 0
            if sseq > seq { return bad("ledger_rolled_back", ["seq": seq, "sealSeq": sseq]) }
            if sseq == seq && str(sealD["hash"]) != str(s["hash"]) {
                return bad("ledger_seal_mismatch", ["seq": seq, "sealSeq": sseq])
            }
            // A crash between writing the sidecar and the seal leaves the seal exactly one behind.
            if sseq < seq && !(sseq == seq - 1 && str(s["prevHash"]) == str(sealD["hash"])) {
                return bad("ledger_seal_behind", ["seq": seq, "sealSeq": sseq])
            }
        } else if seq > 1 {
            return bad("ledger_seal_missing", ["seq": seq])
        }
        return ["state": "verified", "ok": true, "confidence": "Observed", "seq": seq, "signedAt": nn(s["at"]),
                "reason": "HMAC over the exact ledger bytes verified; sequence matches the external seal"]
    }

    public static func number(_ v: Any?) -> Double? {
        if v is String || v is NSNull { return nil }
        if let d = v as? Double { return d }
        if let i = v as? Int { return Double(i) }
        return nil
    }

    /// 'sampling' only while samples keep arriving; otherwise 'stopped' with how long ago.
    public static func freshness(_ samples: [String: Any], _ coverage: [String: Any], now: Double) -> [String: Any] {
        let cadence = ["successGapSecondsP95", "configuredIntervalSeconds", "intervalSeconds"].compactMap { number(coverage[$0]) }
        let limit = max(10.0, 3 * (cadence.max() ?? 3.0))
        guard let last = Clock.parse(samples["lastAt"]) else {
            return ["state": "stopped", "staleSeconds": NSNull(), "staleAfterSeconds": limit]
        }
        let age = now - last
        return ["state": age <= limit ? "sampling" : "stopped", "staleSeconds": round1(age),
                "staleAfterSeconds": round1(limit)]
    }

    /// Ledger + sidecar + seal under a shared flock, only if the sampler's lock file already exists
    /// (the read-only MCP never creates files there).
    public static func readLocked(_ ledger: URL, seal: URL) -> (Data?, Any?, Any?) {
        let lock = sibling(ledger, ".lock")
        var fd: Int32 = -1
        if FileManager.default.fileExists(atPath: lock.path) {
            fd = open(lock.path, O_RDONLY)
            if fd >= 0 { _ = flock(fd, LOCK_SH) }
        }
        defer { if fd >= 0 { close(fd) } }
        let data = try? Data(contentsOf: ledger)
        let side = JSON.parse(try? Data(contentsOf: sibling(ledger, ".mac")))
        let sealObj = JSON.parse(try? Data(contentsOf: seal))
        return (data, side, sealObj)
    }

    public static func load(ledger: URL, seal: URL, key: Data?, crypto: CryptoBox, agent: String?, since: String?,
                     until: String? = nil, limit: Int = 200, now: Double = Date().timeIntervalSince1970) -> [String: Any] {
        let (raw, side, sealObj) = readLocked(ledger, seal: seal)
        let integrity = verify(raw, side, sealObj, key, crypto)
        let tampered = str(integrity["state"]) == "tampered"
        guard let root = JSON.parse(raw) as? [String: Any] else {
            let state = tampered ? "tampered" : "not_running"
            return ["connections": [[String: Any]](), "total": 0, "coverage": [
                "state": state, "confidence": "Unknown", "integrity": integrity,
                "note": state == "not_running"
                    ? "未找到按进程采样的连接记录（socket-sampler 未运行）；未走代理的流量不可见。"
                    : "台账已签过名但现在不见了：按篡改处理，未走代理的流量不可见。",
            ] as [String: Any]]
        }
        let sinceTs = Clock.parse(since)
        let untilTs = Clock.parse(until)
        var rows: [[String: Any]] = []
        for case let row as [String: Any] in (root["connections"] as? [Any] ?? []) {
            if let agent, agent != "all", str(row["agent"]) != agent { continue }
            if let sinceTs, (Clock.parse(row["lastSeen"]) ?? 0) < sinceTs { continue }
            if let untilTs, (Clock.parse(row["lastSeen"]) ?? 0) > untilTs { continue }
            var out: [String: Any] = [:]
            for k in fields { if let v = row[k] { out[k] = v } }
            if tampered {
                // Content no longer matches its signature: nothing in it can be called observed.
                out["evidence"] = "Unknown"
                out["destinationEvidence"] = "Unknown"
                out["ledgerIntegrity"] = "tampered"
            }
            rows.append(out)
        }
        rows.sort { (str($0["lastSeen"]) ?? "") > (str($1["lastSeen"]) ?? "") }
        var coverage = root["coverage"] as? [String: Any] ?? [:]
        let samples = root["samples"] as? [String: Any] ?? [:]
        let fresh = freshness(samples, coverage, now: now)
        var integ = integrity
        integ["integritySince"] = nn(root["integritySince"])
        integ["events"] = root["integrityEvents"] as? [Any] ?? []
        coverage["samples"] = nn(samples["count"])
        coverage["lastSampleAt"] = nn(samples["lastAt"])
        coverage["failures"] = samples["failures"] ?? 0
        coverage["lastFailure"] = nn(samples["lastFailure"])
        coverage["lastFailureAt"] = nn(samples["lastFailureAt"])
        coverage["failureLog"] = Array((samples["failureLog"] as? [Any] ?? []).suffix(20))
        coverage["samplerStartedAt"] = nn(samples["samplerStartedAt"])
        coverage["integrity"] = integ
        for (k, v) in fresh { coverage[k] = v }
        if tampered { coverage["state"] = "tampered" }
        if tampered || str(fresh["state"]) != "sampling" || str(integrity["state"]) != "verified" {
            coverage["confidence"] = "Unknown"
        }
        if coverage["missesShorterThanSeconds"] != nil && isNull(coverage["measurementConfidence"]) {
            // Ledger written by socket-sampler/1: its value was the configured interval, not a measurement.
            coverage["measurementConfidence"] = "Unknown"
            coverage["measurementNote"] = "采样器版本过旧：该值是配置间隔，不是实测周期"
        }
        return ["connections": Redact.any(Array(rows.prefix(limit))), "total": rows.count, "coverage": coverage]
    }

    /// What the app's 首页 / 外网访问 pages get: the same verified, freshness-aware `load` the MCP answers with,
    /// plus whether the integrity key could be read, so the page can say key_unavailable / needs approval
    /// instead of pretending the ledger is signed. `keychainStatus` is only asked when the key is unavailable.
    public static func page(integrity: Integrity, keychainStatus: () -> String, ledger: URL, seal: URL,
                            limit: Int = 300, now: Double = Date().timeIntervalSince1970) -> [String: Any] {
        var keyInfo: [String: Any]
        var key: Data?
        do {
            key = try integrity.loadKey(create: false)
            keyInfo = ["state": "ok"]
        } catch let error as KeyUnavailable {
            keyInfo = ["state": "key_unavailable", "reason": error.reason, "helper": keychainStatus(),
                       "lastError": nn(integrity.keychain.lastError)]
        } catch {
            keyInfo = ["state": "key_unavailable", "reason": "\(error)", "helper": keychainStatus(),
                       "lastError": nn(integrity.keychain.lastError)]
        }
        var out = load(ledger: ledger, seal: seal, key: key, crypto: integrity.crypto, agent: nil, since: nil,
                       limit: limit, now: now)
        out["keychain"] = keyInfo
        return out
    }
}
