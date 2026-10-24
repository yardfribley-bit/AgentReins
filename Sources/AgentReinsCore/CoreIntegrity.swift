import Foundation

// Audit chain, seal, run inventory, evidence MACs and the legacy/current split (evidence.py port).

public final class Integrity {
    public static let accountHmac = "hmac-key"
    public static let accountEra = "signed-era"
    public static let accountBoundary = "integrity-boundary"
    public static let boundaryTool = "integrity-boundary"
    public static let boundaryActor = "agentreins-integrity"
    public static let legacyReason = "signed with deleted pre-migration key"
    public static let limitation = "HMAC 密钥与安装锚点经 Security.framework（AgentReinsKeychainHelper）写入 Keychain，"
        + "访问控制只信任 helper 程序本身；同一用户的其他进程可以直接运行 helper 取得密钥并伪造签名（b6）。"
        + "没有 root 守护进程或远端锚点。"
    public static let entryFields = ["at", "actor", "tool", "argsDigest", "prevHash"]

    public let auditDir: URL
    public let integrityDir: URL
    public let transport: URL
    public let keychain: KeychainStore
    public let crypto: CryptoBox
    public let now: () -> Date
    public let fm = FileManager.default

    public init(auditDir: URL, integrityDir: URL, transport: URL, keychain: KeychainStore, crypto: CryptoBox,
         now: @escaping () -> Date = { Date() }) {
        self.auditDir = auditDir
        self.integrityDir = integrityDir
        self.transport = transport
        self.keychain = keychain
        self.crypto = crypto
        self.now = now
    }

    public var auditLog: URL { auditDir.appendingPathComponent("mcp-supervisor-audit.jsonl") }
    public var auditSeal: URL { auditDir.appendingPathComponent("mcp-supervisor-audit.seal") }
    public var hmacKeyFile: URL { auditDir.appendingPathComponent("mcp-supervisor-hmac.key") }
    public var runInventory: URL { auditDir.appendingPathComponent("transport-run-inventory.jsonl") }
    public var sealDir: URL { integrityDir.appendingPathComponent("seals") }
    public var sealMirror: URL { sealDir.appendingPathComponent("mcp-supervisor-audit.seal") }
    public var signedEraFlag: URL { integrityDir.appendingPathComponent("signed-era") }
    public var runInventoryMac: URL { integrityDir.appendingPathComponent("transport-run-inventory.mac") }
    public var boundaryMirror: URL { integrityDir.appendingPathComponent("integrity-boundary.json") }
    public var legacyManifest: URL { integrityDir.appendingPathComponent("legacy-evidence-manifest.json") }

    public func exists(_ u: URL) -> Bool { fm.fileExists(atPath: u.path) }
    public func isDir(_ u: URL) -> Bool {
        var d: ObjCBool = false
        return fm.fileExists(atPath: u.path, isDirectory: &d) && d.boolValue
    }
    public func read(_ u: URL) -> Data? { try? Data(contentsOf: u) }
    public func readText(_ u: URL) -> String? { read(u).map { String(decoding: $0, as: UTF8.self) } }

    public func writePrivate(_ u: URL, _ text: String) {
        try? text.write(to: u, atomically: true, encoding: .utf8)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path)
    }

    public func ensureDirs() {
        for d in [auditDir, integrityDir] {
            try? fm.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }

    // MARK: key

    /// evidence.py load_or_create_hmac_key. A Keychain *error* never mints a replacement key, and there is
    /// no file-key fallback here: that fallback is what used to sign entries with throwaway keys.
    public func loadKey(create: Bool = true) throws -> Data {
        let (status, existing) = keychain.lookup(Self.accountHmac)
        if status == "found", let existing, existing.count >= 16 {
            try? fm.removeItem(at: hmacKeyFile)
            return existing
        }
        if status == "error" {
            throw KeyUnavailable(reason: "keychain read failed (\(keychain.lastError ?? "unknown")); "
                + "not creating a replacement integrity key")
        }
        if status == "no_helper" { throw KeyUnavailable(reason: "AgentReinsKeychainHelper not found next to AgentReinsMCP") }
        if let raw = read(hmacKeyFile), raw.count >= 16,
           !["keychain", "keychain\n"].contains(String(decoding: raw, as: UTF8.self)) {
            // One-time migration of an old file key into the Keychain (same rule as Python).
            if status == "missing" && keychain.set(Self.accountHmac, raw) { try? fm.removeItem(at: hmacKeyFile) }
            return raw
        }
        guard create else { throw KeyUnavailable(reason: "no integrity key yet") }
        let key = crypto.random(32)
        guard keychain.set(Self.accountHmac, key) else {
            throw KeyUnavailable(reason: "could not store a new integrity key in the Keychain ("
                + "\(keychain.lastError ?? "helper set failed"))")
        }
        return key
    }

    public func fingerprint(_ key: Data) -> String { String(crypto.shaHex(data: key).prefix(32)) }

    // MARK: audit lines

    public func lines(_ log: URL? = nil) -> [String] {
        guard let text = readText(log ?? auditLog) else { return [] }
        return text.components(separatedBy: CharacterSet.newlines)
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    public func prefixSha(_ lines: [String], _ count: Int) -> String {
        crypto.shaHex(lines.prefix(count).joined(separator: "\n"))
    }

    public func entryVerifies(_ line: String, _ key: Data) -> Bool {
        guard let e = JSON.object(line), e["mac"] != nil else { return false }
        var body: [String: Any] = [:]
        for k in Self.entryFields { if let v = e[k] { body[k] = v } }
        return constantTimeEqual(str(e["mac"]) ?? "", crypto.entryMac(body, key))
    }

    public func entryAt(_ line: String) -> String { str(JSON.object(line)?["at"]) ?? "" }

    public func hasBoundaryEntry(_ lines: [String]) -> Bool {
        lines.contains { l in
            guard let e = JSON.object(l) else { return false }
            return str(e["tool"]) == Self.boundaryTool && str(e["actor"]) == Self.boundaryActor
        }
    }

    // MARK: era / boundary

    public func eraAt() -> String? {
        let (s, d) = keychain.lookup(Self.accountEra)
        let blob = s == "found" ? d : read(signedEraFlag)
        guard let blob, let o = JSON.parse(blob) as? [String: Any] else { return nil }
        return str(o["at"])
    }

    public func keychainHasAnchor() -> Bool {
        keychain.lookup(Self.accountEra).0 == "found" || keychain.lookup(Self.accountBoundary).0 == "found"
    }

    public func signedEraActive() -> Bool {
        keychainHasAnchor() || exists(boundaryMirror) || exists(signedEraFlag) || exists(sealMirror)
    }

    public func eraKeyMismatch(_ key: Data) -> Bool {
        let fp = fingerprint(key)
        let (s, d) = keychain.lookup(Self.accountEra)
        if s == "found", let d, let o = JSON.parse(d) as? [String: Any], let stored = str(o["keyFingerprint"]),
           !stored.isEmpty, stored != fp { return true }
        if let o = JSON.objectAt(signedEraFlag), let stored = str(o["keyFingerprint"]), !stored.isEmpty, stored != fp {
            return true
        }
        return false
    }

    public func loadBoundary(_ key: Data) -> ([String: Any]?, String?) {
        let (s, blob) = keychain.lookup(Self.accountBoundary)
        guard s == "found", let blob else { return (nil, nil) }
        guard let marker = JSON.parse(blob) as? [String: Any] else { return (nil, "boundary_marker_unreadable") }
        var body = marker
        body.removeValue(forKey: "mac")
        if !constantTimeEqual(str(marker["mac"]) ?? "", crypto.entryMac(body, key)) {
            return (nil, "boundary_marker_mac_mismatch")
        }
        return (marker, nil)
    }

    public func evidenceFiles() -> [URL] {
        guard let dirs = try? fm.contentsOfDirectory(at: transport, includingPropertiesForKeys: nil,
                                                       options: [.skipsHiddenFiles]) else { return [] }
        var out: [URL] = []
        for d in dirs.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            for name in ["manifest.json", "transport.json"] {
                let u = d.appendingPathComponent(name)
                if exists(u) && !isDir(u) { out.append(u) }
            }
        }
        return out
    }

    public func macFile(_ u: URL) -> URL { u.deletingLastPathComponent().appendingPathComponent(u.lastPathComponent + ".mac") }
    public func rel(_ u: URL) -> String { u.deletingLastPathComponent().lastPathComponent + "/" + u.lastPathComponent }
    public func mtime(_ u: URL) -> Double? {
        ((try? fm.attributesOfItem(atPath: u.path))?[.modificationDate] as? Date)?.timeIntervalSince1970
    }

    /// evidence.py establish_boundary: recorded exactly once, never re-established after deletion.
    @discardableResult
    public func establishBoundary(_ key: Data, fresh: Bool) -> [String: Any]? {
        if keychain.lookup(Self.accountBoundary).0 == "found" { return nil }
        let lines = self.lines()
        if hasBoundaryEntry(lines) { return nil }
        let nowTs = now().timeIntervalSince1970
        let nowIso = Clock.iso(Date(timeIntervalSince1970: nowTs))
        let era = eraAt()
        var index: Int, source: String, cutoff: String
        if fresh || lines.isEmpty {
            index = fresh ? 0 : lines.count
            source = fresh ? "recorded-at-signed-era-start" : "recorded-going-forward"
            cutoff = nowIso
        } else {
            let firstOk = lines.firstIndex { entryVerifies($0, key) } ?? lines.count
            let byTime = lines.firstIndex { l in era.map { entryAt(l) >= $0 } ?? false } ?? lines.count
            index = min(firstOk, byTime)
            for i in 0..<index where i + 1 < lines.count && entryAt(lines[i]) > entryAt(lines[i + 1]) {
                index = i + 1
                break
            }
            source = "upgrade-inferred"
            cutoff = era ?? (firstOk < lines.count ? entryAt(lines[firstOk]) : nowIso)
        }
        if fresh && !lines.isEmpty {
            index = lines.count
            source = "recorded-at-signed-era-start"
        }
        let legacyAudit = lines.prefix(index).filter { !entryVerifies($0, key) }
        var legacyFiles: [[String: Any]] = []
        let cutoffTs = Clock.parse(cutoff) ?? nowTs
        for path in evidenceFiles() {
            let mac = macFile(path)
            guard exists(mac), let data = read(path), let macData = read(mac), let mt = mtime(path) else { continue }
            let stored = String(decoding: macData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            if !constantTimeEqual(stored, crypto.hmacHex(key, data: data)) && mt < cutoffTs {
                legacyFiles.append(["path": rel(path), "sha256": crypto.shaHex(data: data),
                                    "macSha256": crypto.shaHex(data: macData),
                                    "mtime": Clock.iso(Date(timeIntervalSince1970: mt))])
            }
        }
        let manifestText = JSON.string(["schema": 1, "files": legacyFiles] as [String: Any]) + "\n"
        let times = (legacyAudit.map { entryAt($0) }.filter { !$0.isEmpty }
            + legacyFiles.compactMap { $0["mtime"] as? String }).sorted()
        var marker: [String: Any] = [
            "schema": 1, "establishedAt": nowIso, "source": source, "eraAt": nn(era), "cutoff": cutoff,
            "keyFingerprint": fingerprint(key), "auditBoundaryIndex": index,
            "auditPrefixSha256": prefixSha(lines, index), "legacyAuditCount": legacyAudit.count,
            "legacyEvidenceCount": legacyFiles.count, "legacyManifestSha256": crypto.shaHex(manifestText),
            "legacyFrom": nn(times.first), "legacyTo": nn(times.last),
        ]
        marker["mac"] = crypto.entryMac(marker, key)
        let blob = JSON.string(marker)
        // Without the Keychain anchor the boundary could be deleted unnoticed: record nothing weaker.
        guard keychain.set(Self.accountBoundary, Data(blob.utf8)) else { return nil }
        ensureDirs()
        writePrivate(legacyManifest, manifestText)
        writePrivate(boundaryMirror, blob + "\n")
        append(actor: Self.boundaryActor, tool: Self.boundaryTool,
               arguments: ["auditBoundaryIndex": index, "markerSha256": crypto.shaHex(blob)], key: key)
        return marker
    }

    /// evidence.py mark_signed_era (an existing era fingerprint is never overwritten: B12).
    public func markSignedEra(_ key: Data) {
        let (s, existing) = keychain.lookup(Self.accountEra)
        if s == "found", let existing, let prev = JSON.parse(existing) as? [String: Any],
           let fp = str(prev["keyFingerprint"]), !fp.isEmpty {
            ensureDirs()
            if !exists(signedEraFlag) { writePrivate(signedEraFlag, String(decoding: existing, as: UTF8.self) + "\n") }
            if fp == fingerprint(key) { establishBoundary(key, fresh: false) }
            return
        }
        // Python json.dumps(sort_keys=True) with default separators.
        let payload = "{\"at\": \"\(Clock.iso(now()))\", \"keyFingerprint\": \"\(fingerprint(key))\", \"schema\": 2}"
        _ = keychain.set(Self.accountEra, Data(payload.utf8))
        ensureDirs()
        writePrivate(signedEraFlag, payload + "\n")
        establishBoundary(key, fresh: true)
    }
}
