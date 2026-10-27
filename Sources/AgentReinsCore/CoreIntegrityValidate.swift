import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// `Darwin.flock` is the `struct flock` initializer (fcntl), not `flock(2)`.
/// The syscall symbol is still `flock`.
@_silgen_name("flock")
private func agentreins_flock(_ fd: Int32, _ operation: Int32) -> Int32

/// Cross-process lock for the audit chain. `flock` is per-process on Darwin and Linux, so a
/// re-entrant append (seal → boundary → append) must not unlock early, and two threads in one
/// process need a recursive mutex as well. HTTP serializes tools/call; this lock covers a
/// concurrent stdio MCP writing the same chain.
private final class AuditAppendLock {
    static let shared = AuditAppendLock()
    private let gate = NSRecursiveLock()
    private var depth = 0
    private var fd: Int32 = -1

    func withLock(_ path: String, _ body: () -> Void) {
        gate.lock()
        defer { gate.unlock() }
        if depth == 0 {
            fd = AuditFileLock.openLocked(path)
            AuditFileLock.lock(fd)
        }
        depth += 1
        defer {
            depth -= 1
            if depth == 0 {
                AuditFileLock.unlock(fd)
                AuditFileLock.close(fd)
                fd = -1
            }
        }
        body()
    }
}

private enum AuditFileLock {
    static func openLocked(_ path: String) -> Int32 {
        path.withCString { cstr in
            #if canImport(Darwin)
            Darwin.open(cstr, Darwin.O_RDWR | Darwin.O_CREAT | Darwin.O_CLOEXEC, mode_t(0o600))
            #elseif canImport(Glibc)
            Glibc.open(cstr, Glibc.O_RDWR | Glibc.O_CREAT | Glibc.O_CLOEXEC, mode_t(0o600))
            #else
            -1
            #endif
        }
    }

    static func lock(_ fd: Int32) {
        guard fd >= 0 else { return }
        _ = agentreins_flock(fd, 2) // LOCK_EX
    }

    static func unlock(_ fd: Int32) {
        guard fd >= 0 else { return }
        _ = agentreins_flock(fd, 8) // LOCK_UN
    }

    static func close(_ fd: Int32) {
        guard fd >= 0 else { return }
        #if canImport(Darwin)
        _ = Darwin.close(fd)
        #elseif canImport(Glibc)
        _ = Glibc.close(fd)
        #endif
    }
}

extension Integrity {
    // MARK: run inventory

    public func validateRunInventory(_ key: Data) -> [String: Any] {
        var tampered: [[String: Any]] = []
        if exists(runInventoryMac) {
            guard let inv = read(runInventory) else {
                return ["ok": false, "tampered": [["reason": "inventory_missing_after_signed"]]]
            }
            let expected = readText(runInventoryMac)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !constantTimeEqual(expected, crypto.hmacHex(key, data: inv)) {
                tampered.append(["reason": "inventory_mac_mismatch"])
            }
        } else if exists(runInventory) && signedEraActive() {
            tampered.append(["reason": "inventory_mac_missing_after_signed_era"])
        }
        return ["ok": tampered.isEmpty, "tampered": tampered]
    }

    public func knownRunIds() -> Set<String> {
        var out = Set<String>()
        for l in lines(runInventory) {
            if let id = str(JSON.object(l)?["runID"]), !id.isEmpty { out.insert(id) }
        }
        return out
    }

    /// The seal anchors the inventory hash only while the inventory still verifies; otherwise the previously
    /// sealed anchor is kept, so an edit is never re-sealed by the next MCP read.
    public func inventoryAnchor(_ key: Data) -> String? {
        guard let inv = read(runInventory) else { return nil }
        if !exists(runInventoryMac) || (validateRunInventory(key)["ok"] as? Bool) == true { return crypto.shaHex(data: inv) }
        for s in [auditSeal, sealMirror] {
            if let prev = str(JSON.objectAt(s)?["inventorySha256"]), !prev.isEmpty { return prev }
        }
        return nil
    }

    // MARK: append (MCP read audit)

    public func append(actor: String, tool: String, arguments: [String: Any], key: Data) {
        AuditAppendLock.shared.withLock(auditLog.path) {
            self.appendLocked(actor: actor, tool: tool, arguments: arguments, key: key)
        }
    }

    private func appendLocked(actor: String, tool: String, arguments: [String: Any], key: Data) {
        ensureDirs()
        let existing = lines()
        var prev = String(repeating: "0", count: 64)
        if let last = existing.last, let h = str(JSON.object(last)?["hash"]), !h.isEmpty { prev = h }
        var entry: [String: Any] = [
            "at": Clock.iso(now()), "actor": actor, "tool": tool,
            "argsDigest": String(crypto.shaHex(JSON.string(arguments)).prefix(24)), "prevHash": prev,
        ]
        entry["mac"] = crypto.entryMac(entry, key)
        entry["hash"] = crypto.shaHex(JSON.string(entry) + prev)
        let line = JSON.string(entry) + "\n"
        if let h = try? FileHandle(forWritingTo: auditLog) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            h.write(Data(line.utf8))
        } else {
            writePrivate(auditLog, line)
        }
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: auditLog.path)
        writeSeal(head: str(entry["hash"]) ?? prev, count: existing.count + 1, key: key)
    }

    /// Primary seal + mirror outside the audit dir (B9/B10), same body as Python _write_seal.
    public func writeSeal(head: String, count: Int, key: Data) {
        var body: [String: Any] = ["headHash": head, "count": count, "schema": 1]
        if let anchor = inventoryAnchor(key) { body["inventorySha256"] = anchor }
        body["mac"] = crypto.entryMac(body, key)
        let text = JSON.string(body) + "\n"
        writePrivate(auditSeal, text)
        ensureDirs()
        try? fm.createDirectory(at: sealDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        writePrivate(sealMirror, text)
        markSignedEra(key)
    }

    // MARK: evidence files

    public func loadLegacyManifest(_ marker: [String: Any]?) -> ([String: String], String?) {
        guard let marker, (intValue(marker["legacyEvidenceCount"]) ?? 0) > 0 else { return ([:], nil) }
        guard let text = readText(legacyManifest) else { return ([:], "legacy_manifest_missing") }
        if crypto.shaHex(text) != str(marker["legacyManifestSha256"]) { return ([:], "legacy_manifest_modified") }
        guard let o = JSON.object(text), let files = o["files"] as? [[String: Any]] else {
            return ([:], "legacy_manifest_unreadable")
        }
        var out: [String: String] = [:]
        for f in files { if let p = str(f["path"]), let s = str(f["sha256"]) { out[p] = s } }
        return (out, nil)
    }

    public func transportHasAnyRunFile() -> Bool {
        guard let runs = try? fm.contentsOfDirectory(atPath: transport.path) else { return false }
        for r in runs where !r.hasPrefix(".") {
            let items = (try? fm.contentsOfDirectory(atPath: transport.appendingPathComponent(r).path)) ?? []
            if items.contains(where: { !$0.hasPrefix(".") }) { return true }
        }
        return false
    }

    public func validateEvidenceFiles(_ key: Data, _ marker: [String: Any]?) -> [String: Any] {
        var result: [String: Any] = ["ok": true, "checked": 0, "confidence": "Observed", "keyLimitation": Self.limitation]
        var tampered: [[String: Any]] = [], legacyItems: [[String: Any]] = []
        var missingMac: [String] = [], missingRuns: [String] = []
        func finish() -> [String: Any] {
            result["tampered"] = tampered
            result["legacyUnverifiable"] = legacyItems
            result["missingMac"] = missingMac
            result["missingRuns"] = missingRuns
            if !tampered.isEmpty { result["ok"] = false }
            return result
        }
        let (legacy, legacyProblem) = loadLegacyManifest(marker)
        if let legacyProblem { tampered.append(["reason": legacyProblem]) }
        let inv = validateRunInventory(key)
        if (inv["ok"] as? Bool) != true {
            tampered.append(contentsOf: inv["tampered"] as? [[String: Any]] ?? [])
            result["confidence"] = "Unknown"
        }
        let known = knownRunIds()
        if signedEraActive() {
            let primary = exists(auditSeal), mirror = exists(sealMirror)
            if !primary && !mirror && !exists(runInventory) && !(isDir(transport) && transportHasAnyRunFile()) {
                tampered.append(["reason": "signed_era_evidence_wiped"])
                result["confidence"] = "Unknown"
                return finish()
            }
            if !primary && !mirror && !exists(auditLog) && !known.isEmpty {
                tampered.append(["reason": "seal_missing_after_signed_era"])
                result["confidence"] = "Unknown"
            }
        }
        if !isDir(transport) {
            result["note"] = "无运输审计目录"
            if !known.isEmpty || signedEraActive() {
                missingRuns = known.sorted()
                result["confidence"] = "Unknown"
                tampered.append(["reason": "run_directory_missing", "runs": known.sorted()])
            }
            return finish()
        }
        var checked = 0
        let files = evidenceFiles()
        for path in files {
            let mac = macFile(path)
            guard known.contains(path.deletingLastPathComponent().lastPathComponent) || exists(mac) else { continue }
            checked += 1
            guard let expectedRaw = readText(mac) else {
                missingMac.append(path.path)
                tampered.append(["path": path.path, "reason": "missing_mac"])
                continue
            }
            guard let data = read(path) else { continue }
            let expected = expectedRaw.trimmingCharacters(in: .whitespacesAndNewlines)
            if !constantTimeEqual(expected, crypto.hmacHex(key, data: data)) {
                let pinned = legacy[rel(path)]
                if let pinned, pinned == crypto.shaHex(data: data) {
                    // Unchanged since the boundary was recorded; signed with a key that no longer exists.
                    legacyItems.append(["path": path.path, "reason": Self.legacyReason])
                    continue
                }
                tampered.append(["path": path.path,
                                 "reason": pinned != nil ? "legacy_evidence_modified_after_boundary" : "evidence_mac_mismatch"])
            }
        }
        result["checked"] = checked
        let onDisk = Set(files.filter { $0.lastPathComponent == "transport.json" }
            .map { $0.deletingLastPathComponent().lastPathComponent })
        let missing = known.subtracting(onDisk).sorted()
        if !missing.isEmpty {
            missingRuns = missing
            tampered.append(["reason": "run_deleted_from_inventory", "runs": missing])
            result["confidence"] = "Unknown"
        }
        return finish()
    }

    // MARK: b6 + split

    public func keyStorageFacts() -> [String: Any] {
        let status = keychain.lookup(Self.accountHmac).0
        var facts: [String: Any] = [
            "backend": keychain.backend, "keyInKeychain": status == "found", "keychainLookup": status,
            "plaintextKeyFile": exists(hmacKeyFile), "helperPath": nn(keychain.helperPath),
        ]
        var reasons: [String] = []
        if exists(hmacKeyFile) || keychain.backend == "file" { reasons.append("密钥在同一用户可读的文件里") }
        if keychain.backend == "security" {
            facts["keychainAclTrustsHelperByPath"] = true
            facts["helperVerifiesCaller"] = false
            reasons.append("钥匙串条目的访问控制只信任 keychain helper 这个程序本身；同一用户的任何进程都能直接运行它"
                + "（get hmac-key）拿到密钥，helper 不检查是谁在调用它")
        }
        if keychain.backend == "memory" { reasons.append("进程内存后端（只在单元测试里使用）") }
        reasons.append("签名、日志、封条都由同一用户写入，没有 root 守护进程或远端锚点")
        // Every backend available today is readable by same-uid code: True by fact, not by default.
        return ["sameUidCanForge": true, "keyStorage": facts, "reasons": reasons]
    }

    public func boundaryPublic(_ marker: [String: Any]?, _ problem: String?) -> [String: Any] {
        guard let marker else { return ["state": problem ?? "not_recorded"] }
        var out: [String: Any] = ["state": "recorded",
                                  "anchoredIn": "Keychain (HMAC-sealed) + integrity mirror + audit chain entry"]
        for k in ["establishedAt", "source", "eraAt", "cutoff", "auditBoundaryIndex", "legacyAuditCount",
                  "legacyEvidenceCount", "legacyFrom", "legacyTo"] { out[k] = nn(marker[k]) }
        out["confidence"] = str(marker["source"]) == "upgrade-inferred" ? "Inferred" : "Observed"
        return out
    }

    public func finishSplit(_ result: inout [String: Any], _ tampered: [[String: Any]], _ gaps: [[String: Any]],
                     _ legacyAudit: [[String: Any]], _ marker: [String: Any]?) {
        let ev = result["evidenceFiles"] as? [String: Any] ?? [:]
        let legacyFiles = ev["legacyUnverifiable"] as? [[String: Any]] ?? []
        let current = tampered + gaps
        result["tampered"] = tampered
        result["deletedOrGap"] = gaps
        result["ok"] = current.isEmpty
        var reasons: [String: Int] = [:]
        for item in current { reasons[str(item["reason"]) ?? "None", default: 0] += 1 }
        result["currentTampered"] = ["count": current.count, "reasons": reasons] as [String: Any]
        let times = legacyAudit.compactMap { str($0["at"]) }.filter { !$0.isEmpty }.sorted()
        let legacyCount = legacyAudit.count + legacyFiles.count
        let from = str(marker?["legacyFrom"]).flatMap { $0.isEmpty ? nil : $0 } ?? times.first
        let to = str(marker?["legacyTo"]).flatMap { $0.isEmpty ? nil : $0 } ?? times.last
        result["legacyUnverifiable"] = [
            "count": legacyCount, "auditEntries": legacyAudit.count, "evidenceFiles": legacyFiles.count,
            "from": nn(from), "to": nn(to), "reason": Self.legacyReason, "confidence": "Unknown",
            "note": "迁移前用旧密钥签的历史记录：旧密钥已删除，既不能证明完好，也不能证明被改；"
                + "它们自分界点记录后未再变动（字节已固定），不计入 ok。",
            "items": Array((legacyAudit + legacyFiles).prefix(50)),
        ] as [String: Any]
        let text: String
        if !current.isEmpty {
            result["status"] = "current_tampered"
            text = "当前记录有 \(current.count) 处校验失败（迁移后的记录被改、删或伪造），ok=false。"
        } else if legacyCount > 0 {
            result["status"] = "current_ok_legacy_unverifiable"
            text = "迁移后的记录全部校验通过；另有 \(legacyCount) 条迁移前的历史记录无法验证（旧密钥已删除），按 Unknown 处理。"
        } else {
            result["status"] = "ok"
            text = "全部记录校验通过。"
        }
        result["statusText"] = text + " 注意：同一用户的进程能拿到密钥并重写记录（b6），所以这只证明没有被不懂密钥的程序改过。"
    }
}
