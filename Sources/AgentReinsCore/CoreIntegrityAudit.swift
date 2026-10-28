import Foundation

/// HMAC walk over the audit log. A pure append rechecks only the new lines; a rewrite of the prefix
/// (first line or the line at the previous head no longer matches) scans the whole log again.
private enum AuditHmacCache {
    static var path = ""
    static var size: UInt64 = 0
    static var mtime: TimeInterval = -1
    static var checked = 0
    static var nextIndex = 0
    static var head = String(repeating: "0", count: 64)
    static var prev = String(repeating: "0", count: 64)
    static var seenSigned = false
    static var tampered: [[String: Any]] = []
    static var gaps: [[String: Any]] = []
    static var legacy: [[String: Any]] = []
    static var firstLine = ""
    static var headLine = ""
}

extension Integrity {
    /// evidence.py validate_audit: keyed HMAC chain split into current (decides ok) and legacy (Unknown).
    /// Never re-signs anything on read.
    public func validate() -> [String: Any] {
        var result: [String: Any] = [
            "mode": "keyed-HMAC-SHA256 append-only + required seal + evidence MAC + run inventory",
            "keyPath": "keychain:\(Self.accountHmac)", "logPath": auditLog.path, "ok": true, "entriesChecked": 0,
            "confidence": "Observed", "limitation": Self.limitation, "legacyPathPolicy": "never_read_/private/tmp",
            "engine": "swift",
        ]
        var tampered: [[String: Any]] = [], gaps: [[String: Any]] = [], legacyAudit: [[String: Any]] = []
        let key: Data
        do {
            key = try loadKey()
        } catch {
            let reason = (error as? KeyUnavailable)?.reason ?? "\(error)"
            result["ok"] = false
            result["warning"] = "无法读取 HMAC 密钥：\(reason)"
            result["confidence"] = "Unknown"
            result["status"] = "key_unavailable"
            result["statusText"] = "读不到完整性密钥，无法校验（不是篡改结论）。"
            var b6 = keyStorageFacts()
            b6["confidence"] = "Unknown"
            result["b6"] = b6
            return result
        }
        var (marker, problem) = loadBoundary(key)
        if marker == nil && problem == nil && exists(auditLog) {
            if hasBoundaryEntry(lines()) {
                problem = "boundary_marker_deleted"
            } else if establishBoundary(key, fresh: !signedEraActive()) != nil {
                (marker, problem) = loadBoundary(key)
            }
        }
        if let problem {
            tampered.append(["reason": problem])
            result["confidence"] = "Unknown"
        }
        result["boundary"] = boundaryPublic(marker, problem)
        var b6 = keyStorageFacts()
        b6["confidence"] = "Unknown"
        b6["note"] = Self.limitation

        if !exists(auditLog) {
            result["note"] = "尚无审计日志"
            if signedEraActive() {
                tampered.append(["reason": "audit_log_missing_after_signed_era"])
                result["confidence"] = "Unknown"
                if !exists(auditSeal) && !exists(sealMirror) { tampered.append(["reason": "seal_missing_after_signed_era"]) }
                if !isDir(integrityDir) && !isDir(auditDir) {
                    tampered.append(["reason": "integrity_dirs_wiped_after_keychain_anchor"])
                }
            } else if !keychainHasAnchor() && !exists(signedEraFlag) && !exists(sealMirror) {
                result["confidence"] = "Unknown"
                result["note"] = "never_anchored"
                result["neverAnchored"] = true
            }
            let ev = validateEvidenceFiles(key, marker)
            result["evidenceFiles"] = ev
            if (ev["ok"] as? Bool) != true {
                tampered.append(contentsOf: ev["tampered"] as? [[String: Any]] ?? [])
                result["confidence"] = "Unknown"
            }
            finishSplit(&result, tampered, gaps, legacyAudit, marker)
            result["b6"] = b6
            return result
        }
        if eraKeyMismatch(key) {
            tampered.append(["reason": "hmac_key_replaced_after_signed_era"])
            result["confidence"] = "Unknown"
        }
        let lines = self.lines()
        let unchanged = AuditHmacCache.path == auditLog.path && AuditHmacCache.size == Integrity.lineCacheSize
            && AuditHmacCache.mtime == Integrity.lineCacheMtime && AuditHmacCache.nextIndex == lines.count
        let prefixUntouched = AuditHmacCache.nextIndex > 0 && lines.count >= AuditHmacCache.nextIndex
            && lines[0] == AuditHmacCache.firstLine
            && lines[AuditHmacCache.nextIndex - 1] == AuditHmacCache.headLine
        let resume = !unchanged && Integrity.lineCacheAppended && prefixUntouched
            && lines.count >= AuditHmacCache.nextIndex && AuditHmacCache.path == auditLog.path
        var boundary = intValue(marker?["auditBoundaryIndex"]) ?? 0
        if let marker {
            if lines.count < boundary {
                tampered.append(["reason": "audit_truncated_below_boundary", "boundary": boundary])
                boundary = lines.count
            } else if resume && boundary <= AuditHmacCache.nextIndex {
                // Prefix was spot-checked above; do not rebuild it on every appended line.
            } else if prefixSha(lines, boundary) != str(marker["auditPrefixSha256"]) {
                tampered.append(["reason": "legacy_audit_prefix_modified", "boundary": boundary])
                boundary = 0  // pinned legacy bytes changed: nothing before the boundary can be excused any more
            }
        }
        var prev = String(repeating: "0", count: 64)
        var seenSigned = false
        var head = prev
        var checked = 0
        var start = 0
        if unchanged || resume {
            tampered.append(contentsOf: AuditHmacCache.tampered)
            gaps.append(contentsOf: AuditHmacCache.gaps)
            legacyAudit.append(contentsOf: AuditHmacCache.legacy)
            prev = AuditHmacCache.head
            head = AuditHmacCache.head
            checked = AuditHmacCache.checked
            seenSigned = AuditHmacCache.seenSigned
            start = unchanged ? lines.count : AuditHmacCache.nextIndex
        }
        let loopStartTampered = tampered.count
        let loopStartGaps = gaps.count
        let loopStartLegacy = legacyAudit.count
        for (idx, line) in lines.enumerated() where idx >= start {
            let legacyZone = idx < boundary
            guard let entry = JSON.object(line) else {
                if legacyZone {
                    legacyAudit.append(["index": idx, "reason": "invalid_json"])
                } else {
                    tampered.append(["index": idx, "reason": "invalid_json"])
                }
                continue
            }
            checked += 1
            if str(entry["prevHash"]) != prev {
                var gap: [String: Any] = ["index": idx, "reason": "prevHash_mismatch", "expectedPrev": prev,
                                          "gotPrev": nn(entry["prevHash"])]
                if legacyZone {
                    gap["at"] = nn(entry["at"])
                    legacyAudit.append(gap)
                } else {
                    gaps.append(gap)
                }
            }
            var body: [String: Any] = [:]
            for k in Self.entryFields { if let v = entry[k] { body[k] = v } }
            if entry["mac"] == nil {
                let item: [String: Any] = ["index": idx, "reason": "missing_mac", "tool": nn(entry["tool"]),
                                           "at": nn(entry["at"])]
                if legacyZone { legacyAudit.append(item) } else { tampered.append(item) }
            } else {
                seenSigned = true
                if str(entry["mac"]) != crypto.entryMac(body, key) {
                    var item: [String: Any] = ["index": idx, "reason": "mac_mismatch", "tool": nn(entry["tool"]),
                                               "at": nn(entry["at"]), "actor": nn(entry["actor"])]
                    if legacyZone {
                        item["reason"] = Self.legacyReason
                        legacyAudit.append(item)
                    } else {
                        tampered.append(item)  // no allowlist / quarantine can wash this to ok=true
                        result["confidence"] = "Unknown"
                    }
                }
            }
            if let h = str(entry["hash"]), !h.isEmpty { prev = h }
            head = prev
        }
        let freshTampered = Array(tampered.dropFirst(loopStartTampered))
        let freshGaps = Array(gaps.dropFirst(loopStartGaps))
        let freshLegacy = Array(legacyAudit.dropFirst(loopStartLegacy))
        if resume {
            AuditHmacCache.tampered += freshTampered
            AuditHmacCache.gaps += freshGaps
            AuditHmacCache.legacy += freshLegacy
        } else if !unchanged {
            AuditHmacCache.tampered = freshTampered
            AuditHmacCache.gaps = freshGaps
            AuditHmacCache.legacy = freshLegacy
        }
        AuditHmacCache.path = auditLog.path
        AuditHmacCache.size = Integrity.lineCacheSize
        AuditHmacCache.mtime = Integrity.lineCacheMtime
        AuditHmacCache.checked = checked
        AuditHmacCache.nextIndex = lines.count
        AuditHmacCache.head = head
        AuditHmacCache.prev = prev
        AuditHmacCache.seenSigned = seenSigned
        AuditHmacCache.firstLine = lines.first ?? ""
        AuditHmacCache.headLine = lines.isEmpty ? "" : lines[lines.count - 1]
        result["entriesChecked"] = checked
        let sealRequired = seenSigned || checked > 0 || exists(sealMirror) || signedEraActive()
        let activeSeal: URL? = exists(auditSeal) ? auditSeal : (exists(sealMirror) ? sealMirror : nil)
        if sealRequired && activeSeal == nil {
            tampered.append(["reason": signedEraActive() ? "seal_missing_after_signed_era" : "seal_missing_required"])
            result["confidence"] = "Unknown"
        } else if let activeSeal {
            if let seal = JSON.objectAt(activeSeal) {
                var sealBody: [String: Any] = [:]
                for k in ["headHash", "count", "schema", "inventorySha256"] { if let v = seal[k] { sealBody[k] = v } }
                if str(seal["mac"]) != crypto.entryMac(sealBody, key) {
                    tampered.append(["reason": "seal_mac_mismatch"])
                } else if (intValue(seal["count"]) ?? 0) != checked || str(seal["headHash"]) != head {
                    gaps.append(["reason": "truncated_or_count_mismatch", "sealCount": nn(seal["count"]),
                                 "actualCount": checked, "sealHead": nn(seal["headHash"]), "actualHead": head])
                } else if let anchored = str(seal["inventorySha256"]), let inv = read(runInventory),
                          anchored != crypto.shaHex(data: inv) {
                    tampered.append(["reason": "inventory_seal_anchor_mismatch"])
                }
            } else {
                tampered.append(["reason": "seal_unreadable", "error": "JSONDecodeError"])
            }
        }
        let ev = validateEvidenceFiles(key, marker)
        result["evidenceFiles"] = ev
        if (ev["ok"] as? Bool) != true {
            tampered.append(contentsOf: ev["tampered"] as? [[String: Any]] ?? [])
            result["confidence"] = "Unknown"
        }
        finishSplit(&result, tampered, gaps, legacyAudit, marker)
        if (result["ok"] as? Bool) != true { result["confidence"] = "Unknown" }
        result["b6"] = b6
        // Same-uid key forgeability (b6): local MACs alone never claim Observed, even when ok=true.
        if str(result["confidence"]) == "Observed" {
            result["confidence"] = "Unknown"
            result["observedBlockedBy"] = "same_uid_no_external_anchor"
        }
        return result
    }

    public static func summary(_ v: [String: Any]) -> [String: Any] {
        let legacy = v["legacyUnverifiable"] as? [String: Any] ?? [:]
        return [
            "ok": nn(v["ok"]), "status": nn(v["status"]), "statusText": nn(v["statusText"]),
            "currentTampered": nn((v["currentTampered"] as? [String: Any])?["count"]),
            "legacyUnverifiable": nn(legacy["count"]), "legacyRange": [nn(legacy["from"]), nn(legacy["to"])],
            "sameUidCanForge": nn((v["b6"] as? [String: Any])?["sameUidCanForge"]), "confidence": "Unknown",
        ]
    }
}
