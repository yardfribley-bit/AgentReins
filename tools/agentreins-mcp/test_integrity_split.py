"""Legacy (pre-Keychain-migration) vs current integrity: split without whitewashing.

The upgrade scenario is built the way the real Mac got there: entries and evidence MACs written
under an old key K0 that was later deleted, then the Keychain key K1 + signed era, then new entries.
Every attack here must end in ok=false; legacy items are Unknown, never verified.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import evidence
from keychain_fake import FAKE as FAKE_KEYCHAIN

K0 = b"0" * 32  # deleted pre-migration key (fixture)
K1 = b"1" * 32  # current Keychain key (fixture)
ERA_AT = "2026-10-21T15:08:55Z"
LEGACY_AT = ["2026-10-20T22:12:23Z", "2026-10-21T09:00:00Z", "2026-10-21T14:59:59Z"]


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-split-"))
        self.audit, self.transport, self.integrity = (self.tmp / n for n in ("audit", "transport", "integrity"))
        for d in (self.audit, self.transport, self.integrity):
            d.mkdir()
        FAKE_KEYCHAIN.items.clear()
        self.patches = [
            mock.patch.object(evidence, "AUDIT_DIR", self.audit),
            mock.patch.object(evidence, "DEFAULT_TRANSPORT", self.transport),
            mock.patch.object(evidence, "AUDIT_LOG", self.audit / "mcp-supervisor-audit.jsonl"),
            mock.patch.object(evidence, "AUDIT_SEAL", self.audit / "mcp-supervisor-audit.seal"),
            mock.patch.object(evidence, "HMAC_KEY_FILE", self.audit / "mcp-supervisor-hmac.key"),
            mock.patch.object(evidence, "RUN_INVENTORY", self.audit / "transport-run-inventory.jsonl"),
            mock.patch.object(evidence, "INTEGRITY_DIR", self.integrity),
            mock.patch.object(evidence, "PROTECTED_SEAL_DIR", self.integrity / "seals"),
            mock.patch.object(evidence, "SIGNED_ERA_FLAG", self.integrity / "signed-era"),
            mock.patch.object(evidence, "RUN_INVENTORY_MAC", self.integrity / "transport-run-inventory.mac"),
            *FAKE_KEYCHAIN.patches(evidence),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in self.patches:
            p.stop()
        FAKE_KEYCHAIN.items.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers
    def lines(self) -> list[str]:
        return [ln for ln in evidence.AUDIT_LOG.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def write_lines(self, lines: list[str]) -> None:
        evidence.AUDIT_LOG.write_text("".join(ln + "\n" for ln in lines), encoding="utf-8")

    def legacy_world(self) -> None:
        """Pre-migration history signed with K0, then K0 deleted, K1 in Keychain, era started, one new entry."""
        prev = "0" * 64
        out = []
        for i, at in enumerate(LEGACY_AT):
            entry = {"at": at, "actor": "codex-mcp-client/0.1", "tool": "list_alerts",
                     "argsDigest": "%024d" % i, "prevHash": prev}
            entry["mac"] = evidence.entry_hmac(entry, K0)
            entry["hash"] = evidence.sha256_hex(evidence.canonical_json(entry) + prev)
            prev = entry["hash"]
            out.append(evidence.canonical_json(entry))
        self.write_lines(out)
        run = self.transport / "run-legacy"
        run.mkdir()
        for name, body in (("transport.json", '{"legacy":true}'), ("manifest.json", '{"call":"run-legacy"}')):
            path = run / name
            path.write_text(body, encoding="utf-8")
            (run / (name + ".mac")).write_text(evidence.evidence_file_mac(path, K0) + "\n", encoding="utf-8")
            past = evidence._iso_ts(LEGACY_AT[1])
            os.utime(path, (past, past))
        FAKE_KEYCHAIN.items[evidence.KEYCHAIN_ACCOUNT_HMAC] = K1
        era = json.dumps({"at": ERA_AT, "keyFingerprint": evidence._key_fingerprint(K1), "schema": 2},
                         sort_keys=True).encode()
        FAKE_KEYCHAIN.items[evidence.KEYCHAIN_ACCOUNT_ERA] = era
        (self.integrity / "signed-era").write_bytes(era + b"\n")
        # First post-migration activity (new code): an MCP read gets audited.
        evidence.append_audit("codex-mcp-client/0.1", "get_coverage", {})
        new_run = self.transport / "run-new"
        new_run.mkdir()
        (new_run / "transport.json").write_text('{"new":true}', encoding="utf-8")
        evidence.sign_evidence_tree(new_run)

    def reasons(self, v: dict) -> list[str]:
        return [str(t.get("reason")) for t in (v.get("tampered") or []) + (v.get("deletedOrGap") or [])]


class FreshInstall(Base):
    def test_boundary_recorded_at_era_start_with_no_legacy(self) -> None:
        run = self.transport / "run-1"
        run.mkdir()
        (run / "transport.json").write_text("{}", encoding="utf-8")
        evidence.sign_evidence_tree(self.transport)
        evidence.append_audit("tester", "list_alerts", {})
        v = evidence.validate_audit()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["status"], "ok")
        self.assertEqual(v["boundary"]["source"], "recorded-at-signed-era-start")
        self.assertEqual(v["boundary"]["auditBoundaryIndex"], 0)
        self.assertEqual(v["legacyUnverifiable"]["count"], 0)
        tools = [json.loads(ln)["tool"] for ln in self.lines()]
        self.assertIn(evidence.BOUNDARY_TOOL, tools)

    def test_any_edit_after_fresh_boundary_is_current(self) -> None:
        evidence.append_audit("tester", "list_alerts", {})
        lines = self.lines()
        entry = json.loads(lines[-1])
        entry["tool"], entry["at"] = "edited", "2000-01-01T00:00:00Z"
        lines[-1] = evidence.canonical_json(entry)
        self.write_lines(lines)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("mac_mismatch", self.reasons(v))
        self.assertEqual(v["legacyUnverifiable"]["count"], 0)


class Upgrade(Base):
    def test_split_legacy_unknown_current_ok(self) -> None:
        self.legacy_world()
        v = evidence.validate_audit()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["status"], "current_ok_legacy_unverifiable")
        leg = v["legacyUnverifiable"]
        self.assertEqual((leg["auditEntries"], leg["evidenceFiles"]), (3, 2))
        self.assertEqual(leg["reason"], "signed with deleted pre-migration key")
        self.assertEqual(leg["confidence"], "Unknown")
        self.assertEqual(leg["from"], LEGACY_AT[0])
        self.assertEqual(v["currentTampered"]["count"], 0)
        self.assertEqual(v["boundary"]["source"], "upgrade-inferred")
        self.assertEqual(v["boundary"]["confidence"], "Inferred")
        self.assertEqual(v["boundary"]["auditBoundaryIndex"], 3)
        self.assertNotEqual(v["confidence"], "Observed")  # never Observed-verified
        self.assertEqual(v["tampered"], [])

    def test_attacker_edits_post_migration_entry(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        lines = self.lines()
        entry = json.loads(lines[3])
        entry["tool"] = "forged"
        entry["at"] = LEGACY_AT[0]  # pretending to be old does not move it into legacy
        lines[3] = evidence.canonical_json(entry)
        self.write_lines(lines)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertEqual(v["status"], "current_tampered")
        self.assertIn("mac_mismatch", self.reasons(v))
        self.assertEqual(v["legacyUnverifiable"]["auditEntries"], 3)

    def test_deleting_marker_does_not_move_entries_into_legacy(self) -> None:
        self.legacy_world()
        self.assertTrue(evidence.validate_audit()["ok"])
        evidence.keychain_delete(evidence.KEYCHAIN_ACCOUNT_BOUNDARY)
        (self.integrity / "integrity-boundary.json").unlink()
        for _ in range(2):  # and a second read must not quietly re-establish it
            v = evidence.validate_audit()
            self.assertFalse(v["ok"], v)
            self.assertIn("boundary_marker_deleted", self.reasons(v))
            self.assertEqual(v["legacyUnverifiable"]["count"], 0)
            self.assertGreaterEqual(v["currentTampered"]["count"], 3)
        self.assertIsNone(evidence.keychain_get(evidence.KEYCHAIN_ACCOUNT_BOUNDARY))

    def test_forged_marker_without_key_is_rejected(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        marker = json.loads(evidence.keychain_get(evidence.KEYCHAIN_ACCOUNT_BOUNDARY).decode())
        marker["auditBoundaryIndex"] = 99
        marker["mac"] = "f" * 64
        FAKE_KEYCHAIN.items[evidence.KEYCHAIN_ACCOUNT_BOUNDARY] = evidence.canonical_json(marker).encode()
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("boundary_marker_mac_mismatch", self.reasons(v))
        self.assertEqual(v["legacyUnverifiable"]["count"], 0)

    def test_mirror_file_alone_is_not_authoritative(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        (self.integrity / "integrity-boundary.json").write_text('{"auditBoundaryIndex": 99}', encoding="utf-8")
        v = evidence.validate_audit()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["boundary"]["auditBoundaryIndex"], 3)

    def test_editing_a_legacy_entry_after_boundary_is_current_tamper(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        lines = self.lines()
        entry = json.loads(lines[1])
        entry["tool"] = "rewritten-history"
        lines[1] = evidence.canonical_json(entry)
        self.write_lines(lines)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("legacy_audit_prefix_modified", self.reasons(v))

    def test_editing_legacy_evidence_file_is_current_tamper(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        (self.transport / "run-legacy" / "transport.json").write_text('{"legacy":false}', encoding="utf-8")
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("legacy_evidence_modified_after_boundary", self.reasons(v))

    def test_post_migration_evidence_edit_is_current_tamper(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        (self.transport / "run-new" / "transport.json").write_text('{"new":"edited"}', encoding="utf-8")
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("evidence_mac_mismatch", self.reasons(v))

    def test_legacy_manifest_deleted(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        (self.integrity / "legacy-evidence-manifest.json").unlink()
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("legacy_manifest_missing", self.reasons(v))
        self.assertEqual(v["legacyUnverifiable"]["evidenceFiles"], 0)

    def test_truncating_into_legacy_zone(self) -> None:
        self.legacy_world()
        evidence.validate_audit()
        self.write_lines(self.lines()[:2])
        v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertIn("audit_truncated_below_boundary", self.reasons(v))


class KeyFacts(Base):
    def test_b6_reflects_actual_storage(self) -> None:
        evidence.append_audit("tester", "list_alerts", {})
        b6 = evidence.validate_audit()["b6"]
        self.assertIs(b6["sameUidCanForge"], True)
        self.assertEqual(b6["keyStorage"]["backend"], FAKE_KEYCHAIN.backend)
        self.assertTrue(b6["reasons"])

    def test_keychain_read_error_never_mints_a_new_key(self) -> None:
        evidence.append_audit("tester", "list_alerts", {})
        before = dict(FAKE_KEYCHAIN.items)
        with mock.patch.object(evidence, "_keychain_lookup", return_value=("error", None)):
            with self.assertRaises(evidence.KeychainUnavailable):
                evidence.load_or_create_hmac_key()
            v = evidence.validate_audit()
        self.assertFalse(v["ok"])
        self.assertEqual(v["status"], "key_unavailable")
        self.assertEqual(FAKE_KEYCHAIN.items, before)
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())


if __name__ == "__main__":
    unittest.main()
