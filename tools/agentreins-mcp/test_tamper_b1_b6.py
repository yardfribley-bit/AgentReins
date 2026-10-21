"""B1–B6 integrity attacks must yield ok=false (B6: Unknown + limitation)."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import evidence


class TamperBTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-tamper-"))
        self.audit = self.tmp / "audit"
        self.transport = self.tmp / "transport"
        self.audit.mkdir()
        self.transport.mkdir()
        self.patches = [
            mock.patch.object(evidence, "AUDIT_DIR", self.audit),
            mock.patch.object(evidence, "DEFAULT_TRANSPORT", self.transport),
            mock.patch.object(evidence, "AUDIT_LOG", self.audit / "mcp-supervisor-audit.jsonl"),
            mock.patch.object(evidence, "AUDIT_SEAL", self.audit / "mcp-supervisor-audit.seal"),
            mock.patch.object(evidence, "HMAC_KEY_FILE", self.audit / "mcp-supervisor-hmac.key"),
            mock.patch.object(evidence, "RUN_INVENTORY", self.audit / "transport-run-inventory.jsonl"),
            mock.patch.object(evidence, "PROTECTED_SEAL_DIR", self.audit / "seals"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self) -> pathlib.Path:
        run = self.transport / "run-seed-1"
        run.mkdir()
        (run / "transport.json").write_text('{"ok":true,"secret":"x"}', encoding="utf-8")
        (run / "manifest.json").write_text('{"call":"run-seed-1"}', encoding="utf-8")
        evidence.sign_evidence_tree(self.transport)
        evidence.register_run_id("run-seed-1", run)
        evidence.append_audit("tester", "list_alerts", {})
        evidence.append_audit("tester", "get_coverage", {})
        return run

    def test_clean_ok(self) -> None:
        self._seed()
        v = evidence.validate_audit()
        self.assertTrue(v["ok"], v)

    def test_b1_truncate_and_delete_seal(self) -> None:
        self._seed()
        log = evidence.AUDIT_LOG
        lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        log.write_text(lines[0] + "\n", encoding="utf-8")
        evidence.AUDIT_SEAL.unlink(missing_ok=True)
        mirror = evidence.PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
        mirror.unlink(missing_ok=True)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)

    def test_b2_strip_macs_rewrite_chain_delete_seal(self) -> None:
        self._seed()
        # Rewrite unsigned lines without MAC and drop seal.
        log = evidence.AUDIT_LOG
        forged = []
        prev = "0" * 64
        for i in range(2):
            body = {
                "at": "2026-01-01T00:00:00Z",
                "actor": "attacker",
                "tool": "list_alerts",
                "argsDigest": "x",
                "prevHash": prev,
            }
            body["hash"] = evidence.sha256_hex(json.dumps(body, ensure_ascii=False, sort_keys=True) + prev)
            forged.append(json.dumps(body, ensure_ascii=False))
            prev = body["hash"]
        log.write_text("\n".join(forged) + "\n", encoding="utf-8")
        evidence.AUDIT_SEAL.unlink(missing_ok=True)
        (evidence.PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal").unlink(missing_ok=True)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)

    def test_b3_modify_transport_mcp_does_not_wash(self) -> None:
        run = self._seed()
        path = run / "transport.json"
        path.write_text('{"ok":false,"tampered":true}', encoding="utf-8")
        # Calling append_audit (MCP read path) must NOT re-sign / wash.
        evidence.append_audit("tester", "list_alerts", {"probe": 1})
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        self.assertTrue(
            any("evidence_mac_mismatch" in str(t) or "mac_mismatch" in str(t) for t in v.get("tampered") or []),
            v,
        )

    def test_b4_delete_all_mac_files(self) -> None:
        run = self._seed()
        for mac in self.transport.glob("*/*.mac"):
            mac.unlink()
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)

    def test_b5_rm_run_directory(self) -> None:
        run = self._seed()
        shutil.rmtree(run)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        self.assertTrue(v.get("evidenceFiles", {}).get("missingRuns") or any(
            "run_deleted" in str(t) or "run_directory" in str(t) for t in v.get("tampered") or []
        ), v)

    def test_b6_same_uid_forge_documented_unknown(self) -> None:
        self._seed()
        v = evidence.validate_audit()
        self.assertIn("b6", v)
        self.assertEqual(v["b6"]["confidence"], "Unknown")
        self.assertTrue(v["b6"]["sameUidCanForge"])
        self.assertIn("Keychain", v["limitation"] + v["b6"]["note"])


if __name__ == "__main__":
    unittest.main()
