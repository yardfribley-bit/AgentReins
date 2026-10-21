"""B11–B12: full wipe of audit+integrity dirs; wipe+rebuild under new key."""
from __future__ import annotations

import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import evidence
from keychain_fake import FAKE as FAKE_KEYCHAIN


class TamperB11B12Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-tamper11-"))
        self.audit = self.tmp / "audit"
        self.transport = self.tmp / "transport"
        self.integrity = self.tmp / "integrity"
        self.audit.mkdir()
        self.transport.mkdir()
        self.integrity.mkdir()
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

    def _seed(self) -> None:
        run = self.transport / "run-seed-1"
        run.mkdir()
        (run / "transport.json").write_text('{"ok":true}', encoding="utf-8")
        (run / "manifest.json").write_text('{"call":"run-seed-1"}', encoding="utf-8")
        evidence.sign_evidence_tree(self.transport)
        evidence.register_run_id("run-seed-1", run)
        evidence.append_audit("tester", "list_alerts", {})
        self.assertTrue(evidence.keychain_has_install_anchor())

    def test_b11_wipe_both_dirs_detected_via_keychain(self) -> None:
        self._seed()
        shutil.rmtree(self.audit)
        shutil.rmtree(self.integrity)
        # Recreate path objects pointing at missing dirs (validate must not claim ok).
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        reasons = [t.get("reason") for t in v.get("tampered") or []]
        self.assertTrue(
            any(
                r
                in (
                    "audit_log_missing_after_signed_era",
                    "integrity_dirs_wiped_after_keychain_anchor",
                    "seal_missing_after_signed_era",
                )
                for r in reasons
            ),
            v,
        )
        self.assertNotEqual(v.get("confidence"), "Observed")

    def test_b12_wipe_and_rebuild_under_new_key_detected(self) -> None:
        self._seed()
        old_fp = json.loads(evidence.keychain_get(evidence.KEYCHAIN_ACCOUNT_ERA).decode())["keyFingerprint"]
        shutil.rmtree(self.audit)
        shutil.rmtree(self.integrity)
        shutil.rmtree(self.transport)
        self.audit.mkdir()
        self.transport.mkdir()
        self.integrity.mkdir()
        # Attacker replaces Keychain HMAC key but leaves era; forges a fresh history.
        FAKE_KEYCHAIN.items[evidence.KEYCHAIN_ACCOUNT_HMAC] = b"N" * 32
        evidence.append_audit("attacker", "list_alerts", {})
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        reasons = [t.get("reason") for t in v.get("tampered") or []]
        self.assertIn("hmac_key_replaced_after_signed_era", reasons)
        new_key = evidence.load_or_create_hmac_key()
        self.assertNotEqual(evidence._key_fingerprint(new_key), old_fp)
        # Must not claim Observed after rebuild-under-new-key.
        self.assertNotEqual(v.get("confidence"), "Observed")


if __name__ == "__main__":
    unittest.main()
