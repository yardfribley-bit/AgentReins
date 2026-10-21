"""B14–B16: Keychain wipe+rebuild, key exfil rewrite, unsigned quarantine wash."""
from __future__ import annotations

import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import evidence
from keychain_fake import FAKE as FAKE_KEYCHAIN


class TamperB14B16Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-tamper14-"))
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

    def test_b14_delete_keychain_and_wipe_dirs_rebuild_unknown(self) -> None:
        """B14: delete Keychain items + clear dirs, then rebuild → must not be Observed."""
        self._seed()
        evidence.keychain_delete(evidence.KEYCHAIN_ACCOUNT_HMAC)
        evidence.keychain_delete(evidence.KEYCHAIN_ACCOUNT_ERA)
        shutil.rmtree(self.audit)
        shutil.rmtree(self.integrity)
        self.audit.mkdir()
        self.integrity.mkdir()
        # Attacker rebuilds a fresh history under a new key with no era anchor left.
        evidence.append_audit("attacker", "list_alerts", {})
        v = evidence.validate_audit()
        # Missing prior era / wiped integrity after anchor → not Observed.
        if evidence.keychain_has_install_anchor():
            self.assertFalse(v["ok"], v)
            self.assertNotEqual(v.get("confidence"), "Observed")
        else:
            # No Keychain anchor survived: confidence must not claim Observed over rebuilt history.
            self.assertNotEqual(v.get("confidence"), "Observed")

    def test_b15_exfil_key_rewrite_history_detected(self) -> None:
        """B15: read HMAC key and rewrite audit history → mac/seal mismatch or key replace."""
        self._seed()
        stolen = evidence.keychain_get(evidence.KEYCHAIN_ACCOUNT_HMAC)
        self.assertIsNotNone(stolen)
        # Attacker rewrites an entry MAC using the stolen key but breaks the seal count.
        log = evidence.AUDIT_LOG
        lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        entry = json.loads(lines[0])
        # Attacker uses stolen key to forge a plausible MAC on a modified tool name,
        # then also forges a matching seal — still must fail because era fingerprint
        # anchors the original key, OR chain fields diverge from sealed inventory.
        entry["tool"] = "tampered_tool"
        body = {k: entry[k] for k in ("at", "actor", "tool", "argsDigest", "prevHash") if k in entry}
        entry["mac"] = evidence.entry_hmac(body, stolen)  # type: ignore[arg-type]
        # Keep hash stable so only semantic tamper is the tool rename under stolen MAC.
        log.write_text(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        # Also write a forged seal that matches the rewritten line.
        seal_body = {"headHash": entry.get("hash"), "count": 1, "schema": "mcp-supervisor-audit/v1"}
        if evidence.RUN_INVENTORY.is_file():
            seal_body["inventorySha256"] = evidence.sha256_bytes(evidence.RUN_INVENTORY.read_bytes())
        seal = dict(seal_body)
        seal["mac"] = evidence.entry_hmac(seal_body, stolen)  # type: ignore[arg-type]
        evidence.AUDIT_SEAL.write_text(json.dumps(seal, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        v = evidence.validate_audit()
        # Local MAC+seal can look intact after key exfil — that must NOT stay Observed.
        self.assertNotEqual(v.get("confidence"), "Observed", v)
        self.assertEqual(v.get("b6", {}).get("confidence"), "Unknown")
        self.assertEqual(v.get("observedBlockedBy"), "same_uid_no_external_anchor")

    def test_b16_unsigned_quarantine_cannot_wash(self) -> None:
        """B16: alter a row and drop an unsigned quarantine file → still ok=false."""
        self._seed()
        log = evidence.AUDIT_LOG
        lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
        entry = json.loads(lines[0])
        entry["mac"] = "0" * 64
        log.write_text(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        # Attacker writes unsigned quarantine list (legacy path) — must NOT wash.
        q = self.integrity / "historical-mac-mismatch.jsonl"
        q.write_text(json.dumps({"index": 0, "cause": "wash"}) + "\n", encoding="utf-8")
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        reasons = [t.get("reason") for t in v.get("tampered") or []]
        self.assertIn("mac_mismatch", reasons)
        self.assertNotEqual(v.get("confidence"), "Observed")
        # Quarantine APIs must not exist / wash.
        self.assertFalse(hasattr(evidence, "quarantine_historical_mac_mismatch"))


if __name__ == "__main__":
    unittest.main()
