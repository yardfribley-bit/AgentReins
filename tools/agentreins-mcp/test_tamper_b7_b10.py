"""B7–B10 integrity attacks must yield ok=false."""
from __future__ import annotations

import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import evidence


class TamperB7B10Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-tamper7-"))
        self.audit = self.tmp / "audit"
        self.transport = self.tmp / "transport"
        self.integrity = self.tmp / "integrity"
        self.audit.mkdir()
        self.transport.mkdir()
        self.integrity.mkdir()
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
        signed = evidence.sign_evidence_tree(self.transport)
        self.assertTrue(signed.get("ok", True), signed)
        evidence.register_run_id("run-seed-1", run)
        evidence.append_audit("tester", "list_alerts", {})
        evidence.append_audit("tester", "get_coverage", {})
        return run

    def test_clean_ok(self) -> None:
        self._seed()
        v = evidence.validate_audit()
        self.assertTrue(v["ok"], v)

    def test_b7_allow_resign_default_refuses_wash(self) -> None:
        run = self._seed()
        path = run / "transport.json"
        path.write_text('{"ok":false,"tampered":true}', encoding="utf-8")
        # Default allow_resign=False must refuse to re-sign over a mismatched MAC.
        out = evidence.sign_evidence_tree(self.transport)
        self.assertFalse(out.get("ok", True), out)
        self.assertTrue(out.get("refused"), out)
        # MAC file must still be the old (non-matching) one — wash did not happen.
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        self.assertTrue(
            any("evidence_mac_mismatch" in str(t) or "refuse_resign" in str(t) for t in v.get("tampered") or []),
            v,
        )

    def test_b8_deleting_inventory_row_breaks_mac(self) -> None:
        run = self._seed()
        # Attacker removes the run and deletes its inventory line.
        shutil.rmtree(run)
        lines = [
            ln
            for ln in evidence.RUN_INVENTORY.read_text(encoding="utf-8").splitlines()
            if ln.strip() and "run-seed-1" not in ln
        ]
        evidence.RUN_INVENTORY.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        self.assertTrue(
            any(
                t.get("reason") in ("inventory_mac_mismatch", "inventory_seal_anchor_mismatch")
                for t in v.get("tampered") or []
            ),
            v,
        )

    def test_b9_b10_wipe_all_treated_as_tamper_not_unsigned(self) -> None:
        self._seed()
        self.assertTrue(evidence.signed_era_active())
        # Wipe log, seals in audit dir, inventory, all .mac — leave external signed-era flag.
        evidence.AUDIT_LOG.unlink(missing_ok=True)
        evidence.AUDIT_SEAL.unlink(missing_ok=True)
        evidence.RUN_INVENTORY.unlink(missing_ok=True)
        for mac in self.transport.glob("*/*.mac"):
            mac.unlink()
        for run in self.transport.iterdir():
            if run.is_dir():
                shutil.rmtree(run)
        # Also delete mirror seal (attacker who finds it) but keep SIGNED_ERA_FLAG.
        mirror = evidence.PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
        mirror.unlink(missing_ok=True)
        evidence.RUN_INVENTORY_MAC.unlink(missing_ok=True)
        v = evidence.validate_audit()
        self.assertFalse(v["ok"], v)
        reasons = [t.get("reason") for t in v.get("tampered") or []]
        self.assertTrue(
            any(
                r
                in (
                    "audit_log_missing_after_signed_era",
                    "seal_missing_after_signed_era",
                    "signed_era_evidence_wiped",
                )
                for r in reasons
            ),
            v,
        )


if __name__ == "__main__":
    unittest.main()
