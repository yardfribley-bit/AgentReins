"""Keychain helper failures must never hang or kill a reader, never mint a key, and be reported.

Regression for CI run 39655188074: on the macOS runner the packaged AgentReinsKeychainHelper blocked
(Keychain approval prompt nobody can answer) until the 15 s timeout, in the sampler and again in the
MCP. The reader then judged the ledger's freshness *after* that wait and reported a live sampler as
'stopped'. The helpers below are fake shell scripts (test fixtures, not the real helper) that
reproduce the three behaviours the real helper can show: hang, exit 4 (needs approval), exit 3 (missing).
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import tempfile
import time
import unittest
from unittest import mock

import evidence
import server


def fake_helper(directory: pathlib.Path, body: str) -> pathlib.Path:
    path = directory / "fake-keychain-helper.sh"
    path.write_text("#!/bin/sh\n# FIXTURE: stands in for AgentReinsKeychainHelper\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class KeychainFailureBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-kc-"))
        self.audit, self.integrity, self.transport = (self.tmp / n for n in ("audit", "integrity", "transport"))
        for d in (self.audit, self.integrity, self.transport):
            d.mkdir()
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
            mock.patch.object(evidence, "KEYCHAIN_HELPER_TIMEOUT", 1.0),
            mock.patch.dict(evidence._KEYCHAIN_STATE, {"unresponsiveUntil": 0.0, "lastError": None}),
            # Exercise the real helper path on any OS (the fake helper binaries below stand in for the Keychain).
            mock.patch.object(evidence, "_keychain_backend", lambda: "security"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def use_helper(self, body: str) -> pathlib.Path:
        helper = fake_helper(self.tmp, body)
        p = mock.patch.object(evidence, "_find_keychain_helper", return_value=helper)
        p.start()
        self.addCleanup(p.stop)
        return helper


class HelperFailureTests(KeychainFailureBase):
    def test_hanging_helper_is_bounded_reported_and_backed_off(self) -> None:
        calls = self.tmp / "calls"
        self.use_helper('echo x >> "%s"\nexec sleep 30' % calls)
        t0 = time.monotonic()
        with self.assertRaises(evidence.KeychainUnavailable) as ctx:
            evidence.load_or_create_hmac_key()
        self.assertLess(time.monotonic() - t0, 5)
        self.assertIn("timed out", str(ctx.exception))
        # Within the backoff window no further helper process is started (one hang per minute, not per call).
        t1 = time.monotonic()
        for _ in range(3):
            self.assertEqual(evidence._keychain_lookup(evidence.KEYCHAIN_ACCOUNT_HMAC)[0], "error")
        self.assertLess(time.monotonic() - t1, 0.5)
        self.assertEqual(calls.read_text().count("x"), 1)
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())

    def test_needs_approval_exit_is_error_with_reason_and_no_key(self) -> None:
        self.use_helper('echo "get failed: OSStatus -25308" >&2\nexit 4')
        with self.assertRaises(evidence.KeychainUnavailable) as ctx:
            evidence.load_or_create_hmac_key()
        self.assertIn("needs user approval", str(ctx.exception))
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())
        v = evidence.validate_audit()
        self.assertEqual(v["status"], "key_unavailable")
        self.assertFalse(v["ok"])

    def test_missing_item_but_store_refused_never_writes_a_file_key(self) -> None:
        # get -> 3 (missing); set -> 4 (needs approval). Before the fix this fell back to a plaintext key file.
        self.use_helper('[ "$1" = get ] && exit 3\necho "set failed: OSStatus -25308" >&2\nexit 4')
        with self.assertRaises(evidence.KeychainUnavailable) as ctx:
            evidence.load_or_create_hmac_key()
        self.assertIn("could not store", str(ctx.exception))
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())

    def test_python_mcp_still_answers_reads_without_a_key(self) -> None:
        self.use_helper("exit 4")
        out = server.call_tool("get_coverage", {})
        self.assertEqual(out["integritySummary"]["status"], "key_unavailable")
        self.assertFalse(evidence.AUDIT_LOG.exists())  # nothing signed with a throwaway key


class FreshnessTests(KeychainFailureBase):
    def write_ledger(self, last_at: float, rounds: int = 1) -> pathlib.Path:
        ledger = self.tmp / "socket-ledger.json"
        samples = {"count": rounds, "lastAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(last_at))
                   + ".%03dZ" % int((last_at % 1) * 1000),
                   "rounds": [[last_at - 2.0 * (rounds - 1 - i), 0.3, True] for i in range(rounds)]}
        cov = {"configuredIntervalSeconds": 2.0, "successGapSecondsP95": 2.0 if rounds > 1 else None}
        ledger.write_text(json.dumps({"schema": 1, "connections": [], "samples": samples, "coverage": cov}))
        return ledger

    def test_freshness_is_judged_when_the_ledger_was_read_not_after_a_slow_key_lookup(self) -> None:
        ledger = self.write_ledger(time.time() - 8.0)

        def slow_key():
            time.sleep(3.0)  # the CI runner's helper blocked 15 s here
            return None

        with mock.patch.object(evidence, "_ledger_key", side_effect=slow_key):
            cov = evidence.load_socket_ledger(path=ledger, limit=0)["coverage"]
        self.assertEqual(cov["state"], "sampling", cov)
        self.assertLess(cov["staleSeconds"], 10)

    def test_threshold_with_fewer_than_six_rounds(self) -> None:
        now = time.time()
        one = {"lastAt": evidence._iso_from_epoch(now - 9)}
        # One round: no measured gap yet -> max(10 s, 3 x configured 2 s) = 10 s.
        f = evidence.socket_freshness(one, {"configuredIntervalSeconds": 2.0, "successGapSecondsP95": None}, now=now)
        self.assertEqual((f["state"], f["staleAfterSeconds"]), ("sampling", 10.0))
        f = evidence.socket_freshness({"lastAt": evidence._iso_from_epoch(now - 11)},
                                      {"configuredIntervalSeconds": 2.0, "successGapSecondsP95": None}, now=now)
        self.assertEqual(f["state"], "stopped")
        # A few rounds with a slow measured gap: the measured gap widens the window (3 x 5 s = 15 s).
        f = evidence.socket_freshness({"lastAt": evidence._iso_from_epoch(now - 12)},
                                      {"configuredIntervalSeconds": 2.0, "successGapSecondsP95": 5.0}, now=now)
        self.assertEqual((f["state"], f["staleAfterSeconds"]), ("sampling", 15.0))
        # Never sampled at all: stopped, not sampling.
        self.assertEqual(evidence.socket_freshness({}, {"configuredIntervalSeconds": 2.0}, now=now)["state"], "stopped")


_SHIPPED_BACKEND = evidence._keychain_backend  # captured before any test patches it


class NoTestBackendsShip(KeychainFailureBase):
    """Phase 2: the in-memory / file key stores and their env switch are gone from shipped code."""

    def test_no_helper_never_falls_back_to_a_file_key(self) -> None:
        with mock.patch.object(evidence, "_find_keychain_helper", return_value=None):
            with self.assertRaises(evidence.KeychainUnavailable):
                evidence.load_or_create_hmac_key()
            v = evidence.validate_audit()
        self.assertEqual(v["status"], "key_unavailable")
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())

    def test_no_keychain_platform_is_unsigned_not_file_signed(self) -> None:
        with mock.patch.object(evidence, "_keychain_backend", lambda: "unsupported"):
            self.assertEqual(evidence._keychain_lookup(evidence.KEYCHAIN_ACCOUNT_HMAC), ("no_backend", None))
            with self.assertRaises(evidence.KeychainUnavailable):
                evidence.load_or_create_hmac_key()
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())

    def test_env_switch_is_ignored(self) -> None:
        with mock.patch.dict("os.environ", {"AGENTREINS_KEYCHAIN_BACKEND": "memory"}, clear=False), \
                mock.patch.object(evidence.sys, "platform", "linux"):
            self.assertEqual(_SHIPPED_BACKEND(), "unsupported")
        shipped = [pathlib.Path(evidence.__file__), pathlib.Path(evidence.__file__).with_name("server.py")]
        for path in shipped:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("AGENTREINS_KEYCHAIN_BACKEND", text, path)
            self.assertNotIn("_MEMORY_KEYCHAIN", text, path)


if __name__ == "__main__":
    unittest.main()
