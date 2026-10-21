"""The packaged Swift MCP core (Sources/AgentReinsMCP/Core*.swift) must answer exactly like evidence.py.

Builds Tests/SwiftMCPParity (Core*.swift + a portable SHA-256/HMAC + a JSON-file Keychain) with swiftc and
runs both implementations on the same fixture worlds. Also checks that each side accepts the other's
signatures (canonical JSON: sorted keys, no escaped "/", e.g. actor "codex-mcp-client/0.1").

Fixtures are synthetic and labelled; nothing here is live evidence.
Without a Swift toolchain the test is skipped, unless AGENTREINS_REQUIRE_SWIFT_PARITY=1 (CI), then it fails.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import evidence

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "tools" / "socket-sampler"))
import socket_sampler as ss  # noqa: E402
import test_inb_and_destination as inbfx  # noqa: E402

K0 = b"0" * 32  # deleted pre-migration key (fixture)
K1 = b"1" * 32  # current Keychain key (fixture)
ERA_AT = "2026-10-21T15:08:55Z"
LEGACY_AT = ["2026-10-20T22:12:23Z", "2026-10-21T09:00:00Z", "2026-10-21T14:59:59Z"]
ACTOR = "codex-mcp-client/0.1"
HARNESS: pathlib.Path | None = None
BUILD_ERROR: str | None = None


def build_harness() -> None:
    global HARNESS, BUILD_ERROR
    if HARNESS is not None or BUILD_ERROR is not None:
        return
    swiftc = os.environ.get("AGENTREINS_SWIFTC") or shutil.which("swiftc")
    if not swiftc:
        BUILD_ERROR = "swiftc not found"
        return
    out = pathlib.Path(tempfile.mkdtemp(prefix="ar-parity-")) / "harness"
    sources = sorted(str(p) for p in (REPO / "Sources/AgentReinsMCP").glob("Core*.swift"))
    sources += sorted(str(p) for p in (REPO / "Tests/SwiftMCPParity").glob("*.swift"))
    proc = subprocess.run([swiftc, "-O", "-swift-version", "5", "-o", str(out), *sources],
                          capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        BUILD_ERROR = "harness build failed:\n" + proc.stderr[-4000:]
        return
    HARNESS = out


def harness(*args: str) -> dict:
    proc = subprocess.run([str(HARNESS), *args], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise AssertionError("harness %s failed: %s" % (args[0], proc.stderr))
    return json.loads(proc.stdout)


class World:
    """One fixture world on disk: audit dir, integrity dir, transport root and a JSON-file Keychain."""

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        self.audit, self.integrity, self.transport = root / "audit", root / "integrity", root / "transport"
        for d in (self.audit, self.integrity, self.transport):
            d.mkdir(parents=True, exist_ok=True)
        self.kc = root / "keychain.json"
        if not self.kc.exists():
            self.kc.write_text("{}", encoding="utf-8")

    def copy(self, name: str) -> "World":
        dst = self.root.parent / name
        shutil.copytree(self.root, dst)
        return World(dst)

    def patches(self) -> list:
        a, i = self.audit, self.integrity
        return [
            mock.patch.object(evidence, "AUDIT_DIR", a),
            mock.patch.object(evidence, "DEFAULT_TRANSPORT", self.transport),
            mock.patch.object(evidence, "AUDIT_LOG", a / "mcp-supervisor-audit.jsonl"),
            mock.patch.object(evidence, "AUDIT_SEAL", a / "mcp-supervisor-audit.seal"),
            mock.patch.object(evidence, "HMAC_KEY_FILE", a / "mcp-supervisor-hmac.key"),
            mock.patch.object(evidence, "RUN_INVENTORY", a / "transport-run-inventory.jsonl"),
            mock.patch.object(evidence, "INTEGRITY_DIR", i),
            mock.patch.object(evidence, "PROTECTED_SEAL_DIR", i / "seals"),
            mock.patch.object(evidence, "SIGNED_ERA_FLAG", i / "signed-era"),
            mock.patch.object(evidence, "RUN_INVENTORY_MAC", i / "transport-run-inventory.mac"),
            mock.patch.dict("os.environ", {"AGENTREINS_KEYCHAIN_BACKEND": "memory"}, clear=False),
        ]

    def py(self, fn, *args, **kw):
        """Run an evidence.py function inside this world; the memory Keychain round-trips through keychain.json."""
        ps = self.patches()
        for p in ps:
            p.start()
        evidence._MEMORY_KEYCHAIN.clear()
        for k, v in json.loads(self.kc.read_text(encoding="utf-8")).items():
            evidence._MEMORY_KEYCHAIN[k] = bytes.fromhex(v)
        try:
            return fn(*args, **kw)
        finally:
            self.kc.write_text(json.dumps({k: v.hex() for k, v in evidence._MEMORY_KEYCHAIN.items()}), encoding="utf-8")
            evidence._MEMORY_KEYCHAIN.clear()
            for p in reversed(ps):
                p.stop()

    def swift(self, command: str, *extra: str) -> dict:
        return harness(command, "--audit", str(self.audit), "--integrity", str(self.integrity),
                       "--transport", str(self.transport), "--keychain", str(self.kc), *extra)

    def kc_set(self, account: str, value: bytes) -> None:
        items = json.loads(self.kc.read_text(encoding="utf-8"))
        items[account] = value.hex()
        self.kc.write_text(json.dumps(items), encoding="utf-8")

    def kc_del(self, account: str) -> None:
        items = json.loads(self.kc.read_text(encoding="utf-8"))
        items.pop(account, None)
        self.kc.write_text(json.dumps(items), encoding="utf-8")

    @property
    def log(self) -> pathlib.Path:
        return self.audit / "mcp-supervisor-audit.jsonl"

    def lines(self) -> list[str]:
        return [ln for ln in self.log.read_text(encoding="utf-8").splitlines() if ln.strip()]


def projection(v: dict) -> dict:
    """What must be identical between Python and Swift."""
    leg = v.get("legacyUnverifiable") or {}
    cur = v.get("currentTampered") or {}
    b = v.get("boundary") or {}
    return {
        "ok": v.get("ok"), "status": v.get("status"), "statusText": v.get("statusText"),
        "entriesChecked": v.get("entriesChecked"),
        "currentCount": cur.get("count"), "currentReasons": cur.get("reasons"),
        "legacy": [leg.get(k) for k in ("count", "auditEntries", "evidenceFiles", "from", "to", "reason", "confidence")],
        "boundary": [b.get(k) for k in ("state", "source", "auditBoundaryIndex", "legacyAuditCount",
                                        "legacyEvidenceCount", "legacyFrom", "legacyTo", "confidence")],
        "sameUidCanForge": (v.get("b6") or {}).get("sameUidCanForge"),
        "confidence": v.get("confidence"),
    }


def entry(at: str, i: int, prev: str, key: bytes) -> tuple[str, str]:
    e = {"at": at, "actor": ACTOR, "tool": "list_alerts", "argsDigest": "%024d" % i, "prevHash": prev}
    e["mac"] = evidence.entry_hmac(e, key)
    e["hash"] = evidence.sha256_hex(evidence.canonical_json(e) + prev)
    return evidence.canonical_json(e), e["hash"]


def upgrade_world(w: World) -> None:
    """Legacy history under K0 (deleted), K1 + era in the Keychain, one post-migration entry and seal written
    by hand, so the boundary is NOT recorded yet: each implementation has to infer it on its own."""
    prev, out = "0" * 64, []
    for i, at in enumerate(LEGACY_AT):
        line, prev = entry(at, i, prev, K0)
        out.append(line)
    line, prev = entry("2026-10-21T15:30:00Z", 9, prev, K1)
    out.append(line)
    w.log.write_text("".join(ln + "\n" for ln in out), encoding="utf-8")
    seal = {"count": len(out), "headHash": prev, "schema": 1}
    seal["mac"] = evidence.entry_hmac(seal, K1)
    (w.audit / "mcp-supervisor-audit.seal").write_text(evidence.canonical_json(seal) + "\n", encoding="utf-8")
    (w.integrity / "seals").mkdir(exist_ok=True)
    (w.integrity / "seals" / "mcp-supervisor-audit.seal").write_text(evidence.canonical_json(seal) + "\n",
                                                                     encoding="utf-8")
    run = w.transport / "run-legacy"
    run.mkdir()
    for name, body in (("transport.json", '{"legacy":true}'), ("manifest.json", '{"call":"run-legacy"}')):
        path = run / name
        path.write_text(body, encoding="utf-8")
        (run / (name + ".mac")).write_text(evidence.evidence_file_mac(path, K0) + "\n", encoding="utf-8")
        past = evidence._iso_ts(LEGACY_AT[1])
        os.utime(path, (past, past))
    era = json.dumps({"at": ERA_AT, "keyFingerprint": evidence._key_fingerprint(K1), "schema": 2}, sort_keys=True)
    w.kc_set(evidence.KEYCHAIN_ACCOUNT_HMAC, K1)
    w.kc_set(evidence.KEYCHAIN_ACCOUNT_ERA, era.encode())
    (w.integrity / "signed-era").write_text(era + "\n", encoding="utf-8")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        build_harness()
        if HARNESS is None:
            if os.environ.get("AGENTREINS_REQUIRE_SWIFT_PARITY") == "1":
                raise AssertionError(BUILD_ERROR)
            raise unittest.SkipTest(BUILD_ERROR or "no harness")

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-parity-world-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def same(self, a: World, b: World) -> tuple[dict, dict]:
        pv = a.py(evidence.validate_audit)
        sv = b.swift("validate")
        self.assertEqual(projection(pv), projection(sv))
        return pv, sv


class IntegrityParity(Base):
    def test_upgrade_split_each_side_infers_the_same_boundary(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertEqual(pv["status"], "current_ok_legacy_unverifiable")
        self.assertEqual(pv["legacyUnverifiable"]["count"], 5)
        self.assertEqual(sv["boundary"]["auditBoundaryIndex"], 3)

    def test_marker_written_by_swift_is_accepted_by_python_and_vice_versa(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        sw = w.copy("sw")
        sw.swift("validate")  # Swift records the boundary
        pv = sw.py(evidence.validate_audit)
        self.assertTrue(pv["ok"], pv)
        self.assertEqual(pv["boundary"]["state"], "recorded")
        py = w.copy("py")
        py.py(evidence.validate_audit)  # Python records the boundary
        sv = py.swift("validate")
        self.assertTrue(sv["ok"], sv)
        self.assertEqual(sv["boundary"]["state"], "recorded")

    def test_post_migration_edit_is_current_in_both(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        w.py(evidence.validate_audit)
        lines = w.lines()
        e = json.loads(lines[3])
        e["tool"] = "edited"
        lines[3] = evidence.canonical_json(e)
        w.log.write_text("".join(ln + "\n" for ln in lines), encoding="utf-8")
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertFalse(sv["ok"])
        self.assertIn("mac_mismatch", sv["currentTampered"]["reasons"])

    def test_deleted_marker_is_tampering_in_both(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        w.py(evidence.validate_audit)
        w.kc_del(evidence.KEYCHAIN_ACCOUNT_BOUNDARY)
        (w.integrity / "integrity-boundary.json").unlink()
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertFalse(sv["ok"])
        self.assertIn("boundary_marker_deleted", sv["currentTampered"]["reasons"])
        self.assertEqual(sv["legacyUnverifiable"]["auditEntries"], 0)  # nothing moved into legacy

    def test_legacy_evidence_edit_is_current_in_both(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        w.py(evidence.validate_audit)
        (w.transport / "run-legacy" / "transport.json").write_text('{"legacy":false}', encoding="utf-8")
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertIn("legacy_evidence_modified_after_boundary", sv["currentTampered"]["reasons"])

    def test_fresh_install_mixed_writers_chain_verifies(self) -> None:
        w = World(self.tmp / "w")
        w.py(evidence.append_audit, ACTOR, "list_alerts", {"agent": "Codex"})
        w.swift("append", "--actor", ACTOR, "--tool", "get_execution", "--args", '{"execution_id":"a/b"}')
        w.py(evidence.append_audit, "Claude Code/2.0", "list_network", {})
        w.swift("append", "--actor", "codex/1.2 (macOS)", "--tool", "get_coverage", "--args", "{}")
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertTrue(sv["ok"], sv)
        self.assertEqual(sv["status"], "ok")
        self.assertEqual(sv["boundary"]["source"], "recorded-at-signed-era-start")

    def test_swift_reads_do_not_launder_an_inventory_edit(self) -> None:
        w = World(self.tmp / "w")
        run = w.transport / "run-1"
        run.mkdir()
        (run / "transport.json").write_text("{}", encoding="utf-8")
        w.py(evidence.sign_evidence_tree, w.transport)
        w.py(evidence.append_audit, ACTOR, "list_alerts", {})
        shutil.rmtree(run)
        (w.audit / "transport-run-inventory.jsonl").write_text("", encoding="utf-8")
        w.swift("append", "--actor", ACTOR, "--tool", "list_alerts", "--args", "{}")
        pv, sv = self.same(w.copy("py"), w.copy("sw"))
        self.assertFalse(pv["ok"], pv)

    def test_no_key_is_key_unavailable_not_a_new_key(self) -> None:
        w = World(self.tmp / "w")
        upgrade_world(w)
        w.kc_del(evidence.KEYCHAIN_ACCOUNT_HMAC)
        (w.integrity / "seals").mkdir(exist_ok=True)
        sv = w.swift("validate")
        # Swift: no file fallback; a missing Keychain key in a signed era is minted only via the Keychain,
        # and the old entries then fail as current tampering (hmac_key_replaced_after_signed_era).
        self.assertFalse(sv["ok"])
        self.assertIn("hmac_key_replaced_after_signed_era", sv["currentTampered"]["reasons"])


class LedgerParity(Base):
    def test_verify_cases_match_sampler(self) -> None:
        root = self.tmp
        ledger, seal = root / "socket-ledger.json", root / "socket-ledger.json.seal"
        sampler = ss.Sampler(ledger, roots={os.getpid(): "Codex"}, discover=False, resolve=False, route_paths=[],
                             v2ray_log=root / "none", transport_root=root / "t", key=K1, seal_path=seal, interval=1.0)
        for _ in range(3):
            sampler.sample()
        side_path = ss.sidecar_path(ledger)
        good = (ledger.read_bytes(), side_path.read_bytes(), seal.read_bytes())
        side = json.loads(good[1])
        cases = {
            "verified": (good[0], good[1], good[2], K1),
            "edited": (good[0] + b" ", good[1], good[2], K1),
            "wrong key": (good[0], good[1], good[2], b"z" * 32),
            "rolled back": (good[0], json.dumps(dict(side, seq=side["seq"] - 1)).encode(), good[2], K1),
            "no seal": (good[0], good[1], None, K1),
            "deleted": (None, None, good[2], K1),
            "no sidecar": (good[0], None, good[2], K1),
            "never signed": (good[0], b'{"unsigned": true, "reason": "x"}', None, K1),
            "no key": (good[0], good[1], good[2], None),
        }
        for name, (data, sd, sl, key) in cases.items():
            d = root / name.replace(" ", "_")
            d.mkdir()
            paths = {}
            for label, blob in (("ledger", data), ("side", sd), ("seal", sl)):
                p = d / label
                if blob is not None:
                    p.write_bytes(blob)
                paths[label] = p
            py = ss.verify_snapshot(data, json.loads(sd) if sd else None, json.loads(sl) if sl else None, key)
            args = ["verify-ledger", "--ledger", str(paths["ledger"]), "--side", str(paths["side"]),
                    "--seal", str(paths["seal"])]
            if key is not None:
                args += ["--keyhex", key.hex()]
            sw = harness(*args)
            self.assertEqual((py["state"], py.get("reason")), (sw["state"], sw.get("reason")), name)

    def test_tampered_ledger_view_matches(self) -> None:
        root = self.tmp
        ledger, seal = root / "socket-ledger.json", root / "socket-ledger.json.seal"
        data = {"schema": 1, "sampler": "socket-sampler/2", "samples": {"count": 3, "lastAt": ss.utc_iso()},
                "coverage": {"configuredIntervalSeconds": 2.0, "missesShorterThanSeconds": 2.1,
                             "measurementConfidence": "Observed"},
                "connections": [{"id": "x", "agent": "Codex", "remoteAddress": "1.2.3.4:443", "viaProxy": False,
                                 "scope": "public", "evidence": "Observed", "destinationEvidence": "Observed",
                                 "lastSeen": ss.utc_iso()}]}
        raw = ss.save_ledger(ledger, data)
        side = ss.sign_snapshot(raw, 1, "0" * 64, K1)
        for p in (ss.sidecar_path(ledger), seal):
            p.write_text(ss.canonical(side) + "\n", encoding="utf-8")
        for tamper in (False, True):
            if tamper:
                ledger.write_text(ledger.read_text().replace("1.2.3.4", "9.9.9.9"))
            with mock.patch.object(evidence, "_ledger_key", lambda: K1):
                py = evidence.load_socket_ledger(path=ledger)
            sw = harness("ledger", "--ledger", str(ledger), "--seal", str(seal), "--keyhex", K1.hex())
            for k in ("state", "confidence", "measurementConfidence", "failures"):
                self.assertEqual(py["coverage"].get(k), sw["coverage"].get(k), (tamper, k))
            self.assertEqual(py["coverage"]["integrity"]["state"], sw["coverage"]["integrity"]["state"])
            self.assertEqual(py["connections"], sw["connections"])


class RecordParity(Base):
    def records(self) -> dict[str, dict]:
        fx = json.loads((HERE / "fixtures/recorded-proxied-curl/transport.json").read_text(encoding="utf-8"))
        recs = {"proxied": {"connections": fx["connections"], "args": fx["invocation"]["args"]}}
        recs["argv"] = {"connections": [], "args": ["--proxy", "http://127.0.0.1:1087", "https://www.emaildee.com/x"]}
        recs["argv_pseudo"] = {"connections": [{"kind": "connected", "detail": ["git.example.org"], "source": "argv"}],
                               "args": ["git@git.example.org:repo.git"]}
        recs["loopback"] = {"connections": [{"kind": "connected", "detail": ["127.0.0.1 (127.0.0.1) port 18891"]}],
                            "args": []}
        run = self.tmp / "inb"
        (run / "bodies").mkdir(parents=True)
        (run / "bodies" / "7.bin").write_text(inbfx.RESPONSE, encoding="utf-8")
        for name, keep_ctx, keep_body in (("inb_new", True, False), ("inb_rescan", False, True), ("inb_bare", False, False)):
            t = inbfx.inb_transport(name, keep_context=keep_ctx, keep_body=keep_body)
            recs[name] = {"connections": t["connections"], "args": t["invocation"]["args"], "blocks": t["blocks"],
                          "securityAudit": t["securityAudit"], "evidencePath": str(run / "transport.json")}
        return recs

    def test_destination_and_findings_match(self) -> None:
        for name, rec in self.records().items():
            path = self.tmp / (name + ".json")
            path.write_text(json.dumps(rec), encoding="utf-8")
            sw = harness("record", "--record", str(path))
            self.assertEqual(evidence.destination_fields(rec), sw["destination"], name)
            py_f = [evidence.credential_finding_summary(f, rec) for f in (rec.get("securityAudit") or {}).get("findings", [])]
            self.assertEqual(py_f, sw["findings"], name)

    def test_redaction_vectors(self) -> None:
        out = harness("redact-vectors", "--vectors", str(REPO / "tools/redact_vectors.json"))
        self.assertGreater(out["cases"], 30)
        self.assertEqual(out["failures"], 0)


class SwiftHelperKeychainFailures(Base):
    """The shipped Swift HelperKeychain against fake helpers (fixtures): CI run 39655188074 regression."""

    def fake(self, body: str) -> pathlib.Path:
        path = self.tmp / "fake-helper.sh"
        path.write_text("#!/bin/sh\n# FIXTURE: stands in for AgentReinsKeychainHelper\n" + body + "\n")
        path.chmod(0o700)
        for d in ("audit", "integrity", "transport"):
            (self.tmp / d).mkdir(exist_ok=True)
        return path

    def lookups(self, helper: pathlib.Path, n: int) -> dict:
        return harness("helper-lookups", "--helper", str(helper), "--n", str(n), "--audit", str(self.tmp / "audit"),
                       "--integrity", str(self.tmp / "integrity"), "--transport", str(self.tmp / "transport"))

    def test_needs_approval_fails_fast_with_reason(self) -> None:
        out = self.lookups(self.fake('echo "get failed: OSStatus -25308" >&2\nexit 4'), 2)
        for call in out["calls"]:
            self.assertLess(call["seconds"], 5)
            self.assertIn("needs user approval", call["reason"])
        self.assertFalse(out["keyFileExists"])

    def test_hang_costs_one_timeout_then_backs_off(self) -> None:
        calls = self.tmp / "calls"
        out = self.lookups(self.fake('echo x >> "%s"\nexec sleep 40' % calls), 3)
        first, *rest = out["calls"]
        self.assertGreaterEqual(first["seconds"], 14)
        self.assertLess(first["seconds"], 20)
        self.assertIn("timed out", first["reason"])
        for call in rest:
            self.assertLess(call["seconds"], 1)
            self.assertIn("not retried yet", call["reason"])
        self.assertEqual(calls.read_text().count("x"), 1)
        self.assertFalse(out["keyFileExists"])


if __name__ == "__main__":
    unittest.main()
