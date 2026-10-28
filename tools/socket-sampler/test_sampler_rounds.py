"""Sampler v2: failed/timed-out/partial rounds are counted, restarts are recorded, coverage is measured,
and the ledger is signed and checked. ps/lsof output comes from the labelled fixtures (see fixtures/README.md);
the command runner is replaced so the tests can make ps time out on purpose."""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "agentreins-mcp"))
import socket_sampler as ss  # noqa: E402
import evidence  # noqa: E402

FX = HERE / "fixtures"
KEY = b"k" * 32


def ps_texts() -> tuple[str, str]:
    basic, detail = [], []
    heads = {}
    for line in (FX / "ps_macos_args.txt").read_text().splitlines():
        pid, _, args = line.strip().partition(" ")
        heads[pid] = args
    for line in (FX / "ps_macos_format.txt").read_text().splitlines():
        parts = line.split(None, 7)
        pid, ppid, lstart, comm = parts[0], parts[1], " ".join(parts[2:7]), parts[7]
        basic.append("%5s %5s %s" % (pid, ppid, comm))
        detail.append("%5s %s %s" % (pid, lstart, heads.get(pid, comm)))
    return "\n".join(basic) + "\n", "\n".join(detail) + "\n"


class FakeTools:
    """Replays fixture output for ps / lsof. `fail` maps stage -> 'timeout' | 'error' | 'partial'."""

    def __init__(self) -> None:
        self.basic, self.detail = ps_texts()
        self.lsof = (FX / "lsof_macos_format.txt").read_text()
        self.fail: dict[str, str] = {}
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout, stage):
        self.calls.append(list(cmd))
        mode = self.fail.get(stage)
        if mode == "timeout":
            raise ss.SampleError(stage, "timeout", "%s timed out after %.1fs" % (os.path.basename(cmd[0]), timeout))
        if mode == "error":
            raise ss.SampleError(stage, "error", "%s: OSError" % os.path.basename(cmd[0]))
        if stage == "ps":
            out, code, err = self.basic, 0, ""
        elif stage == "ps-detail":
            want = set(cmd[-1].split(",")) if "-p" in cmd else None
            rows = [l for l in self.detail.splitlines() if want is None or l.split()[0] in want]
            out, code, err = "\n".join(rows) + "\n", 0, ""
        else:
            out, code, err = self.lsof, (1 if mode == "partial" else 0), ("lsof: WARNING" if mode == "partial" else "")
        return subprocess.CompletedProcess(cmd, code, out, err)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-sampler-"))
        self.ledger = self.tmp / "socket-ledger.json"
        self.tools = FakeTools()
        self.p = mock.patch.object(ss, "run_tool", self.tools)
        self.p.start()

    def tearDown(self) -> None:
        self.p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sampler(self, **kw) -> ss.Sampler:
        kw.setdefault("interval", 2.0)
        kw.setdefault("backend", "legacy")  # replay fixture ps/lsof; the default collector is procfs/libproc
        return ss.Sampler(self.ledger, roots=None, discover=True, resolve=False, route_paths=[],
                          v2ray_log=self.tmp / "none.log", transport_root=self.tmp / "transport", **kw)

    def data(self) -> dict:
        return json.loads(self.ledger.read_text())


class RoundAccounting(Base):
    def test_ps_timeout_is_counted_with_reason_and_time(self) -> None:
        s = self.sampler()
        s.sample()
        self.tools.fail["ps"] = "timeout"
        out = s.sample()
        self.assertIn("ps/timeout", out["failure"])
        stats = self.data()["samples"]
        self.assertEqual(stats["failures"], 1)
        self.assertEqual(stats["count"], 2)
        self.assertEqual(stats["failureLog"][-1]["kind"], "timeout")
        self.assertEqual(stats["failureLog"][-1]["stage"], "ps")
        self.assertTrue(stats["lastFailureAt"].endswith("Z"))
        self.assertEqual([r[2] for r in stats["rounds"]], [True, False])
        self.assertEqual(self.data()["coverage"]["windowFailedRounds"], 1)

    def test_detail_timeout_and_lsof_error_and_partial_are_failures(self) -> None:
        s = self.sampler()
        self.tools.fail["ps-detail"] = "timeout"
        s.sample()
        self.tools.fail = {"lsof": "error"}
        s.sample()
        self.tools.fail = {"lsof": "partial"}
        out = s.sample()
        self.assertIsNotNone(out["partial"])
        log = self.data()["samples"]["failureLog"]
        self.assertEqual([(e["stage"], e["kind"]) for e in log],
                         [("ps-detail", "timeout"), ("lsof", "error"), ("lsof", "partial")])
        self.assertEqual(self.data()["samples"]["failures"], 3)

    def test_unexpected_exception_does_not_kill_or_vanish(self) -> None:
        s = self.sampler()
        with mock.patch.object(ss, "merge_sample", side_effect=KeyError("boom")):
            out = s.sample()
        self.assertIn("round/error", out["failure"])
        self.assertEqual(self.data()["samples"]["failures"], 1)
        s.sample()  # next round works
        self.assertEqual(self.data()["samples"]["rounds"][-1][2], True)

    def test_ps_runs_cheap_every_round_and_detail_only_for_new_pids(self) -> None:
        s = self.sampler()
        s.sample()
        s.sample()
        s.sample()
        stages = [c for c in self.tools.calls if "-ww" in c or "-axww" in c]
        self.assertEqual(len(stages), 1, "lstart/args must be fetched once and cached")
        basic = [c for c in self.tools.calls if c[1:3] == ["-axo", "pid=,ppid=,comm="]]
        self.assertEqual(len(basic), 3)
        lsof = [c for c in self.tools.calls if c[0] == ss.LSOF]
        self.assertEqual(len(lsof), 3)
        self.assertNotIn("-p", lsof[0], "one lsof -i for all sockets, not per pid")


class Coverage(unittest.TestCase):
    def test_measured_not_configured(self) -> None:
        t = 1_700_000_000.0
        starts = [0, 3.9, 7.8, 11.7, 29.3, 33.2, 37.1, 41.0]  # one 17.6 s stall
        rounds = [[t + x, 0.4, True] for x in starts]
        cov = ss.measured_coverage({"rounds": rounds}, 2.0)
        self.assertEqual(cov["configuredIntervalSeconds"], 2.0)
        self.assertEqual(cov["observedCycleSecondsP50"], 3.9)
        self.assertEqual(cov["maxFirstDetectionDelaySeconds"], 17.6)
        self.assertEqual(cov["missesShorterThanSeconds"], cov["successGapSecondsP95"])
        self.assertGreaterEqual(cov["missesShorterThanSeconds"], 3.9)
        self.assertEqual(cov["measurementConfidence"], "Observed")

    def test_failed_rounds_widen_the_gap(self) -> None:
        t = 1_700_000_000.0
        rounds = [[t + 2 * i, 0.1, i not in (3, 4, 5)] for i in range(10)]
        cov = ss.measured_coverage({"rounds": rounds}, 2.0)
        self.assertEqual(cov["observedCycleSecondsP50"], 2.0)
        self.assertEqual(cov["maxFirstDetectionDelaySeconds"], 8.0)
        self.assertEqual(cov["windowFailedRounds"], 3)

    def test_too_few_rounds_is_unknown(self) -> None:
        cov = ss.measured_coverage({"rounds": [[1.0, 0.1, True], [3.0, 0.1, True]]}, 2.0)
        self.assertEqual(cov["measurementConfidence"], "Unknown")


class Lifecycle(Base):
    def test_restart_after_gap_is_recorded(self) -> None:
        s = self.sampler()
        s.sample()
        data = self.data()
        data["samples"]["lastAt"] = ss.utc_iso(time.time() - 60)
        data_bytes = ss.save_ledger(self.ledger, data)  # unsigned run: no key
        del data_bytes
        s2 = self.sampler()
        s2.note_start()
        log = self.data()["samples"]["failureLog"]
        self.assertEqual(log[-1]["kind"], "restart_gap")
        self.assertGreater(log[-1]["gapSeconds"], 50)
        self.assertEqual(self.data()["samples"]["failures"], 1)

    def test_quick_restart_is_not_a_gap(self) -> None:
        s = self.sampler()
        s.sample()
        self.sampler().note_start()
        self.assertNotIn("restart_gap", [e["kind"] for e in self.data()["samples"].get("failureLog", [])])

    def test_key_unavailable_keeps_sampling_unsigned_and_is_a_counted_failure(self) -> None:
        # CI run 39655188074: the Keychain helper timed out. The sampler must keep sampling, unsigned, and say why.
        reason = "integrity key unavailable: KeychainUnavailable: keychain read failed (keychain helper timed out after 15s)"
        s = self.sampler(key=None, key_reason=reason)
        s.note_start()
        for _ in range(3):
            self.assertIsNone(s.sample()["failure"])
        data = self.data()
        stats = data["samples"]
        self.assertEqual(stats["count"], 3)
        self.assertEqual([e["kind"] for e in stats["failureLog"]], ["key_unavailable"])
        self.assertEqual(stats["failureLog"][0]["stage"], "keychain")
        self.assertIn("timed out", stats["failureLog"][0]["reason"])
        self.assertEqual(stats["failures"], 1)
        self.assertEqual(data["coverage"]["windowFailedRounds"], 0)  # sampling itself did not fail
        side = json.loads(ss.sidecar_path(self.ledger).read_text())
        self.assertEqual(side, {"unsigned": True, "reason": reason})
        verdict = ss.verify_snapshot(self.ledger.read_bytes(), side, None, KEY)
        self.assertEqual(verdict["state"], "unsigned")

    def test_stop_is_logged_but_not_a_failure(self) -> None:
        s = self.sampler()
        s.sample()
        s.note_stop("SIGTERM")
        stats = self.data()["samples"]
        self.assertEqual(stats["failureLog"][-1]["kind"], "stopped")
        self.assertEqual(stats.get("failures", 0), 0)


class Signing(Base):
    def setUp(self) -> None:
        super().setUp()
        self.seal = self.tmp / "seals" / "socket-ledger.seal"
        self.seal.parent.mkdir()

    def signed(self) -> ss.Sampler:
        return self.sampler(key=KEY, seal_path=self.seal)

    def verify(self) -> dict:
        return ss.verify_snapshot(self.ledger.read_bytes() if self.ledger.exists() else None,
                                  ss._read_json(ss.sidecar_path(self.ledger)), ss._read_json(self.seal), KEY)

    def test_chain_verifies_and_advances(self) -> None:
        s = self.signed()
        s.sample()
        s.sample()
        v = self.verify()
        self.assertEqual(v["state"], "verified")
        self.assertEqual(json.loads(ss.sidecar_path(self.ledger).read_text())["seq"], 2)
        self.assertIn("integritySince", self.data())

    def test_edited_ledger_is_tampered_and_quarantined_not_resigned(self) -> None:
        s = self.signed()
        s.sample()
        s.sample()
        text = self.ledger.read_text().replace('"Cursor"', '"Safari"')
        self.ledger.write_text(text)
        self.assertEqual(self.verify()["state"], "tampered")
        s2 = self.signed()
        s2.sample()
        kept = list(self.tmp.glob("socket-ledger.json.tampered-*"))
        self.assertTrue([k for k in kept if not k.name.endswith(".mac")])
        data = self.data()
        self.assertEqual(data["integrityEvents"][0]["kind"], "tamper_detected_at_load")
        self.assertEqual(self.verify()["state"], "verified")  # new chain continues from the seal
        self.assertEqual(json.loads(ss.sidecar_path(self.ledger).read_text())["seq"], 3)

    def test_wrong_key_is_tampered(self) -> None:
        s = self.signed()
        s.sample()
        v = ss.verify_snapshot(self.ledger.read_bytes(), ss._read_json(ss.sidecar_path(self.ledger)),
                               ss._read_json(self.seal), b"x" * 32)
        self.assertEqual(v["state"], "tampered")

    def test_rollback_to_older_signed_copy_is_tampered(self) -> None:
        s = self.signed()
        s.sample()
        old_l, old_s = self.ledger.read_bytes(), ss.sidecar_path(self.ledger).read_bytes()
        s.sample()
        s.sample()
        self.ledger.write_bytes(old_l)
        ss.sidecar_path(self.ledger).write_bytes(old_s)
        self.assertEqual(self.verify()["state"], "tampered")

    def test_deleted_ledger_after_signing_is_not_missing(self) -> None:
        s = self.signed()
        s.sample()
        self.ledger.unlink()
        ss.sidecar_path(self.ledger).unlink()
        self.assertEqual(self.verify()["state"], "tampered")


class McpReadsLedgerIntegrity(Base):
    """evidence.load_socket_ledger must check the same chain and label a broken one tampered/Unknown."""

    def setUp(self) -> None:
        super().setUp()
        self.seal = self.tmp / "socket-ledger.json.seal"
        self.patches = [mock.patch.object(evidence, "SOCKET_LEDGER", self.ledger),
                        mock.patch.object(evidence, "_ledger_key", lambda: KEY)]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in self.patches:
            p.stop()
        super().tearDown()

    def run_rounds(self, n: int = 7) -> None:
        s = self.sampler(key=KEY, seal_path=self.seal)
        for _ in range(n):
            s.sample()

    def test_verified_ledger(self) -> None:
        self.run_rounds()
        out = evidence.load_socket_ledger()
        self.assertEqual(out["coverage"]["integrity"]["state"], "verified")
        self.assertTrue(all(r.get("ledgerIntegrity") != "tampered" for r in out["connections"]))

    def test_tampered_ledger_rows_are_unknown(self) -> None:
        self.run_rounds()
        data = self.data()
        for row in data["connections"]:
            row["realDestination"] = "harmless.example"
        self.ledger.write_text(json.dumps(data))
        out = evidence.load_socket_ledger()
        cov = out["coverage"]
        self.assertEqual(cov["integrity"]["state"], "tampered")
        self.assertEqual(cov["confidence"], "Unknown")
        self.assertTrue(out["connections"])
        for row in out["connections"]:
            self.assertEqual(row["evidence"], "Unknown")
            self.assertEqual(row["destinationEvidence"], "Unknown")
            self.assertEqual(row["ledgerIntegrity"], "tampered")
        net = evidence.list_network(records=[])
        self.assertEqual(net["socketSummary"]["ledgerIntegrity"], "tampered")

    def test_sidecar_removed_after_signing_is_tampered_not_unsigned(self) -> None:
        self.run_rounds(2)
        ss.sidecar_path(self.ledger).unlink()
        self.assertEqual(evidence.load_socket_ledger()["coverage"]["integrity"]["state"], "tampered")

    def test_python_mcp_and_sampler_agree(self) -> None:
        self.run_rounds(3)
        data = self.ledger.read_bytes()
        side = ss._read_json(ss.sidecar_path(self.ledger))
        seal = ss._read_json(self.seal)
        old_side = dict(side, seq=side["seq"] - 1)
        cases = {
            "verified": (data, side, seal, KEY),
            "edited": (data + b" ", side, seal, KEY),
            "wrong key": (data, side, seal, b"z" * 32),
            "deleted": (None, None, seal, KEY),
            "no seal": (data, side, None, KEY),
            "rolled back": (data, old_side, seal, KEY),
            "never signed": (data, {"unsigned": True, "reason": "x"}, None, KEY),
            "no key": (data, side, seal, None),
        }
        for name, args in cases.items():
            a, b = ss.verify_snapshot(*args), evidence.verify_socket_ledger(*args)
            self.assertEqual((a["state"], a.get("reason")), (b["state"], b.get("reason")), name)


if __name__ == "__main__":
    unittest.main()
