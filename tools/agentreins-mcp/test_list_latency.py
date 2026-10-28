"""list_agents stays fast against a large jsonl, and a cold Keychain does not block the first call.

Before this change a tools/call on the Mac waited out the 15s Keychain helper on a cold
cache (first list_agents ~15.2s) and re-read large journals on every later call (warm ~4–5s).
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


def _fake_helper(directory: pathlib.Path, body: str) -> pathlib.Path:
    path = directory / "fake-keychain-helper.sh"
    path.write_text("#!/bin/sh\n# FIXTURE: stands in for AgentReinsKeychainHelper\n" + body + "\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class ListLatency(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ar-list-"))
        self.audit = self.tmp / "audit"
        self.transport = self.tmp / "transport"
        self.audit.mkdir()
        self.transport.mkdir()
        self.routes = self.tmp / "routes.jsonl"
        self.patches = [
            mock.patch.object(evidence, "AUDIT_DIR", self.audit),
            mock.patch.object(evidence, "DEFAULT_TRANSPORT", self.transport),
            mock.patch.object(evidence, "AUDIT_LOG", self.audit / "mcp-supervisor-audit.jsonl"),
            mock.patch.object(evidence, "AUDIT_SEAL", self.audit / "mcp-supervisor-audit.seal"),
            mock.patch.object(evidence, "HMAC_KEY_FILE", self.audit / "mcp-supervisor-hmac.key"),
            mock.patch.object(evidence, "RUN_INVENTORY", self.audit / "transport-run-inventory.jsonl"),
            mock.patch.object(evidence, "INTEGRITY_DIR", self.tmp / "integrity"),
            mock.patch.object(evidence, "PROTECTED_SEAL_DIR", self.tmp / "integrity" / "seals"),
            mock.patch.object(evidence, "SIGNED_ERA_FLAG", self.tmp / "integrity" / "signed-era"),
            mock.patch.object(evidence, "RUN_INVENTORY_MAC", self.tmp / "integrity" / "transport-run-inventory.mac"),
            mock.patch.object(evidence, "ROUTE_JOURNAL", self.routes),
            mock.patch.object(evidence, "SOCKET_LEDGER", self.tmp / "missing-ledger.json"),
        ]
        (self.tmp / "integrity").mkdir()
        for patch in self.patches:
            patch.start()
        evidence._TRANSPORT_INDEX.update({
            "root": None, "rootMtime": None, "names": None, "rows": {}, "parsedFiles": 0, "lastTruncated": False,
        })
        evidence._ROUTE_TAIL.update({"sig": None, "flows": [], "bytesRead": 0})
        evidence._AUDIT_TAIL.update({"sig": None, "entries": [], "bytes": 0})
        evidence._AUDIT_LINES.update({"sig": None, "lines": [], "bytes": 0})
        evidence.AUDIT_TIP.identity = None
        evidence.AUDIT_TIP.bytes_read = 0
        evidence.KEY_WARM.reset()

    def tearDown(self) -> None:
        evidence.KEY_WARM.reset()
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_warm_list_agents_does_not_reread_a_large_jsonl(self) -> None:
        # ~24MB of synthetic audit lines. A full json.loads of every line on each call
        # blows the 500ms budget; the tail cache must not read it again.
        log = evidence.AUDIT_LOG
        line = (json.dumps({"hash": "ab" * 32, "mac": "cd" * 32, "prevHash": "0" * 64, "tool": "list_agents"}) + "\n").encode()
        repeats = (24 * 1024 * 1024) // len(line)
        blob = line * 4096
        written = 0
        with log.open("wb") as fh:
            while written + 4096 <= repeats:
                fh.write(blob)
                written += 4096
            if repeats > written:
                fh.write(line * (repeats - written))
        self.assertGreater(log.stat().st_size, 20 * 1024 * 1024)

        evidence.AUDIT_TIP.bytes_read = 0
        count, prev = evidence.AUDIT_TIP.tip(log)
        first_read = evidence.AUDIT_TIP.bytes_read
        self.assertEqual(count, repeats)
        self.assertEqual(prev, "ab" * 32)
        self.assertGreater(first_read, 20 * 1024 * 1024)

        evidence.AUDIT_TIP.bytes_read = 0
        started = time.perf_counter()
        for _ in range(5):
            again, prev2 = evidence.AUDIT_TIP.tip(log)
            agents = evidence.list_agents(limit=5)
        elapsed = (time.perf_counter() - started) / 5
        self.assertEqual(again, repeats)
        self.assertEqual(prev2, prev)
        self.assertEqual(evidence.AUDIT_TIP.bytes_read, 0)
        self.assertLess(elapsed, 0.5, "warm list_agents %.3fs" % elapsed)
        self.assertIn("agents", agents)

        # Route journal the size of the on-device workbuddy-network-routes.jsonl tail.
        # list_network must read the tail once and then nothing.
        pad = b'{"flowID":"pad","host":"example.com","clientAddress":"127.0.0.1:9","observedAt":"2026-10-28T00:00:00Z"}\n'
        real = (
            b'{"flowID":"live","host":"api.example","clientAddress":"127.0.0.1:40000",'
            b'"observedAt":"2026-10-28T01:00:00Z","attributionState":"via proxy \\u00b7 attribution lost",'
            b'"clientPid":null,"captureStage":"request"}\n'
        )
        with self.routes.open("wb") as fh:
            chunk = pad * 4000
            left = 200_000
            while left:
                n = min(4000, left)
                fh.write(chunk if n == 4000 else pad * n)
                left -= n
            fh.write(real)
        self.assertGreater(self.routes.stat().st_size, 16 * 1024 * 1024)
        flows = evidence.load_proxy_flows(self.routes)
        self.assertLess(evidence._ROUTE_TAIL["bytesRead"], 3 * 1024 * 1024)
        lost = [row for row in flows if row["flowID"] == "live"]
        self.assertEqual(lost[0]["attributionState"], "via proxy · attribution lost")
        self.assertIsNone(lost[0]["pid"])
        self.assertIsNone(lost[0]["agent"])
        evidence._ROUTE_TAIL["bytesRead"] = 123
        again_flows = evidence.load_proxy_flows(self.routes)
        self.assertEqual(evidence._ROUTE_TAIL["bytesRead"], 0)
        self.assertEqual(again_flows[0]["flowID"], lost[0]["flowID"])

        # Many transport runs: the second list_agents must not re-parse them.
        for index in range(400):
            run = self.transport / ("run-%04d" % index)
            run.mkdir()
            (run / "transport.json").write_text(json.dumps({
                "invocation": {
                    "captureMode": "agent-path", "agent": "WorkBuddy", "tool": "curl",
                    "call": "c-%d" % index, "startedAt": "2026-10-28T00:%02d:00Z" % (index % 60),
                    "session": "s",
                },
                "connections": [],
            }), encoding="utf-8")
        evidence._TRANSPORT_INDEX["parsedFiles"] = 0
        first = evidence.list_agents(limit=5)
        parsed = evidence._TRANSPORT_INDEX["parsedFiles"]
        self.assertGreater(parsed, 0)
        self.assertTrue(first["transportTruncated"])
        evidence._TRANSPORT_INDEX["parsedFiles"] = 0
        started = time.perf_counter()
        second = evidence.list_agents(limit=5)
        warm = time.perf_counter() - started
        self.assertEqual(evidence._TRANSPORT_INDEX["parsedFiles"], 0)
        self.assertLess(warm, 0.5, "warm list_agents over %d runs took %.3fs" % (400, warm))
        self.assertEqual(second["agents"][0]["agent"], "WorkBuddy")
        self.assertLess(elapsed, 0.5)

    def test_cold_keychain_first_call_does_not_block(self) -> None:
        evidence.KEY_WARM.reset()
        evidence._KEYCHAIN_STATE["unresponsiveUntil"] = 0.0
        evidence._KEYCHAIN_STATE.pop("statusCache", None)
        helper = _fake_helper(self.tmp, "echo $$ > '%s'\nexec sleep 300" % (self.tmp / "helper.pid"))
        with mock.patch.object(evidence, "_keychain_backend", lambda: "security"), \
                mock.patch.object(evidence, "_find_keychain_helper", return_value=helper), \
                mock.patch.object(evidence, "KEYCHAIN_HELPER_TIMEOUT", 30.0):
            started = time.perf_counter()
            out = server.call_tool("list_agents", {"limit": 5})
            elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 0.5, "cold keychain list_agents took %.3fs" % elapsed)
        self.assertEqual(out.get("keychainStatus"), "pending")
        self.assertIn("agents", out)
        self.assertFalse(evidence.AUDIT_LOG.exists())
        # The background helper is still the one we started; it must not have signed with a throwaway key.
        self.assertFalse(evidence.HMAC_KEY_FILE.exists())
        pid_path = self.tmp / "helper.pid"
        if pid_path.is_file():
            try:
                os.kill(int(pid_path.read_text().strip()), 15)
            except (OSError, ValueError):
                pass

    def test_list_agents_reports_keychain_status_when_the_key_is_ready(self) -> None:
        from keychain_fake import FAKE
        FAKE.items.clear()
        evidence.KEY_WARM.reset()
        evidence._KEYCHAIN_STATE["unresponsiveUntil"] = 0.0
        evidence._KEYCHAIN_STATE.pop("statusCache", None)
        patches = FAKE.patches(evidence)
        for patch in patches:
            patch.start()
        try:
            out = server.call_tool("list_agents", {"limit": 1})
        finally:
            for patch in patches:
                patch.stop()
            evidence.KEY_WARM.reset()
        self.assertEqual(out.get("keychainStatus"), "ok")

    def test_socket_sampling_surfaces_interval_note(self) -> None:
        sampled = evidence._socket_sampling({
            "intervalNote": "已安装的 LaunchAgent 仍传 --interval 2.0",
            "state": "sampling",
            "effectiveIntervalSeconds": 0.5,
        })
        self.assertEqual(sampled["intervalNote"], "已安装的 LaunchAgent 仍传 --interval 2.0")
        self.assertEqual(sampled["effectiveIntervalSeconds"], 0.5)

    def test_warm_list_mcp_audit_reads_the_tail_not_the_whole_log(self) -> None:
        # macOS CI has a Keychain, so the prime call's validate_audit appends one
        # integrity-boundary line after the tail cache is filled (~354 bytes).
        # That line has to land in the cache at write time; the next call reads nothing.
        from keychain_fake import FAKE
        FAKE.items.clear()
        line = (json.dumps({"at": "2026-10-28T00:00:00Z", "tool": "list_agents", "hash": "ab" * 32}) + "\n").encode()
        blob = line * 2000
        with evidence.AUDIT_LOG.open("wb") as fh:
            for _ in range(8):
                fh.write(blob)
        last = (json.dumps({"at": "2026-10-28T01:02:03Z", "tool": "get_coverage", "hash": "cd" * 32}) + "\n").encode()
        with evidence.AUDIT_LOG.open("ab") as fh:
            fh.write(last)
        size_before = evidence.AUDIT_LOG.stat().st_size
        self.assertGreater(size_before, 2_000_000)
        patches = FAKE.patches(evidence)
        for patch in patches:
            patch.start()
        try:
            evidence.list_mcp_audit(limit=5)  # prime; validation appends the boundary line
            self.assertGreater(evidence.AUDIT_LOG.stat().st_size, size_before)
            evidence._AUDIT_TAIL["bytes"] = 0
            evidence._AUDIT_LINES["bytes"] = 0
            started = time.perf_counter()
            out = evidence.list_mcp_audit(limit=5)
            elapsed = time.perf_counter() - started
        finally:
            for patch in patches:
                patch.stop()
            FAKE.items.clear()
        self.assertLess(elapsed, 0.5, "warm list_mcp_audit %.3fs" % elapsed)
        self.assertEqual(evidence._AUDIT_TAIL["bytes"], 0)
        self.assertEqual(evidence._AUDIT_LINES["bytes"], 0)
        tools = [row.get("tool") for row in out["entries"]]
        self.assertIn("get_coverage", tools)
        self.assertEqual(tools[-1], "integrity-boundary")


if __name__ == "__main__":
    unittest.main()
