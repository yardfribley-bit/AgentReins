"""list_network must surface proxy-independent socket samples (read-only, redacted)."""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evidence  # noqa: E402

ROWS = [
    {"id": "a", "agent": "Codex", "pid": 501, "ppid": 500, "processName": "node", "protocol": "TCP",
     "localAddress": "192.168.1.2:50000", "remoteAddress": "140.82.112.4:443", "remoteIP": "140.82.112.4",
     "remotePort": 443, "state": "ESTABLISHED", "firstSeen": "2026-10-21T10:00:00.000Z",
     "lastSeen": "2026-10-21T10:00:06.000Z", "sampleCount": 3, "scope": "public", "viaProxy": False,
     "transportPeer": "140.82.112.4:443", "realDestination": "lb-140-82-112-4-iad.github.com",
     "destinationSource": "dns_inferred", "destinationEvidence": "Inferred", "evidence": "Observed",
     "key": "internal"},
    {"id": "b", "agent": "Codex", "pid": 502, "ppid": 500, "processName": "curl", "protocol": "TCP",
     "localAddress": "127.0.0.1:51100", "remoteAddress": "127.0.0.1:18891", "remoteIP": "127.0.0.1",
     "remotePort": 18891, "state": "ESTABLISHED", "firstSeen": "2026-10-21T10:00:01.000Z",
     "lastSeen": "2026-10-21T10:00:01.000Z", "sampleCount": 1, "scope": "loopback", "viaProxy": True,
     "transportPeer": "127.0.0.1:18891", "realDestination": "api.openai.com",
     "destinationSource": "proxy_observed", "destinationEvidence": "Correlated", "evidence": "Observed",
     "destinationBasis": "Authorization: Bearer sk-live-abcdefghijklmnop0123"},
    {"id": "c", "agent": "Cursor", "pid": 700, "ppid": 1, "processName": "Cursor", "protocol": "UDP",
     "localAddress": "192.168.1.2:61000", "remoteAddress": "104.16.132.229:443", "remoteIP": "104.16.132.229",
     "remotePort": 443, "state": "CONNECTED", "firstSeen": "2026-10-20T10:00:00.000Z",
     "lastSeen": "2026-10-20T10:00:00.000Z", "sampleCount": 1, "scope": "public", "viaProxy": False,
     "transportPeer": "104.16.132.229:443", "realDestination": "104.16.132.229",
     "destinationSource": "socket_sampled", "destinationEvidence": "Observed", "evidence": "Observed"},
]


class ListNetworkSockets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "socket-ledger.json"
        self.write_ledger(dt.datetime.now(dt.timezone.utc))
        self.old = evidence.SOCKET_LEDGER
        evidence.SOCKET_LEDGER = self.path

    def write_ledger(self, last_at):
        stamp = last_at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        self.path.write_text(json.dumps({"schema": 1, "connections": ROWS,
                                         "samples": {"count": 9, "lastAt": stamp},
                                         "coverage": {"intervalSeconds": 3, "missesShorterThanSeconds": 3}}))

    def tearDown(self):
        evidence.SOCKET_LEDGER = self.old
        self.tmp.cleanup()

    def test_sockets_listed_with_proxy_flag_and_destination(self):
        out = evidence.list_network(records=[])
        by_id = {r["id"]: r for r in out["sockets"]}
        self.assertEqual(set(by_id), {"a", "b", "c"})
        self.assertFalse(by_id["a"]["viaProxy"])
        self.assertEqual(by_id["b"]["transportPeer"], "127.0.0.1:18891")
        self.assertEqual(by_id["b"]["realDestination"], "api.openai.com")
        self.assertEqual(out["socketSummary"]["notViaProxyPublic"], 2)
        self.assertEqual(out["socketCoverage"]["state"], "sampling")
        self.assertEqual(out["confidence"], "Observed")
        self.assertNotIn("key", by_id["a"])

    def test_stale_ledger_is_stopped_not_sampling(self):
        self.write_ledger(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5))
        out = evidence.list_network(records=[])
        self.assertEqual(out["socketCoverage"]["state"], "stopped")
        self.assertGreater(out["socketCoverage"]["staleSeconds"], 60)

    def test_live_pid_with_failing_rounds_is_not_called_stopped(self):
        now = dt.datetime.now(dt.timezone.utc)
        old = (now - dt.timedelta(minutes=5)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        recent = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        self.path.write_text(json.dumps({
            "schema": 1, "connections": [],
            "samples": {"count": 9, "lastAt": old, "lastFailureAt": recent, "samplerPid": 2804,
                        "lastFailure": "round/error: TypeError"},
            "coverage": {"configuredIntervalSeconds": 2},
        }))
        out = evidence.list_network(records=[])
        cov = out["socketCoverage"]
        self.assertEqual(cov["state"], "failing")
        note = evidence._socket_blind_spot_from(cov)["note"]
        self.assertNotIn("没有在采样", note)
        self.assertIn("还在", note)
        self.assertIn("2804", note)

    def test_v1_ledger_coverage_is_flagged_as_configured_not_measured(self):
        out = evidence.list_network(records=[])
        cov = out["socketCoverage"]
        self.assertEqual(cov["integrity"]["state"], "unsigned")
        self.assertEqual(cov["measurementConfidence"], "Unknown")
        self.assertIn("配置间隔", cov["measurementNote"])
        self.assertEqual(cov["confidence"], "Unknown")  # unsigned ledger is not Observed coverage

    def test_redacted_and_filtered(self):
        out = evidence.list_network(agent="Codex", since="2026-10-21T00:00:00Z", records=[])
        self.assertEqual({r["id"] for r in out["sockets"]}, {"a", "b"})
        blob = json.dumps(out)
        self.assertNotIn("sk-live-abcdefghijklmnop0123", blob)

    def test_missing_ledger_is_unknown_not_empty_success(self):
        evidence.SOCKET_LEDGER = pathlib.Path(self.tmp.name) / "missing.json"
        out = evidence.list_network(records=[])
        self.assertEqual(out["sockets"], [])
        self.assertEqual(out["socketCoverage"]["confidence"], "Unknown")
        self.assertEqual(out["confidence"], "Unknown")


if __name__ == "__main__":
    unittest.main()
