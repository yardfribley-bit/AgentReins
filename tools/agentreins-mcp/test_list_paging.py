"""Paging, session bounds, until, and the 传输审计 wording for the read-only list tools."""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import evidence

REPO = pathlib.Path(__file__).resolve().parents[2]


def _row(agent: str, call: str, session: str, started: str) -> dict:
    return {
        "agent": agent, "call": call, "session": session, "tool": "curl",
        "startedAt": started, "args": [], "connections": [], "auditBypass": True,
    }


class ListPaging(unittest.TestCase):
    def test_list_agents_bounds_sessions_and_keeps_execution_cap(self) -> None:
        records = [_row("WorkBuddy", "e%02d" % i, "s%02d" % i, "2026-10-28T01:00:%02dZ" % (i % 60))
                   for i in range(45)]
        out = evidence.list_agents(records=records)
        self.assertEqual(out["total"], 1)
        self.assertFalse(out["truncated"])
        self.assertIsNone(out["nextCursor"])
        agent = out["agents"][0]
        self.assertEqual(agent["sessionCount"], 45)
        self.assertEqual(len(agent["sessions"]), 40)
        self.assertTrue(agent["sessionsTruncated"])
        self.assertEqual(agent["executionCount"], 45)
        self.assertEqual(len(agent["executionIds"]), 40)
        self.assertTrue(agent["executionIdsTruncated"])
        self.assertIn("e00", agent["executionIds"])
        self.assertNotIn("e40", agent["executionIds"])
        self.assertIn("传输审计", out["note"])
        self.assertNotIn("运输审计", out["note"])

    def test_list_agents_limit_cursor_and_until(self) -> None:
        records = [
            _row("A", "a1", "s", "2026-10-28T01:00:00Z"),
            _row("B", "b1", "s", "2026-10-28T02:00:00Z"),
            _row("C", "c1", "s", "2026-10-28T03:00:00Z"),
        ]
        first = evidence.list_agents(records=records, limit=2)
        self.assertEqual([a["agent"] for a in first["agents"]], ["A", "B"])
        self.assertTrue(first["truncated"])
        second = evidence.list_agents(records=records, limit=2, cursor=first["nextCursor"])
        self.assertEqual([a["agent"] for a in second["agents"]], ["C"])
        self.assertFalse(second["truncated"])
        bounded = evidence.list_agents(records=records, since="2026-10-28T01:30:00Z", until="2026-10-28T02:30:00Z")
        self.assertEqual([a["agent"] for a in bounded["agents"]], ["B"])
        with self.assertRaises(ValueError):
            evidence.list_agents(records=records, cursor="!!!")

    def test_list_alerts_until_limit_and_cursor(self) -> None:
        records = [
            _row("Cursor", "a", "s", "2026-10-28T01:00:00Z"),
            _row("Cursor", "b", "s", "2026-10-28T03:00:00Z"),
            _row("Cursor", "c", "s", "2026-10-28T05:00:00Z"),
        ]

        def bridge(rows):
            alerts = [{
                "id": row["call"], "rule": "S07", "title": "bypass", "agent": row["agent"],
                "session": row["session"], "call": row["call"], "confidence": "Observed",
                "timestamp": row["startedAt"],
            } for row in rows]
            return alerts, {"engine": "test", "warning": None}

        with mock.patch.object(evidence, "build_alerts_via_bridge", side_effect=bridge):
            window = evidence.list_alerts(records=records, since="2026-10-28T02:00:00Z", until="2026-10-28T04:00:00Z")
            self.assertEqual([a["executionId"] for a in window["alerts"]], ["b"])
            page = evidence.list_alerts(records=records, limit=1)
            self.assertEqual(len(page["alerts"]), 1)
            self.assertEqual(page["total"], 3)
            self.assertTrue(page["truncated"])
            nxt = evidence.list_alerts(records=records, limit=1, cursor=page["nextCursor"])
            self.assertEqual(nxt["offset"], 1)
            self.assertNotEqual(nxt["alerts"][0]["executionId"], page["alerts"][0]["executionId"])

    def test_list_network_until_filters_sockets_and_pages(self) -> None:
        rows = [
            {"id": "early", "agent": "Codex", "protocol": "TCP", "scope": "public", "viaProxy": False,
             "lastSeen": "2026-10-20T00:00:00Z", "remoteAddress": "1.1.1.1:443"},
            {"id": "mid", "agent": "Codex", "protocol": "TCP", "scope": "public", "viaProxy": False,
             "lastSeen": "2026-10-21T00:00:00Z", "remoteAddress": "1.1.1.1:443"},
            {"id": "late", "agent": "Codex", "protocol": "TCP", "scope": "public", "viaProxy": False,
             "lastSeen": "2026-10-22T00:00:00Z", "remoteAddress": "1.1.1.1:443"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "socket-ledger.json"
            path.write_text(json.dumps({"schema": 1, "connections": rows, "samples": {}, "coverage": {}}),
                            encoding="utf-8")
            with mock.patch.object(evidence, "SOCKET_LEDGER", path):
                out = evidence.list_network(records=[], since="2026-10-20T12:00:00Z", until="2026-10-21T12:00:00Z")
        self.assertEqual([s["id"] for s in out["sockets"]], ["mid"])
        self.assertIn("socketsPage", out)
        self.assertFalse(out["socketsPage"]["truncated"])

    def test_list_mcp_audit_pages_newest_first_and_filters_until(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "audit.jsonl"
            lines = [json.dumps({"at": "2026-10-28T00:00:0%dZ" % i, "tool": "t%d" % i}) for i in range(5)]
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            with mock.patch.object(evidence, "AUDIT_LOG", log), \
                    mock.patch.object(evidence, "validate_audit", return_value={"ok": True, "status": "ok"}):
                page = evidence.list_mcp_audit(limit=2)
                self.assertEqual([e["tool"] for e in page["entries"]], ["t3", "t4"])
                self.assertTrue(page["truncated"])
                older = evidence.list_mcp_audit(limit=2, cursor=page["nextCursor"])
                self.assertEqual([e["tool"] for e in older["entries"]], ["t1", "t2"])
                bounded = evidence.list_mcp_audit(until="2026-10-28T00:00:02Z")
                self.assertEqual([e["tool"] for e in bounded["entries"]], ["t0", "t1", "t2"])

    def test_wording_replaced_in_source_not_in_historical_samples(self) -> None:
        files = [
            REPO / "Sources/AgentReinsMCP/AgentReinsMCP.swift",
            REPO / "Sources/AgentReinsCore/CoreIntegrityValidate.swift",
            REPO / "tools/agentreins-mcp/evidence.py",
            REPO / "Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js",
        ]
        for path in files:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("运输审计", text, path)
            self.assertIn("传输审计", text, path)
        sample = REPO / "docs/evidence/en_26fd4180/inb/list_alerts.json"
        self.assertIn("运输审计", sample.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
