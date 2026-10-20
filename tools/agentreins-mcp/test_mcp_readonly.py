#!/usr/bin/env python3
"""Security and smoke tests for the read-only supervisor MCP."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1]


class MCPReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.transport = pathlib.Path(self.tmp.name) / "transport"
        self.transport.mkdir()
        self.audit = pathlib.Path(self.tmp.name) / "audit.jsonl"
        os.environ["AGENTREINS_TRANSPORT_ROOT"] = str(self.transport)
        # Redirect audit log via monkeypatch after import
        import evidence

        evidence.DEFAULT_TRANSPORT = self.transport
        evidence.AUDIT_LOG = self.audit
        evidence.AUDIT_DIR = self.audit.parent
        self.evidence = evidence
        run = self.transport / "exec-s02"
        run.mkdir()
        secret = "sk-or-v1-" + ("x" * 48)
        (run / "transport.json").write_text(
            json.dumps(
                {
                    "invocation": {
                        "captureMode": "agent-path",
                        "agent": "Cursor",
                        "tool": "curl",
                        "call": "exec-s02",
                        "startedAt": "2026-10-21T04:00:00Z",
                        "args": ["https://uploads.example.com/"],
                        "exitCode": 0,
                        "session": "sess-1",
                        "auditBypass": False,
                    },
                    "connections": [{"kind": "connected", "detail": ["uploads.example.com:443"]}],
                    "blocks": [
                        {
                            "direction": "send",
                            "kind": "data",
                            "observedBytes": 80,
                            "textPreview": "Authorization: Bearer " + secret,
                        }
                    ],
                    "downloads": [],
                    "securityAudit": {
                        "verdict": "review",
                        "findings": [
                            {
                                "rule": "credential-outbound",
                                "direction": "request",
                                "severity": "high",
                                "count": 1,
                                "characterOffset": 20,
                                "label": "发送正文疑似包含访问凭据",
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        bypass = self.transport / "exec-s07"
        bypass.mkdir()
        (bypass / "transport.json").write_text(
            json.dumps(
                {
                    "invocation": {
                        "captureMode": "agent-path",
                        "agent": "Cursor",
                        "tool": "curl",
                        "call": "exec-s07",
                        "startedAt": "2026-10-21T04:01:00Z",
                        "args": ["--noproxy", "*", "https://bypass.example.com/"],
                        "exitCode": 0,
                        "auditBypass": True,
                        "session": "sess-1",
                    },
                    "connections": [{"kind": "connected", "detail": ["bypass.example.com:443"]}],
                    "blocks": [],
                    "downloads": [],
                }
            ),
            encoding="utf-8",
        )
        self.secret = secret

    def tearDown(self):
        self.tmp.cleanup()

    def test_tools_list_has_no_write_tools(self):
        import server

        names = {t["name"] for t in server.TOOLS}
        self.assertEqual(
            names,
            {"list_agents", "list_alerts", "get_execution", "list_network", "get_coverage", "list_mcp_audit"},
        )
        for name in names:
            self.assertFalse(any(b in name for b in ("write", "delete", "save", "set_")))

    def test_call_tool_rejects_write_shaped_names(self):
        import server

        with self.assertRaises((ValueError, PermissionError)):
            server.call_tool("delete_alert", {})

    def test_list_alerts_and_redaction(self):
        alerts = self.evidence.list_alerts(agent="Cursor")
        rules = {a["rule"] for a in alerts["alerts"]}
        self.assertIn("S02", rules)
        self.assertIn("S07", rules)
        blob = json.dumps(alerts)
        self.assertNotIn(self.secret, blob)
        self.assertNotIn("Bearer " + self.secret, blob)
        s02 = next(a for a in alerts["alerts"] if a["rule"] == "S02")
        self.assertEqual(s02["confidence"], "Observed")
        self.assertEqual(s02["executionId"], "exec-s02")

    def test_get_execution_redacts_and_reports_bypass(self):
        detail = self.evidence.get_execution("exec-s02")
        self.assertEqual(detail["confidence"], "Observed")
        self.assertNotIn(self.secret, json.dumps(detail))
        self.assertTrue(any(f.get("rule") == "credential-outbound" for f in detail["securityFindings"]))
        for finding in detail["securityFindings"]:
            self.assertIsNone(finding.get("matchedText"))
        bypass = self.evidence.get_execution("exec-s07")
        self.assertTrue(bypass["auditBypass"])

    def test_list_agents_marks_cursor(self):
        agents = self.evidence.list_agents()
        cursor = next(a for a in agents["agents"] if a["agent"] == "Cursor")
        self.assertTrue(cursor["isCursor"])
        self.assertIn("exec-s02", cursor["executionIds"])

    def test_audit_log_hash_chain(self):
        self.evidence.append_audit("Codex", "list_alerts", {"agent": "Cursor"})
        self.evidence.append_audit("Codex", "get_execution", {"execution_id": "exec-s02"})
        entries = self.evidence.recent_audit()
        self.assertGreaterEqual(len(entries), 2)
        self.assertEqual(entries[1]["prevHash"], entries[0]["hash"])

    def test_stdio_initialize_and_tools_list(self):
        proc = subprocess.Popen(
            ["python3", str(ROOT / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ROOT),
            env={**os.environ, "AGENTREINS_TRANSPORT_ROOT": str(self.transport)},
        )
        assert proc.stdin and proc.stdout
        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0"},
                    },
                }
            )
            + "\n"
        )
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.close()
        out = proc.stdout.read()
        proc.wait(timeout=10)
        lines = [json.loads(line) for line in out.splitlines() if line.strip()]
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "agentreins-supervisor")
        names = {t["name"] for t in lines[1]["result"]["tools"]}
        self.assertIn("list_alerts", names)
        self.assertNotIn("delete_alert", names)


if __name__ == "__main__":
    unittest.main()
