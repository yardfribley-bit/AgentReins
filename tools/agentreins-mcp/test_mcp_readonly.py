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
        self.audit_dir = pathlib.Path(self.tmp.name) / "audit"
        self.audit_dir.mkdir()
        self.audit = self.audit_dir / "mcp-supervisor-audit.jsonl"
        os.environ["AGENTREINS_TRANSPORT_ROOT"] = str(self.transport)
        import evidence

        evidence.DEFAULT_TRANSPORT = self.transport
        evidence.AUDIT_LOG = self.audit
        evidence.AUDIT_DIR = self.audit_dir
        evidence.AUDIT_SEAL = self.audit_dir / "mcp-supervisor-audit.seal"
        evidence.HMAC_KEY_FILE = self.audit_dir / "mcp-supervisor-hmac.key"
        evidence.RUN_INVENTORY = self.audit_dir / "transport-run-inventory.jsonl"
        integrity = pathlib.Path(self.tmp.name) / "integrity"
        integrity.mkdir(exist_ok=True)
        evidence.INTEGRITY_DIR = integrity
        evidence.PROTECTED_SEAL_DIR = integrity / "seals"
        evidence.SIGNED_ERA_FLAG = integrity / "signed-era"
        evidence.RUN_INVENTORY_MAC = integrity / "transport-run-inventory.mac"
        from keychain_fake import FAKE as FAKE_KEYCHAIN

        FAKE_KEYCHAIN.items.clear()
        self._keychain_patches = FAKE_KEYCHAIN.patches(evidence)
        for patch in self._keychain_patches:
            patch.start()
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
                        "provenance": "live",
                        "testCapture": False,
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
                        "provenance": "live",
                    },
                    "connections": [{"kind": "connected", "detail": ["bypass.example.com:443"]}],
                    "blocks": [],
                    "downloads": [],
                }
            ),
            encoding="utf-8",
        )
        # Explicit testCapture must be filtered (same as UI)
        seed = self.transport / "exec-seed"
        seed.mkdir()
        (seed / "transport.json").write_text(
            json.dumps(
                {
                    "invocation": {
                        "captureMode": "agent-path",
                        "agent": "Cursor",
                        "tool": "curl",
                        "call": "exec-seed",
                        "startedAt": "2026-10-21T04:02:00Z",
                        "args": ["https://127.0.0.1:9/"],
                        "exitCode": 0,
                        "session": "seed-session",
                        "testCapture": True,
                        "provenance": "test",
                        "auditBypass": True,
                    },
                    "connections": [{"kind": "connected", "detail": ["127.0.0.1:9"]}],
                    "blocks": [],
                    "downloads": [],
                }
            ),
            encoding="utf-8",
        )
        self.secret = secret
        # Collection-time signing — MCP reads must not resign.
        self.evidence.sign_evidence_tree(self.transport)
        for run_dir in self.transport.iterdir():
            if run_dir.is_dir():
                self.evidence.register_run_id(run_dir.name, run_dir)

    def tearDown(self):
        for patch in reversed(self._keychain_patches):
            patch.stop()
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

    def test_redaction_password_class(self):
        raw = "password=SuperSecret99!"
        out = self.evidence.redact_text(raw)
        self.assertNotIn("SuperSecret99!", out)
        self.assertIn("password", out.lower())

    def test_redaction_userpass_flag_class(self):
        raw = "curl -u alice:hunter2 https://example.com/"
        out = self.evidence.redact_text(raw)
        self.assertNotIn("alice:hunter2", out)
        self.assertNotIn("hunter2", out)

    def test_redaction_aws_akia_and_secret_class(self):
        akia = "AKIAIOSFODNN7EXAMPLE"
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        raw = f"aws_access_key_id={akia} aws_secret_access_key={secret}"
        out = self.evidence.redact_text(raw)
        self.assertNotIn(akia, out)
        self.assertNotIn(secret, out)

    def test_redaction_bearer_class(self):
        token = "ya29.a0AfH6SMC_example_token_value"
        raw = "Authorization: Bearer " + token
        out = self.evidence.redact_text(raw)
        self.assertNotIn(token, out)
        self.assertIn("Bearer", out)

    def test_redaction_url_userinfo_class(self):
        raw = "https://bob:s3cretPass@api.example.com/v1"
        out = self.evidence.redact_text(raw)
        self.assertNotIn("bob:s3cretPass", out)
        self.assertNotIn("s3cretPass", out)
        self.assertIn("api.example.com", out)

    def test_redaction_ux_variants_each_class(self):
        cases = [
            ("curl -uX alice:p@ss https://h/", "p@ss"),
            ("curl --user=alice:pww https://h/", "pww"),
            ("curl --user 'alice:b c' https://h/", "b c"),
            ('aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ("export SECRET=TopSecretValue99", "TopSecretValue99"),
            ("Authorization: Bearer abcd", "abcd"),
            ("Authorization: Basic YWxpY2U6c2VjcmV0", "YWxpY2U6c2VjcmV0"),
            ("postgres://u:p@w@host/db", "p@w"),
            ("https://u:p%40ss@host/", "p%40ss"),
            ("tool --password s3cretx", "s3cretx"),
            ("mysql -pSecretMySQL", "SecretMySQL"),
            ("DB_PASS=DbPass99 client_secret=Cs99", "DbPass99"),
        ]
        for raw, secret in cases:
            out = self.evidence.redact_text(raw)
            self.assertNotIn(secret, out, raw)
            self.assertNotIn("sha256=", out, "mask must not include sha256 prefix")

    def test_redact_obj_sensitive_keys(self):
        obj = {"password": "PlainPass99", "nested": {"client_secret": "CsValue"}, "ok": "visible"}
        out = self.evidence.redact_obj(obj)
        blob = json.dumps(out)
        self.assertNotIn("PlainPass99", blob)
        self.assertNotIn("CsValue", blob)
        self.assertIn("visible", blob)

    def test_manifest_disk_has_no_plaintext_userpass(self):
        # Collector redacts argv as a joined command so "-u" + "user:pass" both go away.
        run = self.transport / "manifest-scan"
        run.mkdir()
        raw_args = ["-u", "alice:hunter2manifest", "https://example.com/"]
        joined = " ".join(raw_args)
        redacted = self.evidence.redact_text(joined)
        manifest = {
            "schema": 1,
            "tool": "curl",
            "args": redacted.split(" ", 2),  # store redacted tokens
            "commandRedacted": redacted,
        }
        (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        text = (run / "manifest.json").read_text(encoding="utf-8")
        self.assertNotIn("hunter2manifest", text)
        self.assertNotIn("alice:hunter2manifest", text)
        for path in self.transport.glob("*/manifest.json"):
            body = path.read_text(encoding="utf-8")
            self.assertNotIn("hunter2manifest", body)

    def test_list_alerts_and_redaction(self):
        alerts = self.evidence.list_alerts(agent="Cursor")
        rules = {a["rule"] for a in alerts["alerts"]}
        self.assertIn("S02", rules)
        self.assertIn("S07", rules)
        self.assertNotIn("exec-seed", {a.get("executionId") for a in alerts["alerts"]})
        blob = json.dumps(alerts)
        self.assertNotIn(self.secret, blob)
        self.assertNotIn("Bearer " + self.secret, blob)
        s02 = next(a for a in alerts["alerts"] if a["rule"] == "S02")
        self.assertEqual(s02["confidence"], "Observed")
        self.assertEqual(s02["executionId"], "exec-s02")
        self.assertIn(alerts.get("engine"), ("js-bridge", "swift-jsc-bridge"))

    def test_get_execution_redacts_and_reports_bypass(self):
        detail = self.evidence.get_execution("exec-s02")
        self.assertEqual(detail["confidence"], "Observed")
        self.assertNotIn(self.secret, json.dumps(detail))
        self.assertTrue(any(f.get("rule") == "credential-outbound" for f in detail["securityFindings"]))
        for finding in detail["securityFindings"]:
            self.assertIsNone(finding.get("matchedText"))
            if finding.get("rule") == "instruction-override-inbound":
                self.assertIn("ruleId", finding)
                # Redacted context may be absent if fixture has no body snippet.
                self.assertTrue(
                    finding.get("matchContextRedacted") is None
                    or isinstance(finding.get("matchContextRedacted"), str)
                )
        bypass = self.evidence.get_execution("exec-s07")
        self.assertTrue(bypass["auditBypass"])

    def test_list_agents_marks_cursor(self):
        agents = self.evidence.list_agents()
        cursor = next(a for a in agents["agents"] if a["agent"] == "Cursor")
        self.assertTrue(cursor["isCursor"])
        self.assertIn("exec-s02", cursor["executionIds"])

    def test_audit_hmac_chain_and_tamper_detection(self):
        self.evidence.append_audit("Codex", "list_alerts", {"agent": "Cursor"})
        self.evidence.append_audit("Codex", "get_execution", {"execution_id": "exec-s02"})
        entries = self.evidence.recent_audit()
        self.assertGreaterEqual(len(entries), 2)
        self.assertEqual(entries[1]["prevHash"], entries[0]["hash"])
        self.assertTrue(entries[0].get("mac"))
        ok = self.evidence.validate_audit()
        self.assertTrue(ok["ok"], ok)
        # Tamper a signed record (change body, keep stale MAC) → ok=false
        lines = self.audit.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["tool"] = "tampered_tool"
        lines[0] = json.dumps(first, ensure_ascii=False)
        self.audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
        bad = self.evidence.validate_audit()
        self.assertFalse(bad["ok"])
        self.assertTrue(bad["tampered"], bad)

    def test_audit_strip_mac_after_signed_era(self):
        self.evidence.append_audit("Codex", "list_alerts", {})
        self.evidence.append_audit("Codex", "list_agents", {})
        lines = self.audit.read_text(encoding="utf-8").splitlines()
        second = json.loads(lines[1])
        second.pop("mac", None)
        lines[1] = json.dumps(second, ensure_ascii=False)
        self.audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.evidence.validate_audit()
        self.assertFalse(result["ok"])
        self.assertTrue(any(t.get("reason") in ("missing_mac", "missing_mac_after_signed_era") for t in result["tampered"]), result)

    def test_audit_truncation_via_seal(self):
        self.evidence.append_audit("Codex", "list_agents", {})
        self.evidence.append_audit("Codex", "list_alerts", {})
        self.evidence.append_audit("Codex", "get_coverage", {})
        lines = self.audit.read_text(encoding="utf-8").splitlines()
        # Truncate tail — seal count/head no longer match
        self.audit.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        result = self.evidence.validate_audit()
        self.assertFalse(result["ok"])
        self.assertTrue(
            any(g.get("reason") == "truncated_or_count_mismatch" for g in result["deletedOrGap"]),
            result,
        )

    def test_evidence_file_mac_tamper(self):
        self.evidence.append_audit("Codex", "list_alerts", {})
        # Evidence was signed at collection (setUp); MCP read must not wash. Tamper transport.json.
        tpath = self.transport / "exec-s02" / "transport.json"
        raw = tpath.read_text(encoding="utf-8")
        tpath.write_text(raw.replace("Cursor", "TamperedAgent"), encoding="utf-8")
        result = self.evidence.validate_audit()
        self.assertFalse(result["ok"])
        self.assertTrue(
            any(t.get("reason") == "evidence_mac_mismatch" for t in result["tampered"]),
            result,
        )

    def test_audit_delete_detection(self):
        self.evidence.append_audit("Codex", "list_agents", {})
        self.evidence.append_audit("Codex", "list_alerts", {})
        self.evidence.append_audit("Codex", "get_coverage", {})
        lines = self.audit.read_text(encoding="utf-8").splitlines()
        # Delete the middle entry — chain prevHash breaks
        del lines[1]
        self.audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.evidence.validate_audit()
        self.assertFalse(result["ok"])
        self.assertTrue(result["deletedOrGap"], result)

    def test_never_reads_private_tmp(self):
        legacy = pathlib.Path(self.tmp.name) / "fake-private-tmp"
        # Simulate pointing at legacy path — must return empty
        rows = self.evidence.load_transport_records(root=pathlib.Path("/private/tmp/agentreins-transport-audit"))
        self.assertEqual(rows, [])
        _ = legacy  # keep tempfile root alive

    def test_list_mcp_audit_exposes_validation(self):
        self.evidence.append_audit("Codex", "list_alerts", {})
        payload = self.evidence.list_mcp_audit(limit=10)
        self.assertIn("validation", payload)
        self.assertTrue(payload["validation"]["ok"])

    def test_fallback_warns_explicitly(self):
        # Force fallback by pointing both bridges aside
        old_bridge = self.evidence.BRIDGE
        old_swift = self.evidence.SWIFT_BRIDGE
        self.evidence.BRIDGE = pathlib.Path("/nonexistent/alerts_bridge.cjs")
        self.evidence.SWIFT_BRIDGE = pathlib.Path("/nonexistent/AgentReinsAlertsBridge")
        try:
            _, meta = self.evidence.build_alerts_via_bridge(
                self.evidence.load_transport_records()
            )
            self.assertEqual(meta["engine"], "python-fallback")
            self.assertTrue(meta.get("warning"))
        finally:
            self.evidence.BRIDGE = old_bridge
            self.evidence.SWIFT_BRIDGE = old_swift

    def test_stdio_initialize_and_tools_list(self):
        proc = subprocess.Popen(
            ["python3", str(ROOT / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(ROOT),
            env={
                **os.environ,
                "AGENTREINS_TRANSPORT_ROOT": str(self.transport),
            },
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
