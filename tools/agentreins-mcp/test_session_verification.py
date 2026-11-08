"""Session log parse and host-effect join. Fixtures are synthetic."""
from __future__ import annotations

import pathlib
import tempfile
import unittest
from datetime import datetime, timezone

import session_verification as sv


def effect(**kwargs):
    base = {"timestamp": "2026-11-08T02:00:03Z", "source": "fixture"}
    base.update(kwargs)
    return base


class SessionVerificationTests(unittest.TestCase):
    def test_claude_excerpt_and_codex_completion(self):
        thinking = "想" * 2000
        claude = (
            '{"type":"assistant","timestamp":"2026-11-08T02:00:02Z","sessionId":"sess","message":{"content":'
            '[{"type":"thinking","thinking":"%s"},{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"/tmp/a.swift"}}]}}\n'
            '{"not json"}\n' % thinking
        )
        batch = sv.parse_claude(claude, "/tmp/claude.jsonl")
        self.assertEqual(batch["malformed"], 1)
        self.assertEqual(len(batch["calls"][0]["reasoning"]), sv.EXCERPT)
        self.assertTrue(batch["calls"][0]["reasoningTruncated"])
        self.assertEqual(batch["calls"][0]["claimedPaths"], ["/tmp/a.swift"])
        codex = "\n".join([
            '{"timestamp":"2026-11-08T03:00:01Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"先看本地配置，不访问网络。"}]}}',
            '{"timestamp":"2026-11-08T03:00:02Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\\"command\\":\\"curl https://uploads.example/x\\"}"}}',
            '{"timestamp":"2026-11-08T03:00:20Z","type":"event_msg","payload":{"type":"task_complete","last_agent_message":"已完成"}}',
        ])
        parsed = sv.parse_codex(codex, "/tmp/rollout-2026-11-08T00-00-00-11111111-1111-1111-1111-111111111111.jsonl")
        self.assertEqual(parsed["calls"][0]["reasoning"], "先看本地配置，不访问网络。")
        self.assertEqual(parsed["completions"]["11111111-1111-1111-1111-111111111111"], "已完成")

    def test_three_mismatch_kinds_and_unclaimed(self):
        call = sv.parse_claude(
            '{"type":"assistant","timestamp":"2026-11-08T02:00:02Z","sessionId":"s","message":{"content":[{"type":"text","text":"只改 a.swift。"},{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"/tmp/a.swift"}}]}}\n'
        )["calls"][0]
        quiet = sv.verify([call], [], file_channel=False)
        self.assertEqual(quiet["cards"][0]["status"], "matched")
        self.assertIn("文件观测没接上", quiet["cards"][0]["note"])
        flagged = sv.verify([call], [], file_channel=True)
        self.assertEqual(flagged["cards"][0]["mismatches"][0]["label"], "说了没做")
        shell = sv.parse_codex(
            '{"timestamp":"2026-11-08T02:00:02Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_9","arguments":"{\\"command\\":\\"curl https://uploads.example/x\\"}"}}\n',
            "/tmp/rollout-x-22222222-2222-2222-2222-222222222222.jsonl",
        )["calls"][0]
        shell["reasoning"] = "先看本地配置，不访问网络。"
        document = sv.verify(
            [shell],
            [
                effect(id="n", kind="network", remote="uploads.example", pid=7, toolCallId="call_9"),
                effect(id="a", kind="file", path="/tmp/a.swift", diff="+a\n", pid=7),
                effect(id="b", kind="file", path="/tmp/b.swift", diff="+b\n", pid=7),
                effect(id="c", kind="file", path="/tmp/other.swift", diff="+c\n", timestamp="2026-11-08T04:00:00Z", pid=99),
            ],
            file_channel=True,
        )
        labels = [item["label"] for item in document["cards"][0]["mismatches"]]
        self.assertIn("做了没说", labels)
        self.assertEqual(document["unclaimed"][0]["path"], "/tmp/other.swift")

    def test_missing_directory_and_checklist(self):
        with tempfile.TemporaryDirectory() as tmp:
            loaded = sv.load(str(pathlib.Path(tmp) / "missing-claude"), str(pathlib.Path(tmp) / "missing-codex"))
        self.assertEqual([item["state"] for item in loaded["sources"]], ["absent", "absent"])
        call = sv.parse_claude(
            '{"type":"assistant","timestamp":"2026-11-08T02:00:02Z","sessionId":"s","message":{"content":[{"type":"text","text":"改 a.swift。"},{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"/tmp/a.swift"}}]}}\n'
            '{"type":"assistant","timestamp":"2026-11-08T02:00:40Z","sessionId":"s","message":{"content":[{"type":"text","text":"已完成，改了 1 个文件。"}]}}\n'
        )
        document = sv.verify(
            call["calls"],
            [effect(id="f", kind="file", path="/tmp/a.swift", diff="+a\n"), effect(id="n", kind="network", remote="example.com")],
            completions=call["completions"],
            task_ids={"s": "task-1"},
            file_channel=True,
        )
        checklist = document["checklists"][0]
        self.assertEqual(checklist["claimedFiles"], 1)
        self.assertEqual(checklist["actualFiles"], 1)
        self.assertEqual(checklist["egressCount"], 1)
        self.assertEqual(checklist["taskId"], "task-1")
        self.assertIsInstance(checklist["doneText"], str)

    def test_list_tool_does_not_require_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            import os
            os.environ["AGENTREINS_CLAUDE_PROJECTS"] = str(pathlib.Path(tmp) / "c")
            os.environ["AGENTREINS_CODEX_SESSIONS"] = str(pathlib.Path(tmp) / "x")
            try:
                page = sv.list_tool_calls({"limit": 10}, [])
            finally:
                os.environ.pop("AGENTREINS_CLAUDE_PROJECTS", None)
                os.environ.pop("AGENTREINS_CODEX_SESSIONS", None)
        self.assertEqual(page["cards"], [])
        self.assertTrue(any(item["state"] == "absent" for item in page["sources"]))
        self.assertNotIn("payload", str(page))
