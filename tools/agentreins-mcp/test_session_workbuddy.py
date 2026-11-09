"""WorkBuddy / CodeBuddy session cards stay thin and join a later file path."""
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import time
import unittest

import session_verification as sv


class WorkBuddySessionTests(unittest.TestCase):
    def test_function_call_keeps_the_path_and_joins_a_later_file_change(self) -> None:
        line = json.dumps({
            "type": "function_call",
            "sessionId": "wb-1",
            "timestamp": "2026-11-09T01:00:00Z",
            "name": "Edit",
            "callId": "call-1",
            "arguments": json.dumps({"file_path": "/tmp/proj/add.js", "content": "x" * 5000}),
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            projects = root / "projects"
            projects.mkdir()
            (projects / "session.jsonl").write_text(line + "\n", encoding="utf-8")
            loaded = sv.load(str(root / "missing-claude"), str(root / "missing-codex"), workbuddy=[str(projects)])
        self.assertEqual(len(loaded["calls"]), 1)
        call = loaded["calls"][0]
        self.assertEqual(call["agent"], "WorkBuddy")
        self.assertEqual(call["claimedPaths"], ["/tmp/proj/add.js"])
        self.assertTrue(call["claimsEdit"])
        self.assertLessEqual(len(call["arguments"]), sv.EXCERPT)
        self.assertNotIn("x" * 2000, call["arguments"])
        effect = {
            "id": "f1", "kind": "file", "path": "/tmp/proj/add.js",
            "timestamp": "2026-11-09T01:00:40Z", "source": "file-observe",
        }
        document = sv.verify(loaded["calls"], [effect])
        self.assertEqual(document["fileObservation"], "present")
        self.assertEqual(document["cards"][0]["status"], "matched")
        self.assertEqual(document["cards"][0]["happened"][0]["join"], "path")
        self.assertEqual(document["unclaimed"], [])

    def test_codebuddy_millisecond_line_survives_a_huge_result_and_prefix_session(self) -> None:
        session = "bd89b095-1111-4111-8111-111111111111"
        call = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845000,
            "cwd": "/tmp/proj",
            "sessionId": session,
            "name": "Edit",
            "callId": "call_edit",
            "arguments": json.dumps({"file_path": "/tmp/proj/add.js"}),
        })
        bash = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845100,
            "sessionId": session,
            "name": "Bash",
            "callId": "call_bash",
            "arguments": json.dumps({"command": "ls"}),
        })
        read = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845200,
            "sessionId": session,
            "name": "Read",
            "callId": "call_read",
            "arguments": json.dumps({"file_path": "/tmp/proj/add.js"}),
        })
        huge = json.dumps({
            "type": "function_call_result",
            "timestamp": 1781821846000,
            "sessionId": session,
            "name": "Read",
            "callId": "call_read",
            "output": {"type": "text", "text": "x" * 200_000},
        })
        with tempfile.TemporaryDirectory() as tmp:
            projects = pathlib.Path(tmp) / "projects"
            projects.mkdir()
            (projects / (session + ".jsonl")).write_text(
                "\n".join([call, bash, read, huge]) + "\n", encoding="utf-8")
            loaded = sv.load(str(pathlib.Path(tmp) / "c"), str(pathlib.Path(tmp) / "x"), workbuddy=[str(projects)])
        names = [row["toolName"] for row in loaded["calls"]]
        self.assertEqual(names, ["Edit", "Bash", "Read"])
        self.assertEqual(loaded["calls"][0]["sessionId"], session)
        self.assertTrue(loaded["calls"][0]["claimsEdit"])
        page = sv.list_tool_calls({"session_id": "bd89b095"}, [])
        # list_tool_calls reads the real home; filter the loaded calls directly.
        matched = [row for row in loaded["calls"] if sv.session_matches(row["sessionId"], "bd89b095")]
        self.assertEqual(len(matched), 3)
        self.assertIsNotNone(page)

    def test_large_codebuddy_tree_stays_under_three_seconds_and_keeps_the_edit(self) -> None:
        session = "bd89b095-2222-4222-8222-222222222222"
        call = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845000,
            "sessionId": session,
            "name": "Edit",
            "callId": "call_edit",
            "arguments": json.dumps({"file_path": "/tmp/proj/add.js"}),
        })
        read = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845200,
            "sessionId": session,
            "name": "Read",
            "callId": "call_read",
            "arguments": json.dumps({"file_path": "/tmp/proj/add.js"}),
        })
        bash = json.dumps({
            "type": "function_call",
            "timestamp": 1781821845100,
            "sessionId": session,
            "name": "Bash",
            "callId": "call_bash",
            "arguments": json.dumps({"command": "python3 hold.py"}),
        })
        giant = json.dumps({
            "type": "function_call_result",
            "name": "Read",
            "output": "x" * (900 * 1024),
        })
        old_stamp = time.time() - 10 * 24 * 60 * 60
        with tempfile.TemporaryDirectory() as tmp:
            projects = pathlib.Path(tmp) / "projects"
            projects.mkdir()
            for index in range(120):
                folder = projects / ("old-%03d" % index)
                folder.mkdir()
                target = folder / "old.jsonl"
                target.write_text(json.dumps({"type": "function_call", "name": "Read", "sessionId": "old"}) + "\n", encoding="utf-8")
                os.utime(target, (old_stamp, old_stamp))
            fresh = projects / "fresh"
            fresh.mkdir()
            body = "\n".join([call, bash, read, giant]) + "\n"
            target = fresh / (session + ".jsonl")
            target.write_text(body, encoding="utf-8")
            started = time.monotonic()
            loaded = sv.load(str(pathlib.Path(tmp) / "c"), str(pathlib.Path(tmp) / "x"), workbuddy=[str(projects)])
            elapsed = time.monotonic() - started
            again = time.monotonic()
            cached = sv.load(str(pathlib.Path(tmp) / "c"), str(pathlib.Path(tmp) / "x"), workbuddy=[str(projects)])
            cached_elapsed = time.monotonic() - again
        self.assertLess(elapsed, 3.0, "load took %.2fs" % elapsed)
        self.assertLess(cached_elapsed, 0.5, "cached load took %.2fs" % cached_elapsed)
        names = [row["toolName"] for row in loaded["calls"]]
        self.assertEqual(names, ["Edit", "Bash", "Read"])
        self.assertEqual(cached["calls"][0]["claimedPaths"], ["/tmp/proj/add.js"])
        source = loaded["sources"][-1]
        self.assertLessEqual(source["filesRead"], sv.WORKBUDDY_FILES)
        self.assertEqual(source["filesRead"], 1)


if __name__ == "__main__":
    unittest.main()
