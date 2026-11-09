"""WorkBuddy / CodeBuddy session cards stay thin and join a later file path."""
from __future__ import annotations

import json
import pathlib
import tempfile
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


if __name__ == "__main__":
    unittest.main()
