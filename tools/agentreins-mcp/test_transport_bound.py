"""list_alerts must not parse every transport-audit directory."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import evidence  # noqa: E402


class TransportBoundTests(unittest.TestCase):
    def test_only_newest_runs_are_parsed(self):
        root = tempfile.mkdtemp(prefix="ar-transport-")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        for index in range(12):
            run = os.path.join(root, "run-%02d" % index)
            os.makedirs(run)
            path = os.path.join(run, "transport.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"invocation":{"captureMode":"agent-path","agent":"Cursor","call":"c-%d","startedAt":"2026-01-01T00:00:%02dZ"}}' % (index, index))
            os.utime(run, (1_700_000_000 + index, 1_700_000_000 + index))
        evidence._TRANSPORT_INDEX.clear()
        rows = evidence._load_transport_dir(__import__("pathlib").Path(root), 3)
        calls = [row.get("call") for row in rows]
        self.assertEqual(calls, ["c-11", "c-10", "c-9"])
        self.assertTrue(evidence._TRANSPORT_INDEX["lastTruncated"])


if __name__ == "__main__":
    unittest.main()
