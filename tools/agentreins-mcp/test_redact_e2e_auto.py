"""End-to-end: after a synthetic auto-style write, no raw secrets remain under the run dir."""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from redact_secrets import redact_obj, redact_text  # noqa: E402


class RedactE2E(unittest.TestCase):
    def test_run_dir_has_no_raw_secrets(self) -> None:
        root = pathlib.Path(tempfile.mkdtemp(prefix="ar-redact-e2e-"))
        try:
            run = root / "run-e2e"
            run.mkdir()
            secrets = [
                "s3cretPASS",
                "tok_live_abc123",
                "Bearer shorttok",
                "mysql -uroot -pSecretPass",
            ]
            # Simulate auto.py outputs before/after redaction helpers.
            (run / "manifest.json").write_text(
                json.dumps({"args": ["-u alice:s3cretPASS", "https://h/"], "tool": "curl"}),
                encoding="utf-8",
            )
            (run / "transport.json").write_text(
                json.dumps({"invocation": {"args": ["--user", "alice:s3cretPASS"]}}),
                encoding="utf-8",
            )
            (run / "session.log").write_text(
                "Authorization: Bearer shorttok\nAPI_TOKEN=tok_live_abc123\n",
                encoding="utf-8",
            )
            bodies = run / "bodies"
            bodies.mkdir()
            (bodies / "req.bin").write_bytes(b"Authorization: Basic YWxpY2U6czNjcmV0UEFTUw==\n")

            # Apply the same redaction auto.py uses on session/bodies + text fields.
            for path in [run / "session.log", bodies / "req.bin"]:
                text = path.read_bytes().decode("utf-8", "replace")
                path.write_text(redact_text(text), encoding="utf-8")
            for name in ("manifest.json", "transport.json"):
                obj = json.loads((run / name).read_text(encoding="utf-8"))
                # Match auto.py: redact argv tokens as a joined command line, then store list.
                def scrub(o):
                    if isinstance(o, dict):
                        out = {}
                        for k, v in o.items():
                            if k == "args" and isinstance(v, list):
                                joined = redact_text(" ".join(str(x) for x in v))
                                out[k] = joined.split(" ") if " " in joined else [joined]
                            else:
                                out[k] = scrub(v)
                        return out
                    if isinstance(o, list):
                        return [scrub(x) for x in o]
                    if isinstance(o, str):
                        return redact_text(o)
                    return o
                (run / name).write_text(json.dumps(scrub(obj), ensure_ascii=False), encoding="utf-8")

            blob = b""
            for path in run.rglob("*"):
                if path.is_file():
                    blob += path.read_bytes()
            text = blob.decode("utf-8", "replace")
            for secret in ("s3cretPASS", "tok_live_abc123", "shorttok", "SecretPass", "YWxpY2U6czNjcmV0UEFTUw=="):
                self.assertNotIn(secret, text, f"raw secret leaked: {secret}")
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
