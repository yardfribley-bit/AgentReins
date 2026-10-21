# MCP test fixtures

These are fixtures, not live evidence. Each folder says how it was produced.

- `recorded-proxied-curl/` — recorded on the Linux build box on 2026-10-21: real `curl --trace`
  (`curl -sS --proxy http://127.0.0.1:18999 https://example.com/`) through a small local CONNECT proxy,
  then parsed by the real `tools/transport-audit/parse.py`. `manifest.json` was written by hand to look like
  what `auto.py` writes (agent/call/pid are fixture values). Response body files were not kept.
- INB records in `test_inb_and_destination.py` are built at test time by running the real
  `Sources/AgentReins/Resources/content_audit.py` on a fixture response text (labelled in the test).
