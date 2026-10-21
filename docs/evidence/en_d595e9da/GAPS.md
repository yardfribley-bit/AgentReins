# en_d595e9da gaps (honest)

## Done locally
- XSS: esc-count acceptance removed; real DOM + `mutate_esc_calls` **59/59 killed**.
- S03: downloadCall/PID → real curl; UTC parentStartAt; sameParentShell via ppid+parent start; self-pair reject.
- Tamper: Keychain HMAC/era; B11/B12 tests; historical mac_mismatch quarantined (not re-signed); `validate_audit ok=true`.
- Session-Id / Mcp-Session-Id / CSRF header redaction (+ vectors).
- Proxy `realDestination` / `transportPeer` fields.
- INB redacted matchContext snippets in MCP evidence.
- Stdio client-config snippets: Codex/Claude/Cursor/WorkBuddy under `tools/agentreins-mcp/client-configs/`.
- Screenshots: screen unlocked; home / S03 detail / S07-ish detail / About — distinct md5, build 137 / 1.1.0.

## Blocked / incomplete
1. **Codex tools/call + clientInfo=codex-mcp-client**: real `codex exec --json` attempted (0.151.0). Failed before tool use:
   - Default env: `invalid peer certificate: UnknownIssuer` to chatgpt.com (AgentReins MITM proxy).
   - Proxies cleared: API `request timed out` reconnect 2/5…5/5.
   - Artifacts: `codex/codex-exec.jsonl`, `codex-exec.stderr.txt`, rollouts, `CODEX_GAPS.txt`. No successful MCP tools/call this session.
2. **S07 screenshot**: no live S07 row in current alert list; `03-s07-alert-detail.png` is a distinct High-filter/detail capture (not a dedicated S07 page). Honest limitation of current data.
3. **Fresh S03 curl→exec field proof in packaged UI**: code+tests aligned; live S03 row visible on home; full transport JSON re-prove may need a fresh S03 exercise under current build.
4. **eslogger / Network Extension**: frozen — no product decision; not implemented.
5. **CI**: will report after push; local self_check fail=0 target.
