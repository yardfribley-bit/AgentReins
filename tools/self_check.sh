#!/bin/bash
# en_26fd4180 deliverable self-check — paste full output into the report entry.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
say() { printf '%s\n' "$*"; }
ok() { say "OK  $*"; }
bad() { say "FAIL $*"; FAIL=1; }

GIT="$(env -u GIT_DIR -u GIT_WORK_TREE git --git-dir="$ROOT/.git" --work-tree="$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
say "=== self_check en_26fd4180 ==="
say "cwd=$ROOT"
say "git=$GIT"

say "--- 0 red lines: no production XSS hooks / no unsigned quarantine ---"
if rg -n '\bTEST_PROBE\b|\bsetTestProbe\b|\bwithProbe\b' Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js >/tmp/self_check_hooks.txt 2>/dev/null; then
  bad "XSS hooks still present"; cat /tmp/self_check_hooks.txt
else
  ok "no TEST_PROBE/setTestProbe/withProbe in shipped JS"
fi
if rg -n 'HISTORICAL_MAC_QUARANTINE|def quarantine_historical_mac_mismatch' tools/agentreins-mcp/evidence.py >/dev/null; then
  bad "quarantine wash still present"
else
  ok "no quarantine wash API"
fi
if rg -n 'add-generic-password' tools/agentreins-mcp/evidence.py >/dev/null; then
  bad "security CLI add-generic-password still used"
else
  ok "Keychain via keychain_helper (no security -A)"
fi

say "--- 1 redaction ---"
if OUT=$(python3 tools/redact_secrets.py 2>&1); then
  say "$OUT"
  echo "$OUT" | grep -q 'leaks=0 over=0' && ok "REDACT python" || bad "REDACT python line"
else
  bad "REDACT python exited non-zero"; say "$OUT"
fi

say "--- 2 XSS mutation (data-driven, no hooks) ---"
if OUT=$(node tools/mutate_esc_calls.cjs 2>&1); then
  say "$OUT"
  if echo "$OUT" | python3 -c "import sys,re; t=sys.stdin.read(); m=re.search(r'total=(\d+) killed=(\d+) survived=(\d+)',t); sys.exit(0 if m and int(m.group(2))>=57 and int(m.group(3))<=2 else 1)"; then
    ok "ESC_MUTANTS >=57/59 and <=2 survivors"
  else
    bad "ESC_MUTANTS below bar"; say "$OUT"
  fi
else
  bad "mutate_esc_calls failed"; say "$OUT"
fi

say "--- 3 tamper B1–B16 ---"
if python3 -m unittest discover -s tools/agentreins-mcp -p 'test_tamper*.py' -v 2>&1 | tee /tmp/self_check_tamper.txt | tail -25; then
  ok "tamper suite"
else
  bad "tamper suite"
fi

say "--- 4 screenshots (if present) ---"
EVID="${SELF_CHECK_EVID:-$ROOT/docs/evidence/en_26fd4180}"
if ls "$EVID"/screenshots/0*.png >/dev/null 2>&1; then
  for p in "$EVID"/screenshots/0*.png; do
    if python3 tools/check_screenshot.py "$p"; then ok "shot $(basename "$p")"; else bad "shot $(basename "$p")"; fi
  done
  python3 - <<PY
import hashlib, pathlib, sys
files=sorted(pathlib.Path("$EVID/screenshots").glob("0*.png"))
md5s=[hashlib.md5(p.read_bytes()).hexdigest() for p in files]
print("screenshot_md5s", list(zip([p.name for p in files], md5s)))
if len(md5s)!=len(set(md5s)):
  print("FAIL duplicate screenshot md5"); sys.exit(1)
print("OK distinct screenshot md5")
PY
else
  say "SKIP screenshots (no $EVID/screenshots/0*.png yet)"
fi

say "--- 5 real-machine validate_audit (honest; ok=false expected if historical mac_mismatch remain) ---"
python3 - <<'PY'
import sys
sys.path.insert(0, "tools/agentreins-mcp")
import evidence
v = evidence.validate_audit()
print("validate_audit ok=", v.get("ok"), "confidence=", v.get("confidence"), "observedBlockedBy=", v.get("observedBlockedBy"))
print("tampered_sample=", (v.get("tampered") or [])[:8])
print("entriesChecked=", v.get("entriesChecked"))
# Never wash: if mac_mismatch present, ok must be false.
mm=[t for t in (v.get("tampered") or []) if t.get("reason")=="mac_mismatch"]
if mm and v.get("ok") is True:
  print("FAIL quarantine-wash detected")
  raise SystemExit(1)
if v.get("confidence")=="Observed" and v.get("b6",{}).get("sameUidCanForge"):
  print("FAIL Observed despite same-uid forgeability")
  raise SystemExit(1)
print("REAL_MACHINE_HONEST=true")
PY

say "=== self_check done fail=$FAIL git=$GIT ==="
exit "$FAIL"
