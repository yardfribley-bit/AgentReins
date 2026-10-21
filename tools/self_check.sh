#!/bin/bash
# en_4088c393 deliverable self-check — paste full output into the report entry.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAIL=0
say() { printf '%s\n' "$*"; }
ok() { say "OK  $*"; }
bad() { say "FAIL $*"; FAIL=1; }

say "=== self_check en_4088c393 ==="
say "cwd=$ROOT"
say "git=$(env -u GIT_DIR -u GIT_WORK_TREE git --git-dir="$ROOT/.git" --work-tree="$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

say "--- 1 redaction ---"
if OUT=$(python3 tools/redact_secrets.py 2>&1); then
  say "$OUT"
  echo "$OUT" | grep -q 'leaks=0 over=0' && ok "REDACT python" || bad "REDACT python line"
else
  bad "REDACT python exited non-zero"; say "$OUT"
fi

say "--- 2 XSS mutation (playbook mutate_esc_calls) ---"
if OUT=$(node tools/mutate_esc_calls.cjs 2>&1); then
  say "$OUT"
  echo "$OUT" | grep -E 'ESC_MUTANTS total=[0-9]+ killed=\1|ESC_MUTANTS total=([0-9]+) killed=\1' >/dev/null 2>&1 || true
  if echo "$OUT" | grep -qE 'ESC_MUTANTS total=([0-9]+) killed=\1'; then
    ok "ESC_MUTANTS"
  elif echo "$OUT" | python3 -c "import sys,re; t=sys.stdin.read(); m=re.search(r'total=(\d+) killed=(\d+)',t); sys.exit(0 if m and m.group(1)==m.group(2) else 1)"; then
    ok "ESC_MUTANTS"
  else
    bad "ESC_MUTANTS not fully killed"; say "$OUT"
  fi
else
  bad "mutate_esc_calls failed"; say "$OUT"
fi

say "--- 3 tamper B1–B10 ---"
if python3 -m unittest discover -s tools/agentreins-mcp -p 'test_tamper*.py' -v 2>&1 | tee /tmp/self_check_tamper.txt | tail -20; then
  ok "tamper suite"
else
  bad "tamper suite"
fi

say "--- 4 screenshots (if present) ---"
EVID="${SELF_CHECK_EVID:-$ROOT/docs/evidence/en_4088c393}"
if ls "$EVID"/0*.png >/dev/null 2>&1; then
  for p in "$EVID"/0*.png; do
    if python3 tools/check_screenshot.py "$p"; then ok "shot $(basename "$p")"; else bad "shot $(basename "$p")"; fi
  done
else
  say "SKIP screenshots (no $EVID/0*.png yet)"
fi

say "--- 5 real-machine validate_audit ---"
python3 - <<'PY' || true
import sys
sys.path.insert(0, "tools/agentreins-mcp")
import evidence
v = evidence.validate_audit()
print("validate_audit ok=", v.get("ok"), "confidence=", v.get("confidence"), "neverAnchored=", v.get("neverAnchored"))
print("tampered_sample=", (v.get("tampered") or [])[:6])
print("entriesChecked=", v.get("entriesChecked"))
if v.get("ok") is True:
    print("REAL_MACHINE_OK=true")
else:
    print("REAL_MACHINE_OK=false — paste this block into the report with explanation")
PY

say "=== self_check done fail=$FAIL ==="
exit "$FAIL"
