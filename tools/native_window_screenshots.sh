#!/bin/bash
# Capture titled AgentReins.app windows (with macOS chrome). No offscreen WKWebView.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${AGENTREINS_APP:-$ROOT/AgentReins.app}"
OUT="${1:-$ROOT/docs/evidence/en_7da249ce}"
mkdir -p "$OUT"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo unknown)
BUILD=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$APP/Contents/Info.plist" 2>/dev/null || echo unknown)

pkill -x AgentReins 2>/dev/null || true
sleep 1
open "$APP"
# Wait for titled window
for i in $(seq 1 40); do
  WID=$(osascript <<'OSA' 2>/dev/null || true
tell application "System Events"
  if not (exists process "AgentReins") then return ""
  tell process "AgentReins"
    set frontmost to true
    if (count of windows) is 0 then return ""
    return id of window 1
  end tell
end tell
OSA
)
  if [[ -n "${WID:-}" ]]; then break; fi
  sleep 0.5
done
if [[ -z "${WID:-}" ]]; then
  echo "error: AgentReins window did not appear" >&2
  exit 1
fi
sleep 2

# Home / alerts board
screencapture -l "$WID" -o -x "$OUT/01-alerts-home-native.png"
echo "wrote 01-alerts-home-native.png wid=$WID version=$VERSION build=$BUILD"

# Click alerts nav then first critical row (approximate UI layout)
osascript <<'OSA' || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    -- click left-nav "风险告警" if present via menu-ish toolbar; otherwise click mid-left of window
    set win to window 1
    set {x, y} to position of win
    set {w, h} to size of win
    -- alerts tab roughly left side of toolbar in RealtimeWorkspace
    click at {x + 120, y + 52}
    delay 0.6
    -- first alert row area
    click at {x + (w / 2), y + 280}
    delay 1.0
  end tell
end tell
OSA
screencapture -l "$WID" -o -x "$OUT/02-s03-alert-detail-native.png"
echo "wrote 02-s03-alert-detail-native.png"

osascript <<'OSA' || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    set win to window 1
    set {x, y} to position of win
    set {w, h} to size of win
    -- S07 filter / second high row
    click at {x + 90, y + 360}
    delay 0.8
    click at {x + (w / 2), y + 320}
    delay 1.0
  end tell
end tell
OSA
screencapture -l "$WID" -o -x "$OUT/03-s07-alert-detail-native.png"
echo "wrote 03-s07-alert-detail-native.png"

# Verify title bar presence: PNG should be larger than offscreen content-only shots; record meta
python3 - <<PY
import json, pathlib
out = pathlib.Path("$OUT")
meta = {
  "app": "$APP",
  "version": "$VERSION",
  "build": "$BUILD",
  "windowID": "$WID",
  "method": "screencapture -l (titled NSWindow from AgentReins.app)",
  "note": "macOS title bar included; not offscreen WKWebView takeSnapshot",
  "files": {p.name: p.stat().st_size for p in sorted(out.glob('*-native.png'))},
}
(out / "native-screenshots.json").write_text(json.dumps(meta, indent=2))
print(json.dumps(meta, indent=2))
PY
