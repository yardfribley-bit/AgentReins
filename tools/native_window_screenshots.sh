#!/bin/bash
# Capture titled AgentReins.app windows (with macOS chrome). No offscreen WKWebView.
# Waits until WKWebView has non-empty text so content is visible (not blank chrome-only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${AGENTREINS_APP:-$ROOT/AgentReins.app}"
OUT="${1:-$ROOT/docs/evidence/en_39ed68a7}"
mkdir -p "$OUT"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist" 2>/dev/null || echo unknown)
BUILD=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$APP/Contents/Info.plist" 2>/dev/null || echo unknown)

pkill -x AgentReins 2>/dev/null || true
sleep 1
open "$APP"

# Wait for titled window
WID=""
for i in $(seq 1 60); do
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

# Wait until accessibility tree has risk-alert text (WKWebView populated)
for i in $(seq 1 40); do
  HAS=$(osascript <<'OSA' 2>/dev/null || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    try
      set t to value of static text 1 of window 1
    on error
      set t to ""
    end try
    set entire to ""
    try
      set entire to entire contents of window 1 as string
    end try
    if entire contains "风险告警" or entire contains "CRITICAL" or entire contains "S03" or entire contains "告警" or entire contains "AgentReins" then
      return "yes"
    end if
    return "no"
  end tell
end tell
OSA
)
  if [[ "$HAS" == "yes" ]]; then
    echo "content detected after ${i} polls"
    break
  fi
  sleep 0.75
done
sleep 1.5

# Home / alerts board
screencapture -l "$WID" -o -x "$OUT/01-alerts-home-native.png"
echo "wrote 01-alerts-home-native.png wid=$WID version=$VERSION build=$BUILD"

# Click first critical / S03 row area
osascript <<'OSA' || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    set win to window 1
    set {x, y} to position of win
    set {w, h} to size of win
    -- risk alerts home is default; click mid table first row
    click at {x + (w * 0.45), y + 260}
    delay 1.2
  end tell
end tell
OSA
screencapture -l "$WID" -o -x "$OUT/02-s03-alert-detail-native.png"
echo "wrote 02-s03-alert-detail-native.png"

# Filter / click S07 (high) row further down
osascript <<'OSA' || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    set win to window 1
    set {x, y} to position of win
    set {w, h} to size of win
    -- left filter "High" roughly
    click at {x + 90, y + 320}
    delay 0.6
    click at {x + (w * 0.45), y + 300}
    delay 1.2
  end tell
end tell
OSA
screencapture -l "$WID" -o -x "$OUT/03-s07-alert-detail-native.png"
echo "wrote 03-s07-alert-detail-native.png"

# About window via menu if present
osascript <<'OSA' || true
tell application "System Events"
  tell process "AgentReins"
    set frontmost to true
    try
      click menu item "关于 AgentReins" of menu "AgentReins" of menu bar 1
    on error
      try
        click menu item "About AgentReins" of menu "AgentReins" of menu bar 1
      end try
    end try
    delay 1.0
  end tell
end tell
OSA
ABOUT_WID=$(osascript <<'OSA' 2>/dev/null || true
tell application "System Events"
  tell process "AgentReins"
    if (count of windows) < 1 then return ""
    -- prefer a window whose title contains 关于/About
    repeat with w in windows
      set t to name of w as string
      if t contains "关于" or t contains "About" then return id of w
    end repeat
    return id of window 1
  end tell
end tell
OSA
)
if [[ -n "${ABOUT_WID:-}" ]]; then
  screencapture -l "$ABOUT_WID" -o -x "$OUT/04-about-native.png"
  echo "wrote 04-about-native.png wid=$ABOUT_WID"
fi

python3 - <<PY
import hashlib, json, pathlib
out = pathlib.Path("$OUT")
meta = {"version": "$VERSION", "build": "$BUILD", "app": "$APP", "files": {}}
for name in ["01-alerts-home-native.png","02-s03-alert-detail-native.png","03-s07-alert-detail-native.png","04-about-native.png"]:
    p = out / name
    if not p.is_file():
        continue
    data = p.read_bytes()
    meta["files"][name] = {
        "bytes": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    print(name, meta["files"][name]["bytes"], meta["files"][name]["md5"])
mds = [v["md5"] for v in meta["files"].values()]
meta["distinctMd5"] = len(mds) == len(set(mds))
(out / "native-screenshots.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("distinctMd5", meta["distinctMd5"], "build", meta["build"])
if not meta["distinctMd5"]:
    raise SystemExit("screenshot md5s are not distinct")
PY
