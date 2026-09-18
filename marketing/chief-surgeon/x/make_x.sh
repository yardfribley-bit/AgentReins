#!/bin/bash
set -e
cd "$(dirname "$0")"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
[ -x "$CHROME" ] || { echo "Chrome 未找到" >&2; exit 1; }
mkdir -p png-x
for f in svg-x/*.svg; do
  n=$(basename "$f" .svg)
  "$CHROME" --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
    --force-device-scale-factor=2 --window-size=1080,1350 --virtual-time-budget=4000 \
    --screenshot="png-x/$n.png" "file://$PWD/$f" >/dev/null 2>&1
  printf "%-16s " "$n.png"
  [ -f "png-x/$n.png" ] && sips -g pixelWidth -g pixelHeight "png-x/$n.png" 2>/dev/null \
    | awk '/pixel/{printf "%s ", $2}' && echo "px" || echo "FAILED"
done
