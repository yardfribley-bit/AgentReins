#!/bin/bash
# 生成 X 发表用素材：3:4 竖版多页 PDF + 每页高清 PNG（carousel 用）
set -e
cd "$(dirname "$0")"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PY=/Users/jatsmith/.workbuddy/binaries/python/envs/default/bin/python
[ -x "$CHROME" ] || { echo "Chrome 未找到: $CHROME" >&2; exit 1; }

$PY build_pdf.py

echo "→ 打印 PDF ..."
rm -f "AgentReins-Chief-Surgeon.pdf"
"$CHROME" --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer \
  --run-all-compositor-stages-before-draw --virtual-time-budget=8000 \
  --print-to-pdf="AgentReins-Chief-Surgeon.pdf" \
  "file://$PWD/deck.html" >/dev/null 2>&1
[ -f "AgentReins-Chief-Surgeon.pdf" ] || { echo "PDF 生成失败" >&2; exit 1; }

echo "→ 导出每页 PNG (2400×3000) ..."
mkdir -p png-deck
for f in pages/page-*.html; do
  n=$(basename "$f" .html)
  "$CHROME" --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
    --force-device-scale-factor=2 --window-size=1200,1200 \
    --virtual-time-budget=4000 \
    --screenshot="png-deck/$n.png" "file://$PWD/$f" >/dev/null 2>&1
  printf "   %-10s " "$n.png"
  [ -f "png-deck/$n.png" ] && sips -g pixelWidth -g pixelHeight "png-deck/$n.png" 2>/dev/null \
    | awk '/pixel/{printf "%s ", $2}' && echo "px" || echo "FAILED"
done

$PY - <<'PY'
import re, pathlib
d = pathlib.Path("AgentReins-Chief-Surgeon.pdf").read_bytes()
counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", d)]
box = re.findall(rb"/MediaBox\s*\[([^\]]+)\]", d)
print(f"\n✓ PDF: AgentReins-Chief-Surgeon.pdf")
print(f"  页数 {max(counts) if counts else '?'} · 大小 {len(d)/1024/1024:.2f} MB · 页面 {box[0].decode().strip() if box else '?'} pt")
PY
