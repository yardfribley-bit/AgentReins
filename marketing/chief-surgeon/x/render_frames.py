#!/usr/bin/env python3
"""
渲染带字幕的视频帧（Pillow），输出 ffmpeg concat 清单。

这个 ffmpeg 构建没有 libass / libfreetype（subtitles / drawtext 都不存在），
所以字幕用 Pillow 直接画在底部字幕条上。顺带用逐帧位移做缓慢运镜。

输出：
  frames/seg-0X-NNN.png   字幕帧（1080×1560）
  frames/seg-0X.txt       concat 清单（帧 + 时长）
"""
import json, pathlib, re
from PIL import Image, ImageDraw, ImageFont

BASE = pathlib.Path(__file__).parent
PNG = BASE / "png-x"
SUBS = BASE / "subs"
FRAMES = BASE / "frames"
FRAMES.mkdir(exist_ok=True)

W, H, BAR = 1080, 1350, 210
CANVAS = H + BAR
OVER = 1.10                                   # 运镜 oversample
FONT_PATH = "/System/Library/Fonts/Supplemental/Arial.ttf"
BAR_BG = (15, 23, 42)                         # #0f172a
TAIL = 0.8                                    # 段尾留白


def load_cues(srt_path):
    txt = srt_path.read_text(encoding="utf-8").strip()
    cues = []
    for block in re.split(r"\n\s*\n", txt):
        lines = [l for l in block.split("\n") if l.strip()]
        if len(lines) < 2:
            continue
        m = re.match(r"(\d+):(\d+):([\d,]+)\s*-->\s*(\d+):(\d+):([\d,]+)", lines[1])
        if not m:
            continue
        def sec(h, mi, s):
            return int(h) * 3600 + int(mi) * 60 + float(s.replace(",", "."))
        start = sec(m.group(1), m.group(2), m.group(3))
        end = sec(m.group(4), m.group(5), m.group(6))
        cues.append((start, end, " ".join(lines[2:]).strip()))
    return cues


def font_for(text, max_w, base=46):
    size = base
    while size >= 30:
        f = ImageFont.truetype(FONT_PATH, size)
        if f.getbbox(text)[2] - f.getbbox(text)[0] <= max_w:
            return f
        size -= 2
    return ImageFont.truetype(FONT_PATH, 30)


def render_segment(idx, meta, cues):
    src = Image.open(PNG / f"{meta['img']}.png").convert("RGB")
    base = src.resize((int(W * OVER), int(H * OVER)), Image.LANCZOS)
    ox, oy = base.width - W, base.height - H
    total = cues[-1][1] + TAIL

    items = []
    for i, (s, e, text) in enumerate(cues):
        t = (s + e) / 2 / total                      # 运镜位置按时间线性推进
        frame = base.crop((int(ox * t), int(oy * t),
                           int(ox * t) + W, int(oy * t) + H))
        canvas = Image.new("RGB", (W, CANVAS), BAR_BG)
        canvas.paste(frame, (0, 0))
        if text:
            d = ImageDraw.Draw(canvas)
            f = font_for(text, W - 200)
            bbox = f.getbbox(text)
            tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
            d.text(((W - tw) / 2 - bbox[0], H + (BAR - th) / 2 - bbox[1]),
                   text, font=f, fill=(255, 255, 255))
        p = FRAMES / f"seg-{idx:02d}-{i:03d}.png"
        canvas.save(p, optimize=True)
        items.append((p, e - s))
    items.append((items[-1][0], TAIL))               # 尾帧

    lst = FRAMES / f"seg-{idx:02d}.txt"
    lines = []
    for p, dur in items:
        lines.append(f"file '{p.resolve()}'\nduration {max(dur, 0.05):.3f}")
    lines.append(f"file '{items[-1][0].resolve()}'")  # concat 要求末帧重复
    lst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return total


def main():
    timing = json.loads((BASE / "timing.json").read_text())
    out = []
    for t in timing:
        idx = t["n"]
        cues = load_cues(SUBS / f"seg-{idx:02d}.srt")
        dur = render_segment(idx, t, cues)
        out.append({"n": idx, "list": str(FRAMES / f"seg-{idx:02d}.txt"),
                    "audio": t["audio"], "dur": round(dur, 2)})
        print(f"seg-{idx:02d}  {len(cues):2d} 帧  {dur:5.2f}s")
    (BASE / "frames.json").write_text(json.dumps(out, indent=2))
    print(f"\n总时长 {sum(o['dur'] for o in out):.1f}s")


main()
