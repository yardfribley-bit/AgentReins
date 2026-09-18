#!/usr/bin/env python3
"""
把字幕帧序列 + 旁白音频组装成竖版视频（1080×1560，X 可用）。

注：本机 ffmpeg（homebrew 8.1）未编译 libass / libfreetype，
    subtitles / drawtext 均不可用 —— 字幕已由 render_frames.py 用 Pillow 烧进帧里。

流程：每段 = concat 帧序列 + 旁白 → 单独 mp4 → concat 4 段 → +faststart
"""
import json, pathlib, subprocess, sys

BASE = pathlib.Path(__file__).parent
BUILD = BASE / "build"
BUILD.mkdir(exist_ok=True)
OUT = BASE / "AgentReins-Chief-Surgeon.mp4"

FF = "/usr/local/bin/ffmpeg"
FFPROBE = "/usr/local/bin/ffprobe"

segs = json.loads((BASE / "frames.json").read_text())


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("FFMPEG FAILED:\n", r.stderr[-3000:])
        sys.exit(1)


parts = []
for s in segs:
    n, dur = s["n"], s["dur"]
    dst = BUILD / f"seg-{n:02d}.mp4"
    vf = (f"fps=30,format=yuv420p,"
          f"fade=t=in:st=0:d=0.45,fade=t=out:st={max(dur - 0.45, 0.01):.2f}:d=0.45")
    af = (f"apad,atrim=0:{dur},afade=t=in:st=0:d=0.25,"
          f"afade=t=out:st={max(dur - 0.5, 0.01):.2f}:d=0.5")
    run([FF, "-y", "-f", "concat", "-safe", "0", "-i", s["list"],
         "-i", s["audio"],
         "-filter_complex", f"[0:v]{vf}[v];[1:a]{af}[a]",
         "-map", "[v]", "-map", "[a]",
         "-c:v", "libx264", "-preset", "medium", "-crf", "20",
         "-c:a", "aac", "-b:a", "192k", "-ar", "48000",
         "-t", f"{dur}", "-shortest", "-movflags", "+faststart", str(dst)])
    print(f"seg-{n:02d}.mp4  {dur:5.2f}s  {dst.stat().st_size / 1024 / 1024:5.1f} MB")
    parts.append(dst)

lst = BUILD / "concat.txt"
lst.write_text("".join(f"file '{p.resolve()}'\n" for p in parts))
run([FF, "-y", "-f", "concat", "-safe", "0", "-i", str(lst),
     "-c", "copy", "-movflags", "+faststart", str(OUT)])

info = json.loads(subprocess.run(
    [FFPROBE, "-v", "error", "-select_streams", "v:0",
     "-show_entries", "stream=width,height,r_frame_rate,codec_name",
     "-show_entries", "format=duration,size", "-of", "json", str(OUT)],
    capture_output=True, text=True).stdout)
st, fm = info["streams"][0], info["format"]
print(f"\n✓ {OUT.name}")
print(f"  {st['width']}×{st['height']} · {st['codec_name']} · {st['r_frame_rate']} fps")
print(f"  {float(fm['duration']):.1f}s · {int(fm['size']) / 1024 / 1024:.1f} MB")
