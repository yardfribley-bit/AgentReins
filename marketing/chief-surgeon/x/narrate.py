#!/usr/bin/env python3
"""
生成英文旁白 + 时间轴字幕（edge-tts, en-US-AndrewNeural）。

字幕策略：用 edge-tts 的 SentenceBoundary（带标点的精确时间轴），
句内再按 ~46 字符切成短行，句内时间按字符数比例分配。
比词级对齐稳——数字 1975 会被读成多个词，词级对齐会整体错位。

输出：
  audio/seg-0X.mp3   每段旁白
  subs/seg-0X.srt    每段字幕（时间从 0 开始，供 ffmpeg 单独烧录）
  timing.json        每段时长 / 图片映射
"""
import asyncio, json, pathlib, subprocess
import edge_tts

BASE = pathlib.Path(__file__).parent
AUDIO = BASE / "audio"
SUBS = BASE / "subs"
AUDIO.mkdir(exist_ok=True)
SUBS.mkdir(exist_ok=True)

VOICE = "en-US-AndrewNeural"   # warm, confident, authentic, honest
RATE = "-4%"
MAX_CHARS = 46

SCRIPT = [
    {
        "img": "1-monitor",
        "title": "01 · THE MONITOR",
        "text": (
            "Every agent on your machine — Cursor, Codex, Workbuddy — spawns processes, "
            "rewrites files, opens sockets. AgentReins records all of it. Process lineage. "
            "File mutations. Network destinations. Everything lands in an append-only SQLite WAL, "
            "the evidence spine. But here is the limit. It records every action, "
            "and it can stop none of them. That is a monitor plane."
        ),
    },
    {
        "img": "2-bottleneck",
        "title": "02 · THE BOTTLENECK",
        "text": (
            "Meanwhile, the real bottleneck is not model quality. It is ownership. "
            "Four competent agents, one shared repository, and no shared model of what anyone "
            "is actually trying to do. Context collapse. Conflicting edits. Spaghetti code. "
            "Competence does not compose."
        ),
    },
    {
        "img": "3-brooks",
        "title": "03 · THE PATTERN",
        "text": (
            "Fred Brooks solved this exact problem in 1975. In The Mythical Man-Month, he "
            "described the Surgical Team. One chief programmer owns conceptual integrity, "
            "while co-pilots, testers and toolsmiths clear his path. Now map that onto agents. "
            "AgentReins becomes the surgeon. Your coding tools become the specialists."
        ),
    },
    {
        "img": "4-shift",
        "title": "04 · THE SHIFT",
        "text": (
            "So the monitor plane becomes a control plane. AgentReins holds the global "
            "repository tree, the call graph, and the live intent stream. It issues scoped "
            "task envelopes — scope, budget, gate — and Cursor, Codex and Workbuddy execute "
            "strictly inside that boundary. Every result flows back as evidence, and the loop closes. "
            "Same telemetry. New authority."
        ),
    },
]


def srt_ts(t: float) -> str:
    return f"{int(t // 3600):02d}:{int((t % 3600) // 60):02d}:{t % 60:06.3f}".replace(".", ",")


def split_phrase(s: str, limit: int = MAX_CHARS):
    """在空格处断行，逗号优先；返回 [(start, end, text)]"""
    out, start, last_comma = [], 0, None
    for i, ch in enumerate(s):
        if ch == ",":
            last_comma = i
        if ch == " " and (i - start) >= limit:
            cut = last_comma + 1 if last_comma and (last_comma - start) >= limit * 0.5 else i
            out.append((start, cut, s[start:cut].strip()))
            start, last_comma = cut, None
    out.append((start, len(s), s[start:].strip()))
    return [o for o in out if o[2]]


async def synth(text: str, mp3: pathlib.Path):
    comm = edge_tts.Communicate(text, VOICE, rate=RATE)
    audio, sents = bytearray(), []
    async for ch in comm.stream():
        if ch["type"] == "audio":
            audio.extend(ch["data"])
        elif ch["type"] == "SentenceBoundary":
            sents.append((ch["offset"] / 1e7, ch["duration"] / 1e7, ch["text"].strip()))
    mp3.write_bytes(bytes(audio))
    return sents


def build_cues(sents):
    cues = []
    for off, dur, sent in sents:
        parts = split_phrase(sent)
        total = sum(len(p[2]) for p in parts) or 1
        acc = 0.0
        for _s, _e, txt in parts:
            seg_dur = dur * (len(txt) / total)
            cues.append((off + acc, off + acc + seg_dur, txt))
            acc += seg_dur
    return cues


async def main():
    timing = []
    for i, seg in enumerate(SCRIPT, 1):
        mp3 = AUDIO / f"seg-{i:02d}.mp3"
        sents = await synth(seg["text"], mp3)
        dur = float(subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=nw=1:nk=1", str(mp3)],
            capture_output=True, text=True).stdout.strip())
        cues = build_cues(sents)
        srt = "\n".join(f"{n}\n{srt_ts(a)} --> {srt_ts(b)}\n{txt}\n"
                        for n, (a, b, txt) in enumerate(cues, 1))
        (SUBS / f"seg-{i:02d}.srt").write_text(srt, encoding="utf-8")
        timing.append({"n": i, "img": seg["img"], "title": seg["title"],
                       "audio": str(mp3), "dur": dur, "cues": len(cues)})
        print(f"seg-{i:02d}  {dur:5.2f}s  {len(cues):2d} 行字幕")
    (BASE / "timing.json").write_text(json.dumps(timing, indent=2, ensure_ascii=False))
    print(f"\n总时长 {sum(t['dur'] for t in timing):.1f}s")


asyncio.run(main())
