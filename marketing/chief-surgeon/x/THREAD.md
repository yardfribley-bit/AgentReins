# X 发文文案 — AgentReins: Monitor → Surgeon

配图顺序：1-monitor → 2-bottleneck → 3-brooks → 4-shift（单条 4 图轮播，或 4 条 thread 各配一图）

---

## 方案 A：单条推文 + 4 图轮播（推荐，280 字符内）

```
Your agents aren't dumb. They're unmanaged.

I built AgentReins to see what Cursor, Codex and Workbuddy actually do —
process lineage, file writes, sockets — in an append-only SQLite WAL.

The evidence points at something bigger than observability. 🧵
```

## 方案 B：Thread（4 条，每条配一图）

**1/4**（配 1-monitor）
```
AgentReins watches every agent on your Mac: process lineage (PID/PPID),
file writes, network sockets — into an append-only SQLite WAL.

It records every action. It can stop none of them.

That's the monitor plane. Here's the case for a control plane. 🧵
```

**2/4**（配 2-bottleneck）
```
The bottleneck in multi-agent work isn't model quality. It's ownership.

Four competent agents, one shared repo, zero shared model of intent:

context collapse · conflicting edits · spaghetti code.

Competence does not compose.
```

**3/4**（配 3-brooks）
```
Brooks solved this in 1975.

The Surgical Team: one Chief Programmer owns conceptual integrity.
Co-pilot, testers, toolsmiths — specialists clearing his path.

Map it onto agents: AgentReins is the Surgeon.
Cursor, Codex, Workbuddy are the specialists.
```

**4/4**（配 4-shift）
```
So: monitor plane → control plane.

AgentReins holds the global repo tree, call graph and intent stream,
issues scoped task envelopes (scope · budget · gate),
and your agents execute inside the boundary.

Same telemetry. New authority. The loop closes on evidence.

Alpha, early and fragile — repo in bio.
```

---

## Alt text（无障碍，逐图）

1. "Diagram: Cursor, Codex and Workbuddy feed process, file and socket events into a SQLite WAL evidence spine, which a read-only AgentReins observes."
2. "Diagram: four agent arrows converge on one repository, producing context collapse, conflicting edits and spaghetti code."
3. "Diagram: Brooks' 1975 Surgical Team mapped onto an agent stack — The Surgeon becomes AgentReins; Co-pilot, Tester and Toolsmith become Cursor, Codex and Workbuddy."
4. "Diagram: control plane (AgentReins: repo tree, call graph, intent stream) issues scoped task envelopes down to the execution layer, with a dashed evidence loop closing back up."

## 发布要点

- 单条 4 图轮播在 X 上按 4:5 显示，占屏最大；图片顺序即阅读顺序
- 首图决定点击率：方案 A 用 1-monitor 打头（具体、可验证，不是口号）
- "Alpha, early and fragile" 保留——技术圈对诚实度敏感，吹"生产可用"会被 quote 嘲
- 转发自己的贴加 repo 链接，正文保持无链接（算法权重更高）

---

# 视频版（AgentReins-Chief-Surgeon.mp4）

**规格**：1080×1560 竖版 · H.264 + AAC · 94 秒 · 3.4 MB · 30fps · -16.3 LUFS

**结构**：4 段，每段一图 + 旁白 + 底部字幕条，缓慢运镜，段间淡入淡出

| 段 | 时长 | 画面 | 旁白要点 |
|---|---|---|---|
| 01 THE MONITOR | 27.8s | 图 1 | 记录一切但不能阻止任何动作 = 监控面 |
| 02 THE BOTTLENECK | 18.6s | 图 2 | 瓶颈不是模型能力，是所有权 |
| 03 THE PATTERN | 22.4s | 图 3 | Brooks 1975 外科团队 → 映射到 agent 栈 |
| 04 THE SHIFT | 25.2s | 图 4 | 控制面下发 scope/budget/gate，证据闭环 |

**配音**：en-US-AndrewNeural（Microsoft neural，warm / confident / authentic），速率 -4%
**字幕**：句级时间轴（edge-tts SentenceBoundary），句内按 46 字符切行，Pillow 烧录在底部深蓝黑条上

## 视频发布要点

- X 视频长度上限：普通 2:20（140s），本片 94s，安全
- 首帧决定停留：开场是图 1（具体、可验证），不要换成口号
- 视频自带字幕 → 无声播放也能读，X 上 80% 播放是静音的，这是关键
- 配文用方案 A 的 hook，链接放评论区（正文中链接会压制推荐）
- 如要更短版本：砍掉 02 段（瓶颈论证），保留 01→03→04，约 75s

## 重新生成

```bash
python3 narrate.py        # 1. 旁白 mp3 + 字幕 srt（需联网，edge-tts）
python3 render_frames.py  # 2. Pillow 渲染字幕帧（运镜同步完成）
python3 build_video.py    # 3. 编码 + 拼接 + 响度归一化
```
改文案：编辑 narrate.py 里的 SCRIPT；改图：编辑 svg-x/*.svg 后跑 make_x.sh
换嗓音：narrate.py 顶部 VOICE（en-US-AndrewNeural / en-GB-RyanNeural / en-US-AvaNeural）
