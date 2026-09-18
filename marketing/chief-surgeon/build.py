#!/usr/bin/env python3
# 把 4 张 SVG 内联进一个排版好的 HTML 页面（单一文件，便于预览/分享）
import pathlib, html

BASE = pathlib.Path(__file__).parent
SVG = BASE / "svg"

DIAGRAMS = [
    ("01-passive-monitor.svg",
     "Figure 1 — Today: AgentReins as a Passive Monitor",
     "Use this to open the thread. It shows what the Alpha does now: capture process lineage, "
     "file changes and sockets from every agent, then write them to an append-only SQLite WAL. "
     "The punchline is the amber bar — it records everything and controls nothing."),
    ("02-bottleneck.svg",
     "Figure 2 — The Bottleneck: Many Agents, One Codebase, No Owner",
     "The problem statement. Four agents mutate one repository with no shared memory. "
     "The crossing arrows are the argument: competence does not compose. "
     "Context collapse, hallucinated APIs, conflicting edits, spaghetti code."),
    ("03-surgical-team.svg",
     "Figure 3 — The Classic Pattern: Brooks' Surgical Team (1975)",
     "The credibility slide. You are not inventing a new org chart, you are reviving a proven one. "
     "One surgeon owns the architecture; specialists and clerks remove every obstacle from his path."),
    ("04-chief-surgeon-architecture.svg",
     "Figure 4 — AgentReins as the AI Chief Surgeon (hero image)",
     "The payoff. Control plane on top, scoped task envelope in the middle, execution layer at the bottom, "
     "and a dashed telemetry line closing the loop on the right. If the reader only saves one image, it is this one."),
]

COMPARE = [
    ("Role", "Monitor plane (today)", "Control plane (next)"),
    ("Authority", "read-only observer", "issues and revokes tasks"),
    ("Knowledge", "per-event telemetry", "global repo tree + call graph + intent stream"),
    ("Unit of work", "an event (write, spawn, connect)", "a scoped, budgeted task envelope"),
    ("Failure handling", "records it after the fact", "blocks it before it lands"),
    ("Agents' job", "each agent decides for itself", "each agent executes a narrow slice"),
    ("Outcome", "transparency", "transparency + conceptual integrity"),
]

POST = """Lately I've been building AgentReins, a local-first safety and transparency console for macOS.

Its initial goal was simple: track the process lineage (PID/PPID), file changes, and network sockets of tools like Cursor, Codex, and Workbuddy — to see exactly what these AI agents are doing.

It's still an early, fragile Alpha. But staring at our structured SQLite WAL evidence spine, a radical idea hit me:

Since AgentReins already understands the global context, live states, and intents of every sub-agent... why limit it to being a spectator?

Time to pull the reins and make it the Surgeon."""

TWEETS = [
    "1/ Your agents are not dumb. They are unmanaged.\n\nI've been building AgentReins — a local-first console that watches Cursor, Codex and Workbuddy at the syscall level: process lineage, file writes, network sockets.\n\nHere's what the evidence made obvious. 🧵",
    "2/ This is what AgentReins sees today.\n\nEvery agent. Every spawn. Every file touched. Every socket opened.\n\nWritten to an append-only SQLite WAL evidence spine.\n\nIt records everything.\n\nAnd it controls nothing.",
    "3/ The bottleneck is not model quality.\n\nIt is ownership.\n\nFour agents, one codebase, no shared memory:\n→ context collapse\n→ hallucinated APIs\n→ conflicting edits\n→ spaghetti code\n\nNobody owns the architecture. Everyone edits it.",
    "4/ Fred Brooks solved this in 1975.\n\nThe Surgical Team: one Chief Programmer owns the design so the system keeps its conceptual integrity. Everyone else is a specialist clearing his path.\n\nWe forgot this. Agents made us forget it faster.",
    "5/ So AgentReins stops being a spectator and becomes the Surgeon.\n\nControl plane on top: global repo tree, call graph, intent stream.\nScoped task envelope in the middle: paths, budget, gates.\nExecution layer below: your agents, powerful but narrow.\n\nLoop closed.",
    "6/ The execution layer does not need to know WHY the architecture changed.\n\nCursor: local mutation in narrow file blocks.\nCodex: focused patches, no design calls.\nWorkbuddy: independent builds and tests.\n\nThey execute. One mind decides.",
    "7/ Passive monitor → Chief Surgeon.\n\nSame telemetry. New authority.\n\nAgentReins is early and fragile, but the direction is set: transparency first, then control — and never control without evidence.\n\nRepo in reply. ⬇️",
]

def inline(name: str) -> str:
    txt = (SVG / name).read_text(encoding="utf-8")
    # strip the xml prolog if present
    txt = txt.split("?>", 1)[-1].strip() if txt.startswith("<?xml") else txt
    return txt

figs = []
for fname, title, desc in DIAGRAMS:
    figs.append(f"""
    <section class="fig">
      <h2>{html.escape(title)}</h2>
      <p class="desc">{html.escape(desc)}</p>
      <div class="canvas">{inline(fname)}</div>
      <div class="dl"><a href="svg/{fname}" download>SVG</a><a href="png/{fname.replace('.svg', '.png')}" download>PNG</a></div>
    </section>""")

rows = "\n".join(
    f"<tr><td class='k'>{html.escape(a)}</td><td>{html.escape(b)}</td><td class='hi'>{html.escape(c)}</td></tr>"
    for a, b, c in COMPARE[1:]
)
head = COMPARE[0]

tweets = "\n".join(
    f"<div class='tw'><div class='tw-n'>{i+1}</div><pre>{html.escape(t)}</pre></div>"
    for i, t in enumerate(TWEETS)
)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentReins — From Passive Monitor to Chief Surgeon · Visual Pack</title>
<style>
  :root {{
    --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --panel:#f8fafc;
    --teal:#0f766e; --teal-soft:#f0fdfa; --amber:#92400e; --amber-soft:#fffbeb;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:#f1f5f9; color:var(--ink);
    font:16px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    -webkit-font-smoothing:antialiased;
  }}
  .wrap {{ max-width:1080px; margin:0 auto; padding:56px 24px 96px; }}
  header.hero {{
    background:#0f172a; color:#fff; border-radius:18px; padding:44px 44px 38px; margin-bottom:40px;
  }}
  header.hero .eyebrow {{ font-size:12px; letter-spacing:3px; color:#5eead4; font-weight:700; }}
  header.hero h1 {{ font-size:34px; line-height:1.25; margin:14px 0 12px; }}
  header.hero p {{ margin:0; color:#94a3b8; font-size:15.5px; max-width:760px; }}
  .meta {{ margin-top:22px; display:flex; gap:10px; flex-wrap:wrap; }}
  .meta span {{ background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.14);
    border-radius:999px; padding:5px 13px; font-size:12.5px; color:#cbd5e1; }}

  h2 {{ font-size:20px; margin:0 0 8px; letter-spacing:-.2px; }}
  .desc {{ color:var(--muted); font-size:14.5px; margin:0 0 18px; max-width:820px; }}

  .fig {{ background:#fff; border:1px solid var(--line); border-radius:16px;
    padding:30px 30px 24px; margin-bottom:28px; }}
  .canvas {{ border:1px solid var(--line); border-radius:12px; overflow:hidden; background:#fff; }}
  .canvas svg {{ display:block; width:100%; height:auto; }}
  .dl {{ margin-top:14px; display:flex; gap:10px; }}
  .dl a {{ font-size:12.5px; color:var(--teal); text-decoration:none; border:1px solid #99f6e4;
    background:var(--teal-soft); border-radius:8px; padding:5px 14px; font-weight:600; }}
  .dl a:hover {{ background:#ccfbf1; }}

  table {{ width:100%; border-collapse:collapse; background:#fff; font-size:14.5px; }}
  th, td {{ text-align:left; padding:13px 16px; border-bottom:1px solid var(--line); vertical-align:top; }}
  thead th {{ background:#0f172a; color:#fff; font-size:12px; letter-spacing:1.5px; text-transform:uppercase; }}
  td.k {{ font-weight:700; width:170px; background:var(--panel); }}
  td.hi {{ color:var(--teal); font-weight:600; }}

  .post {{ background:#fff; border:1px solid var(--line); border-radius:16px; padding:30px 32px; }}
  .post pre {{ white-space:pre-wrap; font:15px/1.75 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; }}

  .tw {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:18px 20px; margin-bottom:12px;
    display:flex; gap:16px; }}
  .tw-n {{ flex:0 0 30px; height:30px; border-radius:8px; background:var(--teal-soft); color:var(--teal);
    font-weight:700; font-size:13px; display:flex; align-items:center; justify-content:center; }}
  .tw pre {{ margin:0; white-space:pre-wrap; font:14.5px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }}

  .note {{ background:var(--amber-soft); border:1px solid #fcd34d; border-radius:14px;
    padding:20px 24px; color:#78350f; font-size:14px; }}
  .note b {{ color:var(--amber); }}
  .note ul {{ margin:10px 0 0; padding-left:20px; }}
  .note li {{ margin:5px 0; }}
  h3 {{ font-size:16px; margin:34px 0 14px; }}
  footer {{ margin-top:44px; color:var(--muted); font-size:13px; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">

  <header class="hero">
    <div class="eyebrow">VISUAL PACK · AGENTREINS</div>
    <h1>From “Passive Monitor” to “Chief Surgeon”</h1>
    <p>Four diagrams for the thread that explains why a local-first observability console should grow into a
       control plane — and how Brooks’ Surgical Team gives multi-agent orchestration its conceptual integrity back.
       All artwork text is English-only, ready to post.</p>
    <div class="meta">
      <span>4 diagrams</span><span>SVG + PNG</span><span>1200×720 / 1200×800</span><span>English only</span>
    </div>
  </header>

  {''.join(figs)}

  <section class="fig">
    <h2>Figure 5 — Monitor Plane vs Control Plane</h2>
    <p class="desc">A plain-language table for readers who skim. The single most quotable line:
       “Same telemetry. New authority.”</p>
    <div class="canvas" style="padding:0">
      <table>
        <thead><tr><th>{head[0]}</th><th>{head[1]}</th><th>{head[2]}</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </section>

  <h3>The post (opening, verbatim)</h3>
  <section class="post"><pre>{html.escape(POST)}</pre></section>

  <h3>Suggested thread — 7 posts, one image each</h3>
  {tweets}

  <h3>How to use this pack</h3>
  <div class="note">
    <b>发文建议（中文备注，不会出现在图片里）</b>
    <ul>
      <li><b>配图顺序</b>：Fig 1 开场 → Fig 2 抛问题 → Fig 3 立论（Brooks）→ Fig 4 收尾（主图）。Fig 5 表格单独发一条，适合给不看图的人。</li>
      <li><b>主图</b>用 Fig 4：信息最完整，单张就能讲完整个架构。</li>
      <li>PNG 是 2× 分辨率（2400×1600 左右），X 上会被压缩，建议直接传 PNG；SVG 用于 GitHub README / 官网。</li>
      <li>Fig 1 里出现了 SQLite WAL、PID/PPID 这些真实实现细节——这是你的可信度来源，别删。</li>
      <li>Alpha 阶段的事实在第 7 条里明说了，保持诚实，比吹牛更容易被转发。</li>
    </ul>
  </div>

  <footer>AgentReins visual pack · generated 2026-09-17 · all diagram text in English</footer>
</div>
</body>
</html>
"""

out = BASE / "index.html"
out.write_text(HTML, encoding="utf-8")
print("wrote", out, len(HTML), "bytes")
