#!/usr/bin/env python3
"""
生成「为 X 发表优化」的 PDF / carousel 版式。

设计原则（不是技术报告，是视觉卡片）：
  - 没有 "Figure 1/2/3" 编号 —— 用 BEFORE / BOTTLENECK / PATTERN / SHIFT 这种叙事标签
  - 每页只讲一件事：标签 + 一句标题 + 一张通栏大图 + 一句金句
  - 图通栏出血（1200px 满宽），上下留白，海报式排版
  - 全英文，无任何中文

产出：
  deck.html                 多页打印源（6 页）
  pages/page-01.html ...    单页源，用于逐页导出 PNG carousel
  AgentReins-Chief-Surgeon.pdf   （由 make_pdf.sh 打印）
  png/deck-01.png ...             （由 make_pdf.sh 导出，2400×3000）

内容常量复用 build.py（取 `def inline` 之前），改文案只需改 build.py。
"""
import pathlib, html

BASE = pathlib.Path(__file__).parent
SVG = BASE / "svg"
PAGES_DIR = BASE / "pages"

# ---- 复用 build.py 中的文案常量 ---------------------------------------------
_src = (BASE / "build.py").read_text(encoding="utf-8")
_ns: dict = {"__file__": str(BASE / "build.py"), "__name__": "agentreins_content"}
exec(_src.split("def inline")[0], _ns)
COMPARE = _ns["COMPARE"]

# ---- 卡片内容：label / title / svg / 金句 / 小字 -----------------------------
CARDS = [
    {
        "svg": "01-passive-monitor.svg",
        "label": "BEFORE",
        "title": "AgentReins today: a passive monitor",
        "sub": "Process lineage, file writes and network sockets from every agent, captured to an append-only SQLite WAL.",
        "punch": "Every agent. Every socket. Every file — on the record.",
    },
    {
        "svg": "02-bottleneck.svg",
        "label": "THE BOTTLENECK",
        "title": "Many agents. One codebase. No owner.",
        "sub": "Context collapse, hallucinated APIs, conflicting edits, spaghetti code.",
        "punch": "The bottleneck is not model quality. It is ownership.",
    },
    {
        "svg": "03-surgical-team.svg",
        "label": "THE PATTERN",
        "title": "Brooks solved this in 1975",
        "sub": "The Surgical Team from The Mythical Man-Month, revived for multi-agent orchestration.",
        "punch": "One surgeon owns the design. Everyone else clears the path.",
    },
    {
        "svg": "04-chief-surgeon-architecture.svg",
        "label": "THE SHIFT",
        "title": "AgentReins as the AI Chief Surgeon",
        "sub": "Global repo tree, call graph and intent stream become a scoped task envelope your agents execute inside.",
        "punch": "One mind decides. Many hands execute.",
    },
]

COVER = {
    "eyebrow": "AGENTREINS",
    "title": "Passive Monitor<br>→ Chief Surgeon",
    "lede": "A local-first console stops watching your agents and starts directing them — "
            "so the system keeps its conceptual integrity.",
    "chips": ["4 diagrams", "macOS · local-first", "Alpha, early and fragile"],
}

TOTAL = len(CARDS) + 2  # cover + cards + comparison


def inline(name: str) -> str:
    txt = (SVG / name).read_text(encoding="utf-8")
    if txt.startswith("<?xml"):
        txt = txt.split("?>", 1)[-1].strip()
    return txt


def card_page(c: dict, n: int) -> str:
    return f"""<section class="page">
  <div class="shot">{inline(c['svg'])}</div>
  <div class="foot">
    <div class="punch">{html.escape(c['punch'])}</div>
    <div class="sub">{html.escape(c['sub'])}</div>
  </div>
  <div class="pn">{n:02d} / {TOTAL:02d}</div>
</section>"""


def table_page(n: int) -> str:
    head = COMPARE[0]
    rows = "\n".join(
        f"<tr><td class='k'>{html.escape(a)}</td><td>{html.escape(b)}</td>"
        f"<td class='hi'>{html.escape(c)}</td></tr>"
        for a, b, c in COMPARE[1:]
    )
    return f"""<section class="page">
  <div class="head">
    <div class="label">THE DIFFERENCE</div>
    <h1>Same telemetry. New authority.</h1>
  </div>
  <div class="tablewrap">
    <table>
      <thead><tr><th>{head[0]}</th><th>{head[1]}</th><th>{head[2]}</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="foot tight">
    <div class="punch">Transparency first. Then control. Never control without evidence.</div>
  </div>
  <div class="pn">{n:02d} / {TOTAL:02d}</div>
</section>"""


cover_page = f"""<section class="page cover">
  <div class="cover-inner">
    <div class="eyebrow">{COVER['eyebrow']}</div>
    <h1>{COVER['title']}</h1>
    <p class="lede">{html.escape(COVER['lede'])}</p>
    <div class="chips">{''.join(f"<span>{html.escape(x)}</span>" for x in COVER['chips'])}</div>
  </div>
  <div class="cover-foot"><span>2026-09-17</span><span>why a monitor should become a control plane</span></div>
</section>"""

pages = [cover_page]
for i, c in enumerate(CARDS):
    pages.append(card_page(c, i + 2))
pages.append(table_page(TOTAL))

CSS = """
@page { size: 1200px 1200px; margin: 0; }
* { box-sizing:border-box; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
html, body { margin:0; padding:0; background:#ffffff; }
body {
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  color:#0f172a; -webkit-font-smoothing:antialiased;
}
.page {
  width:1200px; height:1200px; position:relative; overflow:hidden; background:#fff;
  display:flex; flex-direction:column;
  page-break-after:always; break-after:page;
}
.page:last-child { page-break-after:auto; break-after:auto; }

/* --- 上：标签 + 标题 --- */
.head { padding:44px 64px 16px; }
.label { font-size:13px; letter-spacing:3.4px; font-weight:800; color:#0f766e; margin-bottom:18px; }
h1 { font-size:41px; line-height:1.16; letter-spacing:-.8px; margin:0; font-weight:750; }

/* --- 中：通栏大图 --- */
.shot { width:1200px; background:#fff; line-height:0; }
.shot svg { display:block; width:1200px; height:auto; }

/* --- 下：金句 + 小字 --- */
.foot { flex:1; padding:24px 64px 60px; display:flex; flex-direction:column; justify-content:center; }
.foot.tight { justify-content:flex-end; padding-top:12px; }
.punch { font-size:33px; line-height:1.25; font-weight:750; letter-spacing:-.6px; color:#0f172a; }
.punch::before { content:""; display:block; width:64px; height:5px; background:#0f766e;
  border-radius:3px; margin-bottom:18px; }
.sub { margin-top:16px; font-size:17px; line-height:1.65; color:#64748b; max-width:900px; }
.pn { position:absolute; right:64px; bottom:30px; font-size:12.5px; letter-spacing:2px;
  color:#94a3b8; font-weight:600; }

/* --- 表格页 --- */
.tablewrap { padding:8px 64px 0; }
table { width:100%; border-collapse:collapse; font-size:17px; }
th, td { text-align:left; padding:12px 18px; border-bottom:1px solid #e2e8f0; vertical-align:top; }
thead th { background:#0f172a; color:#fff; font-size:12px; letter-spacing:1.8px;
  text-transform:uppercase; padding:15px 18px; }
td.k { font-weight:700; width:210px; background:#f8fafc; }
td.hi { color:#0f766e; font-weight:650; }

/* --- 封面 --- */
.cover { background:#0f172a; color:#fff; padding:0; }
.cover-inner { flex:1; display:flex; flex-direction:column; justify-content:center; padding:0 84px; }
.cover .eyebrow { font-size:14px; letter-spacing:5px; color:#5eead4; font-weight:800; margin-bottom:28px; }
.cover h1 { font-size:66px; line-height:1.08; letter-spacing:-2px; color:#fff; }
.cover .lede { color:#cbd5e1; font-size:21px; line-height:1.6; margin:28px 0 0; max-width:860px; }
.chips { display:flex; gap:12px; flex-wrap:wrap; margin-top:38px; }
.chips span { border:1px solid rgba(255,255,255,.18); background:rgba(255,255,255,.06);
  color:#cbd5e1; border-radius:999px; padding:9px 20px; font-size:15px; }
.cover-foot { display:flex; justify-content:space-between; color:#64748b; font-size:14px;
  padding:0 84px 48px; }
"""

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AgentReins — Passive Monitor → Chief Surgeon</title>
<style>{CSS}</style>
</head>
<body>
{''.join(pages)}
</body>
</html>
"""

PAGES_DIR.mkdir(exist_ok=True)
(BASE / "deck.html").write_text(HTML, encoding="utf-8")
for i, p in enumerate(pages, 1):
    (PAGES_DIR / f"page-{i:02d}.html").write_text(
        f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>AgentReins {i:02d}</title><style>{CSS}</style></head><body>{p}</body></html>",
        encoding="utf-8",
    )

print(f"wrote deck.html + {len(pages)} single pages · {TOTAL} total")
