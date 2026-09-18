#!/usr/bin/env python3
"""
Tree-sitter = industrial metrology for the AI era.
Animated diagram for X: 1080x1350 (4:5), 12s loop @30fps.

Story:
  1. AI (the artist) writes fuzzy, wobbly stream-of-consciousness text
  2. Tree-sitter (the carbide protractor) scans and dissects it into a syntax tree
  3. An ERROR node appears -> REJECT -> loop arrow back to the artist
  4. Rewrite -> clean scan -> one tree, zero ambiguity -> ACCEPT

Render: PIL only (ffmpeg here has no libass/drawtext).
"""
import math
import os
import shutil

from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- canvas
W, H = 1080, 1350
FPS, DUR = 30, 12.0
NFRAMES = int(FPS * DUR)
OUTDIR = "frames"

# palette — engineering-whiteboard: white ground, hairlines, one accent
BG = (255, 255, 255)
INK = (24, 24, 27)
MUTE = (113, 113, 122)
LINE = (212, 212, 216)
FAINT = (244, 244, 245)
Z200 = (228, 228, 231)
TEAL = (15, 118, 110)
TEAL_D = (17, 94, 89)
TEAL_WASH = (230, 248, 245)
AMBER = (180, 83, 9)
AMBER_WASH = (254, 245, 227)
GREY_NODE = (113, 113, 122)

FR = "/System/Library/Fonts/Helvetica.ttc"
_fc = {}


def font(sz, bold=False):
    key = (sz, bold)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FR, sz, index=1 if bold else 0)
    return _fc[key]


# ---------------------------------------------------------------- helpers
def ease(x):
    x = max(0.0, min(1.0, x))
    return x * x * (3 - 2 * x)


def seg(t, a, b):
    return max(0.0, min(1.0, (t - a) / (b - a)))


def lerp(a, b, p):
    return a + (b - a) * p


def tw(d, text, f):
    return d.textlength(text, font=f)


def text(d, xy, s, f, fill, anchor="la"):
    d.text(xy, s, font=f, fill=fill, anchor=anchor)


def fade_layer(lay, k):
    """Scale per-pixel alpha by k. putalpha(scalar) nukes empty pixels too."""
    if k >= 0.999:
        return lay
    a = lay.getchannel("A").point(lambda v: int(v * k))
    lay.putalpha(a)
    return lay


def rr(d, box, r, fill=None, outline=None, width=2):
    d.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def arrow_v(d, x, y0, y1, color, width=2, head=9):
    d.line([(x, y0), (x, y1)], fill=color, width=width)
    s = 1 if y1 > y0 else -1
    d.polygon([(x, y1), (x - head * 0.62, y1 - s * head),
               (x + head * 0.62, y1 - s * head)], fill=color)


def arrow_h(d, y, x0, x1, color, width=2, head=9):
    d.line([(x0, y), (x1, y)], fill=color, width=width)
    s = 1 if x1 > x0 else -1
    d.polygon([(x1, y), (x1 - s * head, y - head * 0.62),
               (x1 - s * head, y + head * 0.62)], fill=color)


def dashed(d, pts, color, width=2, dash=13, gap=9, offset=0):
    """Polyline with a moving dash phase (used for the reject->rewrite loop)."""
    total = 0.0
    segs = []
    for i in range(len(pts) - 1):
        x0, y0 = pts[i]
        x1, y1 = pts[i + 1]
        L = math.hypot(x1 - x0, y1 - y0)
        segs.append((x0, y0, x1, y1, L))
        total += L
    period = dash + gap
    acc = 0.0
    for (x0, y0, x1, y1, L) in segs:
        ux, uy = (x1 - x0) / L, (y1 - y0) / L
        p = 0.0
        while p < L:
            s = (acc + p + offset) % period
            if s < dash:
                run = min(dash - s, L - p)
                d.line([(x0 + ux * p, y0 + uy * p),
                        (x0 + ux * (p + run), y0 + uy * (p + run))],
                       fill=color, width=width)
            else:
                run = min(period - s, L - p)
            p += run
        acc += L


def ortho(d, x0, y0, x1, y1, color, width=2):
    my = (y0 + y1) / 2
    d.line([(x0, y0), (x0, my), (x1, my), (x1, y1)], fill=color, width=width)


# ---------------------------------------------------------------- timeline
T_TITLE = (0.0, 1.0)
T_DRAW1 = (1.0, 3.3)
T_FEED = (3.3, 4.1)
T_SCAN1 = (4.1, 6.0)
T_FAIL = (6.0, 7.1)
T_DRAW2 = (7.1, 8.9)
T_SCAN2 = (8.9, 10.3)
T_PASS = (10.3, 11.3)
T_OUT = (11.3, 12.0)

# ---------------------------------------------------------------- layout
CX0, CX1 = 80, 900          # main content column
LOOPX = 985                 # reject->rewrite return channel
AI_Y = (250, 520)
PS_Y = (570, 880)
VD_Y = (900, 1080)

PRO_CX, PRO_CY, PRO_R = 180, 700, 72
TOK_X0, TOK_Y0, TOK_W, TOK_H, TOK_GX, TOK_GY = 290, 640, 66, 30, 8, 16

TREE = [  # (level, cx, y, w, label)
    (0, 745, 640, 130, "program"),
    (1, 680, 722, 104, "func_decl"),
    (1, 830, 722, 86, "call"),
    (2, 642, 796, 72, "ident"),
    (2, 745, 796, 72, "params"),
    (2, 848, 796, 72, "args"),
]
NODE_H = 36
PARENT = {3: 1, 4: 1, 5: 2, 1: 0, 2: 0}


def wobbles(round2=False, n=8, x0=115, x1=880, y0=342, step=21):
    """The artist's lines: sloppy in round 1, nearly straight in round 2."""
    out = []
    for i in range(n):
        y = y0 + i * step
        length = x1 - x0 - (0 if i % 3 else 96) - (0 if i % 4 else 168)
        amp = 2.0 if round2 else 5.0 + 4.2 * math.sin(i * 2.3)
        freq = 0.030 if round2 else 0.026 + 0.011 * math.cos(i * 1.7)
        ph = i * 1.31
        pts = []
        x = x0
        while x <= x0 + length:
            yy = y + amp * math.sin(x * freq + ph) + (0 if round2 else 1.6 * math.sin(x * 0.11 + i))
            pts.append((x, yy))
            x += 6
        out.append(pts)
    return out


LINES1 = wobbles(False)
LINES2 = wobbles(True)


# ---------------------------------------------------------------- painters
def draw_protractor(d, cx, cy, R, a=1.0):
    """Carbide protractor: half-disc, tick marks, ruler edge."""
    if a <= 0.01:
        return
    col = (15, 118, 110, int(255 * a))
    lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ld = ImageDraw.Draw(lay)
    box = [cx - R, cy - R, cx + R, cy + R]
    ld.arc(box, 180, 360, fill=col, width=3)
    inner = R * 0.80
    ld.arc([cx - inner, cy - inner, cx + inner, cy + inner], 180, 360, fill=col, width=2)
    # ruler edge
    ld.line([(cx - R - 14, cy), (cx + R + 14, cy)], fill=col, width=3)
    # ticks every 10deg, long every 30
    for deg in range(0, 181, 10):
        th = math.radians(180 + deg)
        long_ = (deg % 30 == 0)
        r0 = inner if long_ else R - (R - inner) * 0.45
        x0 = cx + r0 * math.cos(th)
        y0 = cy + r0 * math.sin(th)
        x1 = cx + R * math.cos(th)
        y1 = cy + R * math.sin(th)
        ld.line([(x0, y0), (x1, y1)], fill=col, width=2 if long_ else 1)
    # hub
    ld.ellipse([cx - 5, cy - 5, cx + 5, cy + 5], outline=col, width=2)
    return ld, lay


def draw_frame(t):
    img = Image.new("RGBA", (W, H), BG + (255,))
    d = ImageDraw.Draw(img)

    # ---- progress values
    a_title = ease(seg(t, *T_TITLE))
    p_draw1 = ease(seg(t, *T_DRAW1))
    p_feed = ease(seg(t, *T_FEED))
    p_scan1 = ease(seg(t, *T_SCAN1))
    a_fail = ease(seg(t, *T_FAIL)) * (1 - ease(seg(t, 7.05, 7.55)))
    p_draw2 = ease(seg(t, *T_DRAW2))
    a_clear1 = 1 - ease(seg(t, 6.85, 7.45))
    p_scan2 = ease(seg(t, *T_SCAN2))
    a_pass = ease(seg(t, *T_PASS))
    a_out = 1 - ease(seg(t, *T_OUT))
    loop_a = ease(seg(t, 6.0, 6.6)) * (1 - ease(seg(t, 8.3, 8.9)))

    # ============================================================ header
    if a_title > 0.01:
        lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ld = ImageDraw.Draw(lay)
        f_eye = font(21, True)
        text(ld, (CX0, 48), "WHY EVERY AI CODING TOOL SHIPS A PARSER", f_eye, TEAL + (int(255 * a_title),))
        f_h1 = font(58, True)
        text(ld, (CX0, 96), "AI imagines.", f_h1, INK + (int(255 * a_title),))
        text(ld, (CX0, 158), "Tree-sitter measures.", f_h1, TEAL_D + (int(255 * a_title),))
        f_sub = font(25)
        text(ld, (CX0, 214), "fuzzy in  ·  deterministic out", f_sub, MUTE + (int(255 * a_title),))
        img.alpha_composite(lay)

    # ============================================================ AI block
    rr(d, [CX0, AI_Y[0], CX1, AI_Y[1]], 14, fill=(255, 255, 255, 255), outline=LINE, width=2)
    f_tag = font(19, True)
    # pill
    tag = "AI"
    tpw = tw(d, tag, f_tag)
    rr(d, [CX0 + 22, AI_Y[0] + 20, CX0 + 22 + tpw + 26, AI_Y[0] + 48], 14,
       fill=FAINT, outline=None)
    text(d, (CX0 + 35, AI_Y[0] + 34), tag, f_tag, INK, anchor="lm")
    f_tag2 = font(20)
    text(d, (CX0 + 22 + tpw + 40, AI_Y[0] + 34), "the artist  ·  brains", f_tag2, MUTE, anchor="lm")
    f_attr = font(19)
    txt = "fuzzy · probabilistic · close enough"
    text(d, (CX1 - 22, AI_Y[0] + 34), txt, f_attr, MUTE, anchor="rm")

    # wobbly lines — round 1 (fading) then round 2 (rewriting)
    nl = len(LINES1)
    for i, pts in enumerate(LINES1):
        p = max(0.0, min(1.0, p_draw1 * nl - i))
        if p <= 0.001 or a_clear1 <= 0.01:
            continue
        cut = max(2, int(len(pts) * p))
        col = (148, 163, 184, int(255 * a_clear1))
        d.line(pts[:cut], fill=col, width=3, joint="curve")
    for i, pts in enumerate(LINES2):
        p = max(0.0, min(1.0, p_draw2 * nl - i))
        if p <= 0.001:
            continue
        cut = max(2, int(len(pts) * p))
        d.line(pts[:cut], fill=(82, 82, 91, 235), width=3, joint="curve")

    # feed arrow
    a_feed = max(p_feed, 0.35)
    arrow_v(d, 470, AI_Y[1] + 8, PS_Y[0] - 8, Z200, width=2, head=8)
    f_mid = font(18)
    text(d, (492, (AI_Y[1] + PS_Y[0]) / 2), "raw text", f_mid, MUTE, anchor="lm")

    # ============================================================ parse block
    rr(d, [CX0, PS_Y[0], CX1, PS_Y[1]], 14, fill=(255, 255, 255, 255), outline=LINE, width=2)
    tag2 = "TREE-SITTER"
    t2w = tw(d, tag2, f_tag)
    rr(d, [CX0 + 22, PS_Y[0] + 20, CX0 + 22 + t2w + 26, PS_Y[0] + 48], 14, fill=TEAL_WASH, outline=None)
    text(d, (CX0 + 35, PS_Y[0] + 34), tag2, f_tag, TEAL_D, anchor="lm")
    text(d, (CX0 + 22 + t2w + 40, PS_Y[0] + 34), "the carbide protractor", f_tag2, MUTE, anchor="lm")
    text(d, (CX1 - 22, PS_Y[0] + 34), "deterministic · exact · 0 or 1", f_attr, TEAL, anchor="rm")

    # --- protractor
    res = draw_protractor(d, PRO_CX, PRO_CY, PRO_R, 1.0)
    if res:
        img.alpha_composite(res[1])
        d = ImageDraw.Draw(img)
    f_micro = font(17, True)
    text(d, (PRO_CX, PRO_CY + 34), "0 / 1", f_micro, TEAL, anchor="ma")

    # --- scan state
    round_two = t >= T_DRAW2[0]
    p_scan = p_scan2 if round_two else p_scan1
    scanning = (T_SCAN1[0] <= t <= T_SCAN1[1]) or (T_SCAN2[0] <= t <= T_SCAN2[1])
    scan_y = lerp(612, 852, p_scan)

    # --- token blocks (sliced text)
    for r in range(3):
        for c in range(4):
            x = TOK_X0 + c * (TOK_W + TOK_GX)
            y = TOK_Y0 + r * (TOK_H + TOK_GY)
            act = 1.0 if scan_y >= y + TOK_H * 0.4 else 0.0
            if round_two and t < T_SCAN2[0]:
                act = 0.0
            if act <= 0.0:
                rr(d, [x, y, x + TOK_W, y + TOK_H], 5, fill=FAINT, outline=None)
                continue
            rr(d, [x, y, x + TOK_W, y + TOK_H], 5, fill=(255, 255, 255, 255),
               outline=TEAL, width=2)
            # glyph bars
            gx = x + 9
            for k in range(3):
                gw = 10 + ((r * 4 + c * 3 + k * 5) % 4) * 4
                d.rectangle([gx, y + 11, gx + gw, y + 19], fill=Z200)
                gx += gw + 5

    # --- scan beam
    if scanning and p_scan < 0.999:
        beam = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        bd = ImageDraw.Draw(beam)
        for k in range(9):
            yy = scan_y - k * 3
            a = int(46 * (1 - k / 9))
            bd.line([(CX0 + 16, yy), (CX1 - 16, yy)], fill=TEAL + (a,), width=1)
        bd.line([(CX0 + 14, scan_y), (CX1 - 14, scan_y)], fill=TEAL + (255,), width=3)
        img.alpha_composite(beam)
        d = ImageDraw.Draw(img)

    # --- syntax tree
    node_a = ease(seg(t, T_SCAN1[0] + 0.9, T_SCAN1[1] + 0.15))
    if round_two:
        node_a = ease(seg(t, T_SCAN2[0] + 0.9, T_SCAN2[1] + 0.15))
    # edges first
    for i, (lv, cx, y, w_, lab) in enumerate(TREE):
        if i == 0:
            continue
        p = TREE[PARENT[i]]
        pcx, py = p[1], p[2]
        ea = node_a * (0.35 + 0.65 * max(0.0, min(1.0, node_a * len(TREE) - i)))
        if ea > 0.05:
            ortho(d, pcx, py + NODE_H, cx, y, (163, 163, 173, int(255 * ea)), 2)
    # nodes
    err_idx = 5
    for i, (lv, cx, y, w_, lab) in enumerate(TREE):
        ia = max(0.0, min(1.0, node_a * len(TREE) - i * 0.85))
        if ia <= 0.05:
            continue
        is_err = (i == err_idx) and (not round_two)
        na = ia
        box = [cx - w_ / 2, y, cx + w_ / 2, y + NODE_H]
        if is_err:
            rr(d, box, 6, fill=AMBER_WASH, outline=AMBER, width=2)
            f_n = font(19, True)
            text(d, (cx, y + NODE_H / 2), "ERROR", f_n, AMBER, anchor="mm")
        else:
            rr(d, box, 6, fill=(255, 255, 255, 255), outline=TEAL if lv == 0 else Z200,
               width=2 if lv == 0 else 2)
            f_n = font(19, lv == 0)
            text(d, (cx, y + NODE_H / 2), lab, f_n, TEAL_D if lv == 0 else INK, anchor="mm")

    # ============================================================ verdict
    rr(d, [CX0, VD_Y[0], CX1, VD_Y[1]], 14, fill=(255, 255, 255, 255), outline=LINE, width=2)
    stamp_box = [CX0 + 22, VD_Y[0] + 22, CX0 + 470, VD_Y[1] - 22]
    if a_fail > 0.01:
        lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ld = ImageDraw.Draw(lay)
        sc = lerp(1.18, 1.0, ease(a_fail))
        bw = stamp_box[2] - stamp_box[0]
        bh = stamp_box[3] - stamp_box[1]
        nw, nh = bw * sc, bh * sc
        cxm = (stamp_box[0] + stamp_box[2]) / 2
        cym = (stamp_box[1] + stamp_box[3]) / 2
        b = [cxm - nw / 2, cym - nh / 2, cxm + nw / 2, cym + nh / 2]
        rr(ld, b, 10, fill=AMBER_WASH, outline=AMBER, width=3)
        f_st = font(38, True)
        text(ld, (cxm, cym - 12), "REJECT", f_st, AMBER, anchor="mm")
        f_st2 = font(20)
        text(ld, (cxm, cym + 24), "line 7 · unbalanced delimiter", f_st2, AMBER, anchor="mm")
        fade_layer(lay, a_fail)
        img.alpha_composite(lay)
    if a_pass > 0.01:
        lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ld = ImageDraw.Draw(lay)
        sc = lerp(1.18, 1.0, ease(a_pass))
        bw = stamp_box[2] - stamp_box[0]
        bh = stamp_box[3] - stamp_box[1]
        nw, nh = bw * sc, bh * sc
        cxm = (stamp_box[0] + stamp_box[2]) / 2
        cym = (stamp_box[1] + stamp_box[3]) / 2
        b = [cxm - nw / 2, cym - nh / 2, cxm + nw / 2, cym + nh / 2]
        rr(ld, b, 10, fill=TEAL_WASH, outline=TEAL, width=3)
        f_st = font(38, True)
        text(ld, (cxm, cym - 12), "ACCEPT", f_st, TEAL_D, anchor="mm")
        f_st2 = font(20)
        text(ld, (cxm, cym + 24), "1 tree · 0 ambiguity · 0 or 1", f_st2, TEAL, anchor="mm")
        fade_layer(lay, a_pass)
        img.alpha_composite(lay)
    if a_fail < 0.01 and a_pass < 0.01:
        rr(d, stamp_box, 10, fill=FAINT, outline=None)
        f_idle = font(22)
        text(d, ((stamp_box[0] + stamp_box[2]) / 2, (stamp_box[1] + stamp_box[3]) / 2),
             "awaiting measurement", f_idle, MUTE, anchor="mm")
    # verdict caption
    f_vc = font(21)
    lines = ["The artist improvises.",
             "The protractor does not",
             "negotiate."]
    yy = VD_Y[0] + 40
    for s in lines:
        text(d, (CX1 - 26, yy), s, f_vc, MUTE, anchor="rm")
        yy += 30

    # ============================================================ reject loop
    if loop_a > 0.01:
        lay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ld = ImageDraw.Draw(lay)
        pts = [(CX1 + 6, 1000), (LOOPX, 1000), (LOOPX, 352), (CX1 + 6, 352)]
        dashed(ld, pts, AMBER + (255,), width=3, dash=14, gap=10,
               offset=-(t * 90) % 24)
        arrow_h(ld, 352, LOOPX, CX1 + 12, AMBER + (255,), width=3, head=11)
        f_lp = font(18, True)
        text(ld, (1072, 688), "REJECT", f_lp, AMBER, anchor="rm")
        text(ld, (1072, 712), "REWRITE", f_lp, AMBER, anchor="rm")
        fade_layer(lay, loop_a)
        img.alpha_composite(lay)

    # ============================================================ footer
    fl = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    fd = ImageDraw.Draw(fl)
    a_foot = ease(seg(t, 0.6, 1.4)) * (1 - ease(seg(t, 11.4, 12.0)))
    if a_foot > 0.01:
        d.line([(CX0, 1128), (CX1, 1128)], fill=LINE, width=2)
        f_f1 = font(31, True)
        text(fd, (CX0, 1160), "However wildly the artist draws,", f_f1, INK)
        text(fd, (CX0, 1202), "one measurement settles it.", f_f1, TEAL_D)
        f_f2 = font(22)
        text(fd, (CX0, 1258), "Wrong is wrong. Rejected. Rewrite.   —  AgentReins holds the protractor.",
             f_f2, MUTE)
        fade_layer(fl, a_foot)
        img.alpha_composite(fl)

    # loop fade
    if a_out < 0.999:
        white = Image.new("RGBA", (W, H), (255, 255, 255, int(255 * (1 - a_out))))
        img.alpha_composite(white)

    return img.convert("RGB")


def main():
    if os.path.isdir(OUTDIR):
        shutil.rmtree(OUTDIR)
    os.makedirs(OUTDIR)
    print(f"rendering {NFRAMES} frames @ {W}x{H} ...")
    for i in range(NFRAMES):
        t = i / FPS
        draw_frame(t).save(f"{OUTDIR}/f{i:04d}.png")
        if i % 60 == 0:
            print(f"  {i}/{NFRAMES}")
    print("done.")


if __name__ == "__main__":
    main()
