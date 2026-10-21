#!/usr/bin/env python3
"""Playbook screenshot self-check (en_4088c393): body must not be blank chrome-only."""
from __future__ import annotations

import hashlib
import sys

from PIL import Image, ImageStat


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: check_screenshot.py <png>", file=sys.stderr)
        return 2
    p = sys.argv[1]
    im = Image.open(p).convert("RGB")
    w, h = im.size
    body = im.crop((0, int(h * 0.08), w, h))  # drop title bar
    colors = len(set(body.resize((max(1, w // 4), max(1, h // 4))).getdata()))
    std = sum(ImageStat.Stat(body).stddev) / 3
    ok = colors > 800 and std > 12
    digest = hashlib.md5(open(p, "rb").read()).hexdigest()
    print(f"{p} md5={digest} colors={colors} std={std:.1f} {'OK' if ok else 'BLANK'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
