#!/bin/bash
# Tree-sitter protractor animation -> MP4 (X) + GIF (preview/embed)
set -e
cd "$(dirname "$0")"
FF=/usr/local/bin/ffmpeg
[ -x "$FF" ] || FF=ffmpeg

# 1) MP4 — H.264 yuv420p, loopable, social-ready
"$FF" -y -hide_banner -loglevel error -framerate 30 -i frames/f%04d.png \
  -c:v libx264 -preset slow -crf 21 -pix_fmt yuv420p -movflags +faststart \
  -vf "fps=30" tree-sitter-protractor.mp4

# 2) GIF — palettegen for clean colors
"$FF" -y -hide_banner -loglevel error -framerate 30 -i frames/f%04d.png \
  -vf "fps=24,scale=720:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" \
  tree-sitter-protractor.gif

ls -lh tree-sitter-protractor.mp4 tree-sitter-protractor.gif | awk '{print $5, $9}'
"$FF" -hide_banner -i tree-sitter-protractor.mp4 2>&1 | grep -E "Duration|Stream" | head -3
