#!/usr/bin/env bash
# Rebuild the README animation from scratch.
#
#   scripts/record-demo.sh TARGET [SCRIPT] [OUT]
#
# The picture is rendered, not captured: `knife-record` drives the real
# interface off-screen and writes one JSON frame per step, this rasterizes them
# with a fixed font, and ffmpeg encodes the GIF. Same input, same output, on any
# machine, with none of the tearing a console capture produces.
#
# Needs: a Rust toolchain, python with Pillow, and ffmpeg on PATH.
set -euo pipefail

target=${1:?usage: record-demo.sh TARGET [SCRIPT] [OUT]}
script=${2:-scripts/demo.knife}
out=${3:-assets/demo.gif}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
frames=${FRAMES_DIR:-target/demo-frames}
fps=${FPS:-12}
python=${PYTHON:-py}

echo "== recording =="
cargo run --release --quiet --features record --bin knife-record -- \
    "$target" "$script" "$frames"

echo "== rasterizing =="
"$python" scripts/rasterize-frames.py "$frames"

echo "== encoding =="
# Two passes: a palette built from the whole run, then the encode. One shared
# palette is what keeps the syntax colours from banding between frames.
ffmpeg -y -loglevel error -framerate "$fps" -i "$frames/frame-%04d.png" \
    -vf "palettegen=stats_mode=diff" "$frames/palette.png"
ffmpeg -y -loglevel error -framerate "$fps" -i "$frames/frame-%04d.png" \
    -i "$frames/palette.png" \
    -lavfi "paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" \
    -loop 0 "$out"

ls -lh "$out"
