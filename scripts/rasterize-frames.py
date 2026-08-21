#!/usr/bin/env python3
"""Turn recorded terminal frames into PNG images.

`knife-record` writes one JSON file per frame, each a list of rows of styled
runs.  This paints them with a real monospace font on a fixed cell grid, which
is what makes the README animation reproducible: no terminal emulator, no
console host, no font substitution, no capture artifacts.

    py scripts/rasterize-frames.py FRAMEDIR [--font PATH] [--size PX]

Needs Pillow.  fontTools is optional but recommended: without it, glyphs the
main face lacks (the ``open/follow`` and ``back`` key symbols, for instance)
come out as empty boxes instead of falling back to a font that has them.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

try:
    from fontTools.ttLib import TTFont
except ImportError:  # optional: without it there is no glyph fallback
    TTFont = None

# The interface's own canvas colour, used wherever a cell asks for the
# terminal default (ratatui's `Color::Reset`).
DEFAULT_BG = "#0b1016"
DEFAULT_FG = "#a6adbb"

# Monospace faces to try in order.  Cascadia Mono ships with Windows Terminal
# and draws the box-drawing characters the panes are built from.
FONT_CANDIDATES = [
    r"C:\Windows\Fonts\CascadiaMono.ttf",
    r"C:\Windows\Fonts\CascadiaCode.ttf",
    r"C:\Windows\Fonts\JetBrainsMonoNerdFont-Regular.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]

# Consulted, in order, for characters the main face has no glyph for.  Segoe UI
# Symbol carries the arrows and keycap symbols the footer hints use.
FALLBACK_CANDIDATES = [
    r"C:\Windows\Fonts\seguisym.ttf",
    r"C:\Windows\Fonts\JetBrainsMonoNerdFont-Regular.ttf",
    r"C:\Windows\Fonts\segoeui.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/System/Library/Fonts/Apple Symbols.ttf",
]

# The bold companion for each regular face.  Cascadia is a variable font, so
# the same file carries the weight axis and is asked for Bold after loading.
BOLD_COMPANION = {
    "CascadiaMono.ttf": "CascadiaMono.ttf",
    "CascadiaCode.ttf": "CascadiaCode.ttf",
    "consola.ttf": "consolab.ttf",
    "JetBrainsMonoNerdFont-Regular.ttf": "JetBrainsMonoNerdFont-Bold.ttf",
    "DejaVuSansMono.ttf": "DejaVuSansMono-Bold.ttf",
}


def first_existing(candidates: list[str]) -> pathlib.Path | None:
    for candidate in candidates:
        path = pathlib.Path(candidate)
        if path.exists():
            return path
    return None


def coverage(path: pathlib.Path) -> set[int] | None:
    """Codepoints a font can draw, or None when it cannot be determined."""
    if TTFont is None:
        return None
    try:
        with TTFont(str(path), fontNumber=0, lazy=True) as font:
            return set(font.getBestCmap())
    except Exception:  # a font we cannot parse simply gets no fallback
        return None


class Face:
    """One font at one size, with the codepoints it can actually draw."""

    def __init__(self, path: pathlib.Path, size: int, bold: bool = False):
        self.path = path
        self.font = ImageFont.truetype(str(path), size)
        if bold:
            try:
                self.font.set_variation_by_name("Bold")
            except (AttributeError, OSError):
                pass
        self.covers = coverage(path)

    def has(self, char: str) -> bool:
        return self.covers is None or ord(char) in self.covers


def load_faces(path: pathlib.Path, size: int, extra: str | None):
    """Regular and bold faces, plus the fallback chain for missing glyphs."""
    regular = Face(path, size)
    companion = BOLD_COMPANION.get(path.name)
    bold_path = path.with_name(companion) if companion else None
    if bold_path and bold_path.exists():
        bold = Face(bold_path, size, bold=True)
    else:
        bold = regular

    chain: list[Face] = []
    candidates = ([extra] if extra else []) + FALLBACK_CANDIDATES
    for candidate in candidates:
        fallback = pathlib.Path(candidate)
        if fallback.exists() and fallback != path:
            chain.append(Face(fallback, size))
    return regular, bold, chain


def cell_metrics(face: Face) -> tuple[int, int]:
    """Advance width and line height for the grid.

    Measuring a run of one character and dividing keeps the grid honest against
    faces whose advance is fractional.
    """
    probe = "M" * 100
    width = round(face.font.getlength(probe) / 100)
    ascent, descent = face.font.getmetrics()
    return max(width, 1), ascent + descent


def render(frame: dict, faces, metrics, out: pathlib.Path, missing: set) -> None:
    regular, bold, chain = faces
    cw, ch = metrics
    cols, rows = frame["w"], frame["h"]
    image = Image.new("RGB", (cols * cw, rows * ch), DEFAULT_BG)
    draw = ImageDraw.Draw(image)

    for y, row in enumerate(frame["rows"]):
        x = 0
        top = y * ch
        for text, fg, bg, is_bold in row:
            span = len(text)
            if not span:
                continue
            left = x * cw
            if bg and bg != DEFAULT_BG:
                draw.rectangle([left, top, left + span * cw - 1, top + ch - 1], fill=bg)
            if text.strip():
                primary = bold if is_bold else regular
                colour = fg or DEFAULT_FG
                # Cell by cell: a fallback glyph from a proportional face would
                # otherwise push the rest of the run off the grid.
                for i, char in enumerate(text):
                    if char == " ":
                        continue
                    face = primary
                    if not primary.has(char):
                        face = next((f for f in chain if f.has(char)), primary)
                        if face is primary:
                            missing.add(char)
                    origin = (x + i) * cw
                    # Centre anything not on the monospace grid, so a wider
                    # symbol sits in its cell instead of starting at its edge.
                    if face is not primary:
                        origin += max(0, (cw - round(face.font.getlength(char))) // 2)
                    draw.text((origin, top), char, font=face.font, fill=colour)
            x += span
    image.save(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("frames", help="directory of frame-NNNN.json files")
    parser.add_argument("--font", help="path to a monospace .ttf")
    parser.add_argument("--fallback", help="font to try first for missing glyphs")
    parser.add_argument("--size", type=int, default=15, help="font size in px")
    args = parser.parse_args()

    directory = pathlib.Path(args.frames)
    sources = sorted(directory.glob("frame-*.json"))
    if not sources:
        sys.exit(f"no frame-*.json in {directory}")

    if args.font:
        font_path = pathlib.Path(args.font)
        if not font_path.exists():
            sys.exit(f"font not found: {font_path}")
    else:
        font_path = first_existing(FONT_CANDIDATES)
        if font_path is None:
            sys.exit("no monospace font found; pass --font PATH")

    faces = load_faces(font_path, args.size, args.fallback)
    metrics = cell_metrics(faces[0])

    for stale in directory.glob("frame-*.png"):
        stale.unlink()

    missing: set[str] = set()
    frame = None
    for source in sources:
        with source.open(encoding="utf-8") as handle:
            frame = json.load(handle)
        render(frame, faces, metrics, source.with_suffix(".png"), missing)

    cw, ch = metrics
    print(
        f"{len(sources)} frames -> {frame['w'] * cw}x{frame['h'] * ch} "
        f"({font_path.name} {args.size}px, cell {cw}x{ch})"
    )
    if TTFont is None:
        print("note: fontTools not installed, so missing glyphs were not substituted")
    elif missing:
        glyphs = " ".join(f"{c!r} U+{ord(c):04X}" for c in sorted(missing))
        print(f"note: no font in the chain draws: {glyphs}")


if __name__ == "__main__":
    main()
