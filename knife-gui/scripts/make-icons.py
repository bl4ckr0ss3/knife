#!/usr/bin/env python3
"""Regenerate the application icons.

`icons/source.png` is normally a finished square icon, and is used whole at
every size. If it is instead a full brand sheet, the script finds the app-icon
panel and the K logo inside it and uses the logo for the small sizes, where a
detailed portrait would smear.

Which mode applies is decided by the art: a square image whose content fills it
is already an icon; anything else is treated as a sheet. `--whole` and `--sheet`
force the choice.

Sizes matter here. Windows renders taskbar buttons at 24x24 logical pixels, so
at 125% scaling it needs 30x30 real ones and picks the 32px frame to get there.
Everything in the .ico exists to survive that.

    npm run icons          (from knife-gui/)

Replace icons/source.png with new art and run it again.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

try:
    from PIL import Image, ImageFilter
except ImportError:
    sys.exit("Pillow is required:  py -m pip install pillow")

HERE = pathlib.Path(__file__).resolve().parent
GUI = HERE.parent
SOURCE = GUI / "icons" / "source.png"
OUT = GUI / "src-tauri" / "icons"

# Where to look for each mark, and how far a pixel must differ from the ground
# to count as artwork.
PORTRAIT_SEARCH = (850, 25, 1225, 400)
LOGO_SEARCH = (900, 470, 1230, 730)
TOLERANCE = 26
MIN_RUN = 12
INK = 150

# Below this, use the logo; at or above it, the portrait.
DETAIL_FLOOR = 96

PNG_SIZES = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "256x256.png": 256,
    "icon.png": 512,
}
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]


def square(box: tuple[int, int, int, int], pad: int = 0) -> tuple[int, int, int, int]:
    """Centre a box and make it square, so nothing is stretched later."""
    left, top, right, bottom = box
    cx, cy = (left + right) // 2, (top + bottom) // 2
    half = max(right - left, bottom - top) // 2 + pad
    return (cx - half, cy - half, cx + half, cy + half)


def find_portrait(im: Image.Image) -> tuple[int, int, int, int]:
    """The app-icon panel: the tight box of art on its near-uniform ground."""
    px = im.load()
    x0, y0, x1, y1 = PORTRAIT_SEARCH
    ground = px[x0 + 10, y0 + 15]

    def differs(p) -> bool:
        return any(abs(a - b) > TOLERANCE for a, b in zip(p[:3], ground[:3]))

    xs = [x for x in range(x0, x1) if sum(differs(px[x, y]) for y in range(y0, y1)) > MIN_RUN]
    ys = [y for y in range(y0, y1) if sum(differs(px[x, y]) for x in range(x0, x1)) > MIN_RUN]
    if not xs or not ys:
        sys.exit("could not find the portrait panel; pass --portrait L T R B")
    return square((xs[0], ys[0], xs[-1], ys[-1]))


def find_logo(im: Image.Image) -> tuple[int, int, int, int]:
    """The K mark, trimmed above the wordmark printed beneath it.

    The glyph and the word `KNIFE` share a column with a blank band between
    them, so the first gap of a few empty rows is where the mark ends.
    """
    px = im.load()
    x0, y0, x1, y1 = LOGO_SEARCH

    def ink(x: int, y: int) -> bool:
        return sum(px[x, y][:3]) > INK

    density = [(y, sum(1 for x in range(x0, x1) if ink(x, y))) for y in range(y0, y1)]
    inked = [y for y, n in density if n > 6]
    if not inked:
        sys.exit("could not find the K logo; pass --logo L T R B")
    top = inked[0]

    bottom = inked[-1]
    blank = 0
    for y, n in density:
        if y <= top:
            continue
        blank = blank + 1 if n == 0 else 0
        if blank >= 3:
            bottom = y - blank
            break

    xs = [x for x in range(x0, x1) if any(ink(x, y) for y in range(top, bottom + 1))]
    return square((xs[0], top, xs[-1], bottom), pad=10)


def looks_like_an_icon(im: Image.Image) -> bool:
    """Whether the art is already an icon rather than a sheet to cut up.

    An icon is square and its subject fills it; a sheet has panels floating on a
    wide ground. Comparing the ink's bounding box against the whole image tells
    the two apart without needing to know either layout.
    """
    if abs(im.width - im.height) > 4:
        return False
    small = im.convert("RGB").resize((64, 64), Image.LANCZOS)
    px = small.load()
    ground = px[1, 1]
    box = [64, 64, 0, 0]
    for y in range(64):
        for x in range(64):
            if any(abs(a - b) > TOLERANCE for a, b in zip(px[x, y], ground)):
                box = [min(box[0], x), min(box[1], y), max(box[2], x), max(box[3], y)]
    covered = (box[2] - box[0]) * (box[3] - box[1]) / (64 * 64)
    return covered > 0.55


def render(art: Image.Image, size: int) -> Image.Image:
    """Downscale, then restore the edge the resampling softened."""
    out = art.resize((size, size), Image.LANCZOS)
    if size <= 64:
        out = out.filter(ImageFilter.UnsharpMask(radius=1, percent=110, threshold=2))
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(SOURCE))
    parser.add_argument("--portrait", nargs=4, type=int, metavar=("L", "T", "R", "B"))
    parser.add_argument("--logo", nargs=4, type=int, metavar=("L", "T", "R", "B"))
    parser.add_argument("--whole", action="store_true", help="use the source as-is")
    parser.add_argument("--sheet", action="store_true", help="treat the source as a brand sheet")
    args = parser.parse_args()

    source = pathlib.Path(args.source)
    if not source.exists():
        sys.exit(f"no source art at {source}")
    sheet = Image.open(source).convert("RGBA")

    whole = args.whole or (looks_like_an_icon(sheet) and not args.sheet)
    OUT.mkdir(parents=True, exist_ok=True)

    if whole:
        print(f"whole icon  ({sheet.width}x{sheet.height})")
        for name, size in PNG_SIZES.items():
            render(sheet, size).save(OUT / name)
            print(f"  {name:<16} {size:>3}px")
        frames = [render(sheet, s) for s in ICO_SIZES]
    else:
        pbox = tuple(args.portrait) if args.portrait else find_portrait(sheet)
        lbox = tuple(args.logo) if args.logo else find_logo(sheet)
        portrait, logo = sheet.crop(pbox), sheet.crop(lbox)
        print(f"portrait {pbox}  ({portrait.width}x{portrait.height})")
        print(f"logo     {lbox}  ({logo.width}x{logo.height})")
        for name, size in PNG_SIZES.items():
            art = logo if size < DETAIL_FLOOR else portrait
            render(art, size).save(OUT / name)
            print(f"  {name:<16} {size:>3}px  {'logo' if art is logo else 'portrait'}")
        frames = [render(logo if s < DETAIL_FLOOR else portrait, s) for s in ICO_SIZES]

    frames[-1].save(OUT / "icon.ico", sizes=[(s, s) for s in ICO_SIZES], append_images=frames[:-1])
    print(f"  {'icon.ico':<16} {ICO_SIZES}")


if __name__ == "__main__":
    main()
