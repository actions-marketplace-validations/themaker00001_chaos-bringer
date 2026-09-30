"""Packs the mascot frames into src/chaos_agents/mascot_data.py so the CLI
can render them with the standard library only (zlib + base64), no Pillow.

Two sizes: FULL is 1 sprite pixel per half-block cell (the real art), SMALL
is a 2x reduction used only when the terminal can't fit FULL. Palette index
0 (TRANSPARENT) means "draw nothing" -- the terminal's own background shows
through, so there's no box around Nergal."""

import base64
import sys
import zlib
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_mascot as bm  # noqa: E402

DEFAULT_OUT = bm.HERE.parent.parent / "src" / "chaos_agents" / "mascot_data.py"
COLORS = 96          # including the transparent slot
FRAME_MS = 140
KEY = (255, 0, 255)  # palette slot 0 = transparent; this colour is only a placeholder
# colours the animation hinges on -- the eyes are only a few pixels, and
# median-cut would otherwise merge them away
KEEP = [bm.EYE, bm.EYE_HOT, bm.BREW, bm.BREW_PALE]


def lum(c):
    return 0.299 * c[0] + 0.587 * c[1] + 0.114 * c[2]


def reduce_half(img):
    """Pixel-art 2x reduction: each 2x2 block becomes its most common colour
    (ties to the darkest, so outlines survive); a block of four different
    colours -- fine shading -- takes the one nearest its mean tone instead,
    or shaded skin fills with outline-black specks; and a block holding an
    eye/highlight colour keeps it. Smooth resampling blurs neighbouring
    colours into mud and loses the eyes entirely."""
    w, h = img.size[0] // 2, img.size[1] // 2
    src, out = img.load(), Image.new("RGBA", (w, h), (0, 0, 0, 0))
    opx = out.load()
    keep = {bm.EYE, bm.EYE_HOT, bm.BREW_PALE}
    for x in range(w):
        for y in range(h):
            block = [src[2 * x + dx, 2 * y + dy] for dx in (0, 1) for dy in (0, 1)]
            opaque = [p for p in block if p[3]]
            if len(opaque) < 2:
                continue  # mostly empty: keep the silhouette tight
            special = [p for p in opaque if p[:3] in keep]
            if special:
                opx[x, y] = special[0]
                continue
            counts = {}
            for p in opaque:
                counts[p] = counts.get(p, 0) + 1
            best = max(counts.values())
            if best >= 2:
                opx[x, y] = min((p for p, n in counts.items() if n == best), key=lum)
            else:
                mean = [sum(p[i] for p in opaque) / len(opaque) for i in range(3)]
                opx[x, y] = min(opaque, key=lambda p: sum((p[i] - mean[i]) ** 2 for i in range(3)))
    return out


def pad_even_height(imgs):
    """Half-block rows pair up pixel rows, so heights must be even: pad
    with one clear row when they aren't."""
    w, h = imgs[0].size
    if h % 2 == 0:
        return imgs
    out = []
    for f in imgs:
        c = Image.new("RGBA", (w, h + 1), (0, 0, 0, 0))
        c.paste(f, (0, 0))
        out.append(c)
    return out


def opaque_pixels(img):
    px = img.load()
    return [px[x, y][:3] for x in range(img.width) for y in range(img.height) if px[x, y][3]]



def encode(indexed, w, h, n):
    idx = indexed.load()
    raw = bytearray()
    for i in range(n):
        for y in range(h):
            for x in range(w):
                raw.append(idx[i * w + x, y])
    blob = base64.b64encode(zlib.compress(bytes(raw), 9)).decode()
    return [blob[i: i + 76] for i in range(0, len(blob), 76)]


def main(out_path):
    n = len(bm.FRAMES)
    frames = [Image.open(bm.OUT / f"frame_{i}.png").convert("RGBA") for i in range(n)]

    # crop to everything any frame ever draws, plus a 1px margin
    box = None
    for f in frames:
        b = f.getchannel("A").getbbox()
        box = b if box is None else (min(box[0], b[0]), min(box[1], b[1]), max(box[2], b[2]), max(box[3], b[3]))
    box = (max(0, box[0] - 1), max(0, box[1] - 1), min(bm.W, box[2] + 1), min(bm.H, box[3] + 1))
    full = pad_even_height([f.crop(box) for f in frames])
    fw, fh2 = full[0].size
    small = pad_even_height([reduce_half(f) for f in full])
    sw, sh = small[0].size

    # palette: [KEY (= transparent), KEEP colours, median-cut of everything opaque]
    opaque = [c for f in full + small for c in opaque_pixels(f)]
    sample = Image.new("RGB", (len(opaque), 1))
    sample.putdata(opaque)
    base_n = COLORS - 1 - len(KEEP)
    base = sample.quantize(colors=base_n, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    flat = list(KEY) + [c for rgb in KEEP for c in rgb] + base.getpalette()[: base_n * 3]
    pal = [tuple(flat[i * 3: i * 3 + 3]) for i in range(COLORS)]
    palette = ["#%02x%02x%02x" % c for c in pal]

    # Map pixels to palette slots by hand. Pillow's quantize(palette=...)
    # pads the palette to 256 entries with black, and near-black outline
    # pixels would snap to those padding slots -- indices past our palette.
    nearest_cache = {}

    def nearest(c):
        if c not in nearest_cache:
            nearest_cache[c] = min(range(1, COLORS), key=lambda i: sum((a - b) ** 2 for a, b in zip(c, pal[i])))
        return nearest_cache[c]

    def index_strip(imgs, w, h):
        strip = Image.new("P", (w * len(imgs), h))
        spx = strip.load()
        for i, f in enumerate(imgs):
            fpx = f.load()
            for x in range(w):
                for y in range(h):
                    r, g, b, a = fpx[x, y]
                    spx[i * w + x, y] = nearest((r, g, b)) if a else 0
        return strip

    full_lines = encode(index_strip(full, fw, fh2), fw, fh2, n)
    small_lines = encode(index_strip(small, sw, sh), sw, sh, n)

    def block(name, lines):
        return f"{name} = (\n" + "".join(f'    "{l}"\n' for l in lines) + ")\n"

    with open(out_path, "w") as out:
        out.write('"""Generated by tools/mascot/export_terminal.py -- do not edit by hand.\n\n')
        out.write('Nergal, the chaos-bringer mascot. Demon sprite by Stephen "Redshrike"\n')
        out.write('Challener (with Blarumyrran and LordNeo), from "6 More RPG Enemies" on\n')
        out.write("OpenGameArt.org, CC-BY 3.0 / OGA-BY 3.0; recolored, re-posed and composited\n")
        out.write('with an original cauldron for chaos-bringer. See CREDITS.md.\n"""\n\n')
        out.write(f"FRAMES = {n}\nFRAME_MS = {FRAME_MS}\nTRANSPARENT = 0\n\n")
        out.write(f"FULL_WIDTH = {fw}\nFULL_HEIGHT = {fh2}\nSMALL_WIDTH = {sw}\nSMALL_HEIGHT = {sh}\n\n")
        out.write("PALETTE = (\n")
        for i in range(0, COLORS, 8):
            out.write("    " + ", ".join(f'"{c}"' for c in palette[i: i + 8]) + ",\n")
        out.write(")\n\n")
        out.write(block("FULL_DATA", full_lines) + "\n")
        out.write(block("SMALL_DATA", small_lines))
    print(f"wrote {out_path}: full {fw}x{fh2}, small {sw}x{sh}, {n} frames, "
          f"{sum(map(len, full_lines)) + sum(map(len, small_lines))} base64 chars")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT)
