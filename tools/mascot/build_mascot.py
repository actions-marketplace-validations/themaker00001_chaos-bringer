"""Builds the chaos-bringer mascot animation.

    python tools/mascot/build_mascot.py        # needs Pillow (pip install -e ".[dev]")
    python tools/mascot/export_terminal.py     # then repack the CLI's frame data

Demon sprite: Stephen "Redshrike" Challener (with Blarumyrran, LordNeo),
"6 More RPG Enemies", OpenGameArt.org, CC-BY 3.0 / OGA-BY 3.0 -- the
unmodified sheet is more_rpg_enemies.png next to this file. Changes made
here: skin recolored red -> plague green, glowing eyes added, scythe split
onto its own layer and rocked around the hand to stir, green rim-light from
the brew, legs shadowed behind the pot. The cauldron, brew, fumes, spill and
backdrop are original. See CREDITS.md.
"""

import math
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
DOCS = HERE.parent.parent / "docs"

SKIN_TO_PLAGUE = {
    (0x1e, 0x10, 0x09): (0x0d, 0x1a, 0x0b),
    (0x3d, 0x20, 0x0e): (0x1c, 0x2e, 0x12),
    (0x4d, 0x1c, 0x0a): (0x21, 0x3a, 0x14),
    (0x61, 0x2b, 0x1d): (0x2d, 0x4a, 0x1c),
    (0x74, 0x25, 0x16): (0x35, 0x5c, 0x1f),
    (0x91, 0x4d, 0x35): (0x4f, 0x74, 0x30),
    (0xa6, 0x41, 0x2b): (0x5a, 0x8a, 0x2c),
    (0xbd, 0x6e, 0x4a): (0x7a, 0xa0, 0x4a),
    (0xdf, 0x5e, 0x3b): (0x8f, 0xc2, 0x3a),
    (0xfa, 0xb2, 0x74): (0xd7, 0xf0, 0x8a),
}
PLAGUE_SKIN = set(SKIN_TO_PLAGUE.values())
SCYTHE_COLORS = {(0x20, 0x3B, 0x41), (0x90, 0xB4, 0xB5), (0xDE, 0xCA, 0x7C), (0x71, 0x71, 0x71), (0x1F, 0x1F, 0x1F)}
N4 = ((1, 0), (-1, 0), (0, 1), (0, -1))

W, H = 108, 100
OX, OY = 4, 4                # demon sprite offset on the canvas
PIVOT = (63 + OX, 44 + OY)    # the gripping hand, canvas coords
CX, RIM_Y = 49, 58            # cauldron centre / rim line -- mouth reaches the pole
RIM_RX, RIM_RY = 26, 6
LIP = 3
BODY_H = 30
MAXW = 34

IRON = [(6, 7, 9), (16, 18, 21), (30, 34, 39), (50, 57, 64), (84, 95, 104), (140, 152, 158)]
SHADOW = (3, 5, 4)
BREW_DEEP = (6, 70, 34)
BREW_MID = (22, 170, 84)
BREW = (57, 255, 136)
BREW_PALE = (196, 255, 214)
EYE = (255, 46, 91)
EYE_HOT = (255, 209, 102)
EYES = ((33, 18), (34, 18), (40, 18))  # sprite-local


def lerp(a, b, t):
    t = max(0.0, min(1.0, t))
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def ramp(colors, t):
    t = max(0.0, min(0.999, t)) * (len(colors) - 1)
    i = int(t)
    return lerp(colors[i], colors[i + 1], t - i)


def load_demon():
    im = Image.open(HERE / "more_rpg_enemies.png").convert("RGBA").crop((146, 197, 245, 277))
    px = im.load()
    for x in range(im.width):
        for y in range(im.height):
            r, g, b, a = px[x, y]
            if a and (r, g, b) in SKIN_TO_PLAGUE:
                px[x, y] = (*SKIN_TO_PLAGUE[(r, g, b)], a)
    return im


def split_scythe(demon):
    px = demon.load()
    w, h = demon.size

    def rgb(x, y):
        return px[x, y][:3] if 0 <= x < w and 0 <= y < h and px[x, y][3] else None

    core = {(x, y) for x in range(w) for y in range(h) if rgb(x, y) in SCYTHE_COLORS}
    layer = set(core)
    for x in range(54, w):
        for y in range(h):
            c = rgb(x, y)
            if c is None or c in SCYTHE_COLORS or c in PLAGUE_SKIN or max(c) > 40:
                continue
            near_core = any((x + dx, y + dy) in core for dx in (-1, 0, 1) for dy in (-1, 0, 1))
            touches_skin = any(rgb(x + dx, y + dy) in PLAGUE_SKIN for dx, dy in N4)
            if near_core and not touches_skin:
                layer.add((x, y))

    body = demon.copy()
    scythe = Image.new("RGBA", demon.size, (0, 0, 0, 0))
    bpx, spx = body.load(), scythe.load()
    for x, y in layer:
        spx[x, y] = px[x, y]
        bpx[x, y] = (0, 0, 0, 0)
    return body, scythe


# ------------------------------------------------------------------ pot ---
def rim_ellipse(x, y, rx, ry):
    return ((x - CX) / rx) ** 2 + ((y - RIM_Y) / ry) ** 2 <= 1


def in_mouth(x, y):
    return rim_ellipse(x, y, RIM_RX - LIP, RIM_RY - 1)


def in_lip(x, y):
    return rim_ellipse(x, y, RIM_RX, RIM_RY) and not in_mouth(x, y)


def half_width(dy):
    t = dy / BODY_H
    return MAXW * math.sqrt(max(0.0, 1 - ((t - 0.42) / 0.62) ** 2))


def in_body(x, y):
    dy = y - RIM_Y
    return 0 < dy <= BODY_H and abs(x - CX) <= half_width(dy)


def body_shade(x, y):
    dy = y - RIM_Y
    hw = half_width(dy)
    u = (x - CX) / hw
    v = (dy / BODY_H - 0.42) / 0.62
    nz = math.sqrt(max(0.0, 1 - u * u * 0.85 - v * v * 0.5))
    light = max(0.0, -0.55 * u - 0.35 * v + 0.62 * nz)
    c = ramp(IRON[:5], 0.12 + light * 0.78)
    if light > 0.93:
        c = IRON[5]
    return lerp(c, BREW_MID, 0.22 * max(0.0, 1 - dy / 6))  # brew glow on the upper belly


# ----------------------------------------------------------- the scene ---
def backdrop():
    img = Image.new("RGBA", (W, H))
    px = img.load()
    for y in range(H):
        for x in range(W):
            d = math.hypot((x - CX) / 62, (y - RIM_Y) / 50)
            px[x, y] = (*lerp(SHADOW, (14, 38, 22), (1 - d) ** 1.7 if d < 1 else 0), 255)
    return img


def place_demon(body):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    layer.paste(body, (OX, OY))
    px = layer.load()
    for y in range(H):
        for x in range(W):
            r, g, b, a = px[x, y]
            if not a:
                continue
            if y > RIM_Y + 1:
                px[x, y] = (*lerp((r, g, b), SHADOW, 0.92), a)  # legs sunk in shadow behind the pot
            elif (r, g, b) in PLAGUE_SKIN and y > RIM_Y - 24:
                t = 1 - (RIM_Y - y) / 24
                px[x, y] = (*lerp((r, g, b), BREW, 0.38 * t * t), a)
    return layer


def draw_lip_back(px):
    for x in range(W):
        for y in range(RIM_Y - RIM_RY - 1, RIM_Y + 1):
            if in_lip(x, y):
                px[x, y] = (*(IRON[4] if y <= RIM_Y - RIM_RY + 1 else IRON[2]), 255)


def draw_brew(px, slosh, bubbles):
    for x in range(W):
        for y in range(RIM_Y - RIM_RY, RIM_Y + RIM_RY):
            if not in_mouth(x, y):
                continue
            depth = (y - (RIM_Y - RIM_RY + 1)) / (2 * RIM_RY - 2)
            tilt = slosh * (x - CX) / RIM_RX * 0.12
            glow = 1 - abs((x - CX) / (RIM_RX - LIP)) ** 2
            c = lerp(BREW_DEEP, BREW_MID, min(1.0, depth * 2.2 + tilt))
            c = lerp(c, BREW, glow * 0.75 * min(1.0, depth * 1.8))
            px[x, y] = (*c, 255)
    for bx, by, r in bubbles:
        for x in range(bx - r, bx + r + 1):
            for y in range(by - r, by + r + 1):
                d2 = (x - bx) ** 2 + (y - by) ** 2
                if d2 <= r * r and in_mouth(x, y):
                    px[x, y] = (*(BREW_PALE if d2 >= (r - 1) ** 2 else BREW), 255)


def draw_fumes(px, phase):
    """Wisps drifting up off the brew -- blended into what's behind them."""
    top = RIM_Y - RIM_RY - 2
    for i, (x0, speed) in enumerate(((37, 1.0), (47, 1.4), (57, 0.8), (43, 1.2), (54, 1.1))):
        rise = (phase * 3 * speed + i * 7) % 26
        x = x0 + int(round(math.sin((phase + i) * 0.9) * 2))
        y = int(top - rise)
        alpha = 0.55 * (1 - rise / 26)
        for dx, dy in ((0, 0), (1, 0), (0, -1)):
            xx, yy = x + dx, y + dy
            if 0 <= xx < W and 0 <= yy < H:
                r, g, b, _ = px[xx, yy]
                px[xx, yy] = (*lerp((r, g, b), BREW, alpha), 255)


def draw_pot_front(px):
    for x in range(W):
        for y in range(RIM_Y, RIM_Y + RIM_RY + 1):
            if in_lip(x, y):
                px[x, y] = (*(IRON[3] if y <= RIM_Y + 1 else IRON[1]), 255)
    for y in range(RIM_Y + 1, RIM_Y + BODY_H + 1):
        for x in range(W):
            if in_body(x, y) and not rim_ellipse(x, y, RIM_RX, RIM_RY):
                px[x, y] = (*body_shade(x, y), 255)
    for y in range(RIM_Y + 1, RIM_Y + BODY_H + 2):
        for x in range(W):
            if not in_body(x, y) and not rim_ellipse(x, y, RIM_RX, RIM_RY) and any(
                in_body(x + dx, y + dy) for dx, dy in ((1, 0), (-1, 0), (0, -1))
            ):
                px[x, y] = (2, 3, 3, 255)
    for sx in (-1, 1):  # side handles
        hx = CX + sx * (RIM_RX + 3)
        for dx, dy in ((0, 2), (sx, 3), (sx, 4), (0, 5), (sx * 2, 3), (sx * 2, 4)):
            px[hx + dx, RIM_Y + dy] = (*IRON[3], 255)
    base = RIM_Y + BODY_H  # clawed feet
    for fx in (CX - 13, CX + 9):
        for x in range(fx, fx + 5):
            for y in range(base - 1, base + 3):
                px[x, y] = (*(IRON[3] if y < base + 1 else IRON[1]), 255)
        px[fx - 1, base + 2] = (*IRON[1], 255)
        px[fx + 5, base + 2] = (*IRON[1], 255)


def draw_spill(px, progress):
    """Brew tipping over the front-right lip, running down the belly as a
    thick glowing stream, dripping, and pooling on the ground."""
    if progress <= 0:
        return
    lip_x = CX + 14
    for x in range(lip_x - 3, lip_x + 3):
        for y in (RIM_Y + RIM_RY - 2, RIM_Y + RIM_RY - 1):
            px[x, y] = (*BREW, 255)
    run = int(progress * (BODY_H + 1))
    tip_x = lip_x
    for dy in range(RIM_RY, RIM_RY + run):
        y = RIM_Y + dy
        if y > RIM_Y + BODY_H:
            break
        x = CX + int(half_width(dy - RIM_RY / 2) * 0.46) + int(round(math.sin(dy / 2.6)))
        width = 4 if dy < RIM_RY + 5 else 3
        for i in range(width):
            c = BREW_PALE if i == 0 else (BREW if i < width - 1 else BREW_MID)
            px[x + i - 1, y] = (*c, 255)
        for gx in (x - 2, x + width - 1):
            r, g, b, _ = px[gx, y]
            px[gx, y] = (*lerp((r, g, b), BREW_MID, 0.45), 255)
        tip_x = x
    tip_y = min(RIM_Y + RIM_RY + run, RIM_Y + BODY_H)
    for dx, dy in ((0, 0), (1, 0), (-1, 0), (0, 1), (1, 1), (0, 2)):
        px[tip_x + dx, tip_y + dy] = (*BREW, 255)
    if progress > 0.8:
        pool = 3 + int((progress - 0.8) / 0.2 * 11)
        py = RIM_Y + BODY_H + 3
        for x in range(tip_x - pool, tip_x + pool + 1):
            edge = abs(x - tip_x) >= pool - 1
            px[x, py] = (*(BREW_MID if edge else BREW), 255)
            px[x, py + 1] = (*BREW_DEEP, 255)
        for x in range(tip_x - pool // 2, tip_x + pool // 2):
            px[x, py - 1] = (*lerp(px[x, py - 1][:3], BREW_MID, 0.5), 255)


def draw_droplets(px, drops):
    for x, y in drops:
        for dx, dy, c in ((0, 0, BREW_PALE), (1, 0, BREW), (0, 1, BREW), (1, 1, BREW_MID)):
            if 0 <= x + dx < W and 0 <= y + dy < H:
                px[x + dx, y + dy] = (*c, 255)


def draw_eyes(px, hot):
    color = EYE_HOT if hot else EYE
    for ex, ey in EYES:
        px[ex + OX, ey + OY] = (*color, 255)


def rotated_scythe(scythe, angle):
    pad = 60
    big = Image.new("RGBA", (scythe.width + 2 * pad, scythe.height + 2 * pad), (0, 0, 0, 0))
    big.paste(scythe, (pad, pad))
    pivot_local = (PIVOT[0] - OX + pad, PIVOT[1] - OY + pad)
    return big.rotate(angle, resample=Image.NEAREST, center=pivot_local), (OX - pad, OY - pad)


def draw_pole(px, scythe, angle):
    rot, (sx, sy) = rotated_scythe(scythe, angle)
    rpx = rot.load()
    entry = []
    for x in range(rot.width):
        for y in range(rot.height):
            r, g, b, a = rpx[x, y]
            if not a:
                continue
            cx, cy = x + sx, y + sy
            if not (0 <= cx < W and 0 <= cy < H):
                continue
            if in_mouth(cx, cy) and cy >= RIM_Y - 1:
                continue  # submerged
            if cy > RIM_Y:
                continue  # behind the pot
            px[cx, cy] = (r, g, b, 255)
            if cy == RIM_Y - 2 and in_mouth(cx, cy + 1):
                entry.append(cx)
    if entry:  # ripple ring where the haft breaks the surface
        ex = sum(entry) // len(entry)
        for dx in range(-4, 5):
            yy = RIM_Y - 1 + (1 if abs(dx) > 2 else 0)
            if abs(dx) > 1 and in_mouth(ex + dx, yy):
                px[ex + dx, yy] = (*BREW_PALE, 255)


# 8-frame stir loop: pole angle (deg), surface tilt, bubbles, spill progress,
# droplets flung off the lip, eye flare.
FRAMES = [
    dict(angle=0,  slosh=0,  bubbles=[(41, 58, 2)],              spill=0.0,  drops=[],                   hot=False),
    dict(angle=-4, slosh=2,  bubbles=[(40, 57, 2), (55, 59, 1)], spill=0.18, drops=[(67, 52)],           hot=False),
    dict(angle=-7, slosh=3,  bubbles=[(56, 58, 2)],              spill=0.38, drops=[(70, 50), (68, 54)], hot=True),
    dict(angle=-4, slosh=2,  bubbles=[(33, 59, 1), (56, 57, 2)], spill=0.58, drops=[(73, 53)],           hot=True),
    dict(angle=0,  slosh=0,  bubbles=[(34, 58, 2)],              spill=0.78, drops=[(75, 60)],           hot=False),
    dict(angle=4,  slosh=-2, bubbles=[(34, 57, 2), (48, 60, 1)], spill=0.9,  drops=[],                   hot=False),
    dict(angle=7,  slosh=-3, bubbles=[(48, 58, 2)],              spill=1.0,  drops=[],                   hot=False),
    dict(angle=4,  slosh=-2, bubbles=[(48, 57, 1), (61, 59, 2)], spill=0.0,  drops=[],                   hot=False),
]


def render_frame(body, scythe, spec, phase):
    canvas = backdrop()
    canvas.alpha_composite(place_demon(body))
    px = canvas.load()
    draw_lip_back(px)
    draw_brew(px, spec["slosh"], spec["bubbles"])
    draw_pole(px, scythe, spec["angle"])
    draw_pot_front(px)
    draw_spill(px, spec["spill"])
    draw_droplets(px, spec["drops"])
    draw_fumes(px, phase)
    draw_eyes(px, spec["hot"])
    return canvas


def main():
    demon = load_demon()
    body, scythe = split_scythe(demon)
    frames = [render_frame(body, scythe, spec, i) for i, spec in enumerate(FRAMES)]
    OUT.mkdir(exist_ok=True)
    for i, f in enumerate(frames):
        f.save(OUT / f"frame_{i}.png")

    scale = 4
    sheet = Image.new("RGBA", (W * scale * 4 + 30, H * scale * 2 + 10), (255, 255, 255, 255))
    for i, f in enumerate(frames):
        sheet.paste(f.resize((W * scale, H * scale), Image.NEAREST), ((i % 4) * (W * scale + 10), (i // 4) * (H * scale + 10)))
    sheet.save(OUT / "frames_sheet.png")

    gif = [f.resize((W * scale, H * scale), Image.NEAREST).convert("RGB") for f in frames]
    gif[0].save(DOCS / "nergal.gif", save_all=True, append_images=gif[1:], duration=140, loop=0)
    print(f"ok: {len(frames)} frames in {OUT}, animation at {DOCS / 'nergal.gif'}")


if __name__ == "__main__":
    main()
