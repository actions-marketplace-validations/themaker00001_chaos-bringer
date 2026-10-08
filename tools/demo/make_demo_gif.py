#!/usr/bin/env python3
"""Record the README demo GIF -- from the real CLI, not a mock-up.

    python tools/demo/make_demo_gif.py            # writes docs/demo.gif

It runs the actual commands against the bundled `toolbot` demo agent (no model,
no network), inside a pseudo-terminal sized COLS x ROWS so the tool's own
terminal-width wrapping applies, captures exactly what they print, and renders
those lines as an animated terminal window. Nothing on screen is typed by hand
except the command lines and the `# ...` comments, the way any terminal
recording types them; every line of *output* is what the tool printed on this
run, and the finding id in the later commands is the one the first command
reported. Re-run it after changing the output and the GIF follows.

    run -> finding -> promote to a regression -> replay with a fix -> PASS -> guard

Needs Pillow (`pip install pillow`) and a monospaced font; it looks for
JetBrains Mono, then DejaVu Sans Mono, then Menlo, or take `--font`.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[2]

# ---- look ----------------------------------------------------------------------
BG, FG = (40, 40, 40), (204, 204, 204)
DIM = (126, 134, 126)
GREEN, RED, AMBER = (57, 255, 136), (255, 80, 110), (230, 180, 60)
GOLD, CYAN, PURPLE = (232, 197, 80), (95, 179, 208), (190, 150, 255)
TITLEBAR, TITLE_FG = (54, 54, 54), (150, 150, 150)
KEY = (255, 0, 255)                  # becomes the GIF's transparent colour (the window's rounded corners)

FONT_CANDIDATES = [
    "/Applications/Raycast.app/Contents/Resources/JetBrainsMono-Regular.ttf",
    "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# ---- what to colour (the text itself is never changed) ----------------------------
RULES: list[tuple[re.Pattern, tuple, bool]] = [
    (re.compile(r"\[SECRET [A-Z]+\]"), RED, True),                       # the end of an attack chain
    (re.compile(r"\[(?:CRITICAL|HIGH)\]"), RED, True),
    (re.compile(r"\[MEDIUM\]"), AMBER, True),
    (re.compile(r"NOT REPRODUCED|\bPASS\b|reproducible: yes|no longer fire"), GREEN, True),
    (re.compile(r"\bREPRODUCED\b|\bVULNERABLE\b|\bEXFILTRATION\b|CRITICAL DATA FLOW|STILL VULNERABLE"), RED, True),
    (re.compile(r"CB-[0-9a-f]{8}"), GOLD, True),
    (re.compile(r"OWASP ASI\d+|ATLAS AML\.T\d+(?:\.\d+)?"), PURPLE, False),
    (re.compile(r"^\[\d\] [A-Z]+(?: [A-Z]+)*(?=\s{2,})"), CYAN, True),   # "[5] FINDING", not the words after it
    (re.compile(r"\[[A-Z][A-Z ]+\]"), CYAN, False),
    (re.compile(r"→"), DIM, False),
]


def spans(text: str, base: tuple) -> list[tuple[int, int, tuple, bool]]:
    """Non-overlapping (start, end, colour, bold) runs covering `text`."""
    claimed: list[tuple[int, int, tuple, bool]] = []
    for pattern, colour, bold in RULES:
        for m in pattern.finditer(text):
            if all(m.end() <= a or m.start() >= b for a, b, _, _ in claimed):
                claimed.append((m.start(), m.end(), colour, bold))
    claimed.sort()
    out, pos = [], 0
    for a, b, colour, bold in claimed:
        if a > pos:
            out.append((pos, a, base, False))
        out.append((a, b, colour, bold))
        pos = b
    if pos < len(text):
        out.append((pos, len(text), base, False))
    return out


# ---- running the real commands ------------------------------------------------------
def run_in_pty(argv: list[str], cwd: Path, cols: int, rows: int, env: dict) -> tuple[str, int]:
    """Run `argv` on a pseudo-terminal of the given size; return (output, exit code)."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    proc = subprocess.Popen(argv, cwd=cwd, stdin=slave, stdout=slave, stderr=slave, env=env, close_fds=True)
    os.close(slave)
    chunks: list[bytes] = []
    while True:
        try:
            data = os.read(master, 65536)
        except OSError:                      # EIO: the child closed its side
            break
        if not data:
            break
        chunks.append(data)
    code = proc.wait()
    os.close(master)
    text = ANSI.sub("", b"".join(chunks).decode("utf-8", "replace")).replace("\r\n", "\n").replace("\r", "")
    return text.rstrip("\n"), code


def hard_wrap(line: str, cols: int) -> list[str]:
    """Wrap the way a terminal does, for any line the tool itself left long."""
    return [line[i:i + cols] for i in range(0, max(len(line), 1), cols)] or [""]


@dataclass
class Block:
    comment: str
    command: str
    output: list[str]
    hold_ms: int


def record(cli: str, cols: int, rows: int) -> list[Block]:
    """Run the demo for real, in a scratch directory, and return what happened."""
    work = Path(tempfile.mkdtemp(prefix="chaos-demo-"))
    (work / "campaigns").symlink_to(REPO / "campaigns")     # so the command on screen is the real, copyable one
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(work), "LANG": "en_US.UTF-8", "TERM": "xterm-256color",
           "PYTHONUNBUFFERED": "1"}

    def go(command: str) -> tuple[list[str], int]:
        argv = [cli] + command.split()[1:]               # "chaos-agents run ..." -> [cli, "run", ...]
        out, code = run_in_pty(argv, work, cols, rows, env)
        lines = [row for line in out.split("\n") for row in hard_wrap(line, cols)]
        return lines, code

    try:
        c1 = "chaos-agents run campaigns/demo_quickstart.yaml"
        out1, code1 = go(c1)
        found = re.search(r"id:\s+(CB-[0-9a-f]{8})", "\n".join(out1))
        if code1 != 1 or not found:
            sys.exit(f"the demo run should exit 1 and print a finding id; got exit {code1}:\n" + "\n".join(out1))
        fid = found.group(1)

        c2 = f"chaos-agents finding promote {fid}"
        out2, code2 = go(c2)
        c3 = f"chaos-agents replay {fid} --fix memory_trusted=false --record"
        out3, code3 = go(c3)
        c4 = "chaos-agents regression"
        out4, code4 = go(c4)
        if (code2, code3, code4) != (0, 0, 0):
            sys.exit(f"promote/replay/regression should all exit 0, got {(code2, code3, code4)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    return [
        Block("# 1. attack an agent whose memory can be poisoned", c1, out1, 3600),
        Block("# 2. turn the finding into a regression test", c2, out2, 1500),
        Block("# 3. replay it with a fix applied", c3, out3, 3400),
        Block("# 4. guard it in CI", c4, out4, 1700),
    ]


# ---- laying the blocks out on screens ------------------------------------------------
def pack(blocks: list[Block], rows: int) -> list[list[Block]]:
    """Fill each screen with as many consecutive blocks as fit (plus the live prompt)."""
    screens: list[list[Block]] = []
    used = 0
    for b in blocks:
        need = 2 + len(b.output) + 1                       # comment + prompt + output + a blank line
        if screens and used + need + 1 <= rows:
            screens[-1].append(b)
            used += need
        else:
            screens.append([b])
            used = need
    return screens


# ---- drawing --------------------------------------------------------------------------
class Term:
    def __init__(self, font_path: str, size: int, cols: int, rows: int, title: str):
        self.font = ImageFont.truetype(font_path, size)
        bold_path = font_path.replace("Regular", "Bold")
        self.bold = ImageFont.truetype(bold_path, size) if bold_path != font_path and os.path.exists(bold_path) else self.font
        self.cw = self.font.getlength("M")
        self.lh = round(size * 1.5)
        self.cols, self.rows, self.title = cols, rows, title
        self.pad, self.bar = 16, 34
        self.w = round(self.pad * 2 + self.cw * cols)
        self.h = self.bar + self.pad + self.lh * rows + self.pad // 2

    def frame(self, rows_: list[tuple[str, str]], cursor: tuple[int, int] | None) -> Image.Image:
        """One frame. `rows_` is [(kind, text)], kind in comment|prompt|out; cursor is (row, col)."""
        im = Image.new("RGB", (self.w, self.h), KEY)
        d = ImageDraw.Draw(im)
        d.rounded_rectangle((0, 0, self.w - 1, self.h - 1), radius=11, fill=BG)
        d.rounded_rectangle((0, 0, self.w - 1, self.bar + 10), radius=11, fill=TITLEBAR)
        d.rectangle((0, self.bar - 2, self.w - 1, self.bar + 10), fill=BG)
        d.line((0, self.bar - 2, self.w, self.bar - 2), fill=(30, 30, 30))
        for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse((16 + i * 22, 11, 28 + i * 22, 23), fill=c)
        tw = self.font.getlength(self.title)
        d.text(((self.w - tw) / 2, 9), self.title, font=self.font, fill=TITLE_FG)

        y0 = self.bar + 8
        for r, (kind, text) in enumerate(rows_):
            y = y0 + r * self.lh
            x = self.pad
            if kind == "comment":
                d.text((x, y), text, font=self.font, fill=DIM)
                continue
            if kind == "prompt":
                d.text((x, y), "$", font=self.bold, fill=GREEN)
                d.text((x + self.cw * 2, y), text, font=self.font, fill=(236, 236, 236))
                continue
            for a, b, colour, bold in spans(text, FG):
                d.text((x + self.cw * a, y), text[a:b], font=self.bold if bold else self.font, fill=colour)
        if cursor:
            r, c = cursor
            cx = self.pad + self.cw * c
            cy = y0 + r * self.lh + 2
            d.rectangle((cx, cy, cx + self.cw - 1, cy + self.lh - 5), fill=(220, 220, 220))
        return im


def animate(term: Term, screens: list[list[Block]], type_ms: int, final_hold_ms: int) -> list[tuple[Image.Image, int]]:
    frames: list[tuple[Image.Image, int]] = []

    def emit(rows_, cursor, ms):
        frames.append((term.frame(rows_, cursor), ms))

    for s_i, screen in enumerate(screens):
        rows_: list[tuple[str, str]] = []
        for b_i, b in enumerate(screen):
            if rows_:
                rows_.append(("out", ""))
            # the comment is typed quickly, then the command at a readable pace
            rows_.append(("comment", ""))
            for n in range(0, len(b.comment) + 1, 8):
                rows_[-1] = ("comment", b.comment[:n])
                emit(rows_, None, 20)
            rows_[-1] = ("comment", b.comment)
            rows_.append(("prompt", ""))
            for n in range(0, len(b.command) + 1, 3):
                rows_[-1] = ("prompt", b.command[:n])
                emit(rows_, (len(rows_) - 1, 2 + n), type_ms)
            rows_[-1] = ("prompt", b.command)
            emit(rows_, (len(rows_) - 1, 2 + len(b.command)), 300)           # Enter, the command runs
            for i in range(0, len(b.output), 4):
                rows_.extend(("out", line) for line in b.output[i:i + 4])
                emit(rows_, None, 50)
            last = b_i == len(screen) - 1
            hold = b.hold_ms + (final_hold_ms if last and s_i == len(screens) - 1 else 0)
            prompt_rows = rows_ + [("prompt", "")]                              # the shell is ready again
            emit(prompt_rows, (len(prompt_rows) - 1, 2), hold)
    return frames


def write_gif(frames: list[tuple[Image.Image, int]], out: Path) -> None:
    # merge identical neighbours (holds) so the file stays small
    merged: list[list] = []
    for im, ms in frames:
        if merged and merged[-1][0].tobytes() == im.tobytes():
            merged[-1][1] += ms
        else:
            merged.append([im, ms])
    # Palette: index 0 is reserved for the transparent key (the window's rounded corners); the other 63
    # colours are median-cut from the frames with their corners cropped off, so the key can't be averaged away.
    crop = (12, 12, merged[0][0].width - 12, merged[0][0].height - 12)
    picks = merged[:: max(1, len(merged) // 10)][:12] + merged[-3:]
    sample = Image.new("RGB", (crop[2] - crop[0], (crop[3] - crop[1]) * len(picks)))
    for i, (im, _) in enumerate(picks):
        sample.paste(im.crop(crop), (0, i * (crop[3] - crop[1])))
    colours = sample.quantize(colors=63, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).getpalette()[: 63 * 3]
    flat = list(KEY) + colours
    flat += flat[3:6] * (256 - len(flat) // 3)                  # pad with a real colour, not black
    pal = Image.new("P", (1, 1))
    pal.putpalette(flat)
    quant = [im.quantize(palette=pal, dither=Image.Dither.NONE) for im, _ in merged]
    quant[0].save(out, save_all=True, append_images=quant[1:], duration=[ms for _, ms in merged], loop=0,
                  transparency=0, disposal=1, optimize=False)


def pick_font(explicit: str | None) -> str:
    for cand in ([explicit] if explicit else []) + FONT_CANDIDATES:
        if cand and os.path.exists(cand):
            return cand
    sys.exit("no monospaced font found; pass --font /path/to/font.ttf")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(REPO / "docs" / "demo.gif"))
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--rows", type=int, default=0, help="terminal rows (default: the tallest screen needs)")
    ap.add_argument("--size", type=int, default=13, help="font size in px")
    ap.add_argument("--font")
    ap.add_argument("--cli", default=shutil.which("chaos-agents") or str(REPO / ".venv" / "bin" / "chaos-agents"))
    ap.add_argument("--preview", metavar="DIR", help="also save the last frame of every screen as PNGs here")
    args = ap.parse_args()

    if not os.path.exists(args.cli):
        sys.exit(f"chaos-agents not found at {args.cli}; install the project (pip install -e .) or pass --cli")
    probe_rows = args.rows or 40
    blocks = record(args.cli, args.cols, probe_rows)
    rows = args.rows or max(len(b.output) for b in blocks) + 5
    rows = max(rows, 30)
    screens = pack(blocks, rows)
    needed = max(sum(2 + len(b.output) + 1 for b in s) + 1 for s in screens)
    rows = min(max(needed, 24), 48)
    term = Term(pick_font(args.font), args.size, args.cols, rows, "chaos-agents  ·  demo agent: toolbot (no model needed)")
    frames = animate(term, screens, type_ms=24, final_hold_ms=1500)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_gif(frames, out)
    secs = sum(ms for _, ms in frames) / 1000
    print(f"wrote {out}  {term.w}x{term.h}  {len(screens)} screens  {secs:.1f}s  {out.stat().st_size // 1024} KB")
    if args.preview:
        Path(args.preview).mkdir(parents=True, exist_ok=True)
        for s_i, s in enumerate(screens):                  # one PNG per screen: its fully drawn final state
            rows_: list[tuple[str, str]] = []
            for b in s:
                if rows_:
                    rows_.append(("out", ""))
                rows_ += [("comment", b.comment), ("prompt", b.command)] + [("out", l) for l in b.output]
            rows_.append(("prompt", ""))
            term.frame(rows_, (len(rows_) - 1, 2)).convert("RGB").save(Path(args.preview) / f"screen{s_i + 1}.png")


if __name__ == "__main__":
    main()
