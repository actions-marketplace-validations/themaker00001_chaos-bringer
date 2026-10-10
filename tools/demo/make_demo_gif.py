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

For sharing (LinkedIn and friends play video natively and autoplay it muted) the same
run can be exported slowed down, with a running timecode and on-screen captions:

    python tools/demo/make_demo_gif.py --slow 2.4 --clock \
        --out slow.gif --mp4 demo.mp4 --thumb thumb.png --timeline timeline.json

`--timeline` writes when each step starts and ends, so a written walkthrough can
quote timestamps that match the video. Needs `ffmpeg` for `--mp4`.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import textwrap
from dataclasses import dataclass, field
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
    # on-screen captions for the video export: (label, sentence) while the command runs, then once its output is up
    caption_start: tuple[str, str] = ("", "")
    caption_result: tuple[str, str] = ("", "")


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
        Block("# 1. attack an agent whose memory can be poisoned", c1, out1, 3600,
              ("1 · ATTACK", "A demo agent with memory. An attacker plants a note in it; later, a different user asks "
                             "for a harmless report."),
              ("1 · FINDING: CRITICAL", "The poisoned memory made the agent send a secret to the attacker. Caught at the "
                                        "tool-call level, with the attack path, OWASP ASI06 and MITRE ATLAS AML.T0080.")),
        Block("# 2. turn the finding into a regression test", c2, out2, 1500,
              ("2 · REGRESSION", "Promote the finding into a regression test. It first replays the attack on a fresh "
                                 "agent to check it really reproduces."),
              ("2 · REGRESSION", "reproducible: yes. Saved as four files under regressions/. A memory attack is "
                                 "replayed whole, so it is not shrunk.")),
        Block("# 3. replay it with a fix applied", c3, out3, 3400,
              ("3 · REPLAY WITH A FIX", "Run the same attack again: first on the agent as it was, then with the fix "
                                        "applied (memory_trusted=false)."),
              ("3 · RESULT: PASS", "Before the fix the attack is REPRODUCED and a secret leaves. With the fix the same "
                                   "attack no longer works, and the fix is recorded.")),
        Block("# 4. guard it in CI", c4, out4, 1700,
              ("4 · GUARD IT", "Re-run every saved regression, the way CI would."),
              ("4 · GUARDED", "1/1 pass. If the hole ever reopens, this command exits non-zero and fails the build.")),
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
PAGE_BG = (13, 17, 23)
CAP_LABEL, CAP_TEXT = (57, 255, 136), (226, 232, 226)


class Term:
    """A terminal window. With `canvas` it is placed on a larger page with a caption strip underneath (video)."""

    def __init__(self, font_path: str, size: int, cols: int, rows: int, title: str,
                 canvas: tuple[int, int] | None = None, margin: int = 0):
        self.font = ImageFont.truetype(font_path, size)
        bold_path = font_path.replace("Regular", "Bold")
        self.bold = ImageFont.truetype(bold_path, size) if bold_path != font_path and os.path.exists(bold_path) else self.font
        self.cw = self.font.getlength("M")
        self.lh = round(size * 1.5)
        self.cols, self.rows, self.title = cols, rows, title
        self.pad, self.bar = 16, 34
        self.ww = round(self.pad * 2 + self.cw * cols)               # the window itself
        self.wh = self.bar + self.pad + self.lh * rows + self.pad // 2
        self.margin, self.canvas = margin, canvas
        self.w, self.h = canvas if canvas else (self.ww, self.wh)
        if canvas:
            csize = 26
            self.cap_font = ImageFont.truetype(font_path, csize)
            self.cap_bold = ImageFont.truetype(bold_path, csize + 6) if os.path.exists(bold_path) else self.cap_font
            self.cap_cw = self.cap_font.getlength("M")
            self.cap_lh = round(csize * 1.45)
            self.cap_chars = int((canvas[0] - 2 * margin) // self.cap_cw)
            self.cap_top = margin + self.wh + 26
            self.cap_lines = int((canvas[1] - self.cap_top - margin - 44) // self.cap_lh)
            if self.cap_lines < 2:
                raise SystemExit("the video canvas has no room for captions; use a smaller --video-size")

    def _window(self, rows_: list[tuple[str, str]], cursor: tuple[int, int] | None, clock: str | None) -> Image.Image:
        im = Image.new("RGB", (self.ww, self.wh), KEY)
        d = ImageDraw.Draw(im)
        d.rounded_rectangle((0, 0, self.ww - 1, self.wh - 1), radius=11, fill=BG)
        d.rounded_rectangle((0, 0, self.ww - 1, self.bar + 10), radius=11, fill=TITLEBAR)
        d.rectangle((0, self.bar - 2, self.ww - 1, self.bar + 10), fill=BG)
        d.line((0, self.bar - 2, self.ww, self.bar - 2), fill=(30, 30, 30))
        for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            d.ellipse((16 + i * 22, 11, 28 + i * 22, 23), fill=c)
        tw = self.font.getlength(self.title)
        d.text(((self.ww - tw) / 2, 9), self.title, font=self.font, fill=TITLE_FG)
        if clock:                                               # a running timecode, so a walkthrough can cite times
            d.text((self.ww - 16 - self.font.getlength(clock), 9), clock, font=self.font, fill=TITLE_FG)

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

    def frame(self, rows_: list[tuple[str, str]], cursor: tuple[int, int] | None,
              caption: tuple[str, str] | None = None, clock: str | None = None) -> Image.Image:
        """One frame. `rows_` is [(kind, text)], kind in comment|prompt|out; cursor is (row, col)."""
        win = self._window(rows_, cursor, clock)
        if not self.canvas:
            return win
        im = Image.new("RGB", (self.w, self.h), PAGE_BG)
        mask = Image.new("L", win.size, 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, win.width - 1, win.height - 1), radius=11, fill=255)
        im.paste(win, (self.margin, self.margin), mask)
        if caption and caption[1]:
            d = ImageDraw.Draw(im)
            label, text = caption
            d.text((self.margin, self.cap_top), label, font=self.cap_bold, fill=CAP_LABEL)
            lines = textwrap.wrap(text, width=self.cap_chars)
            if len(lines) > self.cap_lines:
                raise SystemExit(f"caption is too long ({len(lines)} lines > {self.cap_lines}): {text}")
            for i, line in enumerate(lines):
                d.text((self.margin, self.cap_top + 46 + i * self.cap_lh), line, font=self.cap_font, fill=CAP_TEXT)
        return im


# ---- the timeline: what is on screen, when ----------------------------------------------
@dataclass
class Step:
    rows: list[tuple[str, str]]
    cursor: tuple[int, int] | None
    ms: int
    caption: tuple[str, str]


def plan(screens: list[list[Block]], slow: float, type_ms: int, final_hold_ms: int) -> tuple[list[Step], list[dict]]:
    """Lay the whole recording out as timed steps, and note when each command starts, runs and ends."""
    steps: list[Step] = []
    marks: list[dict] = []
    t = 0

    def emit(rows_, cursor, ms, caption):
        nonlocal t
        ms = max(20, round(ms * slow))
        steps.append(Step(list(rows_), cursor, ms, caption))
        t += ms

    def hold(rows_, cursor, ms, caption):
        """A long pause, in one-second beats so a running timecode keeps counting while nothing moves."""
        ms = round(ms * slow)
        while ms > 0:
            beat = min(1000, ms)
            emit(rows_, cursor, beat / slow, caption)
            ms -= beat

    block_no = 0
    for s_i, screen in enumerate(screens):
        rows_: list[tuple[str, str]] = []
        for b_i, b in enumerate(screen):
            block_no += 1
            mark = {"step": block_no, "command": b.command, "start": t}
            if rows_:
                rows_.append(("out", ""))
            rows_.append(("comment", ""))
            for n in range(0, len(b.comment) + 1, 8):                           # the comment, typed quickly
                rows_[-1] = ("comment", b.comment[:n])
                emit(rows_, None, 20, b.caption_start)
            rows_[-1] = ("comment", b.comment)
            rows_.append(("prompt", ""))
            for n in range(0, len(b.command) + 1, 3):                           # then the command, at a readable pace
                rows_[-1] = ("prompt", b.command[:n])
                emit(rows_, (len(rows_) - 1, 2 + n), type_ms, b.caption_start)
            rows_[-1] = ("prompt", b.command)
            emit(rows_, (len(rows_) - 1, 2 + len(b.command)), 300, b.caption_start)    # Enter: the command runs
            mark["enter"] = t
            chunks = range(0, len(b.output), 4)
            for i in chunks:
                rows_.extend(("out", line) for line in b.output[i:i + 4])
                # the caption about the result appears only once the whole result is on screen
                emit(rows_, None, 50, b.caption_result if i == chunks[-1] else b.caption_start)
            mark["output_done"] = t
            last = b_i == len(screen) - 1
            extra = final_hold_ms if last and s_i == len(screens) - 1 else 0
            prompt_rows = rows_ + [("prompt", "")]                              # the shell is ready again
            hold(prompt_rows, (len(prompt_rows) - 1, 2), b.hold_ms + extra, b.caption_result)
            mark["end"] = t
            marks.append(mark)
    return steps, marks


def mmss(ms: int) -> str:
    s = round(ms / 1000)
    return f"{s // 60}:{s % 60:02d}"


def render(term: Term, steps: list[Step], clock: bool) -> list[tuple[Image.Image, int]]:
    total, t, frames = sum(s.ms for s in steps), 0, []
    for st in steps:
        tc = f"{mmss(t)} / {mmss(total)}" if clock else None
        frames.append((term.frame(st.rows, st.cursor, st.caption if term.canvas else None, tc), st.ms))
        t += st.ms
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


def write_mp4(frames: list[tuple[Image.Image, int]], out: Path, fps: int = 30) -> None:
    """H.264 in an MP4, the format LinkedIn plays natively. Variable-length frames become constant-rate video."""
    if not shutil.which("ffmpeg"):
        sys.exit("--mp4 needs ffmpeg on PATH")
    tmp = Path(tempfile.mkdtemp(prefix="chaos-demo-mp4-"))
    try:
        lines, last = [], None
        for i, (im, ms) in enumerate(frames):
            last = tmp / f"f{i:05d}.png"
            im.convert("RGB").save(last)
            lines.append(f"file '{last}'\nduration {ms / 1000:.3f}")
        lines.append(f"file '{last}'")                           # the concat demuxer drops the last duration otherwise
        (tmp / "list.txt").write_text("\n".join(lines) + "\n")
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(tmp / "list.txt"),
                        "-vf", f"fps={fps},format=yuv420p", "-c:v", "libx264", "-preset", "slow", "-crf", "17",
                        "-movflags", "+faststart", "-an", str(out)], check=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def pick_font(explicit: str | None) -> str:
    for cand in ([explicit] if explicit else []) + FONT_CANDIDATES:
        if cand and os.path.exists(cand):
            return cand
    sys.exit("no monospaced font found; pass --font /path/to/font.ttf")


def fit_font_size(font_path: str, cols: int, width: int, margin: int) -> int:
    """The largest font size whose `cols`-column window still fits the video's width."""
    best = 10
    for size in range(10, 40):
        cw = ImageFont.truetype(font_path, size).getlength("M")
        if round(32 + cw * cols) <= width - 2 * margin:
            best = size
    return best


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(REPO / "docs" / "demo.gif"), help="the GIF to write")
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--rows", type=int, default=0, help="terminal rows (default: the tallest screen needs)")
    ap.add_argument("--size", type=int, default=13, help="font size in px for the GIF")
    ap.add_argument("--font")
    ap.add_argument("--cli", default=shutil.which("chaos-agents") or str(REPO / ".venv" / "bin" / "chaos-agents"))
    ap.add_argument("--slow", type=float, default=1.0, help="slow-motion factor: 2.4 plays everything 2.4x slower")
    ap.add_argument("--clock", action="store_true", help="show a running timecode in the title bar")
    ap.add_argument("--mp4", metavar="PATH", help="also write a 1080x1080 MP4 with on-screen captions (needs ffmpeg)")
    ap.add_argument("--thumb", metavar="PATH", help="with --mp4: save the 'finding' frame as a PNG thumbnail")
    ap.add_argument("--timeline", metavar="PATH", help="write when each step starts/ends, as JSON")
    ap.add_argument("--preview", metavar="DIR", help="also save the last frame of every screen as PNGs here")
    args = ap.parse_args()

    if not os.path.exists(args.cli):
        sys.exit(f"chaos-agents not found at {args.cli}; install the project (pip install -e .) or pass --cli")
    blocks = record(args.cli, args.cols, args.rows or 40)
    rows = max(args.rows or max(len(b.output) for b in blocks) + 5, 30)
    screens = pack(blocks, rows)
    needed = max(sum(2 + len(b.output) + 1 for b in s) + 1 for s in screens)
    rows = min(max(needed, 24), 48)
    font = pick_font(args.font)
    title = "chaos-agents  ·  demo agent: toolbot (no model needed)"
    steps, marks = plan(screens, args.slow, type_ms=24, final_hold_ms=1500)
    total_ms = sum(st.ms for st in steps)

    term = Term(font, args.size, args.cols, rows, title)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_gif(render(term, steps, args.clock), out)
    print(f"wrote {out}  {term.w}x{term.h}  {len(screens)} screens  {total_ms / 1000:.1f}s  {out.stat().st_size // 1024} KB")

    if args.mp4:
        side, margin = 1080, 24
        vterm = Term(font, fit_font_size(font, args.cols, side, margin), args.cols, rows, title,
                     canvas=(side, side), margin=margin)
        vframes = render(vterm, steps, args.clock)
        mp4 = Path(args.mp4)
        mp4.parent.mkdir(parents=True, exist_ok=True)
        write_mp4(vframes, mp4)
        print(f"wrote {mp4}  {side}x{side}  {total_ms / 1000:.1f}s  {mp4.stat().st_size // 1024} KB")
        if args.thumb:
            first = marks[0]["output_done"]                        # the moment the finding is fully on screen
            t, pick = 0, vframes[0][0]
            for im, ms in vframes:
                if t >= first:
                    pick = im
                    break
                t += ms
            pick.save(args.thumb)
            print(f"wrote {args.thumb}")

    if args.timeline:
        Path(args.timeline).write_text(json.dumps({
            "total_ms": total_ms, "slow": args.slow,
            "steps": [{**m, **{k + "_label": mmss(m[k]) for k in ("start", "enter", "output_done", "end")}} for m in marks],
        }, indent=2))
        print(f"wrote {args.timeline}")

    if args.preview:
        Path(args.preview).mkdir(parents=True, exist_ok=True)
        for s_i, sc in enumerate(screens):                 # one PNG per screen: its fully drawn final state
            rows_: list[tuple[str, str]] = []
            for b in sc:
                if rows_:
                    rows_.append(("out", ""))
                rows_ += [("comment", b.comment), ("prompt", b.command)] + [("out", l) for l in b.output]
            rows_.append(("prompt", ""))
            term.frame(rows_, (len(rows_) - 1, 2)).convert("RGB").save(Path(args.preview) / f"screen{s_i + 1}.png")


if __name__ == "__main__":
    main()
