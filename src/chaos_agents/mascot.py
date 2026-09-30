"""Nergal, the terminal mascot: an animated pixel-art demon stirring a
spilling cauldron, drawn with half-block characters (two pixels per cell).

The frame shown is picked from the clock at render time, so a `rich.Live`
display keeps it animating on its own refresh thread even while the
campaign loop is blocked on a slow agent call. Requires `rich`.
"""

from __future__ import annotations

import base64
import time
import zlib
from functools import lru_cache

from chaos_agents import mascot_data as data

_UPPER = "▀"  # upper half block: fg paints the top pixel, bg the bottom
_LOWER = "▄"  # lower half block: fg paints the bottom pixel
_SIZES = {
    "full": (data.FULL_WIDTH, data.FULL_HEIGHT, data.FULL_DATA),
    "small": (data.SMALL_WIDTH, data.SMALL_HEIGHT, data.SMALL_DATA),
}


@lru_cache(maxsize=None)
def _frames(which: str) -> tuple[bytes, ...]:
    w, h, blob = _SIZES[which]
    raw = zlib.decompress(base64.b64decode("".join(blob)))
    n = w * h
    frames = tuple(raw[i * n: (i + 1) * n] for i in range(data.FRAMES))
    if any(len(f) != n for f in frames):
        raise ValueError("mascot data is truncated; regenerate it with tools/mascot/export_terminal.py")
    return frames


def _cell(top: int, bottom: int):
    """The glyph + style for one terminal cell holding two stacked pixels.
    Transparent pixels get no colour at all, so the terminal's own
    background shows through -- no box around Nergal."""
    from rich.style import Style

    clear = data.TRANSPARENT
    if top == clear and bottom == clear:
        return " ", None
    if bottom == clear:
        return _UPPER, Style(color=data.PALETTE[top])
    if top == clear:
        return _LOWER, Style(color=data.PALETTE[bottom])
    return _UPPER, Style(color=data.PALETTE[top], bgcolor=data.PALETTE[bottom])


@lru_cache(maxsize=None)
def _frame_lines(which: str):
    """Pre-built rich Segments for every frame, one list per terminal row."""
    from rich.segment import Segment

    w, h, _ = _SIZES[which]
    cells: dict[tuple[int, int], Segment] = {}
    out = []
    for frame in _frames(which):
        lines = []
        for y in range(0, h, 2):
            row = []
            for x in range(w):
                key = (frame[y * w + x], frame[(y + 1) * w + x])
                seg = cells.get(key)
                if seg is None:
                    seg = cells[key] = Segment(*_cell(*key))
                row.append(seg)
            lines.append(row)
        out.append(lines)
    return out


def frame_count() -> int:
    return data.FRAMES


def size(which: str = "full") -> tuple[int, int]:
    """(columns, rows) the mascot occupies in the terminal."""
    w, h, _ = _SIZES[which]
    return w, h // 2


RESERVE_ROWS = 3  # the status line under the mascot, plus a little slack


def can_draw(console) -> bool:
    """An interactive terminal with at least 256 colours -- on basic 16-colour
    terminals the art collapses into a black blob."""
    return console.is_terminal and console.color_system in ("256", "truecolor")


def fits(console, which: str, extra_cols: int = 0, reserve_rows: int = RESERVE_ROWS) -> bool:
    """Whether size `which`, plus `extra_cols` of other content beside it and
    `reserve_rows` of content around it, fits this console."""
    cols, rows = size(which)
    return can_draw(console) and console.width >= cols + extra_cols and console.height >= rows + reserve_rows


def pick_size(console, reserve_rows: int = RESERVE_ROWS, extra_cols: int = 0) -> str | None:
    """The largest size that fits this console alongside `extra_cols` of
    other content, or None if neither does (or it can't draw at all)."""
    for which in ("full", "small"):
        if fits(console, which, extra_cols, reserve_rows):
            return which
    return None


def why_not(console, reserve_rows: int = RESERVE_ROWS) -> str | None:
    """A one-line reason the mascot can't be shown on this interactive
    terminal, or None when it can (or when output isn't a terminal at all,
    where there's nobody to explain it to)."""
    if not console.is_terminal:
        return None
    if console.color_system not in ("256", "truecolor"):
        return "Nergal stays hidden: this terminal only shows basic colours (he needs 256-colour or truecolor)."
    if pick_size(console, reserve_rows) is None:
        cols, rows = size("small")
        return (
            f"Nergal stays hidden: he needs a terminal at least {cols}x{rows + reserve_rows}; "
            f"this one is {console.width}x{console.height}."
        )
    return None


class Mascot:
    """A rich renderable. `frame=None` animates from the clock; an int pins
    one frame (used for screenshots and tests)."""

    def __init__(self, which: str = "full", frame: int | None = None) -> None:
        if which not in _SIZES:
            raise ValueError(f"unknown mascot size {which!r}, expected one of {sorted(_SIZES)}")
        self.which = which
        self.frame = frame

    def _current(self) -> int:
        if self.frame is not None:
            return self.frame % data.FRAMES
        return int(time.monotonic() * 1000 / data.FRAME_MS) % data.FRAMES

    def __rich_console__(self, console, options):
        from rich.segment import Segment

        for row in _frame_lines(self.which)[self._current()]:
            yield from row
            yield Segment.line()

    def __rich_measure__(self, console, options):
        from rich.measure import Measurement

        cols, _ = size(self.which)
        return Measurement(cols, cols)
