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

_HALF = "▀"  # upper half block: fg paints the top pixel, bg the bottom
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


@lru_cache(maxsize=None)
def _frame_lines(which: str):
    """Pre-built rich Segments for every frame, one list per terminal row."""
    from rich.segment import Segment
    from rich.style import Style

    w, h, _ = _SIZES[which]
    styles: dict[tuple[int, int], Style] = {}
    out = []
    for frame in _frames(which):
        lines = []
        for y in range(0, h, 2):
            row = []
            for x in range(w):
                key = (frame[y * w + x], frame[(y + 1) * w + x])
                style = styles.get(key)
                if style is None:
                    style = styles[key] = Style(color=data.PALETTE[key[0]], bgcolor=data.PALETTE[key[1]])
                row.append(Segment(_HALF, style))
            lines.append(row)
        out.append(lines)
    return out


def frame_count() -> int:
    return data.FRAMES


def size(which: str = "full") -> tuple[int, int]:
    """(columns, rows) the mascot occupies in the terminal."""
    w, h, _ = _SIZES[which]
    return w, h // 2


def pick_size(console, reserve_rows: int = 4) -> str | None:
    """The largest size that fits this console, or None if neither does,
    output isn't an interactive terminal, or the terminal can't show more
    than the basic 16 colours (the art collapses to a black blob there)."""
    if not console.is_terminal or console.color_system not in ("256", "truecolor"):
        return None
    for which in ("full", "small"):
        cols, rows = size(which)
        if console.width >= cols and console.height >= rows + reserve_rows:
            return which
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
