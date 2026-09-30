"""A fancier terminal report, for screenshots and for humans watching a
live run. Optional: only imported when `rich` is installed
(`pip install chaos-agents[rich]`); the plain-text `report.py` is always
available and is what CI/log-scraping should rely on.

Palette is deliberately toxic -- a nod to the project's chosen patron, the
Mesopotamian plague-and-underworld god Nergal, standing in for whatever
"chaos god" a given deployment answers to.
"""

from __future__ import annotations

import time

from chaos_agents.corpus import Record

POISON = "#39ff88"  # a survived probe
PLAGUE = "#ff2e5b"  # a finding
ASH = "#8a8f98"  # neutral / info

MIN_SHOW_S = 2.5   # a fast campaign would otherwise flash Nergal and erase him
FINAL_FRAME = 6    # the frame he's left on afterwards: brew fully spilled
INFO_WIDTH = 40    # the text column beside (or under) him in the card
INFO_ROWS = 9      # title, blank, 4 campaign rows, rule, status, tally
CARD_CHROME = 7    # border (2) + panel padding (2) + gap between art and text (3)
STACK_CHROME = 4   # border (2) + panel padding (2)

# Layouts in order of preference: the biggest Nergal that fits wins, then
# the arrangement that suits the terminal's shape. (size, layout, extra
# columns, extra rows) -- rows include the card border and one slack line.
LAYOUTS = (
    ("full", "card", INFO_WIDTH + CARD_CHROME, 3),      # side by side
    ("full", "stacked", STACK_CHROME, INFO_ROWS + 3),    # info under him
    ("small", "card", INFO_WIDTH + CARD_CHROME, 3),
    ("small", "stacked", STACK_CHROME, INFO_ROWS + 3),
    ("small", "bare", 0, 3),                             # just him + status
)


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("chaos-agents")
    except PackageNotFoundError:
        return "dev"


def _clip(text: str, room: int) -> str:
    """Shorten to `room` characters and escape rich markup: payloads are
    attack strings, and "[INST] ... [/INST]" would otherwise be parsed as
    style tags -- and crash the display."""
    from rich.markup import escape

    return escape(text if len(text) <= room else text[: room - 1] + "…")


class NergalStatus:
    """Live display while a campaign runs, laid out like Claude Code's
    welcome card: a rounded box with the animated Nergal (drawn on a clear
    background) and the campaign plus a live status beside him -- or under
    him, on a terminal too narrow for side by side. On one too short for the
    card he appears bare with the status under him; on one too small for
    even that, just the status line and a one-line note saying why.

    Use as a context manager around the campaign loop: `.thinking(payload)`
    from `on_step`, `.result(record)` from `on_result`, `.done(records)`
    before leaving the block. Verdict lines print above the live display.
    With Nergal showing, he stirs for at least `min_show` seconds even if the
    campaign finishes instantly, then stays on screen, on his final frame,
    with the result -- he doesn't vanish."""

    def __init__(self, console, mascot: bool = True, min_show: float = MIN_SHOW_S, campaign=None) -> None:
        from rich.live import Live
        from rich.spinner import Spinner

        from chaos_agents import mascot as nergal

        self.console = console
        self.campaign = campaign
        self.min_show = min_show
        self._nergal = nergal
        self._spinner = Spinner("dots", text=self._line("stirring the brew..."), style=PLAGUE)
        self._tried = 0
        self._findings = 0
        self._records: list[Record] | None = None
        self._finished = False

        self.layout, self.mascot_size = None, None
        if mascot:
            for which, layout, extra_cols, extra_rows in LAYOUTS:
                if nergal.fits(console, which, extra_cols, extra_rows):
                    self.layout, self.mascot_size = layout, which
                    break
        self.hint = nergal.why_not(console) if mascot and not self.layout else None
        self._live = Live(
            get_renderable=self._render,
            console=console,
            refresh_per_second=12,
            transient=self.layout is None,
        )
        self._started = 0.0

    @staticmethod
    def _line(verb: str) -> str:
        return f"[bold {PLAGUE}]Nergal[/bold {PLAGUE}] is {verb}"

    # ---- what's on screen -------------------------------------------------
    def _outcome(self):
        from rich.console import Group
        from rich.text import Text

        records = self._records or []
        failed = sum(1 for r in records if not r.passed)
        color = PLAGUE if failed else POISON
        head = f"[bold {PLAGUE}]Nergal[/bold {PLAGUE}] has finished brewing"
        tally = f"[bold {color}]{len(records) - failed}/{len(records)} payloads survived[/bold {color}]"
        if self.layout in ("card", "stacked"):  # two short lines fit the text column without wrapping
            return Group(Text.from_markup(head + "."), Text.from_markup(tally))
        return Text.from_markup(f"{head}: {tally}")

    def _text_width(self) -> int:
        """How wide the status text can be in the current layout."""
        if self.layout == "card":
            return INFO_WIDTH
        if self.layout == "stacked":
            return self._nergal.size(self.mascot_size)[0]
        return self.console.width

    def _render(self):
        from rich import box
        from rich.console import Group
        from rich.panel import Panel
        from rich.rule import Rule
        from rich.table import Table
        from rich.text import Text

        status = self._outcome() if self._finished else self._spinner
        if self.layout is None:
            return status
        art = self._nergal.Mascot(self.mascot_size, frame=FINAL_FRAME if self._finished else None)
        if self.layout == "bare":
            return Group(art, status)

        def row(label, value):
            return Text.from_markup(f"[{ASH}]{label:<9}[/{ASH}]{_clip(str(value), INFO_WIDTH - 9)}")

        c = self.campaign
        details = [row("campaign", c.name), row("target", c.adapter.plugin),
                   row("vector", c.vector.plugin), row("judge", c.judge.plugin)] if c else []
        tally_color = PLAGUE if self._findings else ASH
        info = Group(
            Text.from_markup(f"[bold {PLAGUE}]Nergal[/bold {PLAGUE}] "
                             + ("rests." if self._finished else "awakens.")),
            Text(""),
            *details,
            Rule(style=ASH),
            status,
            Text.from_markup(f"[{ASH}]{self._tried} tried[/{ASH}]  [{tally_color}]{self._findings} findings[/{tally_color}]"),
        )
        if self.layout == "stacked":  # too narrow for side by side: the info goes under him
            grid = Table.grid()
            grid.add_column(width=self._text_width(), no_wrap=True)
            grid.add_row(art)
            grid.add_row(Text(""))
            grid.add_row(info)
        else:
            grid = Table.grid(padding=(0, 3))
            grid.add_column(no_wrap=True)
            grid.add_column(width=INFO_WIDTH, vertical="middle")
            grid.add_row(art, info)
        return Panel(
            grid,
            box=box.ROUNDED,
            title=f"[bold]chaos-bringer[/bold] [{ASH}]v{_version()}[/{ASH}]",
            title_align="left",
            border_style=POISON,
            padding=(0, 1),
            expand=False,
        )

    # ---- lifecycle ----------------------------------------------------------
    def __enter__(self) -> "NergalStatus":
        if self.hint:
            self.console.print(f"[{ASH}]{self.hint}[/{ASH}]")
        self._started = time.monotonic()
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.layout and exc_type is None:
            left = self.min_show - (time.monotonic() - self._started)
            if left > 0:
                self._spinner.update(text=self._line("stirring the brew..."))
                time.sleep(left)  # the refresh thread keeps him animating meanwhile
            self._finished = True
            self._live.refresh()
        elif self.layout:
            self._live.transient = True  # on a crash/Ctrl-C, clear him away for the traceback
        self._live.__exit__(exc_type, exc, tb)

    # ---- campaign hooks ------------------------------------------------------
    def thinking(self, payload: str) -> None:
        # one line, always: a status that wraps for long payloads and not
        # for short ones makes the whole live region jump in height
        room = max(10, self._text_width() - len("x Nergal is brewing: ") - 2)
        self._spinner.update(text=self._line(f"brewing: {_clip(payload, room)}"))

    def result(self, record: Record) -> None:
        """Narrate one verdict above the display and count it in the card."""
        announce(self.console, record)
        self._tried += 1
        self._findings += not record.passed

    def done(self, records: list[Record]) -> None:
        """Hand over the final records for the closing line."""
        self._records = records


def announce(console, record: Record) -> None:
    """Print a persistent, themed line for one finished trial -- called
    while a NergalStatus display is open, so it appears above the live
    mascot/spinner rather than fighting it for the terminal."""
    shown = _clip(record.payload, 70)
    if record.passed:
        console.print(f"  [{POISON}]Nergal recoils[/{POISON}] from: {shown}")
    else:
        console.print(f"  [bold {PLAGUE}]Nergal swallows it whole[/bold {PLAGUE}]: {shown}")


def render(campaign_name: str, records: list[Record]) -> None:
    from rich.console import Console

    _render_to(Console(), campaign_name, records)


def render_svg(campaign_name: str, records: list[Record], path: str) -> None:
    """Render to an SVG that looks like a terminal window -- for README
    screenshots. Includes the per-payload narration, not just the final
    table, so a single image tells the whole story of the run."""
    from rich.console import Console

    console = Console(record=True, width=100)
    for r in records:
        announce(console, r)
    console.print()
    _render_to(console, campaign_name, records)
    console.save_svg(path, title="chaos-agents")


def _render_to(console, campaign_name: str, records: list[Record]) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    total = len(records)
    failed = [r for r in records if not r.passed]
    passed = total - len(failed)

    score_color = POISON if not failed else PLAGUE
    score = Text(f"{passed}/{total} payloads survived", style=f"bold {score_color}")
    console.print(Panel(score, title=f"[bold]{_clip(campaign_name, 200)}[/bold]", border_style=score_color, expand=False))

    if not failed:
        console.print(f"[{POISON}]No findings.[/{POISON}]")
        return

    table = Table(title=f"{len(failed)} finding(s)", border_style=PLAGUE, header_style=f"bold {PLAGUE}")
    table.add_column("Severity", style="bold")
    table.add_column("Payload", overflow="fold")
    table.add_column("Response", overflow="fold")
    for r in failed:
        sev_style = PLAGUE if r.severity in ("high", "critical") else "yellow"
        # Text(), not str: a str cell is parsed as markup, and payloads and
        # model replies are full of brackets ("[INST]", "[1]", "[link](url)")
        table.add_row(f"[{sev_style}]{r.severity.upper()}[/{sev_style}]", Text(r.payload), Text(r.response))
    console.print(table)
