"""A fancier terminal report, for screenshots and for humans watching a
live run. Optional: only imported when `rich` is installed
(`pip install chaos-agents[rich]`); the plain-text `report.py` is always
available and is what CI/log-scraping should rely on.

Palette is deliberately toxic -- a nod to the project's chosen patron, the
Mesopotamian plague-and-underworld god Nergal, standing in for whatever
"chaos god" a given deployment answers to.
"""

from __future__ import annotations

from chaos_agents.corpus import Record

POISON = "#39ff88"  # a survived probe
PLAGUE = "#ff2e5b"  # a finding
ASH = "#8a8f98"  # neutral / info


class NergalStatus:
    """Live display while a campaign runs: the animated Nergal mascot
    stirring its cauldron (when the terminal is big enough), over a spinner
    line naming the payload in flight. Use as a context manager around the
    campaign loop; call `.thinking(payload)` from `on_step`, and print each
    result with `announce()` from `on_result` -- rich.Live keeps the display
    pinned below anything printed while it's open."""

    def __init__(self, console, mascot: bool = True) -> None:
        from rich.console import Group
        from rich.live import Live
        from rich.spinner import Spinner

        from chaos_agents import mascot as nergal

        self.console = console
        self._spinner = Spinner("dots", text=self._line("stirring the brew..."), style=PLAGUE)
        self.mascot_size = nergal.pick_size(console) if mascot else None
        parts = [nergal.Mascot(self.mascot_size), self._spinner] if self.mascot_size else [self._spinner]
        self._live = Live(Group(*parts), console=console, refresh_per_second=12, transient=True)

    @staticmethod
    def _line(verb: str) -> str:
        return f"[bold {PLAGUE}]Nergal[/bold {PLAGUE}] is {verb}"

    def __enter__(self) -> "NergalStatus":
        self._live.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._live.__exit__(*exc)

    def thinking(self, payload: str) -> None:
        # one line, always: a status that wraps for long payloads and not
        # for short ones makes the whole live region jump in height
        room = max(10, self.console.width - len("x Nergal is brewing: ") - 2)
        shown = payload if len(payload) <= room else payload[: room - 1] + "…"
        self._spinner.update(text=self._line(f"brewing: {shown}"))


def announce(console, record: Record) -> None:
    """Print a persistent, themed line for one finished trial -- called
    while a NergalStatus display is open, so it appears above the live
    mascot/spinner rather than fighting it for the terminal."""
    if record.passed:
        console.print(f"  [{POISON}]Nergal recoils[/{POISON}] from: {record.payload[:70]}")
    else:
        console.print(f"  [bold {PLAGUE}]Nergal swallows it whole[/bold {PLAGUE}]: {record.payload[:70]}")


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
    console.print(Panel(score, title=f"[bold]{campaign_name}[/bold]", border_style=score_color, expand=False))

    if not failed:
        console.print(f"[{POISON}]No findings.[/{POISON}]")
        return

    table = Table(title=f"{len(failed)} finding(s)", border_style=PLAGUE, header_style=f"bold {PLAGUE}")
    table.add_column("Severity", style="bold")
    table.add_column("Payload", overflow="fold")
    table.add_column("Response", overflow="fold")
    for r in failed:
        sev_style = PLAGUE if r.severity in ("high", "critical") else "yellow"
        table.add_row(f"[{sev_style}]{r.severity.upper()}[/{sev_style}]", r.payload, r.response)
    console.print(table)
