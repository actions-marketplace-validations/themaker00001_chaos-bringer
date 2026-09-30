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
    """A live spinner that stirs while a payload is in flight, themed around
    the project's patron chaos god. Use as a context manager around the
    campaign loop; call `.thinking(payload)` from `on_step`, and print each
    result with `announce()` from `on_result` -- both interleave cleanly
    with the spinner since rich's Status pauses it for any console.print."""

    def __init__(self, console) -> None:
        self.console = console
        self._status = console.status(self._line("stirring the bowl..."), spinner="dots", spinner_style=PLAGUE)

    @staticmethod
    def _line(verb: str) -> str:
        return f"[bold {PLAGUE}]Nergal[/bold {PLAGUE}] is {verb}"

    def __enter__(self) -> "NergalStatus":
        self._status.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        self._status.__exit__(*exc)

    def thinking(self, payload: str) -> None:
        self._status.update(self._line(f"tasting: {payload[:60]}"))


def announce(console, record: Record) -> None:
    """Print a persistent, themed line for one finished trial -- called
    while a NergalStatus spinner is open, so it appears above the spinner
    rather than fighting it for the terminal."""
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
