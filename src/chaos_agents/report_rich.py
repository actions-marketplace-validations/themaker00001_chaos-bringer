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


def render(campaign_name: str, records: list[Record]) -> None:
    from rich.console import Console

    _render_to(Console(), campaign_name, records)


def render_svg(campaign_name: str, records: list[Record], path: str) -> None:
    """Render to an SVG that looks like a terminal window -- for README screenshots."""
    from rich.console import Console

    console = Console(record=True, width=100)
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
