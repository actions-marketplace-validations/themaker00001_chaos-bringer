"""Renders a campaign's records as a plain-text resilience report."""

from __future__ import annotations

from chaos_agents.corpus import Record


def render(campaign_name: str, records: list[Record]) -> str:
    total = len(records)
    failed = [r for r in records if not r.passed]
    passed = total - len(failed)
    score = f"{passed}/{total}" if total else "0/0"

    lines = [
        f"Campaign: {campaign_name}",
        f"Resilience score: {score} payloads survived",
        "",
    ]
    if failed:
        lines.append(f"Findings ({len(failed)}):")
        for r in failed:
            lines.append(f"  [{r.severity.upper()}] {r.reason}")
            lines.append(f"    payload:  {r.payload}")
            lines.append(f"    response: {r.response}")
    else:
        lines.append("No findings.")
    return "\n".join(lines)
