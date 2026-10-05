"""Render a ChaosBench Scorecard as a text summary or machine-readable JSON.

Deliberately CLI-only: a terminal summary for humans and JSON for CI. No HTML /
dashboard UI -- the score is a few numbers, and keeping it in the terminal is
the right weight for it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from chaos_agents.benchmark import PROPERTY_TITLES, Scorecard
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS


def to_json(card: Scorecard) -> str:
    doc = {
        "suite": card.suite,
        "version": card.version,
        "target": card.target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "resilience": card.resilience,
        "grade": card.grade,
        "counts": card.counts,
        "families": card.by_family(),
    }
    if card.scoring == "profile":
        doc["scoring"] = "profile"
        doc["profile"] = {prop: {k: v for k, v in stats.items() if k != "note"} | ({"note": stats["note"]} if stats["note"] else {})
                          for prop, stats in card.by_property().items()}
    doc["probes"] = [{
        "id": o.probe.id,
        "category": o.probe.category,
        "technique": o.probe.technique,
        "severity": o.probe.severity,
        **({"property": o.probe.property, "kind": o.probe.kind} if o.probe.property else {}),
        "status": o.status,
        "reason": o.reason,
        "latency_ms": o.latency_ms,
    } for o in card.outcomes]
    return json.dumps(doc, indent=2)


def to_text(card: Scorecard) -> str:
    r = card.resilience
    score = "n/a" if r is None else f"{r}%"
    lines = [
        f"ChaosBench {card.suite} v{card.version}  —  target: {card.target}",
        f"Resilience: {score}   Grade: {card.grade}   "
        f"(held {card.counts[PASS]}, leaked {card.counts[FAIL]}, inconclusive {card.counts[INCONCLUSIVE]})",
        "",
    ]
    if card.scoring == "profile":
        lines.append("Security profile:")
        for prop, s in card.by_property().items():
            pr = "n/a" if s["resilience"] is None else f"{s['resilience']}%"
            detail = f"(held {s[PASS]}/{s['total']})" if s["resilience"] is not None else s["note"]
            lines.append(f"  {PROPERTY_TITLES[prop]:<18} {pr:>7}  {s['grade']:>3}   {detail}")
    else:
        lines.append("By family:")
        for fam, s in card.by_family().items():
            fr = "n/a" if s["resilience"] is None else f"{s['resilience']}%"
            lines.append(f"  {fam:<18} {fr:>6}  (held {s[PASS]}/{s['total']})")
    leaks = [o for o in card.outcomes if o.status == FAIL]
    if leaks:
        lines += ["", "Failed probes:"]
        for o in leaks:
            lines.append(f"  [{o.probe.severity:<8}] {o.probe.id} {o.probe.category}/{o.probe.technique}")
            if card.scoring == "profile":
                lines.append(f"             {o.reason}")
    return "\n".join(lines)


FORMATS = {"text": to_text, "json": to_json}
