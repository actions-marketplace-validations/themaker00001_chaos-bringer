"""Renders a campaign's records as a plain-text resilience report."""

from __future__ import annotations

import shutil
import sys
import textwrap

from chaos_agents import attackgraph, memory, standards
from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id


def terminal_width() -> int | None:
    """The terminal's width -- but only when stdout *is* a terminal, so piped
    output, CI logs and tests keep one line per field."""
    return shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else None


def wrap_words(first: str, text: str, indent: int, width: int | None) -> list[str]:
    """`first + text`, broken at spaces to fit `width` with continuation lines
    indented by `indent`. Unchanged when no width is given, when it already
    fits, or when the text has line breaks of its own."""
    if width is None or len(first) + len(text) <= width or "\n" in text:
        return [first + text]
    return textwrap.wrap(text, width=width, initial_indent=first, subsequent_indent=" " * indent,
                         break_long_words=False, break_on_hyphens=False) or [first]


def wrap_arrows(first: str, parts: list[str], indent: int, width: int | None, joiner: str = " → ") -> list[str]:
    """`first` + parts joined by arrows, breaking only *between* parts: a
    continuation line starts with the arrow, so no bracketed stage is split."""
    line = first + joiner.join(parts)
    if width is None or len(line) <= width:
        return [line]
    lines, cur = [], first + parts[0]
    for part in parts[1:]:
        if len(cur) + len(joiner) + len(part) <= width:
            cur += joiner + part
        else:
            lines.append(cur)
            cur = " " * indent + joiner.lstrip() + part
    return lines + [cur]


def flow_lines(record: Record, width: int | None = None) -> list[str]:
    """The data-flow evidence for a finding: what moved, from where, by which
    route, and which rule it broke. Empty for a finding that is not about
    tracked data."""
    flows = [v for v in record.details.get("policy_violations", []) if v.get("kind") == "data_flow"]
    if not flows:
        return []
    flow = flows[0]
    path = flow.get("attack_path") or record.attack_path
    if record.category == memory.CATEGORY:      # the route began in another session
        path = memory.route(path)
    verb = "CRITICAL" if record.severity == "critical" else record.severity.upper()
    rule = flow.get("rule", "").removeprefix("data_flow.")
    key, _, setting = rule.partition(" = ")
    return [
        f"{verb} DATA FLOW",
        f"  Source: {flow.get('source') or record.source}",
        f"  Data:   {flow.get('data') or record.data}",
        *wrap_arrows("  Path:   ", path, 10, width),
        f"  Policy: {key} = {setting.upper()}" if setting else f"  Policy: {rule}",
        f"  Result: {flow.get('result') or 'DATA FLOW VIOLATION'}",
    ]


def render(campaign_name: str, records: list[Record], width: int | None = None) -> str:
    """The plain report. With a `width` (see `terminal_width`) long fields are
    wrapped to fit it; without one every field stays on a single line."""
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
            lines += wrap_words(f"  [{r.severity.upper()}] ", r.reason, 4, width)
            lines += wrap_words("    payload:  ", r.payload, 14, width)
            lines += wrap_words("    response: ", r.response, 14, width)
            if r.fingerprint:       # the handle for `finding show|promote` and `replay`
                lines.append(f"    id:       {finding_id(r.fingerprint)}")
            if stages := attackgraph.stages_of(r):
                lines += wrap_arrows("    attack:   ", [f"[{st.label}]" for st in stages], 14, width)
            if tags := standards.summary(r):
                lines.append(f"    maps to:  {tags}")
            lines.extend(f"    {line}" for line in flow_lines(r, width - 4 if width else None))
    else:
        lines.append("No findings.")
    return "\n".join(lines)
