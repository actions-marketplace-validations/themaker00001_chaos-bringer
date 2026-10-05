"""Renders a campaign's records as a plain-text resilience report."""

from __future__ import annotations

from chaos_agents.corpus import Record


def flow_lines(record: Record) -> list[str]:
    """The data-flow evidence for a finding: what moved, from where, by which
    route, and which rule it broke. Empty for a finding that is not about
    tracked data."""
    flows = [v for v in record.details.get("policy_violations", []) if v.get("kind") == "data_flow"]
    if not flows:
        return []
    flow = flows[0]
    path = flow.get("attack_path") or record.attack_path
    verb = "CRITICAL" if record.severity == "critical" else record.severity.upper()
    rule = flow.get("rule", "").removeprefix("data_flow.")
    key, _, setting = rule.partition(" = ")
    return [
        f"{verb} DATA FLOW",
        f"  Source: {flow.get('source') or record.source}",
        f"  Data:   {flow.get('data') or record.data}",
        f"  Path:   {' → '.join(path)}",
        f"  Policy: {key} = {setting.upper()}" if setting else f"  Policy: {rule}",
        f"  Result: {flow.get('result') or 'DATA FLOW VIOLATION'}",
    ]


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
            lines.extend(f"    {line}" for line in flow_lines(r))
    else:
        lines.append("No findings.")
    return "\n".join(lines)
