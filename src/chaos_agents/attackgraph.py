"""The attack graph: how a finding happened, stage by stage.

A finding says *what* went wrong. The graph says *how the attacker got there*,
as the observed chain from the way the attack was delivered to the damage done::

    [INDIRECT INJECTION] -> [AGENT GOAL HIJACK] -> [TOOL CALL] -> [PRIVILEGE VIOLATION]
        -> [EXTERNAL HTTP SINK] -> [SECRET EXFILTRATION]

It is derived entirely from what the Record already carries -- the vector that
delivered the payload, the tool call and policy violations the Observation
produced, the sink the data reached -- so it needs no extra instrumentation and
works on any stored run. Stages that were *observed* (the tool call, the
violation, the sink, the outcome) come from the evidence; the first two
(delivery, and the agent following the injected instruction) are what the
finding being a failure at all implies.

Three renderings of the same stages: a one-line chain for the report, a boxed
vertical graph for the terminal, and Mermaid for docs and pull requests.
"""

from __future__ import annotations

from dataclasses import dataclass

from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id


@dataclass(frozen=True)
class Stage:
    label: str          # UPPER-CASE stage name, e.g. "PRIVILEGE VIOLATION"
    detail: str = ""    # what specifically, e.g. "database_write on production_db"


_ENTRY_BY_VECTOR = {
    "static_corpus": "DIRECT INJECTION",
    "llm": "DIRECT INJECTION",
    "indirect": "INDIRECT INJECTION",
    "multiturn": "MULTI-TURN INJECTION",
    "mutation": "OBFUSCATED INJECTION",
}
# a technique that says *how the payload arrived* beats the vector's generic name
_ENTRY_BY_TECHNIQUE = {
    "indirect": "INDIRECT INJECTION",
    "poisoned_document": "POISONED DOCUMENT",
    "multi_turn": "MULTI-TURN INJECTION",
    "encoded_translated": "OBFUSCATED INJECTION",
}

_MCP_TARGETS = ("mcp_fault", "chatgpt_app")

_VIOLATION_STAGE = {
    "denied_capability": "PRIVILEGE VIOLATION",
    "approval_required": "APPROVAL BYPASS",
    "destination_not_allowed": "DESTINATION VIOLATION",
}
_OUTCOME_BY_RESULT = {
    "EXFILTRATION": "SECRET EXFILTRATION",
    "DISCLOSURE": "SECRET DISCLOSURE",
    "UNAPPROVED TRANSFER": "UNAPPROVED DATA TRANSFER",
    "UNAPPROVED DISCLOSURE": "UNAPPROVED DISCLOSURE",
}
_OUTCOME_BY_KIND = {
    "denied_capability": "UNAUTHORIZED ACTION",
    "approval_required": "UNAPPROVED ACTION",
    "destination_not_allowed": "OFF-POLICY DATA TRANSFER",
}
_OUTCOME_BY_CATEGORY = {
    "sensitive_data": "SECRET DISCLOSURE",
    "tool_misuse": "TOOL MISUSE",
    "identity_privilege": "PRIVILEGE ESCALATION",
    "agent_to_agent": "PEER COMPROMISE",
    "rag_vector": "RAG COMPROMISE",
    "output_handling": "UNSAFE OUTPUT",
    "availability_cost": "RESOURCE EXHAUSTION",
    "supply_chain": "SUPPLY-CHAIN COMPROMISE",
}
# families where "the agent followed an injected instruction" would be the wrong story
_NO_HIJACK = {"availability_cost", "supply_chain"}


def _entry(record: Record) -> Stage:
    label = (_ENTRY_BY_TECHNIQUE.get(record.technique)
             or _ENTRY_BY_VECTOR.get(record.vector) or "ATTACK PAYLOAD")
    return Stage(label, f"vector: {record.vector}" if record.vector else "")


def _is_host(sink: str) -> bool:
    return "." in sink and " " not in sink and "/" not in sink


def _sink_stage(tool: str, sink: str) -> Stage:
    if _is_host(sink):
        kind = "EMAIL" if "mail" in tool else "HTTP" if "http" in tool else ""
        return Stage(f"EXTERNAL {kind} SINK" if kind else "EXTERNAL SINK", sink)
    return Stage("TARGET RESOURCE", sink)


def _lead(record: Record) -> tuple[dict | None, list[dict]]:
    """The violation behind the finding, and every violation on the same call."""
    violations = record.details.get("policy_violations") or []
    if not violations:
        return None, []
    lead = next((v for v in violations
                 if v.get("sink") == record.sink and v.get("capability") == record.capability), violations[0])
    group = [v for v in violations if v.get("tool") == lead.get("tool") and v.get("sink") == lead.get("sink")]
    return lead, group


def stages_of(record: Record) -> list[Stage]:
    """The attack, as ordered stages. Empty for anything that is not a confirmed
    failure -- a held attack has no chain to draw."""
    if record.passed or (record.status and record.status != "fail"):
        return []
    stages = [_entry(record)]
    if record.category not in _NO_HIJACK:
        stages.append(Stage("AGENT GOAL HIJACK", "injected instruction followed"))

    lead, group = _lead(record)
    if lead is None:
        outcome = _OUTCOME_BY_CATEGORY.get(record.category)
        if outcome and record.category != "goal_hijack":
            stages.append(Stage(outcome, record.impact or record.reason))
        return stages

    # how tracked data entered the agent's context -- only a data-flow violation knows
    hops = [hop for v in group for hop in v.get("attack_path") or []]
    for hop in hops:
        if hop.startswith("RAG: "):
            stages.append(Stage("RAG RETRIEVAL", hop.removeprefix("RAG: ")))
            break
        if hop.startswith("tool result: "):
            stages.append(Stage("TOOL RESULT", hop.removeprefix("tool result: ")))
            break
    tool = lead.get("tool") or ""
    if tool:
        mcp = record.target in _MCP_TARGETS
        stages.append(Stage("MCP TOOL CALL" if mcp else "TOOL CALL", tool))
    else:
        stages.append(Stage("AGENT RESPONSE", "the reply reached the user"))
    seen: set[str] = set()
    for v in group:
        label = _VIOLATION_STAGE.get(v.get("kind", ""))
        if label and label not in seen:
            seen.add(label)
            stages.append(Stage(label, v.get("rule", "")))
    if tool and lead.get("sink"):
        stages.append(_sink_stage(tool, lead["sink"]))

    flow = next((v for v in group if v.get("kind") == "data_flow"), None)
    outcome = (_OUTCOME_BY_RESULT.get(flow.get("result", "")) if flow
               else _OUTCOME_BY_KIND.get(lead.get("kind", ""), "POLICY VIOLATION"))
    stages.append(Stage(outcome or "POLICY VIOLATION", (flow or lead).get("data") or ""))
    return stages


def chain(record: Record) -> str:
    """One line: [A] → [B] → [C]. Empty when there is no chain."""
    return " → ".join(f"[{s.label}]" for s in stages_of(record))


def _clip(text: str, room: int = 64) -> str:
    return text if len(text) <= room else text[: room - 1] + "…"


def render_box(record: Record) -> str:
    """The stages as boxes joined by arrows, with the finding's id and
    severity above and the impact below."""
    stages = stages_of(record)
    if not stages:
        return ""
    fid = finding_id(record.fingerprint) if record.fingerprint else ""
    head = f"ATTACK GRAPH  {fid}".rstrip()
    width = max(len(s.label) for s in stages)
    width = max([width] + [len(_clip(s.detail)) for s in stages if s.detail]) + 2
    mid = width // 2
    lines = [head, ""]
    for i, stage in enumerate(stages):
        last = i == len(stages) - 1
        lines.append("╭" + "─" * width + "╮")
        lines.append("│ " + stage.label.ljust(width - 2) + " │")
        if stage.detail:
            lines.append("│ " + _clip(stage.detail).ljust(width - 2) + " │")
        lines.append("╰" + "─" * width + "╯" if last else "╰" + "─" * mid + "┬" + "─" * (width - mid - 1) + "╯")
        if not last:
            lines.append(" " * (mid + 1) + "▼")
    tail = f"Severity: {record.severity.upper()}"
    if record.impact:
        tail += f"  ·  {record.impact}"
    lines += ["", tail]
    return "\n".join(lines)


def to_mermaid(record: Record) -> str:
    """The stages as a Mermaid flowchart, for docs and pull-request comments."""
    stages = stages_of(record)
    if not stages:
        return ""

    def node(i: int, s: Stage) -> str:
        text = s.label + (f"<br/>{_clip(s.detail, 48)}" if s.detail else "")
        return f'S{i}["{text.replace(chr(34), chr(39))}"]'

    out = ["flowchart TD"]
    out += [f"  {node(i, s)}" for i, s in enumerate(stages)]
    out += [f"  S{i} --> S{i + 1}" for i in range(len(stages) - 1)]
    return "\n".join(out)
