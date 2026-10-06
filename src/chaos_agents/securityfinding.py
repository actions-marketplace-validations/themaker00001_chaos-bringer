"""The Security Finding: one confirmed weakness, written the way a security
team files it.

A trace Record is a trial -- payload, reply, verdict. A finding is the thing a
person acts on: an id to refer to, a severity and a status, what was attacked
and through which capability, where the data came from and where it went, the
attack that did it, the evidence that proves it, the route it took, which
standards it falls under, and whether it can be reproduced. This module turns a
Record into that, as plain data (``to_dict``, for JSON) and as a readable
report (``render``, for ``chaos-agents finding show``).

Built only from what the Record already carries, so it works on any stored run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from chaos_agents import attackgraph, standards
from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id

OPEN = "open"
FIXED = "fixed"


@dataclass
class SecurityFinding:
    id: str
    severity: str
    status: str = OPEN
    category: str = ""
    technique: str = ""
    target: str = ""
    vector: str = ""
    capability: str = ""
    source: str = ""
    sink: str = ""
    data: str = ""
    impact: str = ""
    summary: str = ""
    attack: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    attack_path: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    reproducible: bool | None = None       # None: nobody has replayed it yet
    fingerprint: str = ""
    regression: str = ""                   # the promoted regression folder, once there is one
    run: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """The finding as JSON-ready data. Empty fields are left out, so a
        policy finding doesn't carry an empty `data`."""
        out: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if value in ("", None, [], {}) and key not in ("reproducible",):
                continue
            out[key] = value
        return out

    # ---- the human report ---------------------------------------------------
    def render(self, graph: str = "") -> str:
        lines = [f"{self.id}  {self.severity.upper()}  {self.status.upper()}", self.summary, ""]
        rows = [
            ("Category", f"{self.category} / {self.technique}" if self.technique else self.category),
            ("Target", self.target + (f"  (vector: {self.vector})" if self.vector else "")),
            ("Capability", self.capability),
            ("Source", self.source),
            ("Sink", self.sink),
            ("Data", self.data),
            ("Impact", self.impact),
            ("Standards", " · ".join(p for p in (
                f"OWASP {', '.join(self.owasp)}" if self.owasp else "",
                f"ATLAS {', '.join(self.mitre_atlas)}" if self.mitre_atlas else "") if p)),
            ("Reproducible", {True: "yes", False: "no (did not reproduce on replay)", None: "unverified"}[self.reproducible]),
            ("Regression", f"{self.regression}/" if self.regression else ""),
            ("Fingerprint", self.fingerprint),
            ("Found in", f"{self.run['campaign']}  run {self.run['run_id']}"
             + (f"  (seen in {self.run['runs_seen']} runs)" if self.run.get("runs_seen", 1) > 1 else "")
             if self.run else ""),
        ]
        lines += [f"  {name:<13} {value}" for name, value in rows if value]

        lines += ["", "Attack"]
        payload = self.attack.get("payload", "")
        if self.attack.get("trigger"):
            lines += [f"  planted in an attacker session:", f"    {payload}",
                      f"  then, in a separate victim session:", f"    {self.attack['trigger']}"]
        else:
            lines += [f"  {payload}"]

        if self.attack_path:
            lines += ["", "Attack path", "  " + " → ".join(self.attack_path)]

        lines += ["", "Evidence"]
        ev = self.evidence
        if ev.get("response"):
            lines.append(f"  reply:  {_clip(ev['response'], 160)}")
        calls = ev.get("tool_calls") or []
        if calls:
            lines.append("  tool calls:")
            lines += [f"    {i}. {_call(c)}" for i, c in enumerate(calls, 1)]
        for v in ev.get("policy_violations") or []:
            lines.append(f"  violated: {v.get('kind', '').replace('_', ' ')} — {v.get('rule', '')}"
                         + (f" -> {v['sink']}" if v.get("sink") else ""))
        mem = ev.get("memory")
        if mem:
            lines.append(f"  control (clean memory): {mem['control'].get('status', '')} — the same request behaved")
        if graph:
            box = attackgraph.to_mermaid if graph == "mermaid" else attackgraph.render_box
            lines += ["", box(self._record())]
        return "\n".join(lines)

    def _record(self) -> Record:
        """A Record carrying just what the attack graph reads (for rendering)."""
        return Record(
            payload=self.attack.get("payload", ""), response=self.evidence.get("response", ""), passed=False,
            severity=self.severity, reason=self.summary, status="fail", category=self.category,
            technique=self.technique, impact=self.impact, target=self.target, vector=self.vector,
            capability=self.capability, sink=self.sink, source=self.source, data=self.data,
            attack_path=self.attack_path, fingerprint=self.fingerprint,
            details={"policy_violations": self.evidence.get("policy_violations") or [],
                     "memory": {"scenario": self.attack} if self.attack.get("trigger") else None},
        )


def _clip(text: str, room: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= room else text[: room - 1] + "…"


def _call(call: dict) -> str:
    args = call.get("arguments", "")
    if isinstance(args, dict):
        args = "  ".join(f"{k}={_clip(repr(v) if not isinstance(v, str) else v, 48)}" for k, v in args.items())
    return f"{call.get('name', '?')}  {_clip(str(args), 120)}"


def from_record(record: Record, run: dict[str, Any] | None = None, *, status: str = OPEN,
                reproducible: bool | None = None, regression: dict | None = None) -> SecurityFinding:
    """Build the finding for a confirmed (failed) Record. `regression` is what
    the regressions folder says about it (``regression.state_of``): once it has
    been promoted, its status and verified reproducibility come from there."""
    if regression:
        status = regression.get("status") or status
        if regression.get("reproducible") is not None:
            reproducible = regression["reproducible"]
    details = record.details or {}
    memory_info = details.get("memory") or None
    attack: dict[str, Any] = {"payload": record.payload}
    if memory_info:
        scenario = memory_info.get("scenario") or {}
        attack = {"payload": scenario.get("poison", record.payload), "trigger": scenario.get("trigger", "")}
    evidence: dict[str, Any] = {"reason": record.reason, "response": record.response}
    if record.tool_calls:
        evidence["tool_calls"] = record.tool_calls
    if details.get("policy_violations"):
        evidence["policy_violations"] = [
            {k: v for k, v in viol.items() if k in ("kind", "severity", "rule", "tool", "sink", "result")}
            for viol in details["policy_violations"]]
    if memory_info:
        evidence["memory"] = {"control": memory_info.get("control", {})}
    owasp, atlas = standards.tags_for(record)
    return SecurityFinding(
        id=finding_id(record.fingerprint) if record.fingerprint else "", severity=record.severity, status=status,
        category=record.category, technique=record.technique, target=record.target, vector=record.vector,
        capability=record.capability, source=record.source, sink=record.sink, data=record.data,
        impact=record.impact, summary=record.reason, attack=attack, evidence=evidence,
        attack_path=list(record.attack_path), owasp=owasp, mitre_atlas=atlas, reproducible=reproducible,
        fingerprint=record.fingerprint, run=run or {}, regression=(regression or {}).get("path", ""),
    )
