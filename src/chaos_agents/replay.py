"""Replay a finding: the whole story, from the original run to a verdict.

    original run -> attack -> agent -> observation -> finding
                                                     -> fix applied -> replay -> PASS

``replay CB-xxxx`` re-runs the attack that produced a finding against a freshly
built target and says what happened *now*: still exploitable, or no longer. Give
it a fix (``--fix hardened=true``: a change to the target's configuration) and it
runs the attack twice -- first against the target as it was, to confirm the hole
is real and reproducible, then against the fixed target -- so "PASS" means the
fix is what closed it, not that the attack happened not to work today. If the
code changed instead of the config, just replay again.

The reproducer comes from the promoted regression (``regressions/CB-xxxx/``)
when there is one, else from the run it was found in. Outcomes:

* PASS         the attack no longer succeeds
* VULNERABLE   it still does
* INCONCLUSIVE a result that can't be trusted: the target errored, the fixed
               target couldn't be built, or -- when verifying a fix -- the
               attack did not reproduce on the original target first
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from chaos_agents import guard, memory, observation, registry, runstore
from chaos_agents import regression
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS
from chaos_agents.observation import Observation
from chaos_agents.policy import Policy

VULNERABLE = "vulnerable"


class ReplayError(RuntimeError):
    """The replay can't be set up (and why)."""


@dataclass
class Attempt:
    """One run of the reproducer against one build of the target."""

    status: str                         # pass | fail | inconclusive
    reason: str
    response: str = ""
    tool_calls: list[dict] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def reproduced(self) -> bool:
        return self.status == FAIL

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reproduced": self.reproduced, "reason": self.reason,
                "response": self.response, "tool_calls": self.tool_calls, "config": self.config}


@dataclass
class Replay:
    id: str
    entry: dict
    run: dict[str, Any]
    original: dict[str, Any]            # the finding as first recorded
    before: Attempt                     # the target as it was
    overrides: dict[str, Any] = field(default_factory=dict)
    after: Attempt | None = None        # the fixed target, when a fix was given
    result: str = INCONCLUSIVE
    summary: str = ""
    recorded: str = ""                  # the regression folder updated by --record

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "original": self.original, "run": self.run,
            "attack": _attack_of(self.entry), "agent": self.before.config,
            "observation": self.before.to_dict(), "result": self.result, "summary": self.summary,
        }
        if self.after is not None:
            out["fix"] = self.overrides
            out["replay"] = self.after.to_dict()
        if self.recorded:
            out["recorded"] = self.recorded
        return out


def _attack_of(entry: dict) -> dict[str, str]:
    scenario = entry.get("scenario")
    if scenario:
        return {"payload": scenario["poison"], "trigger": scenario["trigger"]}
    return {"payload": entry["payload"]}


def parse_fix(pairs: list[str]) -> dict[str, Any]:
    """``["hardened=true", "adapter.model=x"]`` -> ``{"hardened": True, "model": "x"}``.
    Values are read as YAML, so true/false/numbers/null behave; the optional
    ``adapter.`` prefix is accepted."""
    fixes: dict[str, Any] = {}
    for pair in pairs:
        key, sep, raw = pair.partition("=")
        key = key.strip().removeprefix("adapter.")
        if not sep or not key:
            raise ReplayError(f"--fix expects KEY=VALUE (an adapter setting), got {pair!r}")
        fixes[key] = yaml.safe_load(raw) if raw.strip() else ""
    return fixes


def load_entry(found, regressions_dir: str | Path, campaign: dict | None = None) -> dict:
    """The reproducer for a located finding: the promoted regression if there
    is one, else built from the run it was found in."""
    folder = Path(regressions_dir) / found.id
    if (folder / regression.ATTACK).exists():
        return regression._read_folder(folder)
    snap = campaign or (found.snapshot or {}).get("campaign")
    if not snap:
        raise ReplayError(f"run {found.run_id} has no campaign snapshot (it predates snapshots); pass the campaign it "
                          f"ran with: --campaign path/to/campaign.yaml")
    return regression.build_entry(found.record, snap)


def attempt(entry: dict, adapter_overrides: dict[str, Any] | None = None) -> Attempt:
    """Run the reproducer once against a freshly built target (the entry's
    adapter config with `adapter_overrides` applied)."""
    config = {**entry["adapter"].get("config", {}), **(adapter_overrides or {})}
    try:
        adapter = registry.load("chaos_agents.adapters", entry["adapter"]["plugin"], **runstore.expand_env(config))
    except runstore.MissingSecret as exc:
        return Attempt(INCONCLUSIVE, str(exc), config=config)
    except TypeError as exc:                                   # a --fix key the adapter doesn't have
        return Attempt(INCONCLUSIVE, f"the target could not be built: {exc}", config=config)
    policy = Policy.from_dict(entry["policy"]) if entry.get("policy") else None
    judge = guard.build_judge(entry["judge"], policy)
    try:
        if entry.get("scenario"):
            if not memory.supports_memory(adapter):
                return Attempt(INCONCLUSIVE, "the target has no persistent memory to replay a memory attack against",
                               config=config)
            out = memory.run_scenario(adapter, judge, memory.Scenario.from_dict(entry["scenario"]))
            obs, status, reason = out.trigger, out.status, out.reason
        else:
            obs: Observation = observation.observe(adapter, entry["payload"])
            verdict = observation.judge(judge, entry["payload"], obs)
            status, reason = verdict.status, verdict.reason
    except Exception as exc:  # noqa: BLE001 -- a target that errors can't confirm anything
        return Attempt(INCONCLUSIVE, f"target error: {type(exc).__name__}: {exc}", config=config)
    if status == PASS:
        reason = "the attack no longer succeeds"
    return Attempt(status, reason, obs.response, obs.tool_calls_as_dicts(), config)


def replay(found, regressions_dir: str | Path = "regressions", *, fix: dict[str, Any] | None = None,
           campaign: dict | None = None, record: bool = False) -> Replay:
    entry = load_entry(found, regressions_dir, campaign)
    original = {"severity": found.record.severity, "reason": found.record.reason,
                "category": found.record.category, "technique": found.record.technique}
    before = attempt(entry)
    rp = Replay(id=found.id, entry=entry, run=found.run_info(), original=original, before=before)

    if not fix:
        if before.status == FAIL:
            rp.result, rp.summary = VULNERABLE, "the attack still succeeds"
        elif before.status == PASS:
            rp.result, rp.summary = PASS, "the attack no longer succeeds"
        else:
            rp.result, rp.summary = INCONCLUSIVE, before.reason
        if record:
            raise ReplayError("--record needs a fix to verify: pass --fix KEY=VALUE")
        return rp

    rp.overrides = dict(fix)
    if before.status != FAIL:
        rp.result = INCONCLUSIVE
        rp.summary = ("cannot verify the fix: the attack did not reproduce against the original target first "
                      f"({before.reason})")
        return rp
    rp.after = attempt(entry, fix)
    if rp.after.status == PASS:
        rp.result, rp.summary = PASS, "the fix closes it: the attack no longer succeeds"
    elif rp.after.status == FAIL:
        rp.result, rp.summary = VULNERABLE, "the fix does not close it: the attack still succeeds"
    else:
        rp.result, rp.summary = INCONCLUSIVE, rp.after.reason
    if record and rp.result == PASS:
        rp.recorded = record_fix(found.id, regressions_dir, fix, rp)
    elif record:
        raise ReplayError(f"not recording: the fix did not pass ({rp.summary})")
    return rp


def record_fix(finding_id: str, regressions_dir: str | Path, fix: dict[str, Any], rp: Replay) -> str:
    """Make the fix stick: write it into the regression's attack.yaml (so the
    regression now guards the fixed target) and mark the finding fixed."""
    folder = Path(regressions_dir) / finding_id
    if not (folder / regression.ATTACK).exists():
        raise ReplayError(f"{folder}/ does not exist; promote the finding first: chaos-agents finding promote {finding_id}")
    doc = yaml.safe_load((folder / regression.ATTACK).read_text()) or {}
    doc["adapter"]["config"] = {**doc["adapter"].get("config", {}), **fix}
    header = "".join(line + "\n" for line in (folder / regression.ATTACK).read_text().splitlines() if line.startswith("#"))
    (folder / regression.ATTACK).write_text(regression._yaml(doc, header))
    meta_path = folder / regression.METADATA
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {"id": finding_id}
    meta["status"] = "fixed"
    meta["fixed"] = {"at": datetime.now(timezone.utc).isoformat(), "adapter_changes": fix,
                     "verified_by": "replay: reproduced on the original target, closed on the fixed one"}
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    return str(folder)


# ---- the story ---------------------------------------------------------------------

def _calls(calls: list[dict], room: int = 100, cap: int | None = None) -> list[str]:
    out = []
    for i, c in enumerate(calls, 1):
        args = c.get("arguments", "")
        if isinstance(args, dict):
            args = "  ".join(f"{k}={_short(v)}" for k, v in args.items())
        name = c.get("name", "?")
        used = len(f"  {i}. {name}  ")                  # the line's own prefix, inside the gutter
        out.append(f"{i}. {name}  {_short(args, min(room, cap - used) if cap else room)}")
    return out


def _short(value: Any, room: int = 44) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= room else text[: room - 1] + "…"


def _val(value: Any, room: int = 30) -> str:
    """A config value as it would be written in YAML (true, not True)."""
    return _short(json.dumps(value) if isinstance(value, (bool, int, float)) or value is None else value, room)


def _config(cfg: dict) -> str:
    return "  ".join(f"{k}={_val(v)}" for k, v in cfg.items()) or "(defaults)"


def render(rp: Replay, width: int | None = None) -> str:
    """The replay as a numbered story. With a `width` (a terminal's) every
    line is kept within it by shortening the long fields, as before they were
    capped at fixed sizes."""
    cap = max(width - 18, 24) if width else None       # room left of the "[n] NAME          " gutter

    def short(value: Any, room: int, used: int = 0) -> str:
        """`value` cut to `room` characters, or to what is left of the terminal
        after the `used` characters of prefix this item already starts with."""
        return _short(value, max(min(room, cap - used), 12) if cap else room)

    steps: list[tuple[str, list[str]]] = []
    o = rp.original
    sev = f"{o['severity'].upper()}  "
    steps.append(("ORIGINAL RUN", [f"{rp.run.get('campaign', '?')} · run {rp.run.get('run_id', '?')}",
                                   f"{sev}{short(o['reason'], 150, len(sev))}"]))
    atk = _attack_of(rp.entry)
    attack_lines = ([f"planted:  {short(atk['payload'], 110, 10)}", f"trigger:  {short(atk['trigger'], 110, 10)}"]
                    if "trigger" in atk else [short(atk["payload"], 140)])
    steps.append(("ATTACK", attack_lines))
    steps.append(("AGENT", [f"{rp.entry['adapter']['plugin']}  {_config(rp.before.config)}"]))

    def observed(a: Attempt) -> list[str]:
        lines = [f"reply: {short(a.response, 120, 7)}" if a.response else "reply: (none)"]
        calls = _calls(a.tool_calls, 100, cap)
        return lines + (["tool calls:"] + [f"  {c}" for c in calls] if calls else ["tool calls: none"])

    steps.append(("OBSERVATION", observed(rp.before)))
    verdict = {FAIL: "REPRODUCED", PASS: "NOT REPRODUCED", INCONCLUSIVE: "INCONCLUSIVE"}[rp.before.status]
    steps.append(("FINDING", [f"{verdict}  {short(rp.before.reason, 140, len(verdict) + 2)}"]))
    if rp.after is not None:
        steps.append(("FIX APPLIED", [_config(rp.overrides)]))
        steps.append(("REPLAY", observed(rp.after)))
    label = {PASS: "PASS", VULNERABLE: "VULNERABLE", INCONCLUSIVE: "INCONCLUSIVE"}[rp.result]
    steps.append(("RESULT", [f"{label}  {short(rp.summary, 150, len(label) + 2)}"]))

    lines = [f"REPLAY  {rp.id}", ""]
    for i, (name, body) in enumerate(steps, 1):
        lines.append(f"[{i}] {name:<13} {body[0]}")
        lines += [f"    {'':<13} {line}" for line in body[1:]]
    if rp.recorded:
        lines += ["", f"recorded: {rp.recorded}/ now guards the fixed target and is marked fixed"]
    return "\n".join(lines)
