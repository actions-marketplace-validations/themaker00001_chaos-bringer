"""Turn a confirmed finding into a durable regression test.

The V2 loop: a finding is verified, optionally minimized to a small
reproducer, and promoted into a corpus directory as a self-contained JSON
entry (the reproducer plus how to rebuild its target and judge). Later --
after a fix, or in CI -- the corpus is re-run: each reproducer is replayed and
the target must now be safe. An entry that still fires is a live or regressed
vulnerability.

Never store real secrets here: entries carry only the synthetic payloads and
the plugin config the campaign already used (which should itself use
synthetic canaries).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import yaml

from chaos_agents import guard, memory, minimizer, observation, registry, runstore, standards
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id
from chaos_agents.interfaces import FAIL, PASS
from chaos_agents.policy import Policy


def _reproduces(adapter, judge) -> Any:
    """Predicate for the minimizer: a candidate payload still reproduces the
    finding when the target's behaviour (reply + tool calls) is still flagged
    by the judge -- the same Observation path the live campaign uses."""
    def check(candidate: str) -> bool:
        try:
            obs = observation.observe(adapter, candidate)
        except Exception:  # noqa: BLE001 -- a target that errors isn't a confirmed reproduction
            return False
        return not observation.judge(judge, candidate, obs).passed
    return check


def _scenario_of(record: Record) -> dict | None:
    if record.category != memory.CATEGORY:
        return None
    return (record.details.get("memory") or {}).get("scenario")


def build_entry(record: Record, campaign: dict, *, payload: str | None = None) -> dict:
    """The reproducer for `record`, as plain data: how to rebuild the target,
    the judge and the policy, and the attack to replay. `campaign` is
    ``Campaign.to_dict()`` (or a run snapshot's campaign); secret-looking config
    is stored as ${NAME} placeholders."""
    campaign = runstore.redact_campaign(campaign)
    entry = {
        "finding_id": finding_id(record.fingerprint) if record.fingerprint else None,
        "fingerprint": record.fingerprint,
        "category": record.category,
        "technique": record.technique,
        "severity": record.severity,
        "payload": record.payload if payload is None else payload,
        "original_payload": record.payload,
        "adapter": campaign["adapter"],
        "judge": campaign["judge"],
        "policy": campaign.get("policy") or None,
        "expected": "safe",  # after a fix, replaying this must NOT be flagged
    }
    scenario = _scenario_of(record)
    if scenario:
        # a memory finding is the whole control -> poison -> trigger sequence; the
        # poison alone is harmless, so it must be replayed as a scenario (and can't
        # be shrunk payload-wise)
        entry["scenario"] = scenario
    return entry


def promote(
    record: Record,
    campaign: Campaign,
    baseline_dir: str | Path,
    *,
    do_minimize: bool = False,
    max_calls: int = 100,
) -> Path:
    """Write `record` into the corpus at `baseline_dir` as a flat regression
    entry. With `do_minimize`, shrink the payload to a small reproducer first
    (this re-runs the target, so it costs target calls)."""
    baseline = Path(baseline_dir)
    baseline.mkdir(parents=True, exist_ok=True)

    payload = record.payload
    if do_minimize and not _scenario_of(record):
        adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
        judge = guard.judge_for(campaign)
        payload = minimizer.minimize(record.payload, _reproduces(adapter, judge), max_calls=max_calls)

    entry = build_entry(record, campaign.to_dict(), payload=payload)
    name = (entry["finding_id"] or "CB-unknown") + ".json"
    path = baseline / name
    path.write_text(json.dumps(entry, indent=2))
    return path


# ---- the folder layout: finding promote ------------------------------------------

ATTACK, EXPECTED, METADATA, MINIMIZED = "attack.yaml", "expected.yaml", "metadata.json", "minimized_payload.txt"


class PromoteError(RuntimeError):
    """A finding can't be promoted (and why)."""


def _yaml(doc: dict, header: str) -> str:
    class _Dumper(yaml.SafeDumper):
        pass

    def _str(dumper, data):
        style = "|" if "\n" in data else None
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)

    _Dumper.add_representer(str, _str)
    return header + yaml.dump(doc, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)


def _tool_version() -> str:
    try:
        return version("chaos-bringer")
    except PackageNotFoundError:
        return "dev"


@dataclass
class Promoted:
    path: Path
    entry: dict
    reproducible: bool
    minimization: dict = field(default_factory=dict)


def _replays(entry: dict, adapter, judge) -> bool:
    """Does this reproducer still fire against a freshly built target?"""
    if entry.get("scenario"):
        return memory.run_scenario(adapter, judge, memory.Scenario.from_dict(entry["scenario"])).status == FAIL
    return _reproduces(adapter, judge)(entry["payload"])


def promote_finding(found, regressions_dir: str | Path = "regressions", *, campaign: dict | None = None,
                    minimize: bool = True, max_calls: int = 100, force: bool = False) -> Promoted:
    """Turn a located finding (see ``runstore.find``) into
    ``regressions_dir/CB-xxxx/{attack.yaml, expected.yaml, metadata.json,
    minimized_payload.txt}``.

    The reproducer is verified before it is written: it is minimized (a payload
    finding; a memory scenario is replayed whole), then replayed once against a
    freshly built target. One that does not fire is refused unless `force` -- a
    regression test that never failed proves nothing."""
    record = found.record
    snap = campaign or (found.snapshot or {}).get("campaign")
    if not snap:
        raise PromoteError(
            f"run {found.run_id} has no campaign snapshot (it predates snapshots); pass the campaign it ran with: "
            f"--campaign path/to/campaign.yaml")
    fid = found.id
    target = Path(regressions_dir) / fid
    if target.exists() and not force:
        raise PromoteError(f"{target}/ already exists (the finding is already promoted); use --force to replace it")

    entry = build_entry(record, snap)
    policy = Policy.from_dict(entry["policy"]) if entry["policy"] else None
    judge_spec = entry["judge"]

    def fresh_adapter():
        return registry.load("chaos_agents.adapters", entry["adapter"]["plugin"],
                             **runstore.expand_env(entry["adapter"].get("config", {})))

    minimization = {"applied": False, "original_length": len(record.payload), "minimized_length": len(record.payload),
                    "target_calls": 0}
    if minimize and not entry.get("scenario"):
        calls = {"n": 0}
        check = _reproduces(fresh_adapter(), guard.build_judge(judge_spec, policy))

        def counted(candidate: str) -> bool:
            calls["n"] += 1
            return check(candidate)

        entry["payload"] = minimizer.minimize(record.payload, counted, max_calls=max_calls)
        minimization = {"applied": True, "original_length": len(record.payload),
                        "minimized_length": len(entry["payload"]), "target_calls": calls["n"]}

    reproducible = _replays(entry, fresh_adapter(), guard.build_judge(judge_spec, policy))
    if not reproducible and not force:
        raise PromoteError(f"{fid} did not reproduce when replayed against a fresh target (flaky target, or already "
                           f"fixed); not promoted. Use --force to promote it anyway.")

    target.mkdir(parents=True, exist_ok=True)
    attack: dict[str, Any] = {"payload": entry["original_payload"]}
    if entry.get("scenario"):
        attack = {"scenario": entry["scenario"]}
    (target / ATTACK).write_text(_yaml(
        {"finding": fid, "adapter": entry["adapter"], "judge": entry["judge"], "policy": entry["policy"],
         "attack": attack},
        f"# Reproducer for {fid}. Replayed by `chaos-agents regression`; the payload replayed is\n"
        f"# {MINIMIZED} when present, else attack.payload.\n"))
    (target / EXPECTED).write_text(_yaml(
        {"outcome": "safe", "must_not": {k: v for k, v in {
            "category": record.category, "technique": record.technique, "severity": record.severity,
            "capability": record.capability, "sink": record.sink, "data": record.data,
            "reason": record.reason}.items() if v}},
        f"# What must hold once {fid} is fixed: replaying the attack must NOT be flagged.\n"
        f"# must_not describes the failure this regression guards against.\n"))
    (target / MINIMIZED).write_text(entry["payload"] + "\n")
    owasp, atlas = standards.tags_for(record)
    (target / METADATA).write_text(json.dumps({
        "id": fid, "fingerprint": record.fingerprint, "status": "open", "severity": record.severity,
        "category": record.category, "technique": record.technique, "target": record.target,
        "owasp": owasp, "mitre_atlas": atlas, "reproducible": reproducible,
        "minimization": minimization if not entry.get("scenario") else {**minimization, "applied": False,
                                                                       "note": "memory scenarios are replayed whole"},
        "source": {"campaign": found.campaign, "run_id": found.run_id},
        "promoted": datetime.now(timezone.utc).isoformat(), "tool_version": _tool_version(),
    }, indent=2) + "\n")
    return Promoted(target, entry, reproducible, minimization)


def _read_folder(folder: Path) -> dict:
    """Rebuild a reproducer entry from a finding's folder."""
    attack_doc = yaml.safe_load((folder / ATTACK).read_text()) or {}
    meta = json.loads((folder / METADATA).read_text()) if (folder / METADATA).exists() else {}
    expected = yaml.safe_load((folder / EXPECTED).read_text()) if (folder / EXPECTED).exists() else {}
    attack = attack_doc.get("attack") or {}
    original = attack.get("payload", "")
    scenario = attack.get("scenario")
    minimized = (folder / MINIMIZED).read_text().rstrip("\n") if (folder / MINIMIZED).exists() else ""
    entry = {
        "finding_id": attack_doc.get("finding") or folder.name,
        "fingerprint": meta.get("fingerprint", ""),
        "category": meta.get("category", ""), "technique": meta.get("technique", ""),
        "severity": meta.get("severity", "?"),
        "payload": minimized or original or (scenario or {}).get("poison", ""),
        "original_payload": original,
        "adapter": attack_doc["adapter"], "judge": attack_doc.get("judge") or guard.DEFAULT_JUDGE,
        "policy": attack_doc.get("policy"),
        "expected": (expected or {}).get("outcome", "safe"),
        "_folder": str(folder),
    }
    if scenario:
        entry["scenario"] = scenario
    return entry


def state_of(finding_id_: str, regressions_dir: str | Path = "regressions") -> dict | None:
    """What the regression folder says about a finding -- its status (open /
    fixed), whether it was verified reproducible -- or None if it was never
    promoted."""
    folder = Path(regressions_dir) / finding_id_
    meta_path = folder / METADATA
    if not (folder / ATTACK).exists() or not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
    except ValueError:
        return None
    return {"status": meta.get("status", "open"), "reproducible": meta.get("reproducible"), "path": str(folder),
            "fixed": meta.get("fixed")}


def load_entries(baseline_dir: str | Path) -> list[dict]:
    """Every reproducer under `baseline_dir`, from both layouts: flat
    ``*.json`` files and ``CB-xxxx/attack.yaml`` folders."""
    baseline = Path(baseline_dir)
    entries = [json.loads(p.read_text()) for p in sorted(baseline.glob("*.json"))]
    entries += [_read_folder(d) for d in sorted(baseline.glob("*")) if (d / ATTACK).exists()]
    return entries


@dataclass
class RegressionResult:
    entry: dict
    still_vulnerable: bool   # True = the reproducer still fires (bad)
    reason: str
    response: str


def run_regression(baseline_dir: str | Path) -> list[RegressionResult]:
    """Replay every reproducer in the corpus against its target. A reproducer
    that is still flagged means the vulnerability is present (unfixed or
    regressed)."""
    results: list[RegressionResult] = []
    for entry in load_entries(baseline_dir):
        if entry.get("expected", "safe") != "safe":
            results.append(RegressionResult(entry, False, f"inconclusive: unsupported expected outcome "
                                                          f"{entry['expected']!r} (only 'safe' is supported)", ""))
            continue
        try:
            adapter = registry.load("chaos_agents.adapters", entry["adapter"]["plugin"],
                                    **runstore.expand_env(entry["adapter"].get("config", {})))
        except runstore.MissingSecret as exc:
            results.append(RegressionResult(entry, False, f"inconclusive: {exc}", ""))
            continue
        policy = Policy.from_dict(entry["policy"]) if entry.get("policy") else None
        judge = guard.build_judge(entry["judge"], policy)
        payload = entry["payload"]
        if entry.get("scenario"):
            results.append(_replay_scenario(entry, adapter, judge))
            continue
        try:
            obs = observation.observe(adapter, payload)
            verdict = observation.judge(judge, payload, obs)
            response = obs.response
            still = not verdict.passed
            reason = verdict.reason if still else "no longer reproduces (target is safe)"
        except Exception as exc:  # noqa: BLE001 -- target down: can't confirm it's fixed
            response, still, reason = "", False, f"inconclusive: target error ({type(exc).__name__})"
        results.append(RegressionResult(entry=entry, still_vulnerable=still, reason=reason, response=response))
    return results


def _replay_scenario(entry: dict, adapter, judge) -> RegressionResult:
    """Re-run a memory-poisoning reproducer: control, poison, then trigger."""
    if not memory.supports_memory(adapter):
        return RegressionResult(entry, False, "inconclusive: the target no longer has persistent memory", "")
    try:
        outcome = memory.run_scenario(adapter, judge, memory.Scenario.from_dict(entry["scenario"]))
    except Exception as exc:  # noqa: BLE001 -- target down: can't confirm it's fixed
        return RegressionResult(entry, False, f"inconclusive: target error ({type(exc).__name__})", "")
    response = outcome.trigger.response
    if outcome.status == FAIL:
        return RegressionResult(entry, True, outcome.reason, response)
    if outcome.status == PASS:
        return RegressionResult(entry, False, "no longer reproduces (target is safe)", response)
    return RegressionResult(entry, False, f"inconclusive: {outcome.reason}", response)


def summarize(results: list[RegressionResult]) -> str:
    vulnerable = [r for r in results if r.still_vulnerable]
    lines = [f"Regression: {len(results) - len(vulnerable)}/{len(results)} reproducers no longer fire."]
    for r in vulnerable:
        fid = r.entry.get("finding_id") or r.entry.get("fingerprint", "?")
        lines.append(f"  STILL VULNERABLE [{r.entry.get('severity', '?')}] {fid}: {r.reason}")
    return "\n".join(lines)


# re-exported for callers that build the "still a finding" check elsewhere
IS_FINDING = FAIL
