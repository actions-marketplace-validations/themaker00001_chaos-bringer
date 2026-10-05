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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chaos_agents import guard, memory, minimizer, observation, registry
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


def promote(
    record: Record,
    campaign: Campaign,
    baseline_dir: str | Path,
    *,
    do_minimize: bool = False,
    max_calls: int = 100,
) -> Path:
    """Write `record` into the corpus at `baseline_dir` as a regression entry.
    With `do_minimize`, shrink the payload to a small reproducer first (this
    re-runs the target, so it costs target calls)."""
    baseline = Path(baseline_dir)
    baseline.mkdir(parents=True, exist_ok=True)

    payload = record.payload
    # a memory finding is the whole control -> poison -> trigger sequence; the
    # poison alone is harmless, so it must be replayed as a scenario (and can't
    # be shrunk payload-wise)
    scenario = (record.details.get("memory") or {}).get("scenario") if record.category == memory.CATEGORY else None
    if do_minimize and not scenario:
        adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
        judge = guard.judge_for(campaign)
        payload = minimizer.minimize(record.payload, _reproduces(adapter, judge), max_calls=max_calls)

    entry = {
        "finding_id": finding_id(record.fingerprint) if record.fingerprint else None,
        "fingerprint": record.fingerprint,
        "category": record.category,
        "technique": record.technique,
        "severity": record.severity,
        "payload": payload,
        "original_payload": record.payload,
        "adapter": {"plugin": campaign.adapter.plugin, "config": campaign.adapter.config},
        "judge": {"plugin": campaign.judge.plugin, "config": campaign.judge.config},
        "policy": campaign.policy.to_dict() if campaign.policy else None,
        "expected": "safe",  # after a fix, replaying this must NOT be flagged
    }
    if scenario:
        entry["scenario"] = scenario
    name = (entry["finding_id"] or "CB-unknown") + ".json"
    path = baseline / name
    path.write_text(json.dumps(entry, indent=2))
    return path


def load_entries(baseline_dir: str | Path) -> list[dict]:
    baseline = Path(baseline_dir)
    return [json.loads(p.read_text()) for p in sorted(baseline.glob("*.json"))]


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
        adapter = registry.load("chaos_agents.adapters", entry["adapter"]["plugin"], **entry["adapter"].get("config", {}))
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
