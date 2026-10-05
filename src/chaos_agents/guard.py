"""Compose the campaign's judge with its policy.

A campaign has one ``judge`` (did the agent say something it shouldn't?) and an
optional ``policy`` (did the agent *do* something it shouldn't?). Both look at
the same Observation, and a finding is a finding either way -- so rather than
fork the pipeline, the policy is folded *into* the judge. ``GuardedJudge``
wraps the real judge, runs the policy over the same Observation, and returns a
single Verdict. Everything downstream (records, fingerprints, SARIF, the
regression corpus, the minimizer) keeps calling ``observation.judge(...)`` and
needs no idea that a policy exists.

``build_judge`` is the one place a campaign's judge is constructed, so the
orchestrator, the minimizer and the regression runner can never disagree about
what "the judge" is.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from chaos_agents import observation as observation_mod
from chaos_agents import registry
from chaos_agents.interfaces import FAIL, Verdict
from chaos_agents.observation import Observation
from chaos_agents.policy import SEVERITY_RANK, Policy, Violation

DEFAULT_JUDGE = {"plugin": "rule_based", "config": {}}


def _rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)


def merge(base: Verdict, violations: list[Violation]) -> Verdict:
    """Fold policy violations into the judge's verdict.

    No violations: the judge's verdict stands. Otherwise the result is a FAIL
    led by the most severe thing that happened -- the judge's own failure if it
    was at least as severe, else the worst violation -- with every violation
    attached as evidence either way."""
    if not violations:
        return base
    worst = max(violations, key=lambda v: _rank(v.severity))
    details = {**base.details, "policy_violations": [v.to_dict() for v in violations]}
    if not base.passed and base.status == FAIL and _rank(base.severity) >= _rank(worst.severity):
        details.setdefault("finding", worst.finding_fields())
        return replace(base, details=details)
    extra = f" (+{len(violations) - 1} more)" if len(violations) > 1 else ""
    details["finding"] = worst.finding_fields()
    return Verdict(
        passed=False, status=FAIL, severity=worst.severity, reason=worst.reason + extra,
        details=details, category=worst.category, technique=worst.technique, impact=worst.impact,
    )


class GuardedJudge:
    """The campaign's judge, plus the policy, as one ObservingJudge."""

    def __init__(self, inner: Any, policy: Policy) -> None:
        self.inner = inner
        self.policy = policy

    def judge(self, payload: str, observation: Observation) -> Verdict:
        base = observation_mod.judge(self.inner, payload, observation)
        return merge(base, self.policy.check(observation))


def build_judge(judge_spec: dict[str, Any] | None, policy: Policy | None = None) -> Any:
    """Construct the judge from a ``{plugin, config}`` spec (the default rule
    judge when none is given), wrapped with the policy when there is one."""
    spec = judge_spec or DEFAULT_JUDGE
    inner = registry.load("chaos_agents.judges", spec["plugin"], **spec.get("config", {}))
    return GuardedJudge(inner, policy) if policy else inner


def judge_for(campaign) -> Any:
    """The judge for a loaded ``Campaign`` (see ``build_judge``)."""
    spec = {"plugin": campaign.judge.plugin, "config": campaign.judge.config} if campaign.judge else None
    return build_judge(spec, campaign.policy)
