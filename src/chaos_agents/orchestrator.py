"""Wires the four plugin surfaces together and runs one campaign.

Single-shot by default: the vector yields payloads, each is sent to the
target, each reply is judged. When the vector attacks over several turns
(offers `conversations()`) and the target can hold a conversation (offers
`converse()`), the campaign runs multi-turn instead -- each conversation is
one trial, a finding if any reply along the way breaks the policy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from chaos_agents import adaptive, findings, guard, memory, observation, registry, runstore, standards, taxonomy
from chaos_agents.campaign import Campaign, CampaignError
from chaos_agents.corpus import Corpus, Record
from chaos_agents.interfaces import FAIL, INCONCLUSIVE
from chaos_agents.observation import Observation

OnStep = Callable[[str], None]
OnResult = Callable[[Record], None]


@dataclass
class _Context:
    """What the record builders need to tag and fingerprint a trial:
    the target's name and the campaign's default taxonomy tags."""

    target: str
    category: str
    technique: str
    vector: str = ""


def _fp(record: Record, ctx: _Context) -> str:
    return findings.fingerprint(record.category, record.technique, ctx.target, record.payload)


def _error_record(payload: str, exc: Exception, ctx: _Context) -> Record:
    # a target or judge that errors is NOT a confirmed security finding --
    # it's operational and inconclusive, so it never masquerades as a pass or a fail
    record = Record(
        payload=payload,
        response="",
        passed=False,
        severity="medium",
        reason=f"target failed: {type(exc).__name__}: {exc}",
        details={"error": type(exc).__name__, "message": str(exc)},
        status=INCONCLUSIVE,
        confidence=1.0,
        category=taxonomy.OPERATIONAL,
        technique="target_error",
        target=ctx.target,
        vector=ctx.vector,
    )
    record.fingerprint = _fp(record, ctx)
    return record


def _verdict_record(payload: str, response, verdict, ctx: _Context, obs: Observation | None = None,
                    tags: tuple[str, str] | None = None) -> Record:
    # the judge may classify the trial itself; otherwise use the campaign's tags.
    # `tags` overrides both: a memory finding is filed as memory poisoning, with
    # what the poisoned memory made the agent do kept in details["underlying"]
    category = verdict.category or ctx.category
    technique = verdict.technique or ctx.technique
    details = verdict.details
    if tags:
        if category or technique:
            details = {**details, "underlying": {"category": category, "technique": technique}}
        category, technique = tags
    record = Record(
        payload=payload,
        response=response,
        passed=verdict.passed,
        severity=verdict.severity,
        reason=verdict.reason,
        details=details,
        status=verdict.status,
        confidence=verdict.confidence,
        category=category,
        technique=technique,
        impact=verdict.impact,
        target=ctx.target,
        vector=ctx.vector,
    )
    record.details = details
    # a judge or guard that traced the compromise (capability, sink, route) says so
    # in details["finding"]; lift it onto the record's typed fields
    for key, value in (verdict.details.get("finding") or {}).items():
        if hasattr(record, key) and value:
            setattr(record, key, value)
    if record.status == FAIL:  # file a confirmed finding under the frameworks it belongs to
        record.owasp = standards.owasp_for(category, technique)
        record.mitre_atlas = standards.atlas_for(category, technique)
    if obs is not None:  # carry the Observation stage into the corpus
        record.tool_calls = obs.tool_calls_as_dicts()
        record.latency_ms = round(obs.latency_ms, 3)
    record.fingerprint = _fp(record, ctx)
    return record


def _memory_record(outcome: memory.Outcome, ctx: _Context) -> Record:
    """A cross-session trial as a Record: the poison is the payload, the
    victim's reply is the response, and a finding is filed as memory poisoning."""
    scenario = outcome.scenario
    if outcome.status == INCONCLUSIVE and outcome.control_verdict.status != "pass":
        record = Record(
            payload=scenario.poison, response=outcome.trigger.response, passed=False, severity="medium",
            reason=outcome.reason, details={}, status=INCONCLUSIVE, category=taxonomy.OPERATIONAL,
            technique="control_failed", target=ctx.target, vector=ctx.vector,
        )
        record.fingerprint = _fp(record, ctx)
    else:
        tags = (memory.CATEGORY, scenario.technique) if outcome.status == FAIL else None
        record = _verdict_record(scenario.poison, outcome.trigger.response, outcome.verdict, ctx,
                                 obs=outcome.trigger, tags=tags)
        if outcome.status == FAIL:
            record.attack_path = memory.route(record.attack_path)
            record.reason = f"MEMORY POISONING ({scenario.technique}): {record.reason}"
            record.impact = record.impact or "a poisoned memory made the agent act against policy in another session"
    record.details = {**record.details, "memory": outcome.describe()}
    return record


def _run_memory(vector, adapter, judge, ctx, on_step, on_result, sink) -> None:
    for scenario in vector.scenarios():
        if on_step:
            on_step(scenario.poison)
        try:
            outcome = memory.run_scenario(adapter, judge, scenario)
        except Exception as exc:  # noqa: BLE001 -- a target that dies mid-scenario is inconclusive
            sink(_error_record(scenario.poison, exc, ctx))
            continue
        sink(_memory_record(outcome, ctx))


def _is_memory(vector) -> bool:
    return callable(getattr(vector, "scenarios", None))


def _is_adaptive(vector) -> bool:
    return callable(getattr(vector, "propose", None)) and callable(getattr(vector, "feedback", None))


def _run_adaptive(vector, adapter, judge, ctx, on_step, on_result, sink) -> None:
    """Generate -> run -> analyze -> pick the next path (see `chaos_agents.adaptive`).
    Unlike every other vector, this one sees the outcome of each attempt before
    deciding the next one, so the loop lives here instead of just iterating a
    precomputed list."""
    while True:
        candidate = vector.propose()
        if candidate is None:
            break
        if on_step:
            on_step(candidate.poison)
        try:
            outcome = memory.run_scenario(adapter, judge, candidate.scenario())
        except Exception as exc:  # noqa: BLE001 -- a target error is inconclusive; the search keeps going
            sink(_error_record(candidate.poison, exc, ctx))
            vector.feedback(INCONCLUSIVE)
            continue
        record = _memory_record(outcome, ctx)
        record.details = {**record.details, "candidate": candidate.to_dict()}
        sink(record)
        vector.feedback(outcome.status)


def _is_multiturn(vector, adapter) -> bool:
    return callable(getattr(vector, "conversations", None)) and callable(getattr(adapter, "converse", None))


def _run_single(vector, adapter, judge, ctx, on_step, on_result, sink) -> None:
    for payload in vector.generate():
        if on_step:
            on_step(payload)
        try:
            # Attack -> Agent -> Observation -> Judge: the judge rules on what
            # the agent did (reply + tool calls), not just the reply text.
            obs = observation.observe(adapter, payload)
            verdict = observation.judge(judge, payload, obs)
        except Exception as exc:  # noqa: BLE001 -- a failing target is a result, not a reason to stop
            record = _error_record(payload, exc, ctx)
        else:
            record = _verdict_record(payload, obs.response, verdict, ctx, obs=obs)
        sink(record)


def _run_multiturn(vector, adapter, judge, ctx, on_step, on_result, sink) -> None:
    for turns in vector.conversations():
        if on_step:
            on_step(turns[-1])  # name the conversation by the turn that carries the ask
        try:
            # a target may answer with plain replies or full Observations; with the latter the
            # judge and policy see every turn's tool calls, not just what the agent said
            observations = [Observation.of(r) for r in adapter.converse(turns)]
        except Exception as exc:  # noqa: BLE001
            sink(_error_record(" | ".join(turns), exc, ctx))
            continue

        transcript = [{"turn": t, "reply": o.response} for t, o in zip(turns, observations)]
        # a conversation fails the moment any turn breaks the policy
        breach = next(
            ((t, o, v) for t, o in zip(turns, observations)
             for v in [observation.judge(judge, t, o)] if not v.passed),
            None,
        )
        if breach:
            turn, obs, verdict = breach
        else:
            turn, obs = turns[-1], observations[-1]
            verdict = observation.judge(judge, turn, obs)
        record = _verdict_record(turn, obs.response, verdict, ctx, obs=obs if obs.tool_calls else None)
        record.details = {**record.details, "turns": len(turns), "transcript": transcript}
        sink(record)


def run_campaign(
    campaign: Campaign,
    corpus: Corpus,
    on_step: OnStep | None = None,
    on_result: OnResult | None = None,
) -> list[Record]:
    """Run the campaign and return every trial's record.

    `on_step`/`on_result` are optional hooks for a caller that wants to show
    live progress (e.g. the CLI's --fancy display) -- this module stays
    unaware of any UI concern.
    """
    adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
    vector = registry.load("chaos_agents.vectors", campaign.vector.plugin, **campaign.vector.config)
    judge = guard.judge_for(campaign)  # the campaign's judge, with its policy folded in

    ctx = _Context(target=campaign.adapter.plugin, category=campaign.category, technique=campaign.technique,
                   vector=campaign.vector.plugin)
    records: list[Record] = []
    runstore.write_snapshot(corpus.run_dir, campaign)   # so a finding can be rebuilt (promote, replay)

    def sink(record: Record) -> None:
        corpus.record(record)
        records.append(record)
        if on_result:
            on_result(record)

    # fail loudly: running a memory-poisoning vector (adaptive or not) against a
    # target with no memory would "pass" every time and prove nothing
    if _is_adaptive(vector) or _is_memory(vector):
        if not memory.supports_memory(adapter):
            raise CampaignError(
                f"vector {campaign.vector.plugin!r} tests memory poisoning, but adapter "
                f"{campaign.adapter.plugin!r} has no persistent memory "
                f"(it needs reset_memory() and observe_in_session(payload, session))")
        run = _run_adaptive if _is_adaptive(vector) else _run_memory
    else:
        run = _run_multiturn if _is_multiturn(vector, adapter) else _run_single
    run(vector, adapter, judge, ctx, on_step, on_result, sink)
    if hasattr(vector, "summary"):   # the adaptive search's own report: what it tried and why
        (corpus.run_dir / "adaptive_search.json").write_text(json.dumps(vector.summary(), indent=2))
    return records
