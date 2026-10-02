"""Wires the four plugin surfaces together and runs one campaign.

Single-shot by default: the vector yields payloads, each is sent to the
target, each reply is judged. When the vector attacks over several turns
(offers `conversations()`) and the target can hold a conversation (offers
`converse()`), the campaign runs multi-turn instead -- each conversation is
one trial, a finding if any reply along the way breaks the policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from chaos_agents import findings, observation, registry, taxonomy
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus, Record
from chaos_agents.interfaces import INCONCLUSIVE
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
    )
    record.fingerprint = _fp(record, ctx)
    return record


def _verdict_record(payload: str, response, verdict, ctx: _Context, obs: Observation | None = None) -> Record:
    # the judge may classify the trial itself; otherwise use the campaign's tags
    category = verdict.category or ctx.category
    technique = verdict.technique or ctx.technique
    record = Record(
        payload=payload,
        response=response,
        passed=verdict.passed,
        severity=verdict.severity,
        reason=verdict.reason,
        details=verdict.details,
        status=verdict.status,
        confidence=verdict.confidence,
        category=category,
        technique=technique,
        impact=verdict.impact,
    )
    if obs is not None:  # carry the Observation stage into the corpus
        record.tool_calls = obs.tool_calls_as_dicts()
        record.latency_ms = round(obs.latency_ms, 3)
    record.fingerprint = _fp(record, ctx)
    return record


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
            replies = adapter.converse(turns)
        except Exception as exc:  # noqa: BLE001
            sink(_error_record(" | ".join(turns), exc, ctx))
            continue

        transcript = [{"turn": t, "reply": r} for t, r in zip(turns, replies)]
        # a conversation fails the moment any reply along the way breaks the policy
        breach = next(
            ((t, r, v) for t, r in zip(turns, replies)
             for v in [observation.judge(judge, t, Observation.of(r))] if not v.passed),
            None,
        )
        if breach:
            turn, reply, verdict = breach
            record = _verdict_record(turn, reply, verdict, ctx)
        else:
            last_v = observation.judge(judge, turns[-1], Observation.of(replies[-1]))
            record = _verdict_record(turns[-1], replies[-1], last_v, ctx)
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
    judge = registry.load("chaos_agents.judges", campaign.judge.plugin, **campaign.judge.config)

    ctx = _Context(target=campaign.adapter.plugin, category=campaign.category, technique=campaign.technique)
    records: list[Record] = []

    def sink(record: Record) -> None:
        corpus.record(record)
        records.append(record)
        if on_result:
            on_result(record)

    run = _run_multiturn if _is_multiturn(vector, adapter) else _run_single
    run(vector, adapter, judge, ctx, on_step, on_result, sink)
    return records
