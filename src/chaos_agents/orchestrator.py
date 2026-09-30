"""Wires the four plugin surfaces together and runs one campaign.

Single-shot by default: the vector yields payloads, each is sent to the
target, each reply is judged. When the vector attacks over several turns
(offers `conversations()`) and the target can hold a conversation (offers
`converse()`), the campaign runs multi-turn instead -- each conversation is
one trial, a finding if any reply along the way breaks the policy.
"""

from __future__ import annotations

from typing import Callable

from chaos_agents import registry
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus, Record

OnStep = Callable[[str], None]
OnResult = Callable[[Record], None]


def _error_record(payload: str, exc: Exception) -> Record:
    return Record(
        payload=payload,
        response="",
        passed=False,
        severity="medium",
        reason=f"target failed: {type(exc).__name__}: {exc}",
        details={"error": type(exc).__name__, "message": str(exc)},
    )


def _verdict_record(payload: str, response, verdict) -> Record:
    return Record(
        payload=payload,
        response=response,
        passed=verdict.passed,
        severity=verdict.severity,
        reason=verdict.reason,
        details=verdict.details,
    )


def _is_multiturn(vector, adapter) -> bool:
    return callable(getattr(vector, "conversations", None)) and callable(getattr(adapter, "converse", None))


def _run_single(vector, adapter, judge, on_step, on_result, sink) -> None:
    for payload in vector.generate():
        if on_step:
            on_step(payload)
        try:
            response = adapter.invoke(payload)
        except Exception as exc:  # noqa: BLE001 -- a failing target is a result, not a reason to stop
            record = _error_record(payload, exc)
        else:
            record = _verdict_record(payload, response, judge.evaluate(payload, response))
        sink(record)


def _run_multiturn(vector, adapter, judge, on_step, on_result, sink) -> None:
    for turns in vector.conversations():
        if on_step:
            on_step(turns[-1])  # name the conversation by the turn that carries the ask
        try:
            replies = adapter.converse(turns)
        except Exception as exc:  # noqa: BLE001
            sink(_error_record(" | ".join(turns), exc))
            continue

        transcript = [{"turn": t, "reply": r} for t, r in zip(turns, replies)]
        # a conversation fails the moment any reply along the way breaks the policy
        breach = next(
            ((t, r, v) for t, r in zip(turns, replies) for v in [judge.evaluate(t, r)] if not v.passed),
            None,
        )
        if breach:
            turn, reply, verdict = breach
            record = _verdict_record(turn, reply, verdict)
        else:
            last_v = judge.evaluate(turns[-1], replies[-1])
            record = _verdict_record(turns[-1], replies[-1], last_v)
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

    records: list[Record] = []

    def sink(record: Record) -> None:
        corpus.record(record)
        records.append(record)
        if on_result:
            on_result(record)

    run = _run_multiturn if _is_multiturn(vector, adapter) else _run_single
    run(vector, adapter, judge, on_step, on_result, sink)
    return records
