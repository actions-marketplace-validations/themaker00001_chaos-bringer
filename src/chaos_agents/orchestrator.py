"""Wires the four plugin surfaces together and runs one campaign."""

from __future__ import annotations

from typing import Callable

from chaos_agents import registry
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus, Record


def run_campaign(
    campaign: Campaign,
    corpus: Corpus,
    on_step: Callable[[str], None] | None = None,
    on_result: Callable[[Record], None] | None = None,
) -> list[Record]:
    """Run every payload the vector produces against the target, in order.

    `on_step`/`on_result` are optional hooks for a caller that wants to show
    live progress (e.g. the CLI's --fancy display) -- this module stays
    unaware of any UI concern.
    """
    adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
    vector = registry.load("chaos_agents.vectors", campaign.vector.plugin, **campaign.vector.config)
    judge = registry.load("chaos_agents.judges", campaign.judge.plugin, **campaign.judge.config)

    records: list[Record] = []
    for payload in vector.generate():
        if on_step:
            on_step(payload)
        response = adapter.invoke(payload)
        verdict = judge.evaluate(payload, response)
        record = Record(
            payload=payload,
            response=response,
            passed=verdict.passed,
            severity=verdict.severity,
            reason=verdict.reason,
            details=verdict.details,
        )
        corpus.record(record)
        records.append(record)
        if on_result:
            on_result(record)
    return records
