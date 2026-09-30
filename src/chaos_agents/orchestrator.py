"""Wires the four plugin surfaces together and runs one campaign."""

from __future__ import annotations

from chaos_agents import registry
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus, Record


def run_campaign(campaign: Campaign, corpus: Corpus) -> list[Record]:
    adapter = registry.load("chaos_agents.adapters", campaign.adapter.plugin, **campaign.adapter.config)
    vector = registry.load("chaos_agents.vectors", campaign.vector.plugin, **campaign.vector.config)
    judge = registry.load("chaos_agents.judges", campaign.judge.plugin, **campaign.judge.config)

    records: list[Record] = []
    for payload in vector.generate():
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
    return records
