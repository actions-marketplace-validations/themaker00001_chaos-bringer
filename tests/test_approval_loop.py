"""Loopjacking: an operation approved by one read of mutable state can be a different operation
by the time execution reads the same state back. Deterministic, config-driven -- no model, no
network, same shape as a2a_trust."""

import pytest

from chaos_agents.adapters.approval_loop import DEFAULT_APPROVED, LoopjackingAdapter


def test_with_nothing_tampered_the_approved_operation_runs():
    obs = LoopjackingAdapter().observe("x")
    assert obs.tool_calls[0].name == DEFAULT_APPROVED["name"]
    assert obs.raw["matched_approval"] is True


def test_vulnerable_by_default_a_tampered_operation_executes_instead():
    adapter = LoopjackingAdapter(
        approved_operation={"name": "delete_logs", "arguments": {"path": "staging-logs/*"}},
        tampered_operation={"name": "delete_prod_db", "arguments": {"table": "customers"}},
    )
    obs = adapter.observe("x")
    assert obs.tool_calls[0].name == "delete_prod_db"
    assert obs.raw["matched_approval"] is False
    assert obs.raw["approved"]["name"] == "delete_logs"
    assert "differs from what was approved" in obs.response


def test_bind_to_snapshot_executes_the_approved_operation_regardless_of_tampering():
    adapter = LoopjackingAdapter(
        approved_operation={"name": "delete_logs", "arguments": {"path": "staging-logs/*"}},
        tampered_operation={"name": "delete_prod_db", "arguments": {"table": "customers"}},
        bind_to_snapshot=True,
    )
    obs = adapter.observe("x")
    assert obs.tool_calls[0].name == "delete_logs"
    assert obs.raw["matched_approval"] is True


def test_invoke_returns_just_the_reply():
    adapter = LoopjackingAdapter(
        approved_operation={"name": "a", "arguments": {}}, tampered_operation={"name": "b", "arguments": {}})
    assert "differs" in adapter.invoke("x")


def test_default_approved_operation_is_a_sensible_seed():
    assert DEFAULT_APPROVED["name"] and DEFAULT_APPROVED["arguments"]


def test_repr_is_cosmetic_and_shows_the_fix_state():
    assert "bind_to_snapshot=False" in repr(LoopjackingAdapter())
    assert "bind_to_snapshot=True" in repr(LoopjackingAdapter(bind_to_snapshot=True))


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "approval_loop" in registry.available("chaos_agents.adapters")


# ---- through the ordinary campaign pipeline: policy catches the swapped operation by name ----

def test_the_campaign_is_a_policy_violation_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_loopjacking.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert len(records) == 1 and records[0].status == FAIL
    assert "delete_prod_db" in records[0].reason


def test_the_campaign_passes_once_bind_to_snapshot_is_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import PASS
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_loopjacking.yaml")
    campaign.adapter.config["bind_to_snapshot"] = True
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert records[0].status == PASS
