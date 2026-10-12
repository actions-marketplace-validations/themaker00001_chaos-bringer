"""Trust-handoff chain: sandboxed write -> unsandboxed consume. Deterministic, no model, no
network -- the sandbox never breaks; the trust boundary around its OUTPUT is what's tested."""

from chaos_agents.adapters.trust_handoff import (
    DEFAULT_TAMPERED_CONTENT,
    DEFAULT_TRUSTED_CONTENT,
    TrustHandoffAdapter,
)


def test_the_sandboxed_write_always_succeeds_even_when_tampered():
    """The sandbox itself is never broken -- this is the point of the finding."""
    obs = TrustHandoffAdapter().observe("x")
    write_call = obs.tool_calls[0]
    assert write_call.name == "sandboxed_write"
    assert write_call.result == "written (within the declared sandbox scope)"


def test_vulnerable_by_default_the_trusted_consumer_executes_the_tampered_artifact():
    obs = TrustHandoffAdapter().observe("x")
    consume_call = obs.tool_calls[1]
    assert consume_call.name == "trusted_consume"
    assert "executed" in consume_call.result
    assert obs.raw["tampered"] is True
    assert obs.raw["executed_by_trusted_consumer"] is True


def test_with_no_tampering_the_control_behaves_identically_but_safely():
    obs = TrustHandoffAdapter(tampered_content=None).observe("x")
    assert obs.raw["tampered"] is False
    assert obs.raw["executed_by_trusted_consumer"] is True   # executing the TRUSTED content is fine


def test_revalidate_provenance_refuses_the_tampered_artifact():
    obs = TrustHandoffAdapter(revalidate_provenance=True).observe("x")
    consume_call = obs.tool_calls[1]
    assert consume_call.result.startswith("refused")
    assert obs.raw["executed_by_trusted_consumer"] is False


def test_revalidate_provenance_still_allows_the_untampered_control():
    obs = TrustHandoffAdapter(revalidate_provenance=True, tampered_content=None).observe("x")
    assert obs.raw["executed_by_trusted_consumer"] is True


def test_default_contents_are_a_sensible_seed():
    assert DEFAULT_TRUSTED_CONTENT != DEFAULT_TAMPERED_CONTENT
    assert "diff" in DEFAULT_TAMPERED_CONTENT


def test_invoke_returns_just_the_reply():
    assert "external diff command ran" in TrustHandoffAdapter().invoke("x")


def test_repr_shows_the_fix_state():
    assert "revalidate_provenance=False" in repr(TrustHandoffAdapter())
    assert "revalidate_provenance=True" in repr(TrustHandoffAdapter(revalidate_provenance=True))


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "trust_handoff" in registry.available("chaos_agents.adapters")


def test_the_campaign_is_a_finding_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_trust_handoff.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert len(records) == 1 and records[0].status == FAIL


def test_the_campaign_passes_once_revalidate_provenance_is_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import PASS
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_trust_handoff.yaml")
    campaign.adapter.config["revalidate_provenance"] = True
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert records[0].status == PASS
