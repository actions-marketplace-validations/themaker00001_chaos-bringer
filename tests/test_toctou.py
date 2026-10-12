"""TOCTOU path-resolution race, simulated deterministically -- no real OS race needed."""

from chaos_agents.adapters.toctou import TocTouAdapter


def test_with_no_swap_the_write_lands_inside_the_workspace():
    obs = TocTouAdapter(swapped_target=None).observe("x")
    assert obs.tool_calls[0].result == "written"
    assert obs.raw["escaped_workspace"] is False


def test_vulnerable_by_default_a_swapped_symlink_redirects_the_write_outside_the_workspace():
    obs = TocTouAdapter().observe("x")   # default swapped_target="/etc/shadow"
    assert obs.tool_calls[0].name == "write_file"
    assert obs.tool_calls[0].arguments["path"] == "/etc/shadow"
    assert obs.tool_calls[0].result == "written"   # the bug: it actually wrote there
    assert obs.raw["escaped_workspace"] is True


def test_bind_check_to_write_refuses_the_swapped_target():
    obs = TocTouAdapter(bind_check_to_write=True).observe("x")
    assert obs.tool_calls[0].result.startswith("refused")
    assert obs.raw["escaped_workspace"] is True   # still detected as having escaped -- just refused


def test_bind_check_to_write_still_allows_an_unswapped_write():
    obs = TocTouAdapter(bind_check_to_write=True, swapped_target=None).observe("x")
    assert obs.tool_calls[0].result == "written"


def test_invoke_returns_just_the_reply():
    assert TocTouAdapter().invoke("x").startswith("Wrote the fixture to")


def test_repr_shows_the_fix_state():
    assert "bind_check_to_write=False" in repr(TocTouAdapter())
    assert "bind_check_to_write=True" in repr(TocTouAdapter(bind_check_to_write=True))


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "toctou" in registry.available("chaos_agents.adapters")


def test_the_campaign_is_a_finding_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_toctou.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert len(records) == 1 and records[0].status == FAIL


def test_the_campaign_passes_once_bind_check_to_write_is_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import PASS
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_toctou.yaml")
    campaign.adapter.config["bind_check_to_write"] = True
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert records[0].status == PASS
