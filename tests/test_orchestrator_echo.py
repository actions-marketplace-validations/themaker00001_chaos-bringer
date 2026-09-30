from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus
from chaos_agents.orchestrator import run_campaign


def test_demo_echo_campaign_catches_the_injection(tmp_path):
    campaign = Campaign.from_yaml("campaigns/demo_echo.yaml")
    corpus = Corpus(campaign.name, root=tmp_path)

    records = run_campaign(campaign, corpus)

    assert len(records) == 5
    assert all(not r.passed for r in records), "every built-in payload should defeat the naive echo target"
    assert all(r.severity == "high" for r in records)
    assert corpus.read_all() == records
