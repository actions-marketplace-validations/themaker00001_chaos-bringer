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


class _FlakyAdapter:
    """Fails on every other payload, like a target that times out now and then."""

    def __init__(self):
        self.calls = 0

    def invoke(self, payload):
        self.calls += 1
        if self.calls % 2 == 0:
            raise TimeoutError("target took too long")
        return "I can't help with that."


def test_a_failing_target_is_recorded_as_a_finding_and_the_campaign_goes_on(tmp_path, monkeypatch):
    from chaos_agents import registry

    real_load = registry.load

    def load(group, name, **config):
        if group == "chaos_agents.adapters":
            return _FlakyAdapter()
        return real_load(group, name, **config)

    monkeypatch.setattr(registry, "load", load)
    campaign = Campaign.from_yaml("campaigns/demo_echo.yaml")
    corpus = Corpus(campaign.name, root=tmp_path)
    seen = []

    records = run_campaign(campaign, corpus, on_result=seen.append)

    assert len(records) == 5, "every payload still ran"
    errors = [r for r in records if r.reason.startswith("target failed")]
    assert len(errors) == 2
    assert all(not r.passed and r.severity == "medium" for r in errors)
    assert errors[0].details == {"error": "TimeoutError", "message": "target took too long"}
    assert seen == records  # the live display hears about errors too
    assert corpus.read_all() == records


def test_on_step_and_on_result_hooks_fire_once_per_payload(tmp_path):
    campaign = Campaign.from_yaml("campaigns/demo_echo.yaml")
    corpus = Corpus(campaign.name, root=tmp_path)

    steps: list[str] = []
    results: list[bool] = []

    records = run_campaign(
        campaign,
        corpus,
        on_step=steps.append,
        on_result=lambda r: results.append(r.passed),
    )

    assert steps == [r.payload for r in records]
    assert results == [r.passed for r in records]
