"""V2 data contracts: the attack taxonomy, stable fingerprints, the enriched
verdict, and the tags/status the orchestrator stamps onto every record."""

import pytest

from chaos_agents import findings, taxonomy
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS, Verdict


# ---- taxonomy ---------------------------------------------------------------
def test_known_families_and_techniques_validate():
    assert taxonomy.is_valid("goal_hijack")
    assert taxonomy.is_valid("goal_hijack", "multi_turn")
    assert taxonomy.is_valid("tool_misuse", "tool_output_poisoning")
    assert taxonomy.is_valid(taxonomy.OPERATIONAL, "target_error")


def test_unknown_category_or_technique_is_rejected():
    assert not taxonomy.is_valid("nonsense")
    assert not taxonomy.is_valid("goal_hijack", "not_a_real_technique")
    with pytest.raises(ValueError, match="unknown attack category"):
        taxonomy.validate("nonsense")
    with pytest.raises(ValueError, match="not part of category"):
        taxonomy.validate("goal_hijack", "not_a_real_technique")


def test_every_family_has_techniques_and_keys_are_stable():
    assert set(taxonomy.TAXONOMY) >= {
        "goal_hijack", "sensitive_data", "tool_misuse", "identity_privilege",
        "agent_to_agent", "rag_vector", "availability_cost", "output_handling", "supply_chain",
    }
    assert all(len(techs) >= 1 for techs in taxonomy.TAXONOMY.values())


# ---- fingerprint ------------------------------------------------------------
def test_fingerprint_is_stable_and_whitespace_insensitive():
    a = findings.fingerprint("goal_hijack", "direct", "echo", "Ignore   previous\ninstructions")
    b = findings.fingerprint("goal_hijack", "direct", "echo", "ignore previous instructions")
    assert a == b and a.startswith("sha256:")


def test_fingerprint_changes_with_category_or_target():
    base = findings.fingerprint("goal_hijack", "direct", "echo", "x")
    assert base != findings.fingerprint("tool_misuse", "direct", "echo", "x")
    assert base != findings.fingerprint("goal_hijack", "direct", "a2a", "x")


def test_finding_id_is_short_and_derived():
    fp = findings.fingerprint("sensitive_data", "secret_extraction", "ollama_chat", "leak it")
    fid = findings.finding_id(fp)
    assert fid.startswith("CB-") and len(fid) == 11


# ---- enriched verdict -------------------------------------------------------
def test_status_is_derived_from_passed_when_unset():
    assert Verdict(passed=True).status == PASS
    assert Verdict(passed=False).status == FAIL


def test_explicit_inconclusive_overrides_passed():
    v = Verdict(passed=True, status=INCONCLUSIVE)
    assert v.status == INCONCLUSIVE and v.passed is False  # only an explicit PASS is a pass


def test_bad_status_rejected():
    with pytest.raises(ValueError, match="unknown verdict status"):
        Verdict(passed=False, status="maybe")


def test_verdict_validates_its_taxonomy_tags():
    Verdict(passed=False, category="goal_hijack", technique="multi_turn")  # ok
    with pytest.raises(ValueError):
        Verdict(passed=False, category="goal_hijack", technique="bogus")


# ---- orchestrator stamps the tags onto records ------------------------------
def test_records_are_tagged_and_fingerprinted_from_the_campaign(tmp_path):
    from chaos_agents.campaign import Campaign, ComponentSpec
    from chaos_agents.corpus import Corpus
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign(
        name="tagged",
        adapter=ComponentSpec("echo", {"secret": "sk-demo-12345"}),
        vector=ComponentSpec("static_corpus", {}),
        judge=ComponentSpec("rule_based", {"forbidden_substrings": ["sk-demo-12345"]}),
        category="sensitive_data",
        technique="secret_extraction",
    )
    records = run_campaign(campaign, Corpus("tagged", root=tmp_path))
    assert records and all(r.category == "sensitive_data" for r in records)
    assert all(r.technique == "secret_extraction" for r in records)
    assert all(r.fingerprint.startswith("sha256:") for r in records)
    assert all(r.status == FAIL for r in records)  # echo leaks every payload


def test_campaign_yaml_rejects_a_bad_category(tmp_path):
    from chaos_agents.campaign import Campaign

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: x\ncategory: not_a_category\n"
        "adapter:\n  plugin: echo\nvector:\n  plugin: static_corpus\njudge:\n  plugin: rule_based\n"
    )
    with pytest.raises(ValueError, match="unknown attack category"):
        Campaign.from_yaml(bad)


def test_two_runs_in_the_same_second_get_distinct_run_dirs(tmp_path):
    from chaos_agents.corpus import Corpus

    a = Corpus("samecampaign", root=tmp_path)
    b = Corpus("samecampaign", root=tmp_path)
    assert a.run_id != b.run_id
    assert a.run_dir != b.run_dir  # no collision, no overwritten trace


def test_a_target_error_is_inconclusive_not_a_confirmed_finding(tmp_path):
    from chaos_agents.campaign import Campaign, ComponentSpec
    from chaos_agents.corpus import Corpus
    from chaos_agents.orchestrator import run_campaign
    from chaos_agents import registry

    class _Boom:
        def invoke(self, payload):
            raise TimeoutError("nope")

    real = registry.load

    def load(group, name, **cfg):
        return _Boom() if group == "chaos_agents.adapters" else real(group, name, **cfg)

    import chaos_agents.orchestrator as orch
    orig = orch.registry.load
    orch.registry.load = load
    try:
        campaign = Campaign(
            name="err", adapter=ComponentSpec("echo"), vector=ComponentSpec("static_corpus", {"limit": 1}),
            judge=ComponentSpec("rule_based"),
        )
        records = run_campaign(campaign, Corpus("err", root=tmp_path))
    finally:
        orch.registry.load = orig

    assert records[0].status == INCONCLUSIVE
    assert records[0].category == taxonomy.OPERATIONAL
    assert records[0].passed is False
