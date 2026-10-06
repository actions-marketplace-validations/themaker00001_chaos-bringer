import json
import re

import pytest

from chaos_agents import export, report, standards, taxonomy
from chaos_agents.campaign import Campaign
from chaos_agents.cli import main
from chaos_agents.corpus import Corpus, Record
from chaos_agents.orchestrator import run_campaign


def run(tmp_path, campaign_file):
    campaign = Campaign.from_yaml(campaign_file)
    return campaign, run_campaign(campaign, Corpus(campaign.name, root=tmp_path))


# ---- the table itself ------------------------------------------------------

def test_every_taxonomy_technique_has_a_mapping_and_none_is_stale():
    pairs = {(c, t) for c, techs in taxonomy.TAXONOMY.items() for t in techs}
    assert pairs == set(standards._MAP), "add/remove the standards entry when the taxonomy changes"


def test_every_referenced_id_exists_in_its_framework():
    for owasp, atlas in standards._MAP.values():
        assert set(owasp) <= set(standards.OWASP)
        assert set(atlas) <= set(standards.ATLAS)


def test_owasp_ids_are_exactly_the_agentic_top_ten():
    assert list(standards.OWASP) == [f"ASI{i:02d}" for i in range(1, 11)]
    assert standards.OWASP["ASI01"] == "Agent Goal Hijack" and standards.OWASP["ASI06"] == "Memory & Context Poisoning"


def test_atlas_ids_are_well_formed_and_never_include_an_unverified_one():
    assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", i) for i in standards.ATLAS)
    # looked up and not confirmed against the published matrix -- must stay out
    assert not {"AML.T0073", "AML.T0085", "AML.T0077"} & set(standards.ATLAS)


def test_a_framework_entry_that_nothing_maps_to_is_dead_weight():
    used_atlas = {i for _, atlas in standards._MAP.values() for i in atlas}
    assert set(standards.ATLAS) == used_atlas


@pytest.mark.parametrize("category, technique, owasp, atlas", [
    ("identity_privilege", "privilege_escalation", ["ASI03"], ["AML.T0053"]),
    ("sensitive_data", "tool_exfiltration", ["ASI01", "ASI02"], ["AML.T0086", "AML.T0057"]),
    ("goal_hijack", "indirect", ["ASI01"], ["AML.T0051.001"]),
    ("rag_vector", "poisoned_document", ["ASI06"], ["AML.T0070", "AML.T0051.001"]),
    ("agent_to_agent", "malicious_peer", ["ASI07"], []),
    ("supply_chain", "malicious_tool_metadata", ["ASI04"], ["AML.T0010"]),
])
def test_known_mappings(category, technique, owasp, atlas):
    assert standards.owasp_for(category, technique) == owasp
    assert standards.atlas_for(category, technique) == atlas


def test_unknown_or_operational_findings_map_to_nothing():
    assert standards.owasp_for("operational", "target_error") == []
    assert standards.atlas_for("", "") == []
    assert standards.owasp_for("made_up", "made_up") == []


def test_callers_cannot_mutate_the_table():
    standards.owasp_for("goal_hijack", "direct").append("ASI99")
    assert standards.owasp_for("goal_hijack", "direct") == ["ASI01"]


def test_label_and_summary():
    assert standards.label("ASI03") == "ASI03 Identity & Privilege Abuse"
    assert standards.label("AML.T0086") == "AML.T0086 Exfiltration via AI Agent Tool Invocation"
    assert standards.label("ASI99") == "ASI99"
    rec = Record("p", "r", False, "high", "x", {}, status="fail",
                 category="sensitive_data", technique="tool_exfiltration")
    assert standards.summary(rec) == "OWASP ASI01, ASI02 · ATLAS AML.T0086, AML.T0057"
    assert standards.summary(Record("p", "r", False, "high", "x", {}, category="agent_to_agent",
                                    technique="malicious_peer")) == "OWASP ASI07"


def test_an_older_trace_without_tags_is_mapped_on_read_but_stamped_tags_win():
    old = Record("p", "r", False, "high", "x", {}, status="fail", category="goal_hijack", technique="direct")
    assert standards.tags_for(old) == (["ASI01"], ["AML.T0051.000"])
    stamped = Record("p", "r", False, "high", "x", {}, status="fail", category="goal_hijack",
                     technique="direct", owasp=["ASI10"], mitre_atlas=["AML.T0054"])
    assert standards.tags_for(stamped) == (["ASI10"], ["AML.T0054"])


# ---- stamped onto findings -------------------------------------------------

def test_confirmed_findings_are_stamped_and_held_trials_are_not(tmp_path):
    _, records = run(tmp_path, "campaigns/demo_policy.yaml")
    failed = [r for r in records if not r.passed]
    assert failed and all(r.owasp and r.mitre_atlas for r in failed)
    priv = next(r for r in failed if r.reason.startswith("PRIVILEGE"))
    assert priv.owasp == ["ASI03"] and priv.mitre_atlas == ["AML.T0053"]
    assert all(not r.owasp and not r.mitre_atlas for r in records if r.passed)


def test_the_tags_are_persisted_in_the_trace(tmp_path):
    campaign = Campaign.from_yaml("campaigns/demo_dataflow.yaml")
    corpus = Corpus(campaign.name, root=tmp_path)
    run_campaign(campaign, corpus)
    stored = corpus.read_all()
    assert any(r.owasp == ["ASI01", "ASI02"] and "AML.T0086" in r.mitre_atlas for r in stored)


def test_the_tags_do_not_change_a_findings_identity(tmp_path):
    _, a = run(tmp_path / "a", "campaigns/demo_policy.yaml")
    _, b = run(tmp_path / "b", "campaigns/demo_policy.yaml")
    assert [r.fingerprint for r in a] == [r.fingerprint for r in b]


def test_an_errored_target_is_not_filed_under_any_framework(tmp_path, monkeypatch):
    from chaos_agents import registry

    class Down:
        def invoke(self, payload):
            raise TimeoutError("nope")

    real = registry.load
    monkeypatch.setattr(registry, "load", lambda g, n, **c: Down() if g == "chaos_agents.adapters" else real(g, n, **c))
    _, records = run(tmp_path, "campaigns/demo_echo.yaml")
    assert records and all(not r.owasp and not r.mitre_atlas for r in records)


# ---- reports and exports ---------------------------------------------------

def test_the_report_shows_what_each_finding_maps_to(tmp_path):
    campaign, records = run(tmp_path, "campaigns/demo_policy.yaml")
    text = report.render(campaign.name, records)
    assert "    maps to:  OWASP ASI03 · ATLAS AML.T0053" in text
    assert text.count("maps to:") == 3


def test_json_carries_the_tags_on_findings_only(tmp_path):
    campaign, records = run(tmp_path, "campaigns/demo_policy.yaml")
    findings = json.loads(export.to_json(campaign.name, records))["findings"]
    bad = [f for f in findings if f["status"] == "fail"]
    assert all(f["owasp"] and f["mitre_atlas"] for f in bad)
    assert all("owasp" not in f and "mitre_atlas" not in f for f in findings if f["status"] == "pass")


def test_sarif_links_rules_to_both_frameworks(tmp_path):
    campaign, records = run(tmp_path, "campaigns/demo_dataflow.yaml")
    run0 = json.loads(export.to_sarif(campaign.name, records))["runs"][0]
    rule = next(r for r in run0["tool"]["driver"]["rules"] if r["id"] == "sensitive_data/tool_exfiltration")
    assert rule["properties"]["tags"] == ["OWASP-Agentic:ASI01", "OWASP-Agentic:ASI02",
                                          "ATLAS:AML.T0086", "ATLAS:AML.T0057"]
    taxonomies = {t["name"]: {x["id"] for x in t["taxa"]} for t in run0["taxonomies"]}
    assert taxonomies[standards.OWASP_NAME] >= {"ASI01", "ASI02"}
    assert taxonomies[standards.ATLAS_NAME] >= {"AML.T0086", "AML.T0057"}
    # every relationship points at a taxon that is actually declared
    for r in run0["tool"]["driver"]["rules"]:
        for rel in r["relationships"]:
            assert rel["target"]["id"] in taxonomies[rel["target"]["toolComponent"]["name"]]


def test_sarif_omits_taxonomies_when_nothing_was_tagged():
    held = Record("p", "r", True, "info", "", {}, status="pass")
    run0 = json.loads(export.to_sarif("c", [held]))["runs"][0]
    assert "taxonomies" not in run0


def test_cli_sarif_end_to_end(tmp_path, capsys):
    main(["run", "campaigns/demo_policy.yaml", "--runs-dir", str(tmp_path), "--format", "sarif"])
    out = capsys.readouterr().out
    doc = json.loads(out[out.index("{"):])
    tags = {t for r in doc["runs"][0]["tool"]["driver"]["rules"] for t in r["properties"]["tags"]}
    assert "OWASP-Agentic:ASI03" in tags and "ATLAS:AML.T0053" in tags
