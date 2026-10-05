import pytest

from chaos_agents import attackgraph, report
from chaos_agents.attackgraph import Stage, chain, render_box, stages_of, to_mermaid
from chaos_agents.campaign import Campaign
from chaos_agents.cli import main
from chaos_agents.corpus import Corpus, Record
from chaos_agents.orchestrator import run_campaign


def labels(record) -> list[str]:
    return [s.label for s in stages_of(record)]


def failed(**fields) -> Record:
    base = dict(payload="p", response="r", passed=False, severity="high", reason="bad", details={},
                status="fail", fingerprint="sha256:ab12cd34ef56", vector="static_corpus", target="echo")
    base.update(fields)
    return Record(**base)


def run(tmp_path, campaign_file):
    campaign = Campaign.from_yaml(campaign_file)
    return run_campaign(campaign, Corpus(campaign.name, root=tmp_path))


def by_reason(records, prefix):
    return next(r for r in records if r.reason.startswith(prefix))


# ---- policy findings ------------------------------------------------------

def test_privilege_violation_chain(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_policy.yaml"), "PRIVILEGE")
    assert labels(rec) == ["DIRECT INJECTION", "AGENT GOAL HIJACK", "TOOL CALL", "PRIVILEGE VIOLATION",
                           "TARGET RESOURCE", "UNAUTHORIZED ACTION"]
    assert stages_of(rec)[2] == Stage("TOOL CALL", "database_write")
    assert stages_of(rec)[4] == Stage("TARGET RESOURCE", "production_db")


def test_approval_bypass_chain_ends_at_an_email_sink(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_policy.yaml"), "APPROVAL")
    assert labels(rec)[3:] == ["APPROVAL BYPASS", "EXTERNAL EMAIL SINK", "UNAPPROVED ACTION"]


def test_destination_violation_chain(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_policy.yaml"), "DESTINATION")
    assert labels(rec)[3:] == ["DESTINATION VIOLATION", "EXTERNAL HTTP SINK", "OFF-POLICY DATA TRANSFER"]


# ---- data-flow findings ---------------------------------------------------

def test_exfiltration_chain_includes_the_retrieval_and_the_secret(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_dataflow.yaml"), "CRITICAL DATA FLOW: canary CANARY-CHAOS-7F21 "
                    "(customer integration key) flowed into http_request.body and")
    assert labels(rec) == ["DIRECT INJECTION", "AGENT GOAL HIJACK", "RAG RETRIEVAL", "TOOL CALL",
                           "DESTINATION VIOLATION", "EXTERNAL HTTP SINK", "SECRET EXFILTRATION"]
    assert stages_of(rec)[2] == Stage("RAG RETRIEVAL", "search_docs")
    assert stages_of(rec)[-1] == Stage("SECRET EXFILTRATION", "CANARY-CHAOS-7F21")


def test_a_disclosure_in_the_reply_has_no_tool_or_sink(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_dataflow.yaml"), "DATA DISCLOSURE")
    assert labels(rec) == ["DIRECT INJECTION", "AGENT GOAL HIJACK", "RAG RETRIEVAL", "AGENT RESPONSE",
                           "SECRET DISCLOSURE"]


# ---- findings with no policy evidence -------------------------------------

def test_a_judge_only_leak_is_entry_hijack_outcome():
    rec = failed(category="sensitive_data", technique="secret_extraction")
    assert labels(rec) == ["DIRECT INJECTION", "AGENT GOAL HIJACK", "SECRET DISCLOSURE"]


def test_a_goal_hijack_finding_ends_at_the_hijack():
    assert labels(failed(category="goal_hijack", technique="direct")) == ["DIRECT INJECTION", "AGENT GOAL HIJACK"]


def test_availability_findings_do_not_claim_a_hijack():
    assert labels(failed(category="availability_cost", technique="loops")) == ["DIRECT INJECTION", "RESOURCE EXHAUSTION"]


@pytest.mark.parametrize("fields, entry", [
    ({"vector": "indirect"}, "INDIRECT INJECTION"),
    ({"vector": "multiturn"}, "MULTI-TURN INJECTION"),
    ({"vector": "mutation"}, "OBFUSCATED INJECTION"),
    ({"vector": "llm"}, "DIRECT INJECTION"),
    ({"vector": "something_new"}, "ATTACK PAYLOAD"),
    ({"vector": ""}, "ATTACK PAYLOAD"),
    ({"vector": "static_corpus", "technique": "poisoned_document", "category": "rag_vector"}, "POISONED DOCUMENT"),
    ({"vector": "static_corpus", "technique": "indirect", "category": "goal_hijack"}, "INDIRECT INJECTION"),
])
def test_the_entry_stage_names_how_the_attack_arrived(fields, entry):
    assert labels(failed(**fields))[0] == entry


def test_mcp_targets_get_the_mcp_tool_call_label(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_policy.yaml"), "PRIVILEGE")
    rec.target = "mcp_fault"
    assert "MCP TOOL CALL" in labels(rec) and "TOOL CALL" not in labels(rec)


def test_a_held_or_inconclusive_trial_has_no_graph():
    held = Record("p", "r", True, "info", "", {}, status="pass")
    unsure = failed(passed=False, status="inconclusive")
    for rec in (held, unsure):
        assert stages_of(rec) == [] and chain(rec) == "" and render_box(rec) == "" and to_mermaid(rec) == ""


# ---- renderings -----------------------------------------------------------

def test_chain_is_one_line_of_bracketed_stages():
    rec = failed(category="sensitive_data", technique="secret_extraction")
    assert chain(rec) == "[DIRECT INJECTION] → [AGENT GOAL HIJACK] → [SECRET DISCLOSURE]"


def test_the_box_graph_is_a_clean_rectangle_per_stage(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_dataflow.yaml"), "CRITICAL DATA FLOW")
    text = render_box(rec)
    lines = text.splitlines()
    assert lines[0].startswith("ATTACK GRAPH  CB-")
    box = [l for l in lines if l and l[0] in "╭│╰"]
    assert len({len(l) for l in box}) == 1, "every box row has the same width"
    assert sum(l.strip() == "▼" for l in lines) == len(stages_of(rec)) - 1
    assert sum(l.startswith("╭") for l in lines) == len(stages_of(rec))
    assert lines[-1].startswith("Severity: CRITICAL  ·  ")


def test_long_details_are_clipped_not_overflowed():
    rec = failed(category="sensitive_data", technique="secret_extraction", impact="x")
    rec.details = {"policy_violations": [{"kind": "denied_capability", "tool": "t", "sink": "h." + "a" * 200,
                                          "capability": "t", "rule": "r"}]}
    rec.sink, rec.capability = "h." + "a" * 200, "t"
    widths = {len(l) for l in render_box(rec).splitlines() if l and l[0] in "╭│╰"}
    assert len(widths) == 1 and max(widths) < 80


def test_mermaid_is_a_valid_looking_flowchart(tmp_path):
    rec = by_reason(run(tmp_path, "campaigns/demo_policy.yaml"), "PRIVILEGE")
    lines = to_mermaid(rec).splitlines()
    assert lines[0] == "flowchart TD"
    nodes = [l for l in lines if l.strip().startswith("S") and "[" in l]
    edges = [l for l in lines if "-->" in l]
    assert len(nodes) == len(stages_of(rec)) and len(edges) == len(nodes) - 1
    assert '"' not in "".join(n.split('["', 1)[1].rsplit('"]', 1)[0] for n in nodes)


def test_the_report_shows_the_chain_under_each_finding(tmp_path):
    records = run(tmp_path, "campaigns/demo_policy.yaml")
    text = report.render("demo-policy", records)
    assert text.count("    attack:   [DIRECT INJECTION]") == 3


# ---- the CLI --------------------------------------------------------------

def test_cli_graph_flag_draws_the_boxes(tmp_path, capsys):
    code = main(["run", "campaigns/demo_policy.yaml", "--runs-dir", str(tmp_path), "--graph"])
    out = capsys.readouterr().out
    assert code == 1 and out.count("ATTACK GRAPH  CB-") == 3 and "╭" in out


def test_cli_graph_mermaid_flag(tmp_path, capsys):
    main(["run", "campaigns/demo_policy.yaml", "--runs-dir", str(tmp_path), "--graph", "mermaid"])
    out = capsys.readouterr().out
    assert out.count("flowchart TD") == 3 and "╭" not in out


def test_cli_without_graph_flag_draws_no_boxes(tmp_path, capsys):
    main(["run", "campaigns/demo_policy.yaml", "--runs-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert "ATTACK GRAPH" not in out and "attack:   [" in out


def test_cli_graph_is_ignored_for_machine_formats(tmp_path, capsys):
    main(["run", "campaigns/demo_policy.yaml", "--runs-dir", str(tmp_path), "--format", "json", "--graph"])
    out = capsys.readouterr().out
    import json
    json.loads(out)         # still pure JSON, no boxes mixed in
