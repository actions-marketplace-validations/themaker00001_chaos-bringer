import re

import pytest

from chaos_agents import replay, report, runstore
from chaos_agents.campaign import Campaign
from chaos_agents.corpus import Corpus, Record
from chaos_agents.orchestrator import run_campaign
from chaos_agents.report import wrap_arrows, wrap_words


def run(tmp_path, campaign_file):
    campaign = Campaign.from_yaml(campaign_file)
    return campaign, run_campaign(campaign, Corpus(campaign.name, root=tmp_path))


# ---- the two wrappers ----------------------------------------------------------

def test_wrap_words_leaves_a_line_alone_when_there_is_no_width_or_it_fits():
    assert wrap_words("  x: ", "short text", 4, None) == ["  x: short text"]
    assert wrap_words("  x: ", "short text", 4, 80) == ["  x: short text"]


def test_wrap_words_breaks_at_spaces_and_indents_the_continuation():
    lines = wrap_words("    payload:  ", "alpha beta gamma delta epsilon zeta eta theta", 14, 40)
    assert len(lines) > 1 and all(len(l) <= 40 for l in lines)
    assert lines[0].startswith("    payload:  ") and all(l.startswith(" " * 14) for l in lines[1:])
    assert " ".join(l.strip() for l in lines).replace("payload: ", "") .split()[-1] == "theta"


def test_wrap_words_never_rewraps_text_that_has_its_own_line_breaks():
    text = "line one\nline two " + "x " * 60
    assert wrap_words("  x: ", text, 4, 40) == ["  x: " + text]


def test_wrap_words_does_not_split_a_long_unbreakable_token():
    token = "x" * 90
    assert any(token in l for l in wrap_words("  x: ", f"a {token} b", 4, 40))


def test_wrap_arrows_breaks_only_between_stages_and_leads_continuations_with_the_arrow():
    parts = [f"[STAGE NUMBER {i}]" for i in range(8)]
    lines = wrap_arrows("    attack:   ", parts, 14, 70)
    assert len(lines) > 1 and all(len(l) <= 70 for l in lines)
    assert all(l.lstrip().startswith("→ [") for l in lines[1:])
    rebuilt = re.findall(r"\[STAGE NUMBER \d\]", "\n".join(lines))
    assert rebuilt == parts, "every stage survives, in order, unsplit"


def test_wrap_arrows_without_a_width_is_the_single_line_it_always_was():
    assert wrap_arrows("a: ", ["x", "y", "z"], 3, None) == ["a: x → y → z"]


# ---- the run report --------------------------------------------------------------

def test_without_a_width_every_field_is_still_on_one_line(tmp_path):
    campaign, records = run(tmp_path, "campaigns/demo_quickstart.yaml")
    text = report.render(campaign.name, records)
    assert any(len(l) > 150 for l in text.splitlines()), "the long lines are intact for pipes and CI"
    assert text == report.render(campaign.name, records, width=None)


@pytest.mark.parametrize("width", [80, 100, 120])
def test_with_a_width_nothing_overflows_and_nothing_is_lost(tmp_path, width):
    campaign, records = run(tmp_path, "campaigns/demo_quickstart.yaml")
    plain = report.render(campaign.name, records)
    wrapped = report.render(campaign.name, records, width=width)
    assert max(len(l) for l in wrapped.splitlines()) <= width
    # same stages, same id, same flow -- just laid out differently
    for needle in ("MEMORY POISONING", "CB-", "EXFILTRATION", "attacker.example", "ASI06", "AML.T0080"):
        assert needle in wrapped
    assert re.findall(r"\[[A-Z ]+\]", plain.split("attack:")[1].split("maps to")[0]) == \
           re.findall(r"\[[A-Z ]+\]", wrapped.split("attack:")[1].split("maps to")[0])


def test_the_flow_path_wraps_at_arrows_too(tmp_path):
    campaign, records = run(tmp_path, "campaigns/demo_quickstart.yaml")
    lines = report.flow_lines(records[0], width=60)
    path = [l for l in lines if "Path:" in l or l.lstrip().startswith("→")]
    assert len(path) > 1 and all(len(l) <= 60 for l in lines)
    assert "attacker.example (external)" in "\n".join(path)


def test_terminal_width_is_none_when_stdout_is_not_a_terminal(capsys):
    assert report.terminal_width() is None


# ---- the replay story ------------------------------------------------------------

def test_replay_lines_fit_a_width_and_keep_their_meaning(tmp_path):
    campaign, _ = run(tmp_path / "r", "campaigns/demo_quickstart.yaml")
    found = runstore.list_findings(tmp_path / "r")[0]
    rp = replay.replay(found, tmp_path / "regs", fix={"memory_trusted": False})
    wide = replay.render(rp)
    narrow = replay.render(rp, width=90)
    assert max(len(l) for l in narrow.splitlines()) <= 90
    assert max(len(l) for l in wide.splitlines()) > 90, "without a width the long fields keep their old caps"
    for needle in ("ORIGINAL RUN", "ATTACK", "OBSERVATION", "REPRODUCED", "FIX APPLIED", "PASS"):
        assert needle in narrow
