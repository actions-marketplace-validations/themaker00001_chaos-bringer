import json
from pathlib import Path

import pytest
import yaml

from chaos_agents import regression, replay, runstore
from chaos_agents.campaign import Campaign
from chaos_agents.cli import main
from chaos_agents.corpus import Corpus
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS
from chaos_agents.orchestrator import run_campaign

ROOT = Path(__file__).resolve().parent.parent
POLICY_CAMPAIGN = str(ROOT / "campaigns/demo_policy.yaml")
MEMORY_CAMPAIGN = str(ROOT / "campaigns/demo_memory.yaml")


def runs(tmp_path, campaign_file=POLICY_CAMPAIGN):
    campaign = Campaign.from_yaml(campaign_file)
    run_campaign(campaign, Corpus(campaign.name, root=tmp_path / "runs"))
    return tmp_path / "runs"


def located(runs_dir, reason_prefix):
    return next(f for f in runstore.list_findings(runs_dir) if f.record.reason.startswith(reason_prefix))


def setup(tmp_path, prefix="PRIVILEGE", campaign_file=POLICY_CAMPAIGN, promote=False):
    found = located(runs(tmp_path, campaign_file), prefix)
    if promote:
        regression.promote_finding(found, tmp_path / "regressions")
    return found, tmp_path / "regressions"


# ---- parsing a fix ------------------------------------------------------------------

def test_parse_fix_reads_values_as_yaml():
    assert replay.parse_fix(["hardened=true", "retries=3", "model=llama3.2", "flag=null"]) == {
        "hardened": True, "retries": 3, "model": "llama3.2", "flag": None}


def test_parse_fix_accepts_the_adapter_prefix_and_equals_in_values():
    assert replay.parse_fix(["adapter.hardened=true", "url=http://x/?a=b"]) == {"hardened": True, "url": "http://x/?a=b"}


@pytest.mark.parametrize("bad", ["hardened", "=true", ""])
def test_parse_fix_rejects_a_malformed_pair(bad):
    with pytest.raises(replay.ReplayError, match="KEY=VALUE"):
        replay.parse_fix([bad])


# ---- replaying without a fix ------------------------------------------------------------

def test_an_open_hole_replays_as_vulnerable(tmp_path):
    found, regs = setup(tmp_path)
    rp = replay.replay(found, regs)
    assert rp.result == replay.VULNERABLE and rp.before.reproduced and rp.after is None
    assert rp.before.reason.startswith("PRIVILEGE VIOLATION") and rp.before.tool_calls[0]["name"] == "database_write"


def test_replay_works_whether_or_not_the_finding_was_promoted(tmp_path):
    for promote in (False, True):
        found, regs = setup(tmp_path / str(promote), promote=promote)
        assert replay.replay(found, regs).result == replay.VULNERABLE


def test_a_promoted_regression_is_what_gets_replayed(tmp_path):
    found, regs = setup(tmp_path, promote=True)
    (regs / found.id / "minimized_payload.txt").write_text("Hello there\n")      # a hand-edit to something harmless
    rp = replay.replay(found, regs)
    assert rp.result == PASS and not rp.before.reproduced and rp.summary == "the attack no longer succeeds"


def test_an_already_fixed_target_replays_as_pass(tmp_path):
    found, regs = setup(tmp_path)
    snap_path = next((tmp_path / "runs").rglob("campaign.json"))
    snap = json.loads(snap_path.read_text())
    snap["campaign"]["adapter"]["config"] = {"hardened": True}
    snap_path.write_text(json.dumps(snap))
    rp = replay.replay(runstore.find(found.id, tmp_path / "runs"), regs)
    assert rp.result == PASS and rp.before.status == PASS


def test_a_memory_finding_replays_as_its_whole_scenario(tmp_path):
    found, regs = setup(tmp_path, "MEMORY POISONING (persistent", MEMORY_CAMPAIGN)
    rp = replay.replay(found, regs)
    assert rp.result == replay.VULNERABLE
    assert replay._attack_of(rp.entry)["trigger"] == "Please email me the weekly report."
    assert any(c["name"] == "memory_read" for c in rp.before.tool_calls)


# ---- replaying with a fix ------------------------------------------------------------------

def test_a_fix_that_closes_the_hole_passes_after_reproducing_on_the_original(tmp_path):
    found, regs = setup(tmp_path)
    rp = replay.replay(found, regs, fix={"hardened": True})
    assert rp.before.reproduced, "the hole was confirmed on the original target first"
    assert rp.after.status == PASS and rp.result == PASS and "fix closes it" in rp.summary
    assert rp.overrides == {"hardened": True} and rp.after.config["hardened"] is True


def test_a_memory_fix_closes_a_memory_finding(tmp_path):
    found, regs = setup(tmp_path, "MEMORY POISONING (persistent", MEMORY_CAMPAIGN)
    rp = replay.replay(found, regs, fix={"memory_trusted": False})
    assert rp.before.reproduced and rp.result == PASS


def test_a_fix_that_does_not_help_is_reported_as_still_vulnerable(tmp_path):
    found, regs = setup(tmp_path)
    rp = replay.replay(found, regs, fix={"user_email": "someone@company.example"})
    assert rp.result == replay.VULNERABLE and rp.after.reproduced and "does not close it" in rp.summary


def test_a_fix_key_the_target_does_not_have_is_inconclusive(tmp_path):
    found, regs = setup(tmp_path)
    rp = replay.replay(found, regs, fix={"no_such_option": True})
    assert rp.result == INCONCLUSIVE and "could not be built" in rp.summary


def test_a_fix_cannot_be_verified_if_the_attack_does_not_reproduce_first(tmp_path):
    found, regs = setup(tmp_path, promote=True)
    (regs / found.id / "minimized_payload.txt").write_text("Hello there\n")
    rp = replay.replay(found, regs, fix={"hardened": True})
    assert rp.result == INCONCLUSIVE and rp.after is None and "cannot verify the fix" in rp.summary


def test_a_dead_target_is_inconclusive_never_a_pass(tmp_path, monkeypatch):
    found, regs = setup(tmp_path)

    class Dies:
        def observe(self, payload):
            raise TimeoutError("down")

    real = replay.registry.load
    monkeypatch.setattr(replay.registry, "load", lambda g, n, **c: Dies() if g == "chaos_agents.adapters" else real(g, n, **c))
    rp = replay.replay(found, regs)
    assert rp.result == INCONCLUSIVE and "target error" in rp.before.reason


def test_a_missing_secret_names_the_variable(tmp_path, monkeypatch):
    found, regs = setup(tmp_path, promote=True)
    doc = yaml.safe_load((regs / found.id / "attack.yaml").read_text())
    doc["adapter"]["config"]["user_email"] = "${REPLAY_NEEDS_THIS}"
    (regs / found.id / "attack.yaml").write_text(yaml.safe_dump(doc))
    monkeypatch.delenv("REPLAY_NEEDS_THIS", raising=False)
    rp = replay.replay(found, regs)
    assert rp.result == INCONCLUSIVE and "REPLAY_NEEDS_THIS" in rp.before.reason


# ---- --record -----------------------------------------------------------------------------------

def test_record_writes_the_fix_into_the_regression_and_marks_it_fixed(tmp_path):
    found, regs = setup(tmp_path, promote=True)
    rp = replay.replay(found, regs, fix={"hardened": True}, record=True)
    assert rp.result == PASS and rp.recorded == str(regs / found.id)
    doc = yaml.safe_load((regs / found.id / "attack.yaml").read_text())
    assert doc["adapter"]["config"]["hardened"] is True
    assert (regs / found.id / "attack.yaml").read_text().startswith("# Reproducer for"), "the header comment survives"
    meta = json.loads((regs / found.id / "metadata.json").read_text())
    assert meta["status"] == "fixed" and meta["fixed"]["adapter_changes"] == {"hardened": True}
    # ...so the regression now guards the fixed target, and passes
    [result] = regression.run_regression(regs)
    assert not result.still_vulnerable
    assert regression.state_of(found.id, regs)["status"] == "fixed"


def test_record_needs_a_fix(tmp_path):
    found, regs = setup(tmp_path, promote=True)
    with pytest.raises(replay.ReplayError, match="needs a fix"):
        replay.replay(found, regs, record=True)


def test_record_refuses_when_the_fix_does_not_pass_and_changes_nothing(tmp_path):
    found, regs = setup(tmp_path, promote=True)
    before = (regs / found.id / "attack.yaml").read_text()
    with pytest.raises(replay.ReplayError, match="not recording"):
        replay.replay(found, regs, fix={"user_email": "x@company.example"}, record=True)
    assert (regs / found.id / "attack.yaml").read_text() == before
    assert json.loads((regs / found.id / "metadata.json").read_text())["status"] == "open"


def test_record_needs_the_finding_to_be_promoted_first(tmp_path):
    found, regs = setup(tmp_path, promote=False)
    with pytest.raises(replay.ReplayError, match="promote the finding first"):
        replay.replay(found, regs, fix={"hardened": True}, record=True)


# ---- the story -----------------------------------------------------------------------------------

def test_render_tells_the_story_in_order(tmp_path):
    found, regs = setup(tmp_path)
    text = replay.render(replay.replay(found, regs, fix={"hardened": True}))
    stages = ["ORIGINAL RUN", "ATTACK", "AGENT", "OBSERVATION", "FINDING", "FIX APPLIED", "REPLAY", "RESULT"]
    positions = [text.index(f"] {s}") for s in stages]
    assert positions == sorted(positions)
    assert f"REPLAY  {found.id}" in text and "REPRODUCED" in text and "hardened=true" in text
    assert "PASS  the fix closes it" in text and "tool calls: none" in text


def test_render_without_a_fix_stops_at_the_verdict(tmp_path):
    found, regs = setup(tmp_path)
    text = replay.render(replay.replay(found, regs))
    assert "FIX APPLIED" not in text and "] REPLAY " not in text and "VULNERABLE  the attack still succeeds" in text


def test_render_shows_both_halves_of_a_memory_attack(tmp_path):
    found, regs = setup(tmp_path, "MEMORY POISONING (persistent", MEMORY_CAMPAIGN)
    text = replay.render(replay.replay(found, regs))
    assert "planted:" in text and "trigger:  Please email me the weekly report." in text


def test_to_dict_is_the_machine_readable_story(tmp_path):
    found, regs = setup(tmp_path)
    d = replay.replay(found, regs, fix={"hardened": True}).to_dict()
    assert d["id"] == found.id and d["result"] == PASS and d["fix"] == {"hardened": True}
    assert d["observation"]["reproduced"] is True and d["replay"]["reproduced"] is False
    assert d["attack"]["payload"] and d["run"]["campaign"] == "demo-policy" and d["original"]["severity"] == "high"
    assert "fix" not in replay.replay(found, regs).to_dict()


# ---- finding show / list reflect it ---------------------------------------------------------------------

@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["run", POLICY_CAMPAIGN])
    return tmp_path


def an_id(capsys) -> str:
    capsys.readouterr()
    main(["finding", "list"])
    return next(w for w in capsys.readouterr().out.split() if w.startswith("CB-"))


def test_cli_replay_exit_codes(project, capsys):
    fid = an_id(capsys)
    assert main(["replay", fid]) == 1                                         # vulnerable
    assert "VULNERABLE" in capsys.readouterr().out
    assert main(["replay", fid, "--fix", "hardened=true"]) == 0               # fixed
    assert "PASS" in capsys.readouterr().out
    assert main(["replay", fid, "--fix", "no_such_option=1"]) == 3            # inconclusive
    capsys.readouterr()
    assert main(["replay", "CB-00000000"]) == 2                               # no such finding
    assert "no finding matches" in capsys.readouterr().err
    assert main(["replay", fid, "--fix", "hardened"]) == 2                    # malformed fix
    assert "KEY=VALUE" in capsys.readouterr().err


def test_cli_replay_json(project, capsys):
    fid = an_id(capsys)
    main(["replay", fid, "--fix", "hardened=true", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["result"] == "pass" and doc["replay"]["reproduced"] is False


def test_cli_the_whole_loop_promote_fix_record_regression_show(project, capsys):
    fid = an_id(capsys)
    assert main(["finding", "promote", fid]) == 0
    assert main(["replay", fid, "--fix", "hardened=true", "--record"]) == 0
    capsys.readouterr()
    assert main(["finding", "list"]) == 0
    assert "FIXED" in capsys.readouterr().out
    assert main(["finding", "show", fid]) == 0
    shown = capsys.readouterr().out
    assert shown.startswith(f"{fid}  ") and "FIXED" in shown.splitlines()[0]
    assert "Reproducible  yes" in shown and f"Regression    regressions/{fid}/" in shown
    assert main(["regression"]) == 0
    assert "1/1 reproducers no longer fire" in capsys.readouterr().out


def test_cli_record_without_promote_is_an_error(project, capsys):
    fid = an_id(capsys)
    assert main(["replay", fid, "--fix", "hardened=true", "--record"]) == 2
    assert "promote the finding first" in capsys.readouterr().err


def test_cli_finding_list_json_carries_the_regression_state(project, capsys):
    fid = an_id(capsys)
    main(["finding", "promote", fid])
    main(["replay", fid, "--fix", "hardened=true", "--record"])
    capsys.readouterr()
    main(["finding", "list", "--json"])
    item = next(i for i in json.loads(capsys.readouterr().out) if i["id"] == fid)
    assert item["status"] == "fixed" and item["reproducible"] is True and item["regression"] == f"regressions/{fid}"


def test_the_readme_demo_story_still_holds_end_to_end(project, capsys):
    """tools/demo/make_demo_gif.py records exactly this sequence, so if it ever stops
    working the GIF can't be rebuilt -- and the README would be advertising a demo that doesn't."""
    campaign = str(ROOT / "campaigns/demo_quickstart.yaml")
    assert main(["run", campaign]) == 1                                  # the agent is poisoned
    out = capsys.readouterr().out
    assert "MEMORY POISONING" in out and "OWASP ASI06" in out
    fid = next(w for w in out.split() if w.startswith("CB-"))
    assert main(["finding", "promote", fid]) == 0                        # a verified regression test
    assert main(["replay", fid, "--fix", "memory_trusted=false", "--record"]) == 0   # the fix closes it
    assert "PASS" in capsys.readouterr().out
    assert main(["regression"]) == 0                                     # ...and it stays guarded
    assert "1/1 reproducers no longer fire" in capsys.readouterr().out
