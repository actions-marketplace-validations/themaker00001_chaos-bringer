"""Campaign validation: malformed configs fail fast with actionable errors,
before any target is touched -- and the `validate` CLI command surfaces it."""

import pytest

from chaos_agents.campaign import Campaign, CampaignError
from chaos_agents.cli import main

GOOD = (
    "name: ok\ncategory: sensitive_data\ntechnique: secret_extraction\n"
    "adapter:\n  plugin: echo\n  config:\n    secret: sk-demo-12345\n"
    "vector:\n  plugin: static_corpus\n"
    "judge:\n  plugin: rule_based\n  config:\n    forbidden_substrings: [sk-demo-12345]\n"
)


def _write(tmp_path, text, name="c.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_a_good_campaign_loads_and_its_plugins_resolve(tmp_path):
    c = Campaign.from_yaml(_write(tmp_path, GOOD))
    c.check_plugins()  # does not raise
    assert c.category == "sensitive_data"


def test_missing_required_key_names_it(tmp_path):
    text = GOOD.replace("judge:\n  plugin: rule_based\n  config:\n    forbidden_substrings: [sk-demo-12345]\n", "")
    with pytest.raises(CampaignError, match="missing required key"):
        Campaign.from_yaml(_write(tmp_path, text))


def test_component_without_a_plugin_is_rejected(tmp_path):
    text = GOOD.replace("  plugin: static_corpus\n", "  config: {}\n")
    with pytest.raises(CampaignError, match="missing a 'plugin'"):
        Campaign.from_yaml(_write(tmp_path, text))


def test_unknown_plugin_fails_before_running(tmp_path):
    text = GOOD.replace("plugin: static_corpus", "plugin: does_not_exist")
    c = Campaign.from_yaml(_write(tmp_path, text))
    with pytest.raises(CampaignError, match="unknown vector plugin 'does_not_exist'"):
        c.check_plugins()


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(CampaignError, match="not found"):
        Campaign.from_yaml(str(tmp_path / "nope.yaml"))


def test_bad_yaml_is_a_clear_error(tmp_path):
    with pytest.raises(CampaignError, match="not valid YAML"):
        Campaign.from_yaml(_write(tmp_path, "name: x\n  bad: : indent:\n"))


# ---- the validate CLI command -----------------------------------------------
def test_validate_command_accepts_a_good_campaign(tmp_path, capsys):
    assert main(["validate", _write(tmp_path, GOOD)]) == 0
    assert "ok: ok" in capsys.readouterr().out


def test_validate_command_rejects_a_bad_one_with_exit_2(tmp_path, capsys):
    text = GOOD.replace("plugin: rule_based", "plugin: nonexistent_judge")
    assert main(["validate", _write(tmp_path, text)]) == 2
    assert "invalid" in capsys.readouterr().err


def test_run_refuses_an_invalid_campaign_before_executing(tmp_path, capsys):
    text = GOOD.replace("plugin: echo", "plugin: no_such_adapter")
    code = main(["run", _write(tmp_path, text), "--runs-dir", str(tmp_path / "runs")])
    assert code == 2
    assert "invalid campaign" in capsys.readouterr().err
