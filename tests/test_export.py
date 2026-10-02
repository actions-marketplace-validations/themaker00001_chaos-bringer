"""Machine-readable outputs (JSON / SARIF / JUnit) and the CLI --format path."""

import json
import xml.etree.ElementTree as ET

from chaos_agents import export
from chaos_agents.cli import main
from chaos_agents.corpus import Record
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS


def _records():
    return [
        Record("leak me", "the secret is sk-1", False, "high", "leaked", {},
               status=FAIL, category="sensitive_data", technique="secret_extraction",
               fingerprint="sha256:" + "a" * 64),
        Record("hi", "I can't help", True, "info", "clean", {}, status=PASS),
        Record("x", "", False, "medium", "target failed: TimeoutError", {},
               status=INCONCLUSIVE, category="operational", technique="target_error",
               fingerprint="sha256:" + "b" * 64),
    ]


# ---- JSON -------------------------------------------------------------------
def test_json_has_run_metadata_and_a_finding_per_trial():
    doc = json.loads(export.to_json("demo", _records(), run_id="r1"))
    assert doc["run"]["tool"] == "chaos-bringer"
    assert doc["run"]["total"] == 3
    assert doc["run"]["findings"] == 1 and doc["run"]["passed"] == 1 and doc["run"]["inconclusive"] == 1
    assert len(doc["findings"]) == 3
    leak = doc["findings"][0]
    assert leak["category"] == "sensitive_data" and leak["finding_id"] == "CB-" + "a" * 8


# ---- SARIF ------------------------------------------------------------------
def test_sarif_reports_only_confirmed_findings_with_rules_and_fingerprints():
    doc = json.loads(export.to_sarif("demo", _records()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    results = run["results"]
    assert len(results) == 1  # only the confirmed FAIL, not the pass or the inconclusive
    assert results[0]["ruleId"] == "sensitive_data/secret_extraction"
    assert results[0]["level"] == "error"  # high severity
    assert results[0]["partialFingerprints"]["chaosBringer/v1"] == "a" * 64
    assert any(rule["id"] == "sensitive_data/secret_extraction" for rule in run["tool"]["driver"]["rules"])


# ---- JUnit ------------------------------------------------------------------
def test_junit_is_valid_xml_with_failure_and_skipped():
    suite = ET.fromstring(export.to_junit("demo", _records()))
    assert suite.tag == "testsuite"
    assert suite.attrib["tests"] == "3" and suite.attrib["failures"] == "1" and suite.attrib["skipped"] == "1"
    cases = suite.findall("testcase")
    assert len(cases) == 3
    assert cases[0].find("failure") is not None       # the confirmed finding
    assert cases[1].find("failure") is None           # the pass
    assert cases[2].find("skipped") is not None        # the inconclusive


# ---- the CLI --format path --------------------------------------------------
def _echo_campaign(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "name: demo-echo\ncategory: sensitive_data\ntechnique: secret_extraction\n"
        "adapter:\n  plugin: echo\n  config:\n    secret: sk-demo-12345\n"
        "vector:\n  plugin: static_corpus\n  config:\n    limit: 2\n"
        "judge:\n  plugin: rule_based\n  config:\n    forbidden_substrings: [sk-demo-12345]\n"
    )
    return str(p)


def test_run_emits_valid_sarif_to_a_file_and_exits_1_on_findings(tmp_path, capsys):
    out = tmp_path / "chaos.sarif"
    code = main(["run", _echo_campaign(tmp_path), "--runs-dir", str(tmp_path / "runs"),
                 "--format", "sarif", "--output", str(out)])
    assert code == 1  # echo leaks -> confirmed findings -> CI fails
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0" and len(doc["runs"][0]["results"]) == 2


def test_run_json_to_stdout(tmp_path, capsys):
    code = main(["run", _echo_campaign(tmp_path), "--runs-dir", str(tmp_path / "runs"), "--format", "json"])
    assert code == 1
    out = capsys.readouterr().out
    doc = json.loads(out)  # stdout is pure JSON (status/trace lines go to stderr)
    assert doc["run"]["campaign"] == "demo-echo" and doc["run"]["findings"] == 2
