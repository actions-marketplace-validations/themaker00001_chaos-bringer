"""Machine-readable run outputs so Chaos Bringer fits a normal CI pipeline.

- JSON  : the source of truth -- run metadata plus every trial as a finding.
- SARIF : GitHub code-scanning / security tab (confirmed findings as results).
- JUnit : generic CI test reporting (a finding is a failing test).

A trial has one of three outcomes, mapped consistently across formats:
  pass         -> the target held (a passing test, note-level)
  fail         -> a confirmed finding (a failing test, error/warning by severity)
  inconclusive -> couldn't decide, e.g. the target errored (a skipped test)
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id
from chaos_agents.interfaces import FAIL, INCONCLUSIVE, PASS

# severity -> SARIF level
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "warning", "info": "note"}


def _version() -> str:
    try:
        return version("chaos-bringer")
    except PackageNotFoundError:
        return "dev"


def _meta(campaign_name: str, records: list[Record], run_id: str | None) -> dict[str, Any]:
    counts = {PASS: 0, FAIL: 0, INCONCLUSIVE: 0}
    for r in records:
        counts[r.status if r.status in counts else (PASS if r.passed else FAIL)] += 1
    return {
        "tool": "chaos-bringer",
        "version": _version(),
        "campaign": campaign_name,
        "run_id": run_id,
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(records),
        "passed": counts[PASS],
        "findings": counts[FAIL],
        "inconclusive": counts[INCONCLUSIVE],
    }


# detail fields a finding carries when the run observed them (policy and
# data-flow findings); left out when empty so older shapes are unchanged
_DETAIL_FIELDS = ("target", "vector", "capability", "source", "data", "sink", "attack_path")


def _details(r: Record) -> dict[str, Any]:
    return {k: getattr(r, k) for k in _DETAIL_FIELDS if getattr(r, k)}


def _as_finding(r: Record) -> dict[str, Any]:
    return {
        "finding_id": finding_id(r.fingerprint) if r.fingerprint else None,
        "fingerprint": r.fingerprint,
        "status": r.status or (PASS if r.passed else FAIL),
        "severity": r.severity,
        "confidence": r.confidence,
        "category": r.category,
        "technique": r.technique,
        "impact": r.impact,
        "reason": r.reason,
        "payload": r.payload,
        "response": r.response,
        **_details(r),
    }


def to_json(campaign_name: str, records: list[Record], run_id: str | None = None) -> str:
    return json.dumps(
        {"run": _meta(campaign_name, records, run_id), "findings": [_as_finding(r) for r in records]},
        indent=2,
    )


def to_sarif(campaign_name: str, records: list[Record], run_id: str | None = None) -> str:
    # one rule per (category, technique) seen among confirmed findings
    fails = [r for r in records if (r.status or (FAIL if not r.passed else PASS)) == FAIL]
    rules: dict[str, dict] = {}
    results = []
    for r in fails:
        rule_id = f"{r.category or 'uncategorized'}/{r.technique or 'unspecified'}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("/", "-"),
            "shortDescription": {"text": f"{r.category or 'uncategorized'}: {r.technique or 'unspecified'}"},
        })
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(r.severity, "warning"),
            "message": {"text": f"{r.reason or 'finding'} (payload: {r.payload[:200]})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"campaign/{campaign_name}"}}}],
        }
        if r.attack_path or r.sink:
            # the observed route, so a code-scanning view shows where the data went
            result["properties"] = _details(r)
        if r.fingerprint:
            result["partialFingerprints"] = {"chaosBringer/v1": r.fingerprint.split(":", 1)[-1]}
        results.append(result)
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "chaos-bringer",
                "version": _version(),
                "informationUri": "https://github.com/themaker00001/chaos-bringer",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def to_junit(campaign_name: str, records: list[Record], run_id: str | None = None) -> str:
    meta = _meta(campaign_name, records, run_id)
    suite = ET.Element("testsuite", {
        "name": f"chaos-bringer/{campaign_name}",
        "tests": str(meta["total"]),
        "failures": str(meta["findings"]),
        "skipped": str(meta["inconclusive"]),
    })
    for i, r in enumerate(records):
        status = r.status or (PASS if r.passed else FAIL)
        name = f"{r.category or 'trial'}:{r.technique or i} #{i}"
        case = ET.SubElement(suite, "testcase", {"classname": campaign_name, "name": name})
        if status == FAIL:
            fail = ET.SubElement(case, "failure", {"type": r.severity, "message": r.reason or "finding"})
            fail.text = f"payload: {r.payload}\nresponse: {r.response}"
        elif status == INCONCLUSIVE:
            ET.SubElement(case, "skipped", {"message": r.reason or "inconclusive"})
    return ET.tostring(suite, encoding="unicode")


FORMATS = {"json": to_json, "sarif": to_sarif, "junit": to_junit}
