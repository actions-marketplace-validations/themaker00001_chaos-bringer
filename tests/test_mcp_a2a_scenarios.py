"""Integration smoke test for the §10 MCP / A2A deep scenarios example.

Runs the example end to end (local stdlib servers, no model, no network) and
checks that the controls hold and every attack scenario leaks -- i.e. the
scenarios actually discriminate, rather than flagging everything."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RUN = Path(__file__).resolve().parents[1] / "examples" / "mcp_a2a_scenarios" / "run.py"


def test_scenarios_discriminate(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(RUN)],
        cwd=tmp_path,            # Corpus writes under ./runs -- keep it in the tmp dir
        capture_output=True, text=True, timeout=120,
    )
    out = proc.stdout

    # controls hold
    assert "[PASS        ] mcp-control" in out, out
    assert "[PASS        ] a2a-control" in out, out
    # every attack surface leaks
    for scenario in (
        "mcp-description-poisoning",
        "mcp-poisoning-chain",
        "a2a-identity-spoofing",
        "a2a-cross-agent-trust",
    ):
        assert f"[LEAK        ] {scenario}" in out, out

    assert "Resilience score: 2/6 payloads survived" in out, out
    assert proc.returncode == 1, "a run with confirmed findings must exit non-zero"
