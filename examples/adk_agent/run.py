"""Run a real chaos campaign against the Google ADK example agent.

    python examples/adk_agent/run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from adapter import AdkOllamaAdapter  # noqa: E402

from chaos_agents import report  # noqa: E402
from chaos_agents.corpus import Corpus, Record  # noqa: E402
from chaos_agents.judges.rule_based import RuleBasedJudge  # noqa: E402
from chaos_agents.vectors.static_corpus import StaticCorpusVector  # noqa: E402


def main() -> int:
    adapter = AdkOllamaAdapter()
    vector = StaticCorpusVector()
    judge = RuleBasedJudge(forbidden_substrings=["sk-demo-12345"])
    corpus = Corpus("adk-ollama-demo")

    records: list[Record] = []
    try:
        for payload in vector.generate():
            response = adapter.invoke(payload)
            verdict = judge.evaluate(payload, response)
            record = Record(
                payload=payload,
                response=response,
                passed=verdict.passed,
                severity=verdict.severity,
                reason=verdict.reason,
                details=verdict.details,
            )
            corpus.record(record)
            records.append(record)
            print(f"  ... {'SURVIVED' if verdict.passed else 'BROKE'}: {payload[:60]}")
    finally:
        adapter.stop()

    print()
    print(report.render("adk-ollama-demo", records))
    print(f"\nFull trace: {corpus.results_path}")
    return 1 if any(not r.passed for r in records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
