#!/usr/bin/env python3
"""Does the adaptive engine find a *real* sparse hole faster than working the grid blindly?

    python tools/fortress/adaptive_vs_blind.py

tools/eval/adaptive_eval.py measures the search against synthetic oracles. This is the same question
against an actual defect: the fortress with one seeded egress bug (see mutants.py), attacked through
the real memory-poisoning scenario with the large declared grid from siege.py. Only candidates that
spell the destination the buggy validator mishandles get through, so the hole is sparse and clustered
on one slot value -- the case the engine's per-part learning is for.

Reported for each strategy, over many seeds: the attempts it needed to land its first finding, and how
many findings it had within a fixed budget. Every strategy sees the same grid and the same target.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mutants  # noqa: E402
import siege  # noqa: E402
from chaos_agents import guard, memory  # noqa: E402
from chaos_agents.adaptive import AdaptiveSearch, arm_from_dict  # noqa: E402
from chaos_agents.adapters.fortress import FortressAdapter  # noqa: E402
from chaos_agents.campaign import Campaign, ComponentSpec  # noqa: E402
from chaos_agents.interfaces import FAIL  # noqa: E402
from chaos_agents.policy import Policy  # noqa: E402

BUGS = {"userinfo read as the host": "userinfo_as_host", "trusts urlsplit (backslash and friends)": "urlsplit_only",
        "host checked with `in`": "substring_host"}


def target(bug: str):
    bot = FortressAdapter(disable=["provenance"])           # the planner acts on stored notes; egress is the barrier
    bot.egress = mutants.BuggyEgress(bot.egress, bug)
    campaign = Campaign(name="x", adapter=ComponentSpec("fortress", {}), vector=ComponentSpec("static_corpus", {}),
                        judge=ComponentSpec("rule_based", {}), policy=Policy.from_dict(siege.POLICY))
    return bot, guard.judge_for(campaign)


def ground_truth(bug: str) -> dict[str, bool]:
    """Run every candidate once: which ones does the buggy target fall to?"""
    bot, judge = target(bug)
    arms = [arm_from_dict(a) for a in siege.memory_arms()]
    return {c.id: memory.run_scenario(bot, judge, c.scenario()).status == FAIL for i, a in enumerate(arms) for c in a.candidates(i)}


def adaptive(truth: dict[str, bool], budget: int, seed: int) -> list[bool]:
    s = AdaptiveSearch([arm_from_dict(a) for a in siege.memory_arms()], budget=budget, seed=seed)
    out = []
    while (c := s.propose()) is not None:
        hit = truth[c.id]
        out.append(hit)
        s.update("fail" if hit else "pass")
    return out


def blind(truth: dict[str, bool], budget: int, order: list[str]) -> list[bool]:
    return [truth[i] for i in order[:budget]]


def first(hits: list[bool], budget: int) -> int:
    return next((i + 1 for i, h in enumerate(hits) if h), budget + 1)


def evaluate(budget: int = 40, seeds: int = 100) -> dict:
    arms = [arm_from_dict(a) for a in siege.memory_arms()]
    ids = [c.id for i, a in enumerate(arms) for c in a.candidates(i)]
    table = {}
    for label, bug in BUGS.items():
        truth = ground_truth(bug)
        holes = sum(truth.values())
        rows = {"adaptive": [adaptive(truth, budget, s) for s in range(seeds)],
                "random": [blind(truth, budget, random.Random(s).sample(ids, len(ids))) for s in range(seeds)],
                "declared": [blind(truth, budget, ids)]}
        table[label] = {"holes": holes, "grid": len(ids),
                        **{name: (mean(first(h, budget) for h in runs), mean(sum(h) for h in runs)) for name, runs in rows.items()}}
    return table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--budget", type=int, default=40)
    ap.add_argument("--seeds", type=int, default=100)
    args = ap.parse_args()
    table = evaluate(args.budget, args.seeds)
    print(f"grid of {next(iter(table.values()))['grid']} candidates, budget {args.budget}, {args.seeds} seeds. "
          f"attempts to the first finding / findings within budget (budget+1 = never found one):\n")
    print(f"{'seeded defect':<42}{'holes':>6}{'adaptive':>16}{'random':>16}{'declared':>16}")
    for label, row in table.items():
        cells = "".join(f"{row[s][0]:>9.1f} /{row[s][1]:>5.1f}" for s in ("adaptive", "random", "declared"))
        print(f"{label:<42}{row['holes']:>6}{cells}")


if __name__ == "__main__":
    main()
