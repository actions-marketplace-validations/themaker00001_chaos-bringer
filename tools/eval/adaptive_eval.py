#!/usr/bin/env python3
"""Does the adaptive search actually beat not adapting?

    python tools/eval/adaptive_eval.py            # prints a table
    python tools/eval/adaptive_eval.py --seeds 500 --budget 8

The unit tests prove the search's *mechanics* (a fail raises a weight, the budget
stops it). They cannot prove the point of the feature: that using feedback finds
more holes within a budget than working the grid blindly. This measures that.

It needs no target and no model. Each "target" is an oracle -- a function from a
candidate to "vulnerable or not" -- with a known structure, so we know what a good
search *should* exploit. A fresh random instance of the structure is drawn per
seed (which technique, which slot values, which cells), so no strategy benefits
from where one particular instance happens to put its holes:

  arm-clustered   one technique is vulnerable everywhere, the others nowhere
  slot-clustered  vulnerable only for one value of each of two slots, in every
                  technique (a pattern an arm-level learner cannot see)
  sparse-random   ~12% of the grid vulnerable at random (no structure to exploit:
                  adapting should neither help nor hurt)
  none / all      nothing / everything vulnerable (sanity)

Each strategy gets the same grid and the same budget; results are averaged over
many seeds. The strategies are the real `AdaptiveSearch` and two baselines:

  declared  work the grid in declared order, no feedback
  random    uniform random order, no feedback

Reported per target: findings found within the budget (higher is better) and the
share of runs that found at least one hole.

The same question is measured a second time for the *generalized* engine
(`AdaptiveCorpusSearch`, see `chaos_agents.adaptive.AdaptiveCorpusVector`): the grid there is
seeds x mutators rather than techniques x slot values, so the oracle taxonomy is renamed to
match (seed-clustered, mutator-clustered) but the method is identical.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from chaos_agents.adaptive import AdaptiveCorpusSearch, AdaptiveSearch, Arm, Candidate, CorpusCandidate  # noqa: E402
from chaos_agents.mutations import Mutator  # noqa: E402

TECHNIQUES = ("persistent_instruction", "false_fact_injection", "dormant_trigger", "persistent_instruction")
X = ("x0", "x1", "x2", "x3")
Y = ("y0", "y1")


def grid() -> list[Arm]:
    """Four arms (one reuses a technique, as a real campaign might), 4 x 2 = 8 candidates each."""
    return [Arm(technique=t, poison=f"arm{i} {{x}} {{y}}", trigger="t", slots={"x": X, "y": Y})
            for i, t in enumerate(TECHNIQUES)]


def arm_of(c: Candidate) -> int:
    return int(c.poison.split()[0].removeprefix("arm"))


def oracle_arm(seed: int):
    """One technique is vulnerable everywhere (which one differs per seed)."""
    hole = random.Random(seed).randrange(4)
    return lambda c: arm_of(c) == hole


def oracle_slot(seed: int):
    """Vulnerable only for one value of each of two slots, in every technique (which values differ per seed)."""
    rng = random.Random(seed)
    x, y = rng.choice(X), rng.choice(Y)
    return lambda c: c.slots["x"] == x and c.slots["y"] == y


def oracle_sparse(seed: int):
    """~12% of the grid vulnerable at random, no structure (a different map per seed)."""
    rng = random.Random(seed)
    cells = {(i, x, y) for i in range(4) for x in X for y in Y if rng.random() < 0.12}
    return lambda c: (arm_of(c), c.slots["x"], c.slots["y"]) in cells


ORACLES = {
    "arm-clustered": oracle_arm,
    "slot-clustered": oracle_slot,
    "sparse-random": oracle_sparse,
    "none": lambda seed: (lambda c: False),
    "all": lambda seed: (lambda c: True),
}


def run_adaptive(oracle, budget: int, seed: int) -> list[bool]:
    s = AdaptiveSearch(grid(), budget=budget, seed=seed)
    out = []
    while (c := s.propose()) is not None:
        hit = oracle(c)
        out.append(hit)
        s.update("fail" if hit else "pass")
    return out


def _blind(oracle, budget: int, order: list[Candidate]) -> list[bool]:
    return [oracle(c) for c in order[:budget]]


def run_declared(oracle, budget: int, seed: int) -> list[bool]:
    return _blind(oracle, budget, [c for a in grid() for c in a.candidates()])


def run_random(oracle, budget: int, seed: int) -> list[bool]:
    order = [c for a in grid() for c in a.candidates()]
    random.Random(seed).shuffle(order)
    return _blind(oracle, budget, order)


STRATEGIES = {"declared": run_declared, "random": run_random, "adaptive": run_adaptive}


def evaluate(budget: int = 8, seeds: int = 300) -> dict[str, dict[str, tuple[float, float]]]:
    """{oracle: {strategy: (mean findings within budget, share of runs with >=1 finding)}}"""
    table: dict[str, dict[str, tuple[float, float]]] = {}
    for oname, oracle in ORACLES.items():
        table[oname] = {}
        for sname, run in STRATEGIES.items():
            hits = [run(oracle(seed), budget, seed) for seed in range(seeds)]
            table[oname][sname] = (mean(sum(h) for h in hits), mean(1.0 if any(h) else 0.0 for h in hits))
    return table


def render(table: dict, budget: int, seeds: int) -> str:
    total = sum(len(a.candidates()) for a in grid())
    lines = [f"budget {budget} of {total} candidates, {seeds} seeds. "
             f"findings within budget (and % of runs that found at least one):", ""]
    lines.append(f"{'target':<16}" + "".join(f"{s:>20}" for s in STRATEGIES))
    for oname, row in table.items():
        lines.append(f"{oname:<16}" + "".join(f"{row[s][0]:>12.2f} ({row[s][1] * 100:>3.0f}%)" for s in STRATEGIES))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The same measurement for the generalized (corpus) engine: seeds x mutators,
# not techniques x slot values, but otherwise the identical method.
# ---------------------------------------------------------------------------

CORPUS_SEEDS = ("s0", "s1", "s2", "s3")
CORPUS_MUTATORS = [Mutator(f"m{i}", "encoding", "encoded_translated", (lambda n: (lambda p: f"{n}:{p}"))(f"m{i}"))
                  for i in range(8)]   # 4 x 8 = 32 candidates, matching the memory grid's size above


def _corpus_all_candidates() -> list[CorpusCandidate]:
    return [CorpusCandidate(seed_id=i, seed=s, mutator=m.name, technique=m.technique, payload=f"{s}|{m.name}")
            for i, s in enumerate(CORPUS_SEEDS) for m in CORPUS_MUTATORS]


def oracle_seed(seed: int):
    """One seed is vulnerable under every mutator (which seed differs per instance)."""
    hole = random.Random(seed).randrange(len(CORPUS_SEEDS))
    return lambda c: c.seed_id == hole


def oracle_mutator(seed: int):
    """One mutator is vulnerable for every seed (which mutator differs per instance) --
    a pattern a seed-level-only learner can't see, the corpus analogue of slot-clustered."""
    which = random.Random(seed).choice([m.name for m in CORPUS_MUTATORS])
    return lambda c: c.mutator == which


def oracle_sparse_corpus(seed: int):
    """~12% of the grid vulnerable at random, no structure (a different map per instance)."""
    rng = random.Random(seed)
    cells = {(i, m.name) for i in range(len(CORPUS_SEEDS)) for m in CORPUS_MUTATORS if rng.random() < 0.12}
    return lambda c: (c.seed_id, c.mutator) in cells


CORPUS_ORACLES = {
    "seed-clustered": oracle_seed,
    "mutator-clustered": oracle_mutator,
    "sparse-random": oracle_sparse_corpus,
    "none": lambda seed: (lambda c: False),
    "all": lambda seed: (lambda c: True),
}


def run_corpus_adaptive(oracle, budget: int, seed: int) -> list[bool]:
    s = AdaptiveCorpusSearch(list(CORPUS_SEEDS), CORPUS_MUTATORS, budget=budget, seed=seed, include_direct=False)
    out = []
    while (c := s.propose()) is not None:
        hit = oracle(c)
        out.append(hit)
        s.update("fail" if hit else "pass")
    return out


def _corpus_blind(oracle, budget: int, order: list[CorpusCandidate]) -> list[bool]:
    return [oracle(c) for c in order[:budget]]


def run_corpus_declared(oracle, budget: int, seed: int) -> list[bool]:
    return _corpus_blind(oracle, budget, _corpus_all_candidates())


def run_corpus_random(oracle, budget: int, seed: int) -> list[bool]:
    order = _corpus_all_candidates()
    random.Random(seed).shuffle(order)
    return _corpus_blind(oracle, budget, order)


CORPUS_STRATEGIES = {"declared": run_corpus_declared, "random": run_corpus_random, "adaptive": run_corpus_adaptive}


def evaluate_corpus(budget: int = 8, seeds: int = 300) -> dict[str, dict[str, tuple[float, float]]]:
    table: dict[str, dict[str, tuple[float, float]]] = {}
    for oname, oracle in CORPUS_ORACLES.items():
        table[oname] = {}
        for sname, run in CORPUS_STRATEGIES.items():
            hits = [run(oracle(seed), budget, seed) for seed in range(seeds)]
            table[oname][sname] = (mean(sum(h) for h in hits), mean(1.0 if any(h) else 0.0 for h in hits))
    return table


def render_corpus(table: dict, budget: int, seeds: int) -> str:
    total = len(CORPUS_SEEDS) * len(CORPUS_MUTATORS)
    lines = [f"[corpus engine] budget {budget} of {total} candidates, {seeds} seeds. "
             f"findings within budget (and % of runs that found at least one):", ""]
    lines.append(f"{'target':<18}" + "".join(f"{s:>20}" for s in CORPUS_STRATEGIES))
    for oname, row in table.items():
        lines.append(f"{oname:<18}" + "".join(f"{row[s][0]:>12.2f} ({row[s][1] * 100:>3.0f}%)" for s in CORPUS_STRATEGIES))
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--budget", type=int, default=8)
    ap.add_argument("--seeds", type=int, default=300)
    args = ap.parse_args()
    print(render(evaluate(args.budget, args.seeds), args.budget, args.seeds))
    print()
    print(render_corpus(evaluate_corpus(args.budget, args.seeds), args.budget, args.seeds))


if __name__ == "__main__":
    main()
