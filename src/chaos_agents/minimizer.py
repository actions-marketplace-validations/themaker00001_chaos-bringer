"""Shrink a payload that triggered a finding down to a small reproducer.

Delta-debugging in spirit (V2 blueprint): repeatedly drop chunks of the
payload while the same finding still reproduces, so a sprawling mutated attack
becomes a short, human-readable one. The caller supplies a `reproduces`
predicate -- typically "re-run this against the target and the judge still
flags it" -- and a call budget, so minimization can't run away.
"""

from __future__ import annotations

from typing import Callable


def minimize(payload: str, reproduces: Callable[[str], bool], max_calls: int = 200) -> str:
    """Return the shortest payload (by greedy chunk removal) that still makes
    `reproduces` true. If the original doesn't reproduce, it's returned
    unchanged -- we never hand back something we couldn't verify."""
    tokens = payload.split()
    calls = 0

    def check(toks: list[str]) -> bool:
        nonlocal calls
        calls += 1
        return bool(toks) and reproduces(" ".join(toks))

    if len(tokens) <= 1 or not check(tokens):
        return payload

    chunk = max(1, len(tokens) // 2)
    while chunk >= 1 and calls < max_calls:
        removed_something = False
        i = 0
        while i < len(tokens) and calls < max_calls:
            candidate = tokens[:i] + tokens[i + chunk:]
            if check(candidate):
                tokens = candidate          # the removal preserved the finding -- keep it
                removed_something = True
                # retry at the same position; the list shifted under us
            else:
                i += chunk
        if not removed_something:
            chunk //= 2                     # can't drop at this granularity; go finer
    return " ".join(tokens)
