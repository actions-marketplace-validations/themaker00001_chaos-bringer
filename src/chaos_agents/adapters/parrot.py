"""A naive baseline target: an agent that echoes untrusted input into its output.

This is the textbook insecure agent -- it folds the user's message straight into
what it emits, so any injected instruction "succeeds". It exists as ChaosBench's
calibration floor: a parrot scores ~0% resilience, the worst case any real agent
should beat, so a suite run has a known bottom to compare against (EchoAdapter,
which guards a fixed secret, is nearer the top of this particular suite).

Not a model, not a real agent -- zero network, zero dependencies.
"""

from __future__ import annotations


class ParrotAdapter:
    def __init__(self, prefix: str = "You asked: ") -> None:
        self.prefix = prefix

    def invoke(self, payload: str) -> str:
        # echoes the input verbatim -- the canonical "repeats untrusted data" flaw
        return f"{self.prefix}{payload}"
