"""The four plugin surfaces every chaos-agents component is built from.

These are structural (`Protocol`) rather than base classes on purpose: a
third-party plugin package implements the methods below and registers itself
under the matching entry-point group in its own `pyproject.toml` -- it never
needs to import or subclass anything from this package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class Verdict:
    """A judge's ruling on a single (payload, response) exchange."""

    passed: bool
    severity: str = "info"  # info | low | medium | high | critical
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class TargetError(RuntimeError):
    """Raised by an adapter when the target itself failed -- errored, timed
    out, or answered with something that isn't a reply. The orchestrator
    records it as a finding rather than stopping the campaign; any other
    exception from `invoke` is treated the same way."""


@runtime_checkable
class ModelProvider(Protocol):
    """Generates text from a model. Backs the Chaos Engine and, optionally, an LLM judge."""

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        """Return the model's completion for `prompt`."""
        ...


@runtime_checkable
class TargetAdapter(Protocol):
    """Connects chaos-agents to the system under test."""

    def invoke(self, payload: str) -> str:
        """Send `payload` to the target agent and return its response."""
        ...


@runtime_checkable
class ChaosVector(Protocol):
    """A mutation / fault-injection strategy. Produces adversarial payloads."""

    def generate(self) -> list[str]:
        """Return the payloads this vector wants to try, in order."""
        ...


@runtime_checkable
class Judge(Protocol):
    """Decides pass/fail/severity for one (payload, response) exchange."""

    def evaluate(self, payload: str, response: str) -> Verdict:
        ...
