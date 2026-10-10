"""The four plugin surfaces every chaos-agents component is built from.

These are structural (`Protocol`) rather than base classes on purpose: a
third-party plugin package implements the methods below and registers itself
under the matching entry-point group in its own `pyproject.toml` -- it never
needs to import or subclass anything from this package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from chaos_agents import taxonomy

if TYPE_CHECKING:
    from chaos_agents.observation import Observation

# a verdict is one of three outcomes, kept distinct on purpose: a flaky or
# failed trial must never be scored as a clean pass (V2 blueprint).
PASS = "pass"              # the target held -- no finding
FAIL = "fail"              # a confirmed security finding
INCONCLUSIVE = "inconclusive"  # couldn't decide (target/judge error, low confidence)
STATUSES = (PASS, FAIL, INCONCLUSIVE)


@dataclass
class Verdict:
    """A judge's ruling on a single (payload, response) exchange.

    `passed` stays the simple boolean the judges and tests have always set;
    the richer fields default sensibly and are reconciled in __post_init__, so
    a judge can keep returning `Verdict(passed=..., severity=..., reason=...)`
    and still get a valid status/category."""

    passed: bool
    severity: str = "info"  # info | low | medium | high | critical
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    status: str = ""        # pass | fail | inconclusive; derived from passed if unset
    confidence: float = 1.0
    category: str = ""       # attack family from the taxonomy
    technique: str = ""
    impact: str = ""

    def __post_init__(self) -> None:
        if not self.status:
            self.status = PASS if self.passed else FAIL
        if self.status not in STATUSES:
            raise ValueError(f"unknown verdict status {self.status!r}; expected one of {STATUSES}")
        # keep the boolean and the status in agreement: only an explicit PASS is a pass
        self.passed = self.status == PASS
        if self.category:
            taxonomy.validate(self.category, self.technique or None)


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
class ConversationVector(Protocol):
    """A vector that attacks over several turns, not one shot. Each item is a
    conversation: an ordered list of user messages sent to the same session.
    The orchestrator uses this path only when the target can hold a
    conversation (see `MultiTurnTarget`); otherwise it falls back to
    `generate()` if the vector also offers it."""

    def conversations(self) -> list[list[str]]:
        ...


@runtime_checkable
class MultiTurnTarget(Protocol):
    """A target that keeps conversation state. `converse` sends each user
    turn in order within one fresh session and returns the reply after each,
    so an attack can build across turns the way a real chat does. A target that
    acts through tools may return an ``Observation`` per turn instead of a bare
    reply, so the judge and policy see what it did on every turn."""

    def converse(self, turns: list[str]) -> "list[str | Observation]":
        ...


@runtime_checkable
class Judge(Protocol):
    """Decides pass/fail/severity for one (payload, response) exchange."""

    def evaluate(self, payload: str, response: str) -> Verdict:
        ...


@runtime_checkable
class ObservingTarget(Protocol):
    """An adapter that returns a structured `Observation` -- the agent's full
    observable behaviour (reply, tool calls, error, latency), not just the
    reply text. Optional: an adapter that only has text keeps implementing
    `invoke`, and the orchestrator wraps its string into an Observation."""

    def observe(self, payload: str) -> "Observation":
        ...


@runtime_checkable
class ObservingJudge(Protocol):
    """A judge that rules on a whole `Observation` and can inspect tool calls,
    not just the reply text. Optional: a text-only judge keeps implementing
    `evaluate`, and is handed the flattened reply-plus-tool-activity text."""

    def judge(self, payload: str, observation: "Observation") -> Verdict:
        ...
