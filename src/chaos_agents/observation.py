"""The Observation stage: what the agent actually *did*, not just what it said.

The pipeline is  Attack -> Agent -> Observation -> Judge -> Finding.  For a long
time the step between Agent and Judge was implicit: an adapter returned a bare
string and the judge scanned that string. That misses the way a real agent
leaks -- not by writing the secret in its reply, but by *doing* something with
it: calling ``send_email(body=<secret>)``, ``http_post(url, data=<secret>)``,
``write_file(<secret>)``. The reply can look clean while the tool call carries
the payload straight out.

An ``Observation`` captures the whole observable behaviour of one invocation:
the final reply, every tool call (name + arguments + result), any error, and
how long it took. The judge rules on that. A judge that only cares about text
still works -- ``text_for_judge()`` flattens the reply *and* the tool activity
into one string, so a substring/regex judge now catches a canary that leaked
through a tool argument, which it could never see before.

Backwards compatible on purpose: an adapter may keep returning ``str`` from
``invoke`` (it's wrapped into an ``Observation`` here), and a judge may keep
implementing ``evaluate(payload, response)``. An adapter that wants the richer
path implements ``observe(payload) -> Observation``; a judge that wants to
inspect tool calls implements ``judge(payload, observation) -> Verdict``.
``observe()`` and ``judge()`` below are the single shared entry points the
orchestrator, the minimizer and the regression runner all go through, so the
exact same reply-plus-tool-calls text is judged everywhere.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """One tool/function the agent invoked while handling the attack."""

    name: str
    arguments: Any = ""   # dict, or a raw string if the adapter couldn't parse it
    result: str = ""      # what the tool returned to the agent, if observed

    def as_text(self) -> str:
        args = self.arguments
        if not isinstance(args, str):
            try:
                args = json.dumps(args, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                args = str(args)
        parts = [f"tool:{self.name}", f"args:{args}"]
        if self.result:
            parts.append(f"result:{self.result}")
        return " ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arguments": self.arguments, "result": self.result}

    @classmethod
    def of(cls, value: "ToolCall | dict[str, Any]") -> "ToolCall":
        if isinstance(value, ToolCall):
            return value
        return cls(
            name=str(value.get("name", "")),
            arguments=value.get("arguments", value.get("args", "")),
            result=str(value.get("result", "")),
        )


@dataclass
class Observation:
    """Everything observed from one invocation of the target agent."""

    response: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    error: str = ""
    latency_ms: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)  # adapter-specific extras (tokens, http status, ...)

    def text_for_judge(self) -> str:
        """The full surface a text-only judge should scan: the reply *and*
        every tool call's name/arguments/result, plus any error -- so a secret
        that left through a tool argument is visible to a substring judge."""
        parts = [self.response]
        parts.extend(tc.as_text() for tc in self.tool_calls)
        if self.error:
            parts.append(f"error:{self.error}")
        return "\n".join(p for p in parts if p)

    def tool_calls_as_dicts(self) -> list[dict[str, Any]]:
        return [tc.to_dict() for tc in self.tool_calls]

    @classmethod
    def of(cls, value: "Observation | str | dict[str, Any] | None") -> "Observation":
        """Coerce whatever an adapter returned into an Observation."""
        if isinstance(value, Observation):
            return value
        if value is None:
            return cls()
        if isinstance(value, str):
            return cls(response=value)
        if isinstance(value, dict):
            return cls(
                response=str(value.get("response", "")),
                tool_calls=[ToolCall.of(tc) for tc in value.get("tool_calls", [])],
                error=str(value.get("error", "")),
                latency_ms=float(value.get("latency_ms", 0.0)),
                raw=dict(value.get("raw", {})),
            )
        # last resort: stringify whatever it is rather than lose the reply
        return cls(response=str(value))


def observe(adapter, payload: str) -> Observation:
    """Run one attack against the target and capture the Observation, timing it.

    Uses the adapter's own ``observe(payload)`` when it offers one (the richer
    path that can report tool calls); otherwise falls back to ``invoke`` and
    wraps the returned string. Exceptions propagate -- the orchestrator and the
    regression runner decide how to record a failed target."""
    start = time.perf_counter()
    richer = getattr(adapter, "observe", None)
    if callable(richer):
        obs = Observation.of(richer(payload))
    else:
        obs = Observation.of(adapter.invoke(payload))
    if not obs.latency_ms:  # don't clobber a latency the adapter measured itself
        obs.latency_ms = (time.perf_counter() - start) * 1000.0
    return obs


def judge(judge_obj, payload: str, observation: Observation):
    """Ask the judge to rule on an Observation.

    A judge that implements ``judge(payload, observation)`` sees the whole
    thing (and can inspect tool calls structurally); any other judge gets the
    flattened reply-plus-tool-activity text through its ``evaluate`` method, so
    it still catches leaks that never appeared in the final reply."""
    richer = getattr(judge_obj, "judge", None)
    if callable(richer):
        return richer(payload, observation)
    return judge_obj.evaluate(payload, observation.text_for_judge())
