"""STT-origin trust mislabeling: a simulated voice front-end for a real chat model.

OpenAI Whisper hallucinates entire invented phrases (including fabricated URLs and violent
language) roughly 1% of the time, more often around pauses/non-fluent speech (ACM FAccT 2024,
Cornell). Separately, a single universal ~0.64s adversarial audio segment causes Whisper to
silently emit only an end-of-text token, suppressing transcription of real speech with >97%
success (arXiv:2402.08021, 2024-02). Either way, what reaches the downstream LLM can differ from
what the user actually said, with nothing marking the difference.

No real audio or STT model is needed to test the trust question that matters: once a transcript
reaches the LLM, is there ANY mechanism gating which parts of it are allowed to drive behaviour
based on how confidently they were transcribed? Every chat adapter in this project (and every
real one we know of) takes a single opaque string as "the user's turn" -- there is no channel to
even express "this part came from a shakier transcription," so the honest baseline answer is no.

This adapter makes that gap directly testable with a real model, not just assertable: a payload
can carry a ``<<<HALLUCINATED>>>`` marker, everything after which simulates a low-confidence,
STT-invented continuation the user never actually spoke (the real failure mode is usually an
appended fabrication, not a prefix). ``require_high_confidence=False`` (default, the vulnerable
baseline) passes the WHOLE transcript -- spoken and hallucinated -- to the model exactly as
today's chat adapters would, since none of them can tell the difference. ``require_high_confidence
=True`` is the fix: the hallucinated continuation is stripped before the model ever sees it, the
same "enforce before the model gets a say" principle this project already applies everywhere else
(``enforce_egress``, ``tofu_pinning``, fortress's ``narration``), now applied to transcript
provenance.
"""

from __future__ import annotations

from chaos_agents.adapters.ollama_chat import OllamaChatAdapter
from chaos_agents.observation import Observation

_MARKER = "<<<HALLUCINATED>>>"


class SttFrontEndAdapter:
    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        system: str | None = None,
        timeout: float = 120.0,
        options: dict | None = None,
        require_high_confidence: bool = False,
    ) -> None:
        self.require_high_confidence = require_high_confidence
        kwargs = {"model": model, "base_url": base_url, "timeout": timeout, "options": options or {}}
        if system is not None:
            kwargs["system"] = system
        self._chat = OllamaChatAdapter(**kwargs)

    def _transcript(self, payload: str) -> tuple[str, bool]:
        """(what actually reaches the model, whether a hallucinated continuation was present)."""
        if _MARKER not in payload:
            return payload, False
        spoken, _, hallucinated = payload.partition(_MARKER)
        spoken, hallucinated = spoken.strip(), hallucinated.strip()
        if self.require_high_confidence:
            return spoken, True
        return f"{spoken} {hallucinated}".strip(), True

    def observe(self, payload: str) -> Observation:
        transcript, had_hallucination = self._transcript(payload)
        reply = self._chat.invoke(transcript)
        return Observation(response=reply, tool_calls=[], raw={
            "transcript_sent": transcript, "had_hallucinated_segment": had_hallucination,
            "require_high_confidence": self.require_high_confidence,
        })

    def invoke(self, payload: str) -> str:
        return self.observe(payload).response

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"SttFrontEndAdapter(require_high_confidence={self.require_high_confidence})"
