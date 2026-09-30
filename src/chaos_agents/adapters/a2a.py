"""A target adapter for A2A (Agent-to-Agent) agents.

A2A agents speak JSON-RPC 2.0 over HTTP: a client sends `message/send` with a
user message, the agent replies with a Message or a Task. This adapter sends
the attack payload as the user message and returns the agent's reply text, so
any A2A agent can be a chaos target -- including one agent probing another.

Text is pulled best-effort from the reply, across the shapes A2A results take
(a Message's parts, a Task's status message, its artifacts, or its history),
since the exact shape varies by agent and spec revision. The method name is
configurable for that same reason.
"""

from __future__ import annotations

import uuid
from typing import Any

import requests

from chaos_agents.interfaces import TargetError


def _texts_from_parts(parts: Any) -> list[str]:
    out = []
    if isinstance(parts, list):
        for p in parts:
            if isinstance(p, dict):
                # {"kind":"text","text":...} or {"type":"text","text":...} or {"text":...}
                if isinstance(p.get("text"), str):
                    out.append(p["text"])
    return out


def extract_text(result: Any) -> str:
    """Best-effort reply text from an A2A `message/send` result."""
    if isinstance(result, str):
        return result
    if not isinstance(result, dict):
        return ""

    texts: list[str] = []
    texts += _texts_from_parts(result.get("parts"))              # a Message result
    status = result.get("status")
    if isinstance(status, dict):
        msg = status.get("message")
        if isinstance(msg, dict):
            texts += _texts_from_parts(msg.get("parts"))          # a Task's status message
    for artifact in result.get("artifacts", []) or []:            # a Task's artifacts
        if isinstance(artifact, dict):
            texts += _texts_from_parts(artifact.get("parts"))
    if not texts:
        for entry in result.get("history", []) or []:             # fall back to history
            if isinstance(entry, dict) and entry.get("role") != "user":
                texts += _texts_from_parts(entry.get("parts"))
    return "\n".join(t for t in texts if t)


class A2AAdapter:
    def __init__(
        self,
        agent_url: str,
        method: str = "message/send",
        timeout: float = 60.0,
    ) -> None:
        self.agent_url = agent_url
        self.method = method
        self.timeout = timeout

    def invoke(self, payload: str) -> str:
        request = {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": self.method,
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": payload}],
                    "messageId": uuid.uuid4().hex,
                }
            },
        }
        try:
            resp = requests.post(self.agent_url, json=request, timeout=self.timeout)
            resp.raise_for_status()
            body = resp.json()
        except requests.RequestException as exc:
            raise TargetError(f"could not reach A2A agent at {self.agent_url}: {exc}") from exc
        except ValueError as exc:
            raise TargetError(f"A2A agent returned non-JSON: {exc}") from exc

        if "error" in body:
            raise TargetError(f"A2A agent returned an error: {body['error']}")
        return extract_text(body.get("result"))
