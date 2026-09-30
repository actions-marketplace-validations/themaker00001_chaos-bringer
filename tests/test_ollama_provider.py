"""OllamaProvider request-shaping, with requests.post stubbed -- no network."""

import pytest

from chaos_agents.providers import ollama as mod
from chaos_agents.providers.ollama import OllamaProvider, OllamaProviderError


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise mod.requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _capture(monkeypatch, payload=None):
    sent = {}

    def fake_post(url, json=None, timeout=None):
        sent["url"], sent["json"], sent["timeout"] = url, json, timeout
        return _Resp(payload or {"message": {"content": "ok"}})

    monkeypatch.setattr(mod.requests, "post", fake_post)
    return sent


def test_options_are_sent_in_the_request(monkeypatch):
    sent = _capture(monkeypatch)
    OllamaProvider(model="m", options={"temperature": 0}).complete("hi")
    assert sent["json"]["options"] == {"temperature": 0}
    assert sent["json"]["model"] == "m" and sent["json"]["stream"] is False


def test_options_default_to_empty(monkeypatch):
    sent = _capture(monkeypatch)
    OllamaProvider().complete("hi")
    assert sent["json"]["options"] == {}


def test_system_prompt_becomes_a_leading_message(monkeypatch):
    sent = _capture(monkeypatch)
    OllamaProvider().complete("do the thing", system="be terse")
    roles = [(m["role"], m["content"]) for m in sent["json"]["messages"]]
    assert roles == [("system", "be terse"), ("user", "do the thing")]


def test_unreachable_server_raises_a_clear_error(monkeypatch):
    def boom(*a, **k):
        raise mod.requests.ConnectionError("refused")

    monkeypatch.setattr(mod.requests, "post", boom)
    with pytest.raises(OllamaProviderError, match="could not reach Ollama"):
        OllamaProvider().complete("hi")
