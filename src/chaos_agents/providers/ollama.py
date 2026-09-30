"""The default, free model provider: a local Ollama server.

Cloud providers are separate plugins under the same `chaos_agents.providers`
group -- nothing here is special-cased, this is just the one that ships
enabled by default because it costs nothing and needs no API key.
"""

from __future__ import annotations

import requests


class OllamaProviderError(RuntimeError):
    pass


class OllamaProvider:
    def __init__(
        self,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={"model": self.model, "messages": messages, "stream": False},
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise OllamaProviderError(
                f"could not reach Ollama at {self.base_url} (is `ollama serve` running, "
                f"and is model {self.model!r} pulled?): {exc}"
            ) from exc

        data = resp.json()
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise OllamaProviderError(f"unexpected Ollama response shape: {data!r}") from exc
