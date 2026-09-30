"""The generic hook: an HTTP reverse proxy that injects chaos into any
OpenAI/Ollama-shaped chat-completion call.

Point a real framework's model `base_url` at this proxy's `.url` instead of
the real provider, and every call it makes passes through here first. This
module proves the mechanism in isolation (arm a payload, send a request
through the proxy, watch it get injected and forwarded); wiring a specific
external framework's config to actually point at it is the next, separate
integration step -- deliberately not faked here.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests


def _extract_content(data: dict[str, Any]) -> str:
    """Best-effort content extraction across Ollama- and OpenAI-shaped responses."""
    try:
        return data["message"]["content"]
    except (KeyError, TypeError):
        pass
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        pass
    return json.dumps(data)


class GenericProxyAdapter:
    def __init__(
        self,
        upstream_url: str,
        host: str = "127.0.0.1",
        port: int = 0,
        timeout: float = 30.0,
        default_fields: dict[str, Any] | None = None,
    ) -> None:
        self.upstream_url = upstream_url
        self.host = host
        self.port = port
        self.timeout = timeout
        # Merged into every forwarded request that doesn't already set them --
        # e.g. Ollama/OpenAI both require "model", which a generic caller may omit.
        self.default_fields = default_fields or {}
        self.trace: list[dict[str, Any]] = []
        self._armed_payload: str | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("proxy not started")
        return f"http://{self.host}:{self._server.server_address[1]}"

    def start(self) -> None:
        if self._server is not None:
            return
        adapter = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # silence stdlib access log
                pass

            def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    original = json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    original = {}

                mutated = dict(original)
                for key, value in adapter.default_fields.items():
                    mutated.setdefault(key, value)
                if adapter._armed_payload is not None:
                    messages = list(mutated.get("messages", []))
                    messages.append({"role": "user", "content": adapter._armed_payload})
                    mutated["messages"] = messages

                try:
                    upstream = requests.post(adapter.upstream_url, json=mutated, timeout=adapter.timeout)
                    status, body = upstream.status_code, upstream.json()
                except requests.RequestException as exc:
                    status, body = 502, {"error": f"upstream unreachable: {exc}"}

                adapter.trace.append({"original": original, "mutated": mutated, "response": body})

                payload = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def arm(self, payload: str) -> None:
        """Arm `payload` to be injected into the next call(s) that pass
        through the proxy. Use this when a real framework is driving traffic
        through `.url` on its own -- `invoke()` is only the self-test path."""
        self.start()
        self._armed_payload = payload

    def invoke(self, payload: str) -> str:
        """Arm `payload` as the injected message, send a seed request through
        the proxy, and return the (possibly compromised) upstream reply."""
        self.arm(payload)
        seed = {"messages": [{"role": "user", "content": "What can you help me with today?"}]}
        resp = requests.post(self.url, json=seed, timeout=self.timeout)
        return _extract_content(resp.json())

    def __del__(self) -> None:
        self.stop()
