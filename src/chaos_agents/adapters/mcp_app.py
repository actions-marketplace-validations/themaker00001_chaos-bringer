"""A target adapter for MCP-based apps, e.g. ChatGPT Apps.

A ChatGPT App is, underneath, an MCP server whose tools the host (ChatGPT)
calls. This adapter plays the host: it calls one of the app's tools with the
attack payload as an argument and returns the tool's text result, so a
developer can chaos-test their own app the way an adversarial host would --
feeding hostile arguments and seeing what the tool does or discloses.

(To test how an *agent* copes with a misbehaving tool, put `mcp_fault` in
front of the server instead. This adapter attacks the app itself.)
"""

from __future__ import annotations

from typing import Any

import requests

from chaos_agents.interfaces import TargetError


def extract_text(result: Any) -> str:
    """Text from an MCP `tools/call` result's content list."""
    if not isinstance(result, dict):
        return ""
    parts = [c.get("text", "") for c in result.get("content", []) if isinstance(c, dict)]
    return "".join(p for p in parts if p)


class McpAppAdapter:
    def __init__(
        self,
        app_url: str,
        tool: str,
        arg: str = "query",
        arguments: dict | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.app_url = app_url
        self.tool = tool
        self.arg = arg
        self.base_arguments = dict(arguments or {})
        self.timeout = timeout

    def invoke(self, payload: str) -> str:
        arguments = {**self.base_arguments, self.arg: payload}
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": self.tool, "arguments": arguments},
        }
        try:
            resp = requests.post(self.app_url, json=request, timeout=self.timeout)
            resp.raise_for_status()
            body = resp.json()
        except requests.RequestException as exc:
            raise TargetError(f"could not reach MCP app at {self.app_url}: {exc}") from exc
        except ValueError as exc:
            raise TargetError(f"MCP app returned non-JSON: {exc}") from exc

        if "error" in body:
            raise TargetError(f"MCP app returned an error: {body['error']}")
        result = body.get("result", {})
        if isinstance(result, dict) and result.get("isError"):
            # a tool-level error is still the app's answer -- hand it to the judge
            return extract_text(result) or "tool reported isError"
        return extract_text(result)
