"""MCP sandboxed-tool implementation bugs: `mcp_fault.py` already fakes a tool's *definition*
(rug pull, schema poisoning) -- this models a vulnerable tool *implementation* instead, the thing
sitting behind a definition that looks perfectly fine.

Two real, independently disclosed shapes:

  CVE-2025-53372 (`node-code-sandbox-mcp`) -- an input parameter is interpolated unsanitized into
  `child_process.execSync`, so a crafted parameter achieves arbitrary command execution on the
  host, bypassing the sandbox the server is supposed to provide. `safe_exec=False` (default)
  interpolates the command into a shell-quoted string with no escaping at all, so a bare `'` in
  the argument breaks out of the intended quoting; `safe_exec=True` escapes it properly.

  CVE-2025-53109/53110 ("EscapeRoute", Cymulate) -- Anthropic's own reference Filesystem MCP
  server, <0.6.3: naive prefix-matching lets `/allow_dir_sensitive` pass a check meant to allow
  only `/allow_dir`. `safe_path_check=False` (default) uses exactly that naive `str.startswith`
  check; `safe_path_check=True` requires an exact match or a true subdirectory boundary -- the
  same suffix-boundary discipline `chaos_agents.hosts` already applies to hostnames, now applied
  to filesystem paths. Worth noting explicitly: `hosts.py` already avoids the prefix-match class
  for hostnames, which is why this is a real, positive contrast to point at, not just another
  vulnerability demo.

Deterministic, no model needed -- this tests the tool implementations themselves, not a model's
decision to call them. Payload selects which tool: ``exec:<command>`` or ``read:<path>``.
"""

from __future__ import annotations

from chaos_agents.observation import Observation, ToolCall

DEFAULT_ALLOWED_DIR = "/data/public"


class McpToolImplementationAdapter:
    def __init__(self, allowed_dir: str = DEFAULT_ALLOWED_DIR, safe_path_check: bool = False,
                safe_exec: bool = False) -> None:
        self.allowed_dir = allowed_dir.rstrip("/")
        self.safe_path_check = safe_path_check
        self.safe_exec = safe_exec

    # ---- CVE-2025-53109/53110-style: naive prefix match on a filesystem path -------------------
    def _path_allowed(self, path: str) -> bool:
        if self.safe_path_check:
            return path == self.allowed_dir or path.startswith(self.allowed_dir + "/")
        return path.startswith(self.allowed_dir)   # the bug: a bare prefix, not a true boundary

    def _read_file(self, path: str) -> Observation:
        true_boundary = path == self.allowed_dir or path.startswith(self.allowed_dir + "/")
        allowed = self._path_allowed(path)
        escaped = allowed and not true_boundary
        result = f"contents of {path}" if allowed else "refused: path is outside the allowed directory"
        call = ToolCall(name="read_file", arguments={"path": path}, result=result)
        return Observation(response=result, tool_calls=[call], raw={"escaped_scope": escaped, "tool": "read_file"})

    # ---- CVE-2025-53372-style: unsanitized string interpolation into a shell command -----------
    def _exec(self, command: str) -> Observation:
        if self.safe_exec:
            escaped_command = command.replace("'", "'\\''")
            shell_line = f"docker exec sandbox sh -c '{escaped_command}'"
            escaped = False
        else:
            shell_line = f"docker exec sandbox sh -c '{command}'"   # no escaping at all
            escaped = "'" in command   # a bare quote breaks out of the intended quoting
        call = ToolCall(name="sandboxed_exec", arguments={"command": command}, result=shell_line)
        return Observation(response=f"Ran: {shell_line}", tool_calls=[call],
                           raw={"escaped_scope": escaped, "tool": "sandboxed_exec"})

    def observe(self, payload: str) -> Observation:
        text = payload.strip()
        if text.startswith("exec:"):
            return self._exec(text[len("exec:"):])
        if text.startswith("read:"):
            return self._read_file(text[len("read:"):])
        return Observation(response=f"Unrecognized request: {text!r} (use 'exec:<command>' or 'read:<path>')",
                           tool_calls=[])

    def invoke(self, payload: str) -> str:
        return self.observe(payload).response

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"McpToolImplementationAdapter(safe_path_check={self.safe_path_check}, safe_exec={self.safe_exec})"
