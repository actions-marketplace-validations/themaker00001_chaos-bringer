"""Plugin discovery.

Every plugin -- including the ones that ship in this package -- is found the
same way: an entry-point under one of the four `chaos_agents.*` groups. There
is no hardcoded mapping of names to classes; a third party ships
`pip install chaos-agents-plugin-x` with its own entry-points and it shows up
here exactly like a built-in.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

_GROUPS = (
    "chaos_agents.providers",
    "chaos_agents.adapters",
    "chaos_agents.vectors",
    "chaos_agents.judges",
)


def available(group: str) -> dict[str, str]:
    """Name -> "module:attr" for every plugin registered under `group`."""
    if group not in _GROUPS:
        raise ValueError(f"unknown plugin group {group!r}, expected one of {_GROUPS}")
    return {ep.name: ep.value for ep in entry_points(group=group)}


def load(group: str, name: str, **config: Any):
    """Instantiate the plugin registered as `name` under `group` with `config`."""
    matches = [ep for ep in entry_points(group=group) if ep.name == name]
    if not matches:
        known = ", ".join(sorted(available(group))) or "(none installed)"
        raise KeyError(f"no {group!r} plugin named {name!r}. Installed: {known}")
    cls = matches[0].load()
    return cls(**config)
