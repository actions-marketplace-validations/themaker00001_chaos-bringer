"""Campaign config: which adapter, vector, and judge to wire up, and how."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from chaos_agents import registry, taxonomy


class CampaignError(ValueError):
    """A campaign config is malformed. Raised before any target is touched,
    with a message that names the exact problem."""


@dataclass
class ComponentSpec:
    plugin: str
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], where: str) -> ComponentSpec:
        if not isinstance(data, dict):
            raise CampaignError(f"{where!r} must be a mapping with a 'plugin' key, got {type(data).__name__}")
        if "plugin" not in data or not str(data["plugin"]).strip():
            raise CampaignError(f"{where!r} is missing a 'plugin' name")
        config = data.get("config", {})
        if not isinstance(config, dict):
            raise CampaignError(f"{where!r}.config must be a mapping, got {type(config).__name__}")
        return cls(plugin=data["plugin"], config=config)


_GROUP = {"adapter": "chaos_agents.adapters", "vector": "chaos_agents.vectors", "judge": "chaos_agents.judges"}


@dataclass
class Campaign:
    name: str
    adapter: ComponentSpec
    vector: ComponentSpec
    judge: ComponentSpec
    # optional taxonomy tags: what family/technique this campaign exercises.
    # Stamped onto findings unless the judge classifies a trial itself.
    category: str = ""
    technique: str = ""

    @classmethod
    def from_yaml(cls, path: str | Path) -> Campaign:
        path = Path(path)
        if not path.exists():
            raise CampaignError(f"campaign file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            raise CampaignError(f"{path} is not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise CampaignError(f"{path} must be a YAML mapping at the top level")

        missing = [k for k in ("name", "adapter", "vector", "judge") if k not in data]
        if missing:
            raise CampaignError(f"{path} is missing required key(s): {', '.join(missing)}")

        category = data.get("category", "")
        technique = data.get("technique", "")
        if category:
            try:
                taxonomy.validate(category, technique or None)
            except ValueError as exc:
                raise CampaignError(str(exc)) from exc

        return cls(
            name=data["name"],
            adapter=ComponentSpec.from_dict(data["adapter"], "adapter"),
            vector=ComponentSpec.from_dict(data["vector"], "vector"),
            judge=ComponentSpec.from_dict(data["judge"], "judge"),
            category=category,
            technique=technique,
        )

    def check_plugins(self) -> None:
        """Confirm each named plugin is actually installed, so a typo fails
        fast with the list of what's available -- not deep inside a run."""
        for role, spec in (("adapter", self.adapter), ("vector", self.vector), ("judge", self.judge)):
            group = _GROUP[role]
            available = registry.available(group)
            if spec.plugin not in available:
                known = ", ".join(sorted(available)) or "(none installed)"
                raise CampaignError(f"unknown {role} plugin {spec.plugin!r}; installed: {known}")
