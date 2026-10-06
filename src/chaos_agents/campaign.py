"""Campaign config: which adapter, vector, and judge to wire up, and how."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from chaos_agents import registry, taxonomy
from chaos_agents.policy import Policy, PolicyError


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
    # optional capability policy: what the agent may do, checked against every
    # tool call it makes (see chaos_agents.policy)
    policy: Policy | None = None
    # the file this campaign was loaded from (empty when built in code)
    source: str = ""

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

        # a policy-only campaign needs no judge: the policy is the verdict rule
        required = ("name", "adapter", "vector") + (() if "policy" in data else ("judge",))
        missing = [k for k in required if k not in data]
        if missing:
            raise CampaignError(f"{path} is missing required key(s): {', '.join(missing)}")

        category = data.get("category", "")
        technique = data.get("technique", "")
        if category:
            try:
                taxonomy.validate(category, technique or None)
            except ValueError as exc:
                raise CampaignError(str(exc)) from exc

        policy = None
        if "policy" in data:
            try:
                policy = Policy.from_dict(data["policy"])
            except PolicyError as exc:
                raise CampaignError(f"{path}: {exc}") from exc

        judge = (ComponentSpec.from_dict(data["judge"], "judge") if "judge" in data
                 else ComponentSpec(plugin="rule_based"))
        return cls(
            name=data["name"],
            adapter=ComponentSpec.from_dict(data["adapter"], "adapter"),
            vector=ComponentSpec.from_dict(data["vector"], "vector"),
            judge=judge,
            category=category,
            technique=technique,
            policy=policy,
            source=str(path.resolve()),
        )

    def to_dict(self) -> dict:
        """The campaign as plain data -- what a run snapshot and a regression
        entry store so the same target can be rebuilt later."""
        out: dict = {"name": self.name}
        if self.category:
            out["category"] = self.category
        if self.technique:
            out["technique"] = self.technique
        out["adapter"] = {"plugin": self.adapter.plugin, "config": self.adapter.config}
        out["vector"] = {"plugin": self.vector.plugin, "config": self.vector.config}
        out["judge"] = {"plugin": self.judge.plugin, "config": self.judge.config}
        if self.policy:
            out["policy"] = self.policy.to_dict()
        return out

    def check_plugins(self) -> None:
        """Confirm each named plugin is actually installed, so a typo fails
        fast with the list of what's available -- not deep inside a run."""
        for role, spec in (("adapter", self.adapter), ("vector", self.vector), ("judge", self.judge)):
            group = _GROUP[role]
            available = registry.available(group)
            if spec.plugin not in available:
                known = ", ".join(sorted(available)) or "(none installed)"
                raise CampaignError(f"unknown {role} plugin {spec.plugin!r}; installed: {known}")
