"""Campaign config: which adapter, vector, and judge to wire up, and how."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from chaos_agents import taxonomy


@dataclass
class ComponentSpec:
    plugin: str
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ComponentSpec:
        return cls(plugin=data["plugin"], config=data.get("config", {}))


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
        data = yaml.safe_load(Path(path).read_text())
        category = data.get("category", "")
        technique = data.get("technique", "")
        if category:
            taxonomy.validate(category, technique or None)
        return cls(
            name=data["name"],
            adapter=ComponentSpec.from_dict(data["adapter"]),
            vector=ComponentSpec.from_dict(data["vector"]),
            judge=ComponentSpec.from_dict(data["judge"]),
            category=category,
            technique=technique,
        )
