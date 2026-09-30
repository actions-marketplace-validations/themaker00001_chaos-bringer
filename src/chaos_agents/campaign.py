"""Campaign config: which adapter, vector, and judge to wire up, and how."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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

    @classmethod
    def from_yaml(cls, path: str | Path) -> Campaign:
        data = yaml.safe_load(Path(path).read_text())
        return cls(
            name=data["name"],
            adapter=ComponentSpec.from_dict(data["adapter"]),
            vector=ComponentSpec.from_dict(data["vector"]),
            judge=ComponentSpec.from_dict(data["judge"]),
        )
