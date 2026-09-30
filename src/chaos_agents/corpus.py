"""Local, offline replayable results store -- one JSON Lines file per run.

No database, no network: every finding is a line of JSON on disk, so a
failing case can be re-read and re-run later without any service running.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Record:
    payload: str
    response: str
    passed: bool
    severity: str
    reason: str
    details: dict[str, Any]


class Corpus:
    def __init__(self, campaign_name: str, root: str | Path = "runs") -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = Path(root) / campaign_name / stamp
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.results_path = self.run_dir / "results.jsonl"

    def record(self, record: Record) -> None:
        with self.results_path.open("a") as fh:
            fh.write(json.dumps(asdict(record)) + "\n")

    def read_all(self) -> list[Record]:
        if not self.results_path.exists():
            return []
        with self.results_path.open() as fh:
            return [Record(**json.loads(line)) for line in fh if line.strip()]
