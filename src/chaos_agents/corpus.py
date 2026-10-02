"""Local, offline replayable results store -- one JSON Lines file per run.

No database, no network: every finding is a line of JSON on disk, so a
failing case can be re-read and re-run later without any service running.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
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
    # V2 contract fields: optional with defaults so old traces still load and
    # existing callers (and tests) that build a Record positionally keep working.
    status: str = ""            # pass | fail | inconclusive
    confidence: float = 1.0
    category: str = ""           # attack family from the taxonomy
    technique: str = ""
    impact: str = ""
    fingerprint: str = ""        # stable finding identity (sha256:...)
    minimized_payload: str = ""  # the shortest payload that still reproduces, when minimized
    # Observation stage: what the agent *did*, not just the reply text in `response`
    tool_calls: list[dict[str, Any]] = field(default_factory=list)  # name/arguments/result per call
    latency_ms: float = 0.0      # how long the target took to answer this trial


class Corpus:
    def __init__(self, campaign_name: str, root: str | Path = "runs") -> None:
        # collision-resistant run id: millisecond timestamp + random suffix, so
        # two runs of the same campaign in the same second don't share a dir
        now = datetime.now(timezone.utc)
        self.run_id = now.strftime("%Y%m%dT%H%M%S.") + f"{now.microsecond // 1000:03d}Z-{secrets.token_hex(3)}"
        self.run_dir = Path(root) / campaign_name / self.run_id
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
