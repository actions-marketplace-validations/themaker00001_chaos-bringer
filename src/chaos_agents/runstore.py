"""Find a finding again, and rebuild the target it came from.

Every run leaves a directory ``runs/<campaign>/<run_id>/`` holding the trace
(``results.jsonl``) and, since a finding is only useful if it can be reproduced,
a snapshot of the campaign that produced it (``campaign.json``). This module
reads that layout back: it locates a finding by id across every run, and hands
the snapshot to whatever needs to rebuild the adapter, judge and policy
(promote, replay).

A snapshot is written next to results that may be shared or committed, so
secret-looking config values (``api_key``, ``token``, ``password``,
``authorization`` ...) are replaced with a ``${NAME}`` placeholder. Rebuilding a
target expands those from the environment and says exactly which variable is
missing -- a secret is never written to disk by this tool.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from chaos_agents.corpus import Record
from chaos_agents.findings import finding_id
from chaos_agents.interfaces import FAIL

SNAPSHOT = "campaign.json"

_SECRET_KEY = re.compile(r"api[_-]?key|token|passw(?:or)?d|secret|authorization|bearer|credential|private[_-]?key", re.I)
_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class MissingSecret(RuntimeError):
    """A config value was stored as a ${NAME} placeholder and NAME is not set."""


class FindingNotFound(LookupError):
    pass


class AmbiguousFinding(LookupError):
    pass


# ---- secrets -----------------------------------------------------------------

def redact(obj: Any, _key: str = "") -> Any:
    """A copy of `obj` with every secret-looking value replaced by ``${KEY}``.
    A value is secret when the *key* it sits under looks like one; a nested
    mapping under such a key is redacted whole."""
    if isinstance(obj, dict):
        return {k: redact(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, _key) for v in obj]
    if _key and _SECRET_KEY.search(_key) and isinstance(obj, str) and obj and not _PLACEHOLDER.match(obj):
        return "${" + re.sub(r"[^A-Za-z0-9]+", "_", _key).strip("_").upper() + "}"
    return obj


def expand_env(obj: Any) -> Any:
    """The reverse of `redact`: replace each ``${NAME}`` with the environment
    variable NAME, or raise MissingSecret naming it."""
    if isinstance(obj, dict):
        return {k: expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_env(v) for v in obj]
    if isinstance(obj, str):
        m = _PLACEHOLDER.match(obj)
        if m:
            name = m.group(1)
            if name not in os.environ:
                raise MissingSecret(f"this config needs the secret {name}, which is not stored on disk; "
                                    f"set the environment variable {name} and retry")
            return os.environ[name]
    return obj


# ---- the snapshot --------------------------------------------------------------

def write_snapshot(run_dir: Path, campaign) -> Path:
    """Record the campaign next to its results (secrets redacted)."""
    doc = {
        "campaign": redact(campaign.to_dict()),
        "source": campaign.source,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    path = Path(run_dir) / SNAPSHOT
    path.write_text(json.dumps(doc, indent=2))
    return path


def read_snapshot(run_dir: Path) -> dict | None:
    path = Path(run_dir) / SNAPSHOT
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


# ---- locating findings ------------------------------------------------------------

@dataclass
class Located:
    """A finding as last seen: its record, the run it came from, and how often it recurred."""

    id: str
    record: Record
    run_dir: Path
    campaign: str
    run_id: str
    occurrences: int = 1

    @property
    def snapshot(self) -> dict | None:
        return read_snapshot(self.run_dir)

    def run_info(self) -> dict[str, Any]:
        return {"campaign": self.campaign, "run_id": self.run_id, "runs_seen": self.occurrences,
                "trace": str(self.run_dir / "results.jsonl")}


def _runs(runs_dir: Path) -> Iterator[Path]:
    """Every run directory, oldest first (run ids start with a UTC timestamp)."""
    dirs = [d for camp in sorted(runs_dir.glob("*")) if camp.is_dir()
            for d in camp.glob("*") if (d / "results.jsonl").exists()]
    return iter(sorted(dirs, key=lambda d: (d.name, d.parent.name)))


def _records(run_dir: Path) -> Iterator[Record]:
    for line in (run_dir / "results.jsonl").read_text().splitlines():
        if not line.strip():
            continue
        try:
            yield Record(**json.loads(line))
        except (TypeError, ValueError):
            continue            # a line from a newer/older shape: skip it, don't fail the lookup


def list_findings(runs_dir: str | Path = "runs") -> list[Located]:
    """Every distinct confirmed finding across all runs, each as its most
    recent occurrence, newest first. Identity is the fingerprint, so the same
    weakness found in ten runs is one finding seen ten times."""
    seen: dict[str, Located] = {}
    for run_dir in _runs(Path(runs_dir)):
        for rec in _records(run_dir):
            if rec.status != FAIL or not rec.fingerprint:
                continue
            fid = finding_id(rec.fingerprint)
            prev = seen.get(fid)
            seen[fid] = Located(fid, rec, run_dir, run_dir.parent.name, run_dir.name,
                                (prev.occurrences if prev else 0) + 1)
    return sorted(seen.values(), key=lambda f: (f.run_id, f.id), reverse=True)


def normalize_id(text: str) -> str:
    t = text.strip().lower()
    return t if t.startswith("cb-") else "cb-" + t


def find(ident: str, runs_dir: str | Path = "runs") -> Located:
    """The finding with this id (``CB-956b1f46``, or any unambiguous prefix of it)."""
    wanted = normalize_id(ident)
    hits = [f for f in list_findings(runs_dir) if f.id.lower().startswith(wanted)]
    if not hits:
        raise FindingNotFound(f"no finding matches {ident!r} under {runs_dir}/ (list them with: chaos-agents finding list)")
    if len(hits) > 1:
        raise AmbiguousFinding(f"{ident!r} matches {len(hits)} findings: " + ", ".join(h.id for h in hits[:6]))
    return hits[0]
