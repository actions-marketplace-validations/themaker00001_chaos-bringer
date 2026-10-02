"""Stable identity for a finding.

A fingerprint lets the same weakness be recognised across runs -- so it can be
deduplicated, promoted into the regression corpus, and tracked as fixed or
regressed. It is deliberately built from *what the finding is* (category,
technique, target, and a normalised form of the payload), not from volatile
details like timestamps, run ids, or the exact model wording, so re-running
the same attack against the same target yields the same fingerprint.
"""

from __future__ import annotations

import hashlib
import re


def _normalize(text: str) -> str:
    """Collapse whitespace and lowercase, so trivial reformatting of a payload
    doesn't change its fingerprint. Not a security boundary -- just stability."""
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def fingerprint(category: str, technique: str, target: str, payload: str) -> str:
    """A `sha256:...` identity for a finding. Same (category, technique,
    target, normalised payload) -> same fingerprint."""
    basis = "\x1f".join([category or "", technique or "", target or "", _normalize(payload)])
    return "sha256:" + hashlib.sha256(basis.encode("utf-8")).hexdigest()


def finding_id(fp: str) -> str:
    """A short, human-usable id derived from the fingerprint (e.g. CB-ab12cd34)."""
    digest = fp.split(":", 1)[-1]
    return "CB-" + digest[:8]
