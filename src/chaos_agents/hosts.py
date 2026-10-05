"""Destination parsing shared by everything that decides "is this place allowed?".

The sandbox's exfiltration allowlist and the policy engine's per-capability
destination rules must agree on what a destination *is*, and on what counts as
a match: a host matches an allowed domain exactly or as a true subdomain --
never by substring, or "vault.internal.evil.com" slips past "vault.internal".
"""

from __future__ import annotations

from urllib.parse import urlparse


def host_of(destination: str) -> str:
    """Extract the hostname from a destination, which may be a URL
    (https://host/path), an email (user@host), or a bare host. Returns a
    lowercased host with any port and trailing dot stripped."""
    d = (destination or "").strip().lower()
    if "://" in d:
        host = urlparse(d).hostname or ""
    elif "@" in d:
        host = d.rsplit("@", 1)[-1]
    else:
        host = d
    host = host.split("/", 1)[0].split(":", 1)[0]  # drop any path/port if present
    return host.rstrip(".")


def host_allowed(host: str, allowed: list[str]) -> bool:
    """True if `host` is one of `allowed` or a true subdomain of one."""
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in (x.lower().rstrip(".") for x in allowed) if a)
