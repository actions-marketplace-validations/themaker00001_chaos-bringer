"""Destination parsing shared by everything that decides "is this place allowed?".

The sandbox's exfiltration allowlist and the policy engine's per-capability
destination rules must agree on what a destination *is*, and on what counts as
a match: a host matches an allowed domain exactly or as a true subdomain --
never by substring, or "vault.internal.evil.com" slips past "vault.internal".

Parsing is where allowlists usually fail, so this module **fails closed**:
anything that cannot be read unambiguously is not guessed at and not skipped.
It comes back as an explicit *invalid destination* marker, which is never an
allowed host. That closes three families of blind spot:

* **destinations that vanish** -- an IPv6 literal or a scheme-relative
  ``//host/x`` used to parse to an empty host, be ignored, and so raise no
  violation at all.
* **parser differentials** -- ``https://evil.example\\.allowed.com/``: Python reads
  a subdomain of allowed.com, a browser reads ``\\`` as ``/`` and connects to
  evil.example. Whitespace, control characters, backslashes and non-ASCII text
  in a destination's authority are never legitimate from an agent, so they are
  invalid rather than interpreted. So is userinfo (``user@host`` in a URL).
* **several recipients in one string** -- ``evil@x.example;ok@allowed.com``: reading
  only the last ``@`` saw only the allowed one. Every address is checked.
"""

from __future__ import annotations

import re

INVALID_PREFIX = "<invalid destination"

_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_LOCAL = re.compile(r"^[a-z0-9._%+'=-]+$")
_IPV6 = re.compile(r"^[0-9a-f:.]+$")
_SEPARATORS = re.compile(r"[,;\s]+")
_ANGLE = re.compile(r"<([^<>]*)>")
_UNSAFE = re.compile(r"[\x00-\x20\x7f\\]|[^\x00-\x7f]")      # whitespace, controls, backslash, non-ASCII


def invalid(raw: str) -> str:
    """The marker for a destination that could not be read unambiguously. It quotes
    the offending text (escaped, so a newline or backslash is visible in a report)."""
    shown = raw if len(raw) <= 48 else raw[:47] + "…"
    return f"{INVALID_PREFIX} {shown!r}>"


def is_invalid(host: str) -> bool:
    return host.startswith(INVALID_PREFIX)


def _clean_host(host: str) -> str | None:
    """A lowercase host name or IPv6 literal, or None if it is neither."""
    host = host.lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):          # an IPv6 literal: an address, never a name an allowlist lists
        inner = host[1:-1]
        return inner if ":" in inner and _IPV6.match(inner) else None
    return host if _HOST.match(host) and ".." not in host else None


def _authority_host(authority: str) -> str | None:
    if "@" in authority:
        return None                                            # credentials in a URL: no agent needs them, and parsers disagree on them
    if authority.startswith("["):
        m = re.fullmatch(r"(\[[^\]]+\])(?::\d*)?", authority)
        return _clean_host(m.group(1)) if m else None
    host, _, port = authority.partition(":")
    return _clean_host(host) if port.isdigit() or not port else None


def _one(token: str) -> str:
    """The host of one URL, address or bare host -- or an invalid marker."""
    raw, text = token, token.strip()
    low = text.lower()
    if not text:
        return invalid(raw)
    if "://" in low or low.startswith("//"):
        rest = low.split("://", 1)[1] if "://" in low else low[2:]
        authority = re.split(r"[/?#]", rest, maxsplit=1)[0]   # only the authority decides where it goes
        host = None if _UNSAFE.search(authority) else _authority_host(authority)
        return host or invalid(raw)
    if _UNSAFE.search(text):
        return invalid(raw)
    if "@" in low:                                             # an address: exactly one '@' or it is ambiguous
        local, _, domain = low.rpartition("@")
        host = _clean_host(domain) if "@" not in local and _LOCAL.match(local) else None
        return host or invalid(raw)
    host = _authority_host(re.split(r"[/?#]", low, maxsplit=1)[0])   # a bare host, maybe with a port or path
    return host or invalid(raw)


def destination_hosts(destination: str) -> list[str]:
    """Every host named by a free-form destination string: one URL, one address, or
    several addresses joined by commas, semicolons or whitespace, optionally with
    display names (``Alice <a@x.example>``). Whatever cannot be read comes back as an
    invalid marker, never dropped. An empty destination names no host."""
    text = (destination or "").strip()
    if not text:
        return []
    if "://" in text or text.startswith("//"):
        return [_one(text)]                                    # one URL: a single request goes to one place
    named = _ANGLE.findall(text)
    if named:
        rest = _ANGLE.sub(" ", text)
        if "@" in rest or "<" in rest or ">" in rest:          # an address hiding in the display name, or unbalanced brackets
            return [invalid(text)]
        return [_one(t) for t in named]
    return [_one(t) for t in _SEPARATORS.split(text) if t]


def host_of(destination: str) -> str:
    """The hostname of a single destination (a URL, an address, or a bare host),
    lowercased with any port and trailing dot stripped. A destination that names
    several hosts, or none that can be read, is invalid: never guessed at."""
    hosts = destination_hosts(destination)
    if not hosts:
        return ""
    return hosts[0] if len(hosts) == 1 else invalid(destination)


def host_allowed(host: str, allowed: list[str]) -> bool:
    """True if `host` is one of `allowed` or a true subdomain of one. An empty or
    invalid host is never allowed."""
    host = (host or "").lower().rstrip(".")
    if not host or is_invalid(host):
        return False
    return any(host == a or host.endswith("." + a) for a in (x.lower().rstrip(".") for x in allowed) if a)
