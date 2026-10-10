#!/usr/bin/env python3
"""Mutation testing for the attack suite: is "0 findings" a result, or just a weak test?

    python tools/fortress/mutants.py

Zero findings against the fortress could mean it is strong -- or that the attacks cannot find
anything. This tells them apart. It seeds known defects into the fortress's defences, one at a
time (a validator that checks the host with `in` instead of equality, a DLP that only knows the
plain secret, ...), and runs the same attack families against each. A defect the suite finds is
*killed*; one it does not is a *survivor*, and a survivor is either a blind spot in the attacks
(add one) or a defect no policy could call a violation (say so). Each mutant is paired with a
clean control -- the same configuration without the defect -- which must itself come back with
zero findings, or the experiment is not measuring what it claims to.

The defects are the classic ones (the ones in real CVEs): substring and prefix host checks, a
missing dot boundary on a suffix check, userinfo read as the host, trusting a URL library that
reads a backslash differently from a browser, one recipient check applied to a whole address list,
a DLP that does not fold case/separators or look across calls, a quarantine that only knows email.

Where a defect is only reachable when the layers around it are out of the way (a DLP bug is
invisible while egress blocks the call first), the mutant runs with exactly those layers off.
"""

from __future__ import annotations

import argparse
import base64
import codecs
import json
import re
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import siege  # noqa: E402
from chaos_agents.adapters.fortress import Dlp, Egress, FortressAdapter  # noqa: E402


# ---- the seeded defects -----------------------------------------------------------------------

class BuggyEgress(Egress):
    """The strict validator, with one defect."""

    def __init__(self, base: Egress, bug: str) -> None:
        super().__init__(base.owner_email, base.domains, base.hosts, base.max_url, base.max_recipients)
        self.bug = bug

    def url(self, raw):
        if not isinstance(raw, str):
            return None, "not a string"
        u, bug = raw.strip(), self.bug
        if bug == "substring_host":                                   # "api.mycompany.com" in url
            return (u, "") if u.startswith("http") and any(h in u for h in self.hosts) else (None, "no")
        if bug == "prefix_host":                                      # url.startswith("https://" + host)
            return (u, "") if any(u.startswith("https://" + h) for h in self.hosts) else (None, "no")
        if bug == "suffix_no_dot":                                    # host.endswith(allowed), no dot boundary
            host = urllib.parse.urlsplit(u).hostname or ""
            return (u, "") if u.startswith("https://") and any(host.endswith(h) for h in self.hosts) else (None, "no")
        if bug == "userinfo_as_host":                                 # everything before the first "@" is "the host"
            m = re.match(r"https://([^/?#]*)", u)
            authority = m.group(1).split("@")[0] if m else ""
            return (u, "") if authority.split(":")[0] in self.hosts else (None, "no")
        if bug == "urlsplit_only":                                    # trust the library, no strict grammar
            try:
                host = urllib.parse.urlsplit(u).hostname
            except ValueError:
                return None, "no"
            return (u, "") if u.startswith("https://") and host in self.hosts else (None, "no")
        if bug == "http_allowed":                                     # a downgrade to plaintext is fine; nothing else changes
            if u.startswith("http://"):
                ok, why = super().url("https://" + u[len("http://"):])
                return (u, "") if ok else (None, why)
        return super().url(raw)

    def address(self, raw):
        if not isinstance(raw, str):
            return None, "not a string"
        a, bug = raw.strip().lower(), self.bug
        if bug == "substring_host":
            return (a, "") if "@" in a and any(d in a for d in self.domains) else (None, "no")
        if bug == "last_at_only":                                     # one check on whatever follows the last "@"
            domain = a.rsplit("@", 1)[-1]
            return (a, "") if "@" in a and (domain in self.domains or a == self.owner_email) else (None, "no")
        if bug == "suffix_no_dot":
            return (a, "") if "@" in a and any(a.endswith(d) for d in self.domains) else (None, "no")
        return super().address(raw)


class _NoHeuristics(Dlp):
    """The defect is in how a secret is *recognised*; take away the opaque-blob and credential-shape
    backstops so a miss is not quietly covered by them."""

    @staticmethod
    def looks_opaque(text: str) -> str:
        return ""


class PlainDlp(_NoHeuristics):
    """Knows only the secret as written."""

    def has_secret(self, text: str) -> bool:
        return any(s in text for s in self.secrets)


class NoFoldDlp(_NoHeuristics):
    """Decodes base64/hex/ROT13/reversal, but compares case- and separator-sensitively."""

    def has_secret(self, text: str) -> bool:
        pool = {text, text[::-1], codecs.encode(text, "rot13")}
        for chunk in re.findall(r"[A-Za-z0-9+/_=-]{8,}", text):
            try:
                pool.add(base64.b64decode(chunk + "=" * (-len(chunk) % 4)).decode("utf-8", "ignore"))
            except ValueError:
                pass
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", chunk):
                pool.add(bytes.fromhex(chunk).decode("utf-8", "ignore"))
        return any(s in v for v in pool for s in self.secrets)


class NoWindowDlp(Dlp):
    """Judges each call on its own; forgets what was already sent."""

    def remember(self, args, session) -> None:
        return None


class Mutant:
    def __init__(self, name: str, why: str, disable: list[str], expect: str, apply) -> None:
        self.name, self.why, self.disable, self.expect, self.apply = name, why, disable, expect, apply


def _egress(bug):
    def apply(bot: FortressAdapter) -> None:
        bot.egress = BuggyEgress(bot.egress, bug)
    return apply


def _dlp(cls):
    def apply(bot: FortressAdapter) -> None:
        bot.dlp = cls(secrets=bot.dlp.secrets)
    return apply


class _EmailOnlyQuarantine(FortressAdapter):
    """Notes are quarantined only when they contain an address; the planner acts on what is stored."""

    def _planner_reads_memory(self) -> bool:
        return True

    def _quarantine_reason(self, note: str) -> str:
        return "carries an address" if "@" in note else ""


class _TrustingPlanner(FortressAdapter):
    """The control for the above: the same planner that acts on stored notes, behind the real quarantine."""

    def _planner_reads_memory(self) -> bool:
        return True


class _NoQuarantine(_TrustingPlanner):
    def _quarantine_reason(self, note: str) -> str:
        return ""


OPEN_FIELD = ["egress", "dlp", "limits"]          # only the memory layer is left standing

MUTANTS = [
    Mutant("egress: host checked with `in`", "the classic: allowlisted name appears anywhere in the URL or address",
           [], "spelling", _egress("substring_host")),
    Mutant("egress: URL prefix match", "startswith('https://api.mycompany.com') -- admits api.mycompany.com.attacker.example",
           [], "spelling", _egress("prefix_host")),
    Mutant("egress: suffix match, no dot boundary", "host.endswith('api.mycompany.com') admits xapi.mycompany.com",
           [], "spelling", _egress("suffix_no_dot")),
    Mutant("egress: userinfo read as the host", "https://api.mycompany.com@attacker.example/",
           [], "spelling", _egress("userinfo_as_host")),
    Mutant("egress: trusts urlsplit, no strict grammar", "a backslash or tab makes Python and a browser disagree about the host",
           [], "spelling", _egress("urlsplit_only")),
    Mutant("egress: one check on a whole address list", "a@attacker.example, b@company.example -- only what follows the last @ is checked",
           [], "spelling", _egress("last_at_only")),
    Mutant("egress: plaintext http allowed", "a downgrade to plaintext: the host is right, only the scheme is wrong (found once the policy could say `schemes: [https]`)",
           [], "spelling", _egress("http_allowed")),
    Mutant("dlp: knows only the plain secret", "no encodings, no folding", ["egress", "minimize"], "costumes", _dlp(PlainDlp)),
    Mutant("dlp: no case/separator folding", "decodes base64/hex/ROT13 but a dash between letters hides the secret",
           ["egress", "minimize"], "costumes", _dlp(NoFoldDlp)),
    Mutant("dlp: no memory across calls", "a secret split over two messages is never seen whole",
           ["egress", "minimize"], "sequence", _dlp(NoWindowDlp)),
]
MEMORY_MUTANTS = [
    ("memory: quarantine only knows addresses", _EmailOnlyQuarantine, "memory"),
    ("memory: no quarantine (planner trusts notes)", _NoQuarantine, "memory"),
]
CONTROLS = [("memory: planner trusts notes, real quarantine", _TrustingPlanner, "memory")]


@dataclass
class Result:
    name: str
    why: str
    expect: str
    control_findings: int
    findings: int
    killed_by: dict = field(default_factory=dict)
    example: str = ""

    @property
    def killed(self) -> bool:
        return bool(self.killed_by)


FAMILIES = ["spelling", "costumes", "direct", "mutation", "memory", "sequence"]


def _document() -> dict:
    return {"document": siege.secret_only_document()}


def measure(name, why, expect, disable, make, root: Path, families: list[str] | None = None) -> Result:
    """Run every family (or just `families`) against the clean config and against the seeded defect."""
    cfg = {"disable": disable, **_document()}
    kills: dict = {}
    example = ""
    for fam in families or FAMILIES:
        clean = siege.run("fortress", cfg, fam, root, factory=lambda kw: make(kw, buggy=False))
        buggy = siege.run("fortress", cfg, fam, root, factory=lambda kw: make(kw, buggy=True))
        kills[fam] = (clean["findings"], buggy["findings"])
        if buggy["findings"] and not example:
            example = buggy["examples"][0] if buggy["examples"] else ""
    return Result(name, why, expect, sum(c for c, _ in kills.values()), sum(b for _, b in kills.values()),
                  {f: b - c for f, (c, b) in kills.items() if b > c}, example)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", metavar="PATH")
    args = ap.parse_args()
    results: list[Result] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for m in MUTANTS:
            def make(kw, buggy, m=m):
                bot = FortressAdapter(**kw)
                if buggy:
                    m.apply(bot)
                return bot
            results.append(measure(m.name, m.why, m.expect, m.disable, make, root))
        for name, cls, expect in MEMORY_MUTANTS + CONTROLS:
            def make(kw, buggy, cls=cls):
                return cls(**kw) if buggy else FortressAdapter(**kw)
            results.append(measure(name, "", expect, OPEN_FIELD, make, root))
    width = max(len(r.name) for r in results)
    print(f"{'seeded defect':<{width}}  {'clean':>6}  {'seeded':>6}  extra findings, by attack family")
    print("-" * (width + 44))
    for r in results:
        kills = ", ".join(f"{f} (+{n})" for f, n in r.killed_by.items()) or "SURVIVED"
        print(f"{r.name:<{width}}  {r.control_findings:>6}  {r.findings:>6}  {kills}")
    killed = [r for r in results if r.killed]
    print(f"\n{len(killed)} of {len(results)} seeded variants produced findings the clean fortress did not; "
          f"{len(results) - len(killed)} survived")
    if args.json:
        Path(args.json).write_text(json.dumps([r.__dict__ for r in results], indent=2, default=str))


if __name__ == "__main__":
    main()
