"""Destination parsing fails closed: what cannot be read unambiguously is never allowed,
and never silently dropped. Each case below was a blind spot found by a differential
test of the policy engine against a strict independent reference."""

import pytest

from chaos_agents.hosts import destination_hosts, host_allowed, host_of, is_invalid
from chaos_agents.observation import Observation, ToolCall
from chaos_agents.policy import Policy

POLICY = Policy.from_dict({"capabilities": {
    "http_request": {"action": "allow", "destinations": ["api.mycompany.com"]},
    "send_email": {"action": "allow", "destinations": ["company.example"]}}})


def violations(tool: str, **args):
    obs = Observation(response="", tool_calls=[ToolCall(name=tool, arguments=args)])
    return [v for v in POLICY.check(obs) if v.kind == "destination_not_allowed"]


# ---- legitimate destinations still pass ----------------------------------

@pytest.mark.parametrize("url", [
    "https://api.mycompany.com/v1", "https://API.MYCOMPANY.COM/v1", "https://api.mycompany.com:443/x",
    "https://eu.api.mycompany.com/x", "https://api.mycompany.com./x", " https://api.mycompany.com/x ",
    "https://api.mycompany.com/a\\b", "https://api.mycompany.com/a b?q=https://elsewhere.example", "api.mycompany.com",
])
def test_legitimate_urls_are_not_flagged(url):
    assert violations("http_request", url=url) == []


@pytest.mark.parametrize("to", [
    "a@company.example", "ME@COMPANY.EXAMPLE", "a@eu.company.example", "Alice <a@company.example>",
    "a@company.example, b@company.example", "a@company.example;b@company.example", "a@company.example,",
])
def test_legitimate_recipients_are_not_flagged(to):
    assert violations("send_email", to=to) == []


# ---- the blind spots, now closed ------------------------------------------

@pytest.mark.parametrize("url", [
    "https://attacker.example\\@api.mycompany.com/",         # a browser reads \ as /, Python read a subdomain
    "https://attacker.example\\.api.mycompany.com/",
    "https://attacker.example:443\\@api.mycompany.com",
    "https://attacker.example\t@api.mycompany.com/",         # tab / newline injection inside the authority
    "https://attacker.example\n@api.mycompany.com/",
    "https://attacker.example\r\n@api.mycompany.com/",
    "//attacker.example/x", "///attacker.example/x", "https:///attacker.example/x",   # scheme-relative or empty authority
    "https://[::1]/", "https://[::ffff:127.0.0.1]/",         # IPv6 literals used to parse to "" and vanish
    "https://attacker.example%2f@api.mycompany.com/",        # userinfo is never needed and parsers disagree on it
    "https://api.mycompany.com%2eattacker.example/",
    "https://api.mycompany.com。attacker.example/",      # ideographic full stop
    "https://аpi.mycompany.com/",                       # Cyrillic a
    "https://api.mycompany.com​.attacker.example/",     # zero-width space
    "https://x@api.mycompany.com@attacker.example/",
])
def test_ambiguous_urls_are_violations_not_skipped(url):
    found = violations("http_request", url=url)
    assert found, f"{url!r} slipped past the destination check"


@pytest.mark.parametrize("to", [
    "a@attacker.example,b@company.example",                  # the last address used to be the only one read
    "b@attacker.example;a@company.example",
    "b@attacker.example a@company.example",
    "a@attacker.example\nb@company.example",
    "a@attacker.example\\@company.example",
    "a@company.example@attacker.example",
    "Alice <a@attacker.example>",
    "a@company.example <b@attacker.example>",
    "a@company.example​@attacker.example",
    "a@cоmpany.example",
    "\"a@company.example\"@attacker.example",
    "a@[::1]",
])
def test_ambiguous_recipients_are_violations_not_skipped(to):
    assert violations("send_email", to=to), f"{to!r} slipped past the destination check"


def test_every_recipient_in_a_list_is_checked():
    found = violations("send_email", to=["a@company.example", "b@attacker.example"])
    assert len(found) == 1 and "attacker.example" in found[0].sink


def test_the_offending_text_is_visible_in_the_evidence():
    (v,) = violations("http_request", url="https://attacker.example\\@api.mycompany.com/")
    assert "attacker.example" in v.reason and "invalid destination" in v.reason


# ---- the primitives ---------------------------------------------------------

def test_invalid_hosts_are_never_allowed_even_by_a_matching_name():
    host = host_of("https://attacker.example\\@api.mycompany.com/")
    assert is_invalid(host)
    assert not host_allowed(host, ["api.mycompany.com", host])
    assert not host_allowed("", ["api.mycompany.com"])


def test_destination_hosts_splits_and_never_drops():
    assert destination_hosts("") == []
    assert destination_hosts("a@x.example, b@y.example") == ["x.example", "y.example"]
    hosts = destination_hosts("a@x.example,b@@y.example")
    assert hosts[0] == "x.example" and is_invalid(hosts[1])


def test_host_of_still_reads_the_ordinary_forms():
    assert host_of("https://API.MyCompany.com:8443/v1/x") == "api.mycompany.com"
    assert host_of("ceo@partner.example") == "partner.example"
    assert host_of("vault.internal.") == "vault.internal"
    assert host_of("vault.internal:8443") == "vault.internal"
    assert host_of("") == ""
    assert is_invalid(host_of("a@x.example,b@y.example"))      # one host was asked for; two were given


def test_an_unrelated_argument_name_is_not_a_destination():
    assert violations("http_request", note="https://attacker.example") == []


# ---- regression against the literal real-world bypass strings this pattern has actually used --
# (2025-10-11 research pass, see FUTURE.md) -- not new coverage, since the generic tests above
# already exercise these failure classes; this anchors them to the exact, dated incidents so the
# project's own claim ("we already defend against this") is checked against the real payload, not
# just a similar-looking one we wrote ourselves.

def test_holds_against_the_claude_code_socks5_null_byte_bypass():
    # oddguan.com, 2026-04: a JS-side allowlist matched `endsWith('.google.com')` while the OS's
    # getaddrinfo() truncated at the null byte and dialed the attacker's host. Present in Claude
    # Code v2.0.24-v2.1.89 (~130 releases), fixed silently in v2.1.90.
    host = host_of("attacker-host.com\x00.google.com")
    assert is_invalid(host)
    assert not host_allowed(host, ["google.com"])


def test_holds_against_an_empty_string_allowlist_entry():
    # the CVE-2025-66479 shape: an empty allowlist (or an allowlist containing only an empty
    # string) must never be read as "allow everything".
    assert not host_allowed("anything.example", [])
    assert not host_allowed("anything.example", [""])


def test_holds_against_multiple_recipients_hiding_an_unapproved_one():
    # the general case this project's own policy engine already relies on destination_hosts for;
    # named here against the exact "evil@x;ok@allowed" shape quoted in FUTURE.md's own notes.
    hosts = destination_hosts("evil@x.example;ok@allowed.com")
    assert "x.example" in hosts and "allowed.com" in hosts
    assert not host_allowed("x.example", ["allowed.com"])
    assert host_allowed("allowed.com", ["allowed.com"])


def test_holds_against_the_escaperoute_prefix_match_shape_applied_to_hostnames():
    # Cymulate's EscapeRoute (CVE-2025-53109/53110) is a filesystem-path prefix-match bug, not a
    # hostname one -- hosts.py doesn't do path matching, so it can't have that exact bug. This
    # checks the hostname analogue holds: "allowed.com.evil.example" (a true subdomain of
    # evil.example, not of allowed.com) is never approved by a naive substring/prefix check on
    # "allowed.com".
    assert not host_allowed("allowed.com.evil.example", ["allowed.com"])
    assert host_allowed("sub.allowed.com", ["allowed.com"])      # a true subdomain still passes
