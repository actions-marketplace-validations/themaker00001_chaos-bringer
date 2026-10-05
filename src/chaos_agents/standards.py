"""Where a finding sits in the two frameworks security teams already report against.

* OWASP Top 10 for Agentic Applications (2026), ASI01-ASI10 -- the *risk* the
  attack exercises.
* MITRE ATLAS -- the adversary *technique* it corresponds to.

A finding already carries a taxonomy ``category`` and ``technique``; this module
maps every (category, technique) pair to the framework entries that describe
it, so a finding can be filed against an existing control or compliance
register without a translation step.

The map errs on the side of leaving a slot empty. An ATLAS technique is listed
only if it was confirmed against the published matrix and is a direct fit; an
attack with no good ATLAS entry (agent-to-agent traffic, for one) maps to
nothing rather than to the nearest-sounding ID. OWASP's agentic list has no
entry for data leakage as such, so those findings are tagged with the risk that
*caused* them (ASI01, the injected instruction; ASI06, a poisoned memory).

The mapping is stamped onto each Record when it is produced, so a stored trace
keeps the tags it was filed under even if this table is refined later. Older
traces without tags are mapped on read (``tags_for``).
"""

from __future__ import annotations

from chaos_agents.corpus import Record

OWASP_NAME = "OWASP Top 10 for Agentic Applications (2026)"
ATLAS_NAME = "MITRE ATLAS"

OWASP: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# every ID here was checked against the published ATLAS matrix; do not add one
# that hasn't been
ATLAS: dict[str, str] = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
}

# (category, technique) -> (OWASP ids, ATLAS ids)
_MAP: dict[tuple[str, str], tuple[tuple[str, ...], tuple[str, ...]]] = {
    ("goal_hijack", "direct"): (("ASI01",), ("AML.T0051.000",)),
    ("goal_hijack", "indirect"): (("ASI01",), ("AML.T0051.001",)),
    ("goal_hijack", "multi_turn"): (("ASI01",), ("AML.T0051", "AML.T0054")),
    ("goal_hijack", "authority_spoofing"): (("ASI01",), ("AML.T0051",)),
    ("goal_hijack", "encoded_translated"): (("ASI01",), ("AML.T0051", "AML.T0068")),
    ("goal_hijack", "instruction_collision"): (("ASI01",), ("AML.T0051",)),

    ("sensitive_data", "secret_extraction"): (("ASI01",), ("AML.T0057",)),
    ("sensitive_data", "system_prompt_leakage"): (("ASI01",), ("AML.T0056",)),
    ("sensitive_data", "memory_context_leakage"): (("ASI06",), ("AML.T0057",)),
    ("sensitive_data", "cross_user_leakage"): (("ASI06",), ("AML.T0057",)),
    ("sensitive_data", "tool_exfiltration"): (("ASI01", "ASI02"), ("AML.T0086", "AML.T0057")),

    ("tool_misuse", "tool_output_poisoning"): (("ASI01", "ASI02"), ("AML.T0051.001", "AML.T0053")),
    ("tool_misuse", "argument_mutation"): (("ASI02",), ("AML.T0053",)),
    ("tool_misuse", "unsafe_selection"): (("ASI02",), ("AML.T0053",)),
    ("tool_misuse", "schema_manipulation"): (("ASI02",), ("AML.T0053",)),

    ("identity_privilege", "over_privileged_tool"): (("ASI03",), ("AML.T0053",)),
    ("identity_privilege", "confused_deputy"): (("ASI03",), ("AML.T0053",)),
    ("identity_privilege", "agent_impersonation"): (("ASI03", "ASI07"), ()),
    ("identity_privilege", "privilege_escalation"): (("ASI03",), ("AML.T0053",)),

    ("agent_to_agent", "malicious_peer"): (("ASI07",), ()),
    ("agent_to_agent", "delegation_abuse"): (("ASI07", "ASI03"), ()),
    ("agent_to_agent", "message_tampering"): (("ASI07",), ()),
    ("agent_to_agent", "cascading_failure"): (("ASI08",), ()),

    ("rag_vector", "poisoned_document"): (("ASI06",), ("AML.T0070", "AML.T0051.001")),
    ("rag_vector", "retrieval_collision"): (("ASI06",), ("AML.T0070",)),
    ("rag_vector", "metadata_isolation"): (("ASI06",), ()),
    ("rag_vector", "embedding_weakness"): (("ASI06",), ()),

    ("availability_cost", "token_amplification"): ((), ("AML.T0034",)),
    ("availability_cost", "loops"): (("ASI08",), ("AML.T0029",)),
    ("availability_cost", "tool_call_storms"): (("ASI08",), ("AML.T0029",)),
    ("availability_cost", "timeout_latency"): ((), ("AML.T0029",)),

    ("output_handling", "unsafe_structured_output"): ((), ()),
    ("output_handling", "shell_sql_url_injection"): (("ASI05",), ()),
    ("output_handling", "renderer_abuse"): ((), ("AML.T0067",)),

    ("supply_chain", "malicious_tool_metadata"): (("ASI04",), ("AML.T0010",)),
    ("supply_chain", "dependency_model_mismatch"): (("ASI04",), ("AML.T0010",)),
}


def owasp_for(category: str, technique: str) -> list[str]:
    return list(_MAP.get((category, technique), ((), ()))[0])


def atlas_for(category: str, technique: str) -> list[str]:
    return list(_MAP.get((category, technique), ((), ()))[1])


def tags_for(record: Record) -> tuple[list[str], list[str]]:
    """The (OWASP, ATLAS) tags for a record: the ones stamped when it was
    produced, else mapped from its category/technique (an older trace)."""
    return (record.owasp or owasp_for(record.category, record.technique),
            record.mitre_atlas or atlas_for(record.category, record.technique))


def label(framework_id: str) -> str:
    """'ASI01' -> 'ASI01 Agent Goal Hijack'; an unknown id comes back as is."""
    name = OWASP.get(framework_id) or ATLAS.get(framework_id)
    return f"{framework_id} {name}" if name else framework_id


def summary(record: Record) -> str:
    """One line for a report: 'OWASP ASI01, ASI02 · ATLAS AML.T0086'. Empty if untagged."""
    owasp, atlas = tags_for(record)
    parts = ([f"OWASP {', '.join(owasp)}"] if owasp else []) + ([f"ATLAS {', '.join(atlas)}"] if atlas else [])
    return " · ".join(parts)


def sarif_taxonomies(used_owasp: set[str], used_atlas: set[str]) -> list[dict]:
    """SARIF `taxonomies` entries for the frameworks a run actually used."""
    def component(name: str, org: str, names: dict[str, str], used: set[str]) -> dict:
        return {
            "name": name, "organization": org,
            "taxa": [{"id": i, "name": names[i], "shortDescription": {"text": names[i]}} for i in sorted(used)],
        }
    out = []
    if used_owasp:
        out.append(component(OWASP_NAME, "OWASP GenAI Security Project", OWASP, used_owasp))
    if used_atlas:
        out.append(component(ATLAS_NAME, "MITRE", ATLAS, used_atlas))
    return out
