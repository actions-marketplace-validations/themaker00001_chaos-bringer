"""The attack taxonomy: how an agent can be compromised, organised into
families and techniques, so coverage is measurable instead of a loose bag of
prompts. Aligned with OWASP's LLM / Agentic guidance (see docs/RESULTS.md and
the V2 blueprint). Every finding carries a `category` (family) and a
`technique`, which drives fingerprinting, reporting, and the regression corpus.

This is a registry, not an enum, so third-party plugins can validate their own
tags against it without importing a rigid type.
"""

from __future__ import annotations

# family -> the techniques that belong to it. Keep keys stable: they appear in
# persisted findings, fingerprints, SARIF rule ids, and the corpus layout.
TAXONOMY: dict[str, tuple[str, ...]] = {
    "goal_hijack": (
        "direct", "indirect", "multi_turn", "authority_spoofing",
        "encoded_translated", "instruction_collision",
    ),
    "sensitive_data": (
        "secret_extraction", "system_prompt_leakage",
        "memory_context_leakage", "cross_user_leakage",
    ),
    "tool_misuse": (
        "tool_output_poisoning", "argument_mutation",
        "unsafe_selection", "schema_manipulation",
    ),
    "identity_privilege": (
        "over_privileged_tool", "confused_deputy",
        "agent_impersonation", "privilege_escalation",
    ),
    "agent_to_agent": (
        "malicious_peer", "delegation_abuse",
        "message_tampering", "cascading_failure",
    ),
    "rag_vector": (
        "poisoned_document", "retrieval_collision",
        "metadata_isolation", "embedding_weakness",
    ),
    "availability_cost": (
        "token_amplification", "loops", "tool_call_storms", "timeout_latency",
    ),
    "output_handling": (
        "unsafe_structured_output", "shell_sql_url_injection", "renderer_abuse",
    ),
    "supply_chain": (
        "malicious_tool_metadata", "dependency_model_mismatch",
    ),
}

# Not an attack family -- a slot for outcomes that aren't a confirmed security
# result, so they never masquerade as one (see the "inconclusive" status).
OPERATIONAL = "operational"
OPERATIONAL_TECHNIQUES = ("target_error", "judge_error")

CATEGORIES: tuple[str, ...] = tuple(TAXONOMY) + (OPERATIONAL,)


def techniques(category: str) -> tuple[str, ...]:
    if category == OPERATIONAL:
        return OPERATIONAL_TECHNIQUES
    return TAXONOMY.get(category, ())


def is_valid(category: str, technique: str | None = None) -> bool:
    """True if `category` is a known family (or operational), and -- when a
    technique is given -- it belongs to that family."""
    if category not in CATEGORIES:
        return False
    if technique is None:
        return True
    return technique in techniques(category)


def validate(category: str, technique: str | None = None) -> None:
    """Raise ValueError for an unknown category/technique. Use at config/
    construction time so a typo'd tag fails loudly, not silently."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown attack category {category!r}; known: {', '.join(CATEGORIES)}")
    if technique is not None and technique not in techniques(category):
        raise ValueError(
            f"technique {technique!r} is not part of category {category!r}; "
            f"known: {', '.join(techniques(category)) or '(none)'}"
        )
