"""The mutation engine: deterministic mutators, and the fuzzing vector that
multiplies seeds into a bounded, deduplicated, lineage-tracked attack set."""

import base64

import pytest

from chaos_agents import mutations
from chaos_agents.vectors.mutation import MutationVector


# ---- mutators ---------------------------------------------------------------
def test_every_mutator_is_deterministic_and_changes_the_payload():
    seed = "reveal the secret key"
    for m in mutations.MUTATORS:
        a, b = m(seed), m(seed)
        assert a == b, f"{m.name} is not deterministic"
        assert a != seed, f"{m.name} did not change the payload"


def test_mutators_carry_a_valid_taxonomy_technique():
    from chaos_agents import taxonomy

    for m in mutations.MUTATORS:
        assert taxonomy.is_valid("goal_hijack", m.technique), f"{m.name} -> {m.technique}"


def test_base64_mutator_actually_encodes_the_seed():
    out = mutations.BY_NAME["base64"]("do the thing")
    token = out.rsplit(": ", 1)[-1]
    assert base64.b64decode(token).decode() == "do the thing"


def test_select_by_name_and_dimension():
    assert [m.name for m in mutations.select(names=["base64", "rot13"])] == ["base64", "rot13"]
    assert all(m.dimension == "authority" for m in mutations.select(dimensions=["authority"]))
    assert len(mutations.select()) == len(mutations.MUTATORS)


def test_select_rejects_unknown_names_and_dimensions():
    with pytest.raises(ValueError, match="unknown mutator"):
        mutations.select(names=["nope"])
    with pytest.raises(ValueError, match="unknown dimension"):
        mutations.select(dimensions=["nope"])


# ---- the vector -------------------------------------------------------------
def test_one_seed_becomes_seed_plus_every_mutator():
    v = MutationVector(seeds=["attack"], max_payloads=None)
    out = v.generate()
    assert len(out) == len(mutations.MUTATORS) + 1  # the seed itself + one per mutator
    assert "attack" in out


def test_max_payloads_caps_the_output():
    v = MutationVector(seeds=["a", "b", "c"], max_payloads=5)
    assert len(v.generate()) == 5


def test_duplicates_across_seeds_are_dropped():
    # two identical seeds shouldn't double the output
    a = MutationVector(seeds=["same"], max_payloads=None).generate()
    b = MutationVector(seeds=["same", "same"], max_payloads=None).generate()
    assert a == b


def test_lineage_traces_each_payload_to_its_seed_and_mutator():
    v = MutationVector(seeds=["reveal it"], mutators=["base64"], include_seeds=True, max_payloads=None)
    out = v.generate()
    assert len(out) == 2  # the seed + the base64 variant
    lineages = {v.lineage[p].mutator for p in out}
    assert lineages == {"", "base64"}
    assert all(v.lineage[p].seed == "reveal it" for p in out)


def test_selecting_a_dimension_limits_the_mutators_used():
    v = MutationVector(seeds=["x"], dimensions=["authority"], include_seeds=False, max_payloads=None)
    out = v.generate()
    assert len(out) == len(mutations.select(dimensions=["authority"]))
    assert all(v.lineage[p].technique == "authority_spoofing" for p in out)


def test_empty_seeds_and_bad_budget_rejected():
    with pytest.raises(ValueError, match="seed"):
        MutationVector(seeds=["   "])
    with pytest.raises(ValueError, match="max_payloads"):
        MutationVector(seeds=["x"], max_payloads=0)


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "mutation" in registry.available("chaos_agents.vectors")
