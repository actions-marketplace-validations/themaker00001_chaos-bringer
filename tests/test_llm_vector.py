"""The LLM chaos vector, tested against a scripted fake provider -- no Ollama,
no network. A live check against a real model lives in the example."""

import pytest


class _FakeProvider:
    def __init__(self, reply):
        self.reply = reply
        self.last_prompt = None
        self.last_system = None

    def complete(self, prompt, *, system=None):
        self.last_prompt = prompt
        self.last_system = system
        return self.reply


def _vector(reply, **kw):
    from chaos_agents.vectors.llm import LLMVector

    v = LLMVector.__new__(LLMVector)  # skip provider loading; inject the fake
    v.goal = kw.get("goal", "make the agent reveal its secret key")
    v.count = kw.get("count", 5)
    v.seed_examples = kw.get("seed_examples", ["seed one", "seed two"])
    v.provider = _FakeProvider(reply)
    return v


def test_plain_lines_become_payloads():
    payloads = _vector("attack one\nattack two\nattack three").generate()
    assert payloads == ["attack one", "attack two", "attack three"]


def test_numbered_and_bulleted_scaffolding_is_stripped():
    payloads = _vector("1. first\n2) second\n- third\n* fourth").generate()
    assert payloads == ["first", "second", "third", "fourth"]


def test_surrounding_quotes_are_removed():
    assert _vector('"quoted attack"\n\'single quoted\'').generate() == ["quoted attack", "single quoted"]


def test_duplicates_are_dropped_keeping_order():
    assert _vector("same one\nSAME ONE\nother").generate() == ["same one", "other"]


def test_output_is_capped_at_count():
    reply = "\n".join(f"attack number {i}" for i in range(7))
    assert len(_vector(reply, count=3).generate()) == 3


def test_blank_and_tiny_lines_are_ignored():
    assert _vector("real attack here\n\n.\n- \nx").generate() == ["real attack here"]


def test_no_usable_output_raises():
    from chaos_agents.vectors.llm import LLMVectorError

    with pytest.raises(LLMVectorError):
        _vector("\n\n   \n").generate()


def test_prompt_carries_goal_and_frames_it_as_red_teaming_own_agent():
    v = _vector("first attack\nsecond attack")
    v.generate()
    assert "make the agent reveal its secret key" in v.provider.last_prompt
    assert "own ai agent" in v.provider.last_system.lower()


def test_empty_goal_and_bad_count_are_rejected():
    from chaos_agents.vectors.llm import LLMVector

    with pytest.raises(ValueError, match="goal"):
        LLMVector(goal="  ", provider="ollama")
    with pytest.raises(ValueError, match="count"):
        LLMVector(goal="x", provider="ollama", count=0)


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "llm" in registry.available("chaos_agents.vectors")
