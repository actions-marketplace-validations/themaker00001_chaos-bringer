"""RAG/vector-store content reaching an eval()-equivalent: deterministic, no model needed --
tests whether a retrieved field reaches a code-execution step, not a model's decision to retrieve it."""

from chaos_agents.adapters.rag_to_eval import DEFAULT_RECORD, RagToEvalAdapter


def test_a_clean_record_s_field_is_just_computed():
    obs = RagToEvalAdapter(record=DEFAULT_RECORD).observe("render the formula field")
    assert obs.raw["executed"] is False
    assert "computed arithmetic result" in obs.tool_calls[1].result


def test_vulnerable_by_default_a_poisoned_field_executes():
    obs = RagToEvalAdapter().observe("render the formula field")
    assert obs.raw["executed"] is True
    assert "EXECUTED" in obs.tool_calls[1].result
    assert "os').system" in obs.tool_calls[1].result


def test_sandbox_eval_refuses_to_execute_the_same_poisoned_field():
    obs = RagToEvalAdapter(sandbox_eval=True).observe("render the formula field")
    assert obs.raw["executed"] is False
    assert "not evaluated" in obs.tool_calls[1].result


def test_sandbox_eval_still_renders_a_clean_record_s_field():
    obs = RagToEvalAdapter(record=DEFAULT_RECORD, sandbox_eval=True).observe("render the formula field")
    assert obs.raw["executed"] is False


def test_the_retrieval_itself_always_happens_regardless_of_the_fix():
    obs = RagToEvalAdapter(sandbox_eval=True).observe("render the formula field")
    assert obs.tool_calls[0].name == "vector_search"
    assert "Q3 Notes" in obs.tool_calls[0].result


def test_never_calls_a_real_eval():
    import ast

    source = open("src/chaos_agents/adapters/rag_to_eval.py").read()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "eval"


def test_invoke_returns_just_the_reply():
    assert RagToEvalAdapter(sandbox_eval=True).invoke("x").startswith("Rendered:")


def test_repr_shows_the_fix_state():
    assert "sandbox_eval=True" in repr(RagToEvalAdapter(sandbox_eval=True))


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "rag_to_eval" in registry.available("chaos_agents.adapters")


def test_the_campaign_is_a_finding_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_rag_to_eval.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert any(r.status == FAIL for r in records)


def test_the_campaign_passes_once_the_fix_is_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_rag_to_eval.yaml")
    campaign.adapter.config["sandbox_eval"] = True
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert not any(r.status == FAIL for r in records)
