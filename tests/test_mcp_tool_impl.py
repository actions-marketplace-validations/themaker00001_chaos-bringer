"""MCP sandboxed-tool implementation bugs: deterministic, no model needed -- tests the tool
implementations themselves, not a model's decision to call them."""

from chaos_agents.adapters.mcp_tool_impl import DEFAULT_ALLOWED_DIR, McpToolImplementationAdapter


# ---- CVE-2025-53109/53110-style: naive prefix match -----------------------------------------

def test_a_file_truly_inside_the_allowed_dir_is_fine():
    obs = McpToolImplementationAdapter().observe("read:/data/public/notes.txt")
    assert obs.tool_calls[0].result.startswith("contents of")
    assert obs.raw["escaped_scope"] is False


def test_vulnerable_by_default_a_sibling_directory_passes_the_naive_prefix_check():
    # "/data/public_secrets" is NOT inside "/data/public" -- it just shares the string prefix
    obs = McpToolImplementationAdapter().observe("read:/data/public_secrets/file")
    assert obs.tool_calls[0].result.startswith("contents of")   # the bug: it reads it anyway
    assert obs.raw["escaped_scope"] is True


def test_safe_path_check_refuses_the_sibling_directory():
    obs = McpToolImplementationAdapter(safe_path_check=True).observe("read:/data/public_secrets/file")
    assert obs.tool_calls[0].result.startswith("refused")
    assert obs.raw["escaped_scope"] is False   # never got the chance to escape


def test_safe_path_check_still_allows_the_legitimate_directory():
    obs = McpToolImplementationAdapter(safe_path_check=True).observe("read:/data/public/notes.txt")
    assert obs.tool_calls[0].result.startswith("contents of")


def test_the_allowed_dir_itself_with_no_trailing_segment_is_allowed():
    obs = McpToolImplementationAdapter(safe_path_check=True).observe(f"read:{DEFAULT_ALLOWED_DIR}")
    assert obs.tool_calls[0].result.startswith("contents of")


# ---- CVE-2025-53372-style: unsanitized string interpolation ---------------------------------

def test_an_ordinary_command_is_fine():
    obs = McpToolImplementationAdapter().observe("exec:ls -la")
    assert obs.raw["escaped_scope"] is False


def test_vulnerable_by_default_a_quote_breaks_out_of_the_intended_quoting():
    obs = McpToolImplementationAdapter().observe("exec:'; cat /etc/passwd; echo '")
    assert obs.raw["escaped_scope"] is True
    assert "cat /etc/passwd" in obs.tool_calls[0].result   # the raw, unescaped command made it through


def test_safe_exec_escapes_the_quote():
    obs = McpToolImplementationAdapter(safe_exec=True).observe("exec:'; cat /etc/passwd; echo '")
    assert obs.raw["escaped_scope"] is False
    assert "'\\''" in obs.tool_calls[0].result   # properly escaped, not interpolated raw


# ---- plumbing --------------------------------------------------------------------------------

def test_an_unrecognized_request_is_refused_cleanly():
    obs = McpToolImplementationAdapter().observe("delete everything")
    assert obs.tool_calls == []
    assert "Unrecognized" in obs.response


def test_invoke_returns_just_the_reply():
    assert McpToolImplementationAdapter().invoke("read:/data/public/x").startswith("contents of")


def test_repr_shows_the_fix_state():
    r = repr(McpToolImplementationAdapter(safe_path_check=True, safe_exec=True))
    assert "safe_path_check=True" in r and "safe_exec=True" in r


def test_registered_as_a_plugin():
    from chaos_agents import registry

    assert "mcp_tool_impl" in registry.available("chaos_agents.adapters")


def test_the_campaign_is_a_finding_through_the_real_pipeline(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_mcp_tool_impl.yaml")
    campaign.check_plugins()
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert any(r.status == FAIL for r in records)


def test_the_campaign_passes_once_both_fixes_are_applied(tmp_path):
    from chaos_agents.campaign import Campaign
    from chaos_agents.corpus import Corpus
    from chaos_agents.interfaces import FAIL
    from chaos_agents.orchestrator import run_campaign

    campaign = Campaign.from_yaml("campaigns/demo_mcp_tool_impl.yaml")
    campaign.adapter.config.update({"safe_path_check": True, "safe_exec": True})
    records = run_campaign(campaign, Corpus(campaign.name, root=tmp_path))
    assert not any(r.status == FAIL for r in records)
