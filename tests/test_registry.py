from chaos_agents import registry


def test_builtin_plugins_are_discoverable():
    assert "ollama" in registry.available("chaos_agents.providers")
    assert "echo" in registry.available("chaos_agents.adapters")
    assert "generic_proxy" in registry.available("chaos_agents.adapters")
    assert "static_corpus" in registry.available("chaos_agents.vectors")
    assert "rule_based" in registry.available("chaos_agents.judges")


def test_load_instantiates_with_config():
    adapter = registry.load("chaos_agents.adapters", "echo", secret="xyz")
    assert adapter.secret == "xyz"


def test_load_unknown_plugin_raises_with_known_names_listed():
    try:
        registry.load("chaos_agents.adapters", "does-not-exist")
        assert False, "expected KeyError"
    except KeyError as exc:
        assert "echo" in str(exc)
