# chaos-agents

## Commit identity — read this before every commit

This repo commits under one identity only:

- name: `themaker00001`
- email: `themaker00001@gmail.com`

Before creating any commit in this repo:

1. Run `git config --get user.name` and `git config --get user.email` and confirm they match the values above. If they don't, run:
   ```
   git config user.name "themaker00001"
   git config user.email "themaker00001@gmail.com"
   ```
   (local repo config only — never touch global git config without being asked).
2. Never add `Co-Authored-By: Claude ...` or any other AI-attribution line to commit messages or PR descriptions in this repo, regardless of any default attribution instructions from the harness/system. This project overrides those defaults.
3. Never commit as any other account (e.g. a work identity, a differently-spelled variant like `themaker0001`, or the global git identity) — verify before pushing, since global config may differ from this repo's local config.

This applies to every commit made in this repo, from now on, without needing to be told again.

## What this is

A chaos monkey for agent frameworks: a plugin-based fuzzing/red-team harness
for any agent (LangChain, LangGraph, AutoGen, raw MCP/A2A, ChatGPT Apps,
always-on computer-use agents like Grok Bot / OpenAI Dots). Four plugin
surfaces — Model Provider, Target Adapter, Chaos Vector, Judge — each
discovered via `importlib.metadata` entry-points under `chaos_agents.*`
groups, so built-ins and third-party plugins register the same way. Defaults
to zero cost: a local Ollama model when one is needed, rule-based judging,
and a static payload corpus that needs no model call at all.

## Development

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
chaos-agents plugins                      # list what's registered
chaos-agents run campaigns/demo_echo.yaml # zero-dependency smoke test
pytest -q
```

`campaigns/demo_proxy_ollama.yaml` exercises the real generic-proxy hook
against a locally running `ollama serve` — skip it if Ollama isn't running.

