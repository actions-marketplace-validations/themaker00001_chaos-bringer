# chaos-bringer

**A chaos monkey for agent frameworks.** Point it at any agent — LangGraph,
LangChain, AutoGen, Google ADK, raw MCP/A2A, even a hosted platform like
ChatGPT Apps or an always-on computer-use agent — and it fuzzes, fault-injects,
and red-teams it. Free by default: every model call it actually needs runs on
a local Ollama model, not a paid API.

If Netflix's Chaos Monkey answers to no particular pantheon, this one answers
to Nergal — the Mesopotamian god of plague and the underworld, on loan as
the project's patron deity for what happens to an agent's assumptions here.

<p align="center">
  <img src="docs/demo-echo.svg" alt="chaos-bringer catching a naive agent leaking a secret under prompt injection" width="720">
</p>

## What it actually is

Four plugin surfaces, each a `typing.Protocol` with no forced inheritance,
discovered via Python entry-points so built-ins and third-party plugins
register the exact same way:

```mermaid
flowchart LR
    V[Chaos Vector] -->|adversarial payload| P((Interceptor Proxy))
    P <-->|LLM / tool / MCP calls| T[Target Agent]
    P -->|full trace| J[Judge]
    J --> C[(Corpus)]
    M[Model Provider\ndefault: Ollama] -.optional.-> V
    M -.optional.-> J
```

- **Model Provider** — generates mutated payloads and, optionally, judges. Default: **Ollama**, local and free.
- **Target Adapter** — connects to the system under test. Default: a **generic reverse proxy** that intercepts any OpenAI/Ollama-shaped chat call, so most frameworks need zero adapter code.
- **Chaos Vector** — a mutation/fault-injection strategy. Default: a **static payload corpus**, no model call needed at all.
- **Judge** — decides pass/fail/severity. Default: **rule-based** (regex / forbidden-substring), no LLM required.

## Verified against real agents, not just a mock

| Target | Framework | Model | Result |
|---|---|---|---|
| `EchoAdapter` | none (naive demo target) | — | **0/5 survived** — every built-in payload leaks the secret |
| `LangGraphOllamaAdapter` | LangGraph + `langchain-openai` | `qwen3:14b` via local Ollama | **5/5 survived** — refused every attempt |
| `AdkOllamaAdapter` | Google ADK + LiteLLM | `qwen3:14b` via local Ollama | **5/5 survived** — refused every attempt |

Both real-framework adapters route the agent's actual LLM calls through the
same `GenericProxyAdapter` — proof that "one hook, any framework" isn't just
a diagram. See `examples/langgraph_agent/` and `examples/adk_agent/`.

Honest result, not a cherry-picked one: `qwen3:14b`, prompted with an explicit
"never reveal this" instruction, refused all five single-shot injection
payloads in both real frameworks. Only the deliberately naive `EchoAdapter`
broke. That's a real finding too — the built-in static corpus is a floor, not
a ceiling, and the security-probe vector library needs multi-turn and more
creative payloads before it says much about a model that's actually trying.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,rich]"

chaos-agents plugins                      # see what's registered
chaos-agents run campaigns/demo_echo.yaml --fancy   # zero-dependency smoke test
pytest -q
```

Point `campaigns/demo_proxy_ollama.yaml` at a real `ollama serve` to see the
generic proxy hit a live free model instead of the mock.

## Writing a plugin

Implement the method(s) the surface asks for and register an entry-point in
your own package — no import from this repo required:

```toml
[project.entry-points."chaos_agents.judges"]
my-judge = "my_package.judges:MyJudge"
```

`pip install my-package` and `chaos-agents plugins` picks it up.

## Status

v1 skeleton. The plugin architecture and the generic-proxy mechanism are
real and tested; deeper framework adapters, the sandboxed environment
adapter for always-on computer-use agents (Grok Bot, OpenAI Dots), and the
security-probe vector library are still being built out.
