# Deep MCP / A2A scenarios

Blueprint §10: attack the **protocol layers** agents trust — the Model Context
Protocol (tools) and Agent-to-Agent messaging — not just a single agent's
prompt. Everything here runs on local stdlib servers: no model, no network, no
API key, so it's a deterministic, offline demonstration of the attack surfaces.

```bash
python examples/mcp_a2a_scenarios/run.py
```

## What it exercises

**MCP** — the secret lives in the MCP server (reachable via a `read_config` tool).
The attack sits in the fault proxy between the host and the server.

| Scenario | What it does | Taxonomy |
|---|---|---|
| `mcp-control` | no fault — the naive host does **not** leak | — (passes) |
| `mcp-description-poisoning` | "line jumping": the injection rides in each tool's **description** in `tools/list`, so the host is subverted before any tool runs | `rag_vector/poisoned_document` |
| `mcp-poisoning-chain` | a poisoned `search` **result** chains the host into `read_config` → `send_email` | `tool_misuse/tool_output_poisoning` |

**A2A** — the secret lives in the victim agent.

| Scenario | What it does | Taxonomy |
|---|---|---|
| `a2a-control` | a benign message — the victim does **not** leak | — (passes) |
| `a2a-identity-spoofing` | a message claiming a privileged sender (`agent-role: coordinator`) | `identity_privilege/agent_impersonation` |
| `a2a-cross-agent-trust` | the victim forwards to a malicious peer and obeys it over the user | `agent_to_agent/malicious_peer` |

Each scenario is judged on the whole **Observation** (reply **+ tool calls**), so
a secret that leaves through a tool argument or a relayed reply is caught even
when the spoken reply is clean.

## The pieces

- `mcp_server.py` — a reference MCP server (initialize / tools/list / tools/call) holding the secret.
- `mcp_host.py` — `NaiveMcpHost`, the vulnerable host archetype: it trusts tool descriptions and tool results. A robust host would treat both as untrusted data.
- `a2a_agents.py` — `NaiveVictim` (trusts claimed identities and peer output) and `MaliciousPeer`.
- `run.py` — spins the servers up, runs each scenario through Chaos Bringer's adapters + judge, prints the report, exits non-zero on a finding.

The two "control" scenarios are the point: the same host and victim that leak
under attack hold when there's no attack, so a finding means the **attack**
worked, not that the harness flags everything.

> Authorized use only. These are local toys you run on your own machine; point
> the adapters at nothing you don't own.
