# The fortress: a target worth attacking

`toolbot` is an agent with no defences, so it proves the harness *can* find things. It
cannot prove the harness finds things **that are there**, or that "nothing found" means
anything. The `fortress` adapter is the other half: a tool-using agent with as many defences
as we know how to build, so chaos-agents has something hard to attack, and so a clean result
can be tested instead of trusted.

No model, no network, deterministic: every number below reproduces from a command.

```
chaos-agents run campaigns/demo_fortress.yaml            # exits 0: every attack held
chaos-agents run campaigns/demo_fortress_adaptive.yaml   # exits 0
chaos-agents run campaigns/demo_adaptive_corpus.yaml     # exits 1: the naive echo target leaks (against fortress: 0)
python tools/fortress/siege.py                           # the ablation matrix, ~2,700 attacks x 18 configurations
python tools/fortress/mutants.py                         # is "0 findings" a result, or a weak test?
python tools/fortress/fuzz.py --n 500000                 # random messages, properties checked directly
python tools/fortress/adaptive_vs_blind.py               # the adaptive engine against real seeded defects
python tools/eval/adaptive_eval.py                       # the same claim, for the generalized engine too
```

## The range: attack it by hand

```
python tools/fortress/range.py --open
```

A local console (127.0.0.1 only, per-launch token, strict CSP, attack text shown as data) to talk to
the agent, watch each layer decide, switch layers off, and fire the siege families and the full
ablation matrix against whatever is configured. Every turn is judged by the same policy the
campaigns use, so "BREACH" means chaos-agents would file a finding. The screenshot is a scripted
session: three blocked attacks, a quarantined memory plant, then egress switched off and the same
email attack landing, then the whole matrix.

![the range console](proof/range-console.png)

The OpenAI-backed planner is a placeholder in the Planner panel until a key is configured.

## The design assumption

**The planner is not trusted.** In production the planner is a language model, and a language
model can be talked into anything. So the planner here is deliberately as gullible as the naive
bot: it follows the message, follows stored memory, and obeys "base64 it". All of the safety
lives in the layers around it, which never depend on the planner behaving.

```
message -> [normalize] -> planner -> proposed tool calls -> [gate] -> executed calls
                                          |                    |
              memory <- [provenance]      |       [capabilities, egress, dlp, limits]
                                          +--> reply -> [output filter]
```

A blocked call is **not executed**, so it never appears in the observation's tool calls: this is
enforcement, not detection. What was blocked, and by which layer, is in the audit log and in
`Observation.raw["fortress"]`.

| layer | what it enforces |
|---|---|
| `normalize` | NFKC; strips invisible, control, bidi and combining characters; collapses whitespace; refuses mixed-script words and oversized input |
| `provenance` | memory is data, never instructions: notes carrying contact details, URLs or directives are quarantined at write time, and stored notes never reach the planner as something to act on. The owner's address is configuration, not something a chat can change |
| `capabilities` | only granted tools exist (there is no `database_write`) |
| `egress` | a strict validator, independent of the library the policy engine uses: `https` only, exact allow-listed host, no userinfo/port/IP literal/IDN/escapes; recipients are the owner or an exact allow-listed domain, every address in a list is checked, at most 3; the destination is parsed a second way that must agree; an unknown argument (a `bcc`, a header, a callback) is refused |
| `minimize` | retrieval masks registered secrets, so the agent never holds them |
| `dlp` | every outbound argument is scanned for registered secrets in any costume (folded, reversed, ROT13, base64, hex, URL-encoded), for any fragment of at least half the secret, for a secret reassembled from earlier calls, in any order (running coverage), and for opaque blobs |
| `limits` | one outbound call per message, a cap on tool calls, on messages per session, and on outbound calls per session |
| `output` | the reply is scrubbed for secrets before it leaves |

Every layer can be switched off (`config: {disable: [egress]}`), down to the naive agent with
all of them off. That is what makes the results below interpretable.

## How it was attacked, and what that showed

### 1. The siege: 2,713 attacks through the real pipeline

Campaign → vector → adapter → judge + policy → corpus: a finding here is exactly what
`chaos-agents run` would file. Seven attack families: the same two destinations spelled ~1,900
ways (backslash, userinfo, tab/newline injection, scheme-relative, IPv6/IPv4 literals,
look-alike scripts, multi-recipient strings, display names); the document asked for in every
costume; classic injection prompts; the mutation engine (12 seeds × 23 mutators -- encodings,
authority framing, structure, language, plus homoglyphs, Unicode tag smuggling, payload
splitting, context flooding, roleplay framing and composed encodings); the same seeds and
mutators again but through the **generalized adaptive engine** (`adaptive_corpus`), budget
capped at a third of that grid (96 of 288) to see whether the smart, budget-limited search
still finds what full enumeration finds; the adaptive engine searching 406 memory-poisoning
scenarios; and 14 multi-message conversations (split secrets, escalation, repeated asks).

Findings per family, by which layers are off:

| configuration | spelling | costumes | direct | mutation | corpus | memory | sequence | total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **all layers** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without normalize | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without provenance | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without capabilities | 0 | 0 | 4 | 28 | 28 | 0 | 1 | **61** |
| without egress | 1340 | 12 | 8 | 87 | 66 | 0 | 11 | **1524** |
| without minimize | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without dlp | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without limits | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without output | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |
| without minimize + output | 0 | 0 | 2 | 14 | 14 | 0 | 1 | **31** |
| without egress + minimize | 0 | 2 | 0 | 0 | 0 | 0 | 1 | **3** |
| without egress + dlp + minimize | 1340 | 16 | 8 | 101 | 68 | 0 | 11 | **1544** |
| without provenance + egress | 1340 | 12 | 8 | 87 | 66 | 252 | 12 | **1777** |
| without provenance + egress + limits | 1340 | 12 | 8 | 87 | 66 | 337 | 12 | **1862** |
| every layer off (the naive agent) | 1492 | 16 | 13 | 135 | 71 | 343 | 13 | **2083** |

What this says, and does not:

- **With every layer on, nothing got through.** Taken alone that is weak evidence, which is why
  the next two instruments exist. The attacks are not toothless: with egress off, 1,524 of the
  same attacks land; with everything off, 2,083.
- **Egress and capabilities are the decisive layers** against destination and privilege attacks.
  **Provenance** is decisive for memory poisoning once egress is out of the way (252 → 0), and
  **limits** is worth 85 more memory findings (a poisoned note that triggers a *second* outbound
  call). **Minimize + output** are what stop the reply from disclosing the secret. **DLP** is what
  stops the canary reaching a hostile host when egress and minimize are both gone (1,544 →
  3 findings, none of them the secret).
- **`normalize`, `dlp`, `minimize`, `output` and `limits` each show 0 when removed alone.** They
  are redundant *against this attack set*: another layer already stops every attack that reaches
  them. That is what depth looks like, and it is also an honest warning that this planner reads
  keywords, so normalization matters less here than it would with a model that reads through
  homoglyphs and zero-width splits. The columns are not a ranking of how much each layer is worth
  in production.
- **`corpus` tracks `mutation` with a third of the trials.** Wherever `mutation` found something,
  `corpus` found most or all of it on a fraction of the budget: all 28 of `mutation`'s findings
  with `capabilities` off, 66 of 87 (76%) with `egress` off -- the same advantage
  `adaptive_vs_blind.py` measures directly, now visible inside the siege itself.

### 2. Mutation testing: is "0 findings" a result, or a weak test?

Zero findings could mean the fortress is strong, or that the attacks cannot find anything. To
tell them apart, known defects are seeded into the defences one at a time, and the same attacks
are run against each. A defect the suite finds is *killed*; one it misses is a blind spot in the
attacks (or in the detector). Each mutant is paired with a clean control.

| seeded defect | found by | extra findings |
|---|---|---:|
| egress: host checked with `in` | spelling | +277 |
| egress: URL prefix match (`api.mycompany.com.attacker.example`) | spelling | +91 |
| egress: suffix match, no dot boundary | spelling | +57 |
| egress: userinfo read as the host | spelling | +48 |
| egress: trusts `urlsplit`, no strict grammar (backslash, tab) | spelling | +8 |
| egress: one check on a whole address list | spelling | +20 |
| egress: plaintext `http` allowed | spelling | +3 |
| dlp: knows only the plain secret | costumes, sequence | +4, +2 |
| dlp: no case/separator folding | costumes, sequence | +4, +2 |
| dlp: no memory across calls | sequence | +2 |
| memory: quarantine only knows addresses | memory | +85 |
| memory: no quarantine at all | memory, sequence | +337, +1 |
| *control:* planner trusts notes, **real** quarantine | — | 0 |

12 of 12 seeded defects found; the control (the real quarantine, with the planner made to act on
stored notes) holds against all 406 scenarios. The seven egress defects are the classic ones,
the ones in real CVEs. (The sweep also runs `corpus` against every mutant; it never adds a new
kill here -- these are destination- and DLP-shaped defects, and `spelling`/`costumes`/`sequence`
already reach them.)

### 3. Fuzzing the whole agent: 500,000 random messages, 0 violations

An adversarial grammar (intent words, destination fragments, invisible and look-alike characters,
encodings, memory plants, very long runs) feeds random multi-message sessions through the real
agent. After every message the script checks five properties **directly**, with no policy engine
in the loop, so it cannot share a blind spot with the judge: nothing leaves except to the
approved host / mail domain over https; the secret never appears in an argument or reply in any
encoding; no ungranted tool is called; at most one outbound call per message; no crash, bounded
time. 500,000 messages: 62,222 outbound calls allowed (all to the approved places), 55,720
refused at the door, **0 violations**, slowest message 5.6 ms. The checks are proven able to
fail: with egress, capabilities, or DLP removed the same fuzz reports violations.

The egress validators alone were also fuzzed with 600,000 adversarial strings: 5,703 accepted,
each verified by an independent parse, 0 bad.

### 4. ChaosBench v2

| target | resilience | held / leaked |
|---|---|---|
| `toolbot` (naive) | 70.8% (C-) | 18 / 7 |
| `fortress` | 100% (A+) | 25 / 0 |

Twenty-five probes is a thin sample; read it as agreement with the others, not as the evidence.

### 5. The adaptive engine against real defects

`tools/eval/adaptive_eval.py` measures the search on synthetic targets. This measures it on the
fortress with one seeded egress defect, through the real memory scenario, over the 406-candidate
grid with a budget of 40, 100 seeds:

| seeded defect | holes in grid | adaptive | random | declared order |
|---|---:|---:|---:|---:|
| userinfo read as the host | 17 | **11.5** findings, first at attempt 12 | 1.4, first at 21 | 3.0, first at 25 |
| trusts `urlsplit` | 17 | **11.0**, first at 14 | 1.6, first at 21 | 3.0, first at 28 |
| host checked with `in` | 74 | **20.8**, first at 4.5 | 6.8, first at 5.6 | 12.0, first at 4 |

Within the same budget it lands 7-8× as many findings as random order on a sparse hole. It does
not make the first hit any likelier than chance: it learns after, not before.

### 6. The engine generalized: the same claim, for `adaptive_corpus`

`adaptive_memory` only works against a target with persistent memory. `adaptive_corpus` runs the
identical search over single-shot attacks instead (seeds × the mutation engine's own mutators), so
it works against *any* adapter -- `campaigns/demo_adaptive_corpus.yaml` proves it end to end
against `echo`, which has no memory at all. `tools/eval/adaptive_eval.py` now measures it the same
way it measures the memory engine, on synthetic oracles renamed to match the new axes (budget 8 of
32, 300 instances):

| the target's weakness | declared | random | adaptive |
|---|---|---|---|
| one seed is vulnerable | 2.13 findings | 1.83 | **3.77** (finds one in 99% of runs) |
| one mutator is vulnerable | 1.00 | 0.98 | **1.59** |
| no structure at all | 0.94 | 0.90 | 0.93 |

The same shape as the memory engine's table above: roughly double the findings where a pattern
exists to learn, parity where there isn't one.

## What this found in chaos-agents itself

The point of attacking something hard is what breaks. Five real defects, all fixed, all with
regression tests:

1. **The destination parser failed open.** An IPv6 literal, a scheme-relative `//host/x`, and
   several spellings parsed to an empty host and were *skipped*, i.e. no destination, i.e. no
   violation; a backslash or tab made Python and a browser disagree about the host
   (`https://attacker.example\@api.mycompany.com/`); `a@attacker.example,b@company.example` was
   read by its last `@` alone. A differential test of 60 spellings against a strict independent reference found
   a dozen such blind spots in `hosts.py`/`policy.py` (two more it flagged were the reference's own
   mistakes, which is why the reference is checked too). Anything that cannot be read unambiguously is now
   an explicit *invalid destination*, never an allowed host and never dropped.
2. **Multi-turn judged only the reply text.** A conversation that exfiltrated through a tool call
   on turn 2 was invisible to policy. `converse()` may now return Observations, and the policy
   sees every turn's tool calls.
3. **The policy could not say "https only".** A seeded plaintext-downgrade defect survived the
   whole suite until a `schemes: [https]` rule existed; it is found now.
4. **The fortress's own DLP did not reassemble a split secret.** The mutation experiment's clean
   control caught it: the window joined whole argument lists, so the next call's method and URL
   sat between the halves. My first unit test passed for the wrong reason (the default document's
   halves do not straddle the secret). Now each argument is joined to the earlier ones, fragments
   of at least half the secret are blocked outright, and running coverage catches pieces sent in
   any order.
5. **A harness artifact, caught before it was reported.** The first siege run showed `limits`
   "stopping" 1,702 attacks: every single-shot attack shared one session and spent its outbound
   budget. Each independent attack now gets its own session. A number that looks like a result
   is checked for what is actually producing it.

## What it does not show

- **The planner is deterministic and keyword-driven.** It can only be made to emit what its six
  intents allow. A model is a far richer attacker *and* a far richer victim; the layers are
  built so the planner's behaviour does not matter, but that is a design argument until it is
  measured against one. (The OpenAI-backed variant planned next is for exactly that: a real
  model proposes calls, the same gate decides.)
- **Zero findings is not proof.** The siege is 2,713 attacks, the fuzz 500,000 messages. By the
  rule of three the true failure rate of *these message shapes* is below about 1 in 170,000 at
  95% confidence. Nothing is claimed beyond them.
- **DNS rebinding and redirects are not modelled**, because there is no network. A real egress
  proxy must pin the resolved address and refuse redirects.
- **A planner that holds the secret can still dribble it out** in pieces of one or two
  characters over many calls (the running total counts runs of three). Minimize is the real
  defence there, which is why the planner does not hold the secret; DLP is the backstop.
- **Output costumes are untested**: this planner cannot produce a base64 *reply*, so the output
  filter's encoding coverage is not exercised.
- The fortress is a test target, not a product, and `bugs`/mutants live under `tools/`, not in
  the adapter.
