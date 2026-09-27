<div align="center">

<img src="docs/assets/banner.png" alt="XSS Specialist × KEV — Fast reasoning. Verified execution." width="100%">

# xss-specialist

### A KEV-gated continual-learning XSS specialist SLM **+** an execution-authoritative live assessment system

*Can a small language model become a deep XSS expert through gated continual learning — and can a
browser oracle turn its reasoning into evidence-backed, hard-to-fool findings?*

**We built it, measured it honestly, and report the negatives.**

![status](https://img.shields.io/badge/status-research%20prototype-blue)
![readiness](https://img.shields.io/badge/live%20system-AUTHORIZED%20PILOT%20READY-orange)
![tests](https://img.shields.io/badge/tests-22%2F22%20passing-brightgreen)
![license](https://img.shields.io/badge/license-Apache--2.0-lightgrey)
![use](https://img.shields.io/badge/use-authorized%20testing%20only-red)

</div>

---

> **Authorized-use only.** This project assists **authorized** penetration testers, application-security
> engineers, and researchers. It does **not** autonomously attack third-party systems, and every path
> to active testing is gated behind explicit scope + authorization. See [Security & Boundaries](#security--boundaries).

---

## Table of contents
- [The one-paragraph version](#the-one-paragraph-version)
- [Why this exists](#why-this-exists)
- [Two systems, one repo](#two-systems-one-repo)
- [Headline results](#headline-results)
- [The research: KEV-gated continual learning](#the-research-kev-gated-continual-learning)
- [The live system: execution-authoritative assessment](#the-live-system-execution-authoritative-assessment)
- [The near-miss problem (the interesting part)](#the-near-miss-problem-the-interesting-part)
- [Quick Install](#quick-install)
- [How to use](#how-to-use)
- [Repository layout](#repository-layout)
- [Benchmarks & reproducibility](#benchmarks--reproducibility)
- [Security & boundaries](#security--boundaries)
- [Honest limitations](#honest-limitations)
- [Research questions, answered](#research-questions-answered)
- [Roadmap / blockers to production](#roadmap--blockers-to-production)
- [License & credits](#license--credits)

---

## The one-paragraph version

`xss-specialist` is a **research prototype** with two halves. The first is an offline study: can a small
(8B) open model be specialized into a deep XSS reasoner using retrieval, LoRA fine-tuning, and a
**KEV-gated continual-learning pipeline** where a frozen decision model (Kev-4B) decides what knowledge
is even *allowed* to reach the weights? The second is a **live, authorized assessment system** that
crawls a target in scope, plans **marker-first, non-destructive** probes, and confirms XSS with a
**headless-browser oracle** — where *execution*, not model confidence, is the sole authority for a
`CONFIRMED` finding. The most important results are the **honest negatives**: a specialist model can
fix false positives and execution-context accuracy but **cannot** solve near-miss sanitizer/entity
leakage — so the frozen promotion gate **rejected every model candidate**, while the **live layer**
neutralizes the same problem at the execution boundary (leakage `1.00 → 0.00`).

---

## Why this exists

Most "AI security scanner" projects overclaim: they wire an LLM to a crawler and trust its verdicts.
Two things go wrong:

1. **LLMs hallucinate safety.** They pattern-match names — a function called `DOMPvrify.sanitize`
   *looks* safe, so the model says safe. That's **near-miss entity leakage**, and it is dangerous.
2. **Confidence ≠ vulnerability.** A model that's 0.9 confident is still wrong often enough to bury
   analysts in false positives, or worse, miss real bugs.

This project takes the opposite stance:

- **Knowledge must be earned, not absorbed.** A gate + independent verification decide what becomes
  model weights vs. what stays in retrieval. Poisoning and prompt-injection must never reach training.
- **The browser is the judge.** A finding is only `CONFIRMED` when a real headless browser *executes*
  a sentinel. The model advises; the oracle decides.
- **Report the negatives.** Every rejected candidate, every failed category, every unsolved problem is
  measured and published — never hidden.

---

## Two systems, one repo

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  PART 1 — OFFLINE RESEARCH: the specialist & its learning pipeline                  │
│                                                                                    │
│  External XSS knowledge → KEV gate → verification → knowledge store                 │
│        ├─► RAG (volatile facts stay here, never weights)                            │
│        └─► training buffer → consolidation → LoRA → candidate SLM                   │
│                → XSSBench evaluation → PROMOTION GATE → versioned registry           │
│                                                                                    │
│  No direct edge from internet/user input → model weights. Gated, verified,          │
│  reproducible, reversible. (docs/ARCHITECTURE.md)                                   │
└──────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────┐
│  PART 2 — LIVE (authorized): evidence-backed assessment                             │
│                                                                                    │
│  Target + explicit Scope → Crawler → Input mapper → Context classifier              │
│    → Safe probe planner (marker-first) → Headless executor                          │
│    → BROWSER ORACLE (authoritative for CONFIRMED)                                   │
│    → Sanitizer identity verification (exact-only; near-miss ⇒ UNKNOWN)              │
│    → Finding correlation → Evidence-backed report                                   │
│                                                                                    │
│  127.0.0.1 first. External refused until the local gate passes AND the operator     │
│  explicitly authorizes the target. (docs/LIVE_ASSESSMENT.md)                        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**Separation of concerns is the whole design:** KEV decides *routing*, verification decides *trust*,
RAG holds *volatile* knowledge, training holds *stable reusable* knowledge, evaluation decides
*acceptance*, and deployment controls decide *reach*. No component is the "truth engine."

---

## Headline results

*All numbers are measured in this repo on frozen, deterministic benchmarks. The offline locked test
was **never read** to build the live system.*

### Live assessment — XSS-LiveBench-v2 (102 cases, final frozen run)

| Metric | v1 (emulated) | **v2** | Frozen gate |
|---|---|---|---|
| Precision | 0.935 | **0.941** | ≥ 0.90 (pass) |
| Recall | 0.906 | **1.000** | ≥ 0.90 (pass) |
| False-positive rate | 0.105 | **0.105** | ≤ 0.15 (pass) |
| False-negative rate | 0.094 | **0.000** | ≤ 0.10 (pass) |
| Confirmed-execution accuracy | — | **0.938** | ≥ 0.80 (pass) |
| **Near-miss sanitizer leakage** | 0.00 | **0.00** | ≤ 0.05 (pass) |
| Sanitizer false-safe rate | 0.00 | **0.00** | ≤ 0.05 (pass) |
| Route / input discovery recall | — | **1.00 / 1.00** | ≥ 0.95 (pass) |
| Control-plane injection breaches | — | **0 / 9** | = 0 (pass) |
| Calibration (ECE) | — | **0.041** | ≤ 0.10 (pass) |

**Paired bootstrap (v2 − v1, per-case accuracy):** **+0.059, 95% CI [+0.020, +0.108]** — significant,
driven by recall (interaction-aware oracle + JS-code probes + stored-XSS correlation catch executions
v1 missed). **All 13 frozen acceptance criteria pass.**

### The ablation that matters: the oracle, not the model, drives quality

| Configuration | Precision | Recall | FPR |
|---|---|---|---|
| Reflection-only ("input echoes") | 0.62 | 0.95 | **0.97** |
| Encoding-aware (no execution) | 0.87 | 0.41 | 0.11 |
| **+ browser oracle** | **0.94** | **1.00** | 0.11 |

> A naive "the input is reflected" scanner flags 97% of safe pages. Execution verification is what
> makes findings trustworthy — **system quality comes from the live layer, not the LLM.**

### Real-world demo (public sandbox)

Against **Google's XSS-game level 1** (`xss-game.appspot.com`, a sanctioned public training target):
**`CONFIRMED` reflected XSS** in 2 requests — the oracle fired an `<img onerror>` sentinel in headless
Chromium; the `query` parameter reflects into HTML text with no encoding. *(Demo, not evidence: level 1
is trivial reflected XSS.)*

---

## The research: KEV-gated continual learning

The offline study asks whether a specialist SLM can be *safely* improved through continual learning.

**Setup:** base `Qwen3-8B` (4-bit MLX) · a frozen **Kev-4B decision model** as the knowledge-routing
gate (used zero-shot, never fine-tuned) · a TF-IDF RAG layer over a verified corpus · LoRA/QLoRA
adaptation · a real headless-browser oracle for label verification · a frozen promotion gate.

**What parameter adaptation fixed** (dev split, vs. base model):

| | Base | Base+RAG | Specialist v1 | Specialist v2 |
|---|---|---|---|---|
| Accuracy | 0.794 | 0.912 | 0.941 | **1.000** |
| False-positive rate | 0.27 | 0.16 | **0.00** | **0.00** |
| Execution-context accuracy | 0.52 | 0.39 | **1.00** | **1.00** |
| Generalization (held-out shapes) | 0.762 | 0.833 | 0.595 | **0.905** |

- Specialization **eliminated false positives** and made **execution-context classification perfect** —
  things RAG alone did *not* achieve.
- v1 **overfit** (generalization collapsed to 0.595); **breadth-replay** in v2 recovered it to 0.905,
  significantly beating the base — a clean demonstration of catastrophic-narrowing *and its fix*.

**What it could NOT fix — and the gate that caught it:** see below.

**Pipeline safety, measured:** an adversarial suite of 15 poisoning / prompt-injection / private-data /
near-duplicate attacks reached training **0 times** — a claim becomes training data only if KEV routes
it `TRAINING_CANDIDATE` **and** independent verification marks it `VERIFIED` **and** privacy/injection
filters pass.

---

## The live system: execution-authoritative assessment

The live layer turns analysis into **evidence**.

- **Scope enforcement** — allowed hosts/subdomains/prefixes, exclusions, depth & request budgets, rate
  limits, and **post-redirect re-checks**. Out-of-scope URLs are blocked *before* the request. Scope
  never auto-expands.
- **Deterministic crawler + input mapper** — JS-aware BFS discovering links, forms (GET/POST), query
  params, DOM sources, and JS-referenced routes. On XSS-LiveBench-v2: **route & input recall = 1.00**.
- **Marker-first probe planner** — a harmless unique marker first (learn *if* and *where* input
  reflects), then **context-tailored** execution probes that do nothing but set a per-marker flag.
  No persistence, no exfiltration, no off-target navigation.
- **Interaction-aware oracle** — derives bounded interactions (hover / focus / click / hashnav) from the
  reflection context to reach interaction-gated sinks, **each recorded**.
- **Reflection judged on the raw HTTP body**, not the re-serialized DOM, with a backslash guard so
  `\"`-escaped quotes don't false-match — this is what keeps precision high on encoded-but-scary inputs.
- **Finding state machine:** `CONFIRMED` (oracle executed) · `LIKELY` (dangerous payload reflected
  unencoded, no execution) · `INCONCLUSIVE` · `NOT_VULNERABLE`. **A finding is never upgraded to
  `CONFIRMED` from model confidence.**
- **Stored-XSS workflow** — submit → separate view → correlate execution at the view step.
- **Full evidence preservation** — crawl graph, route/input/candidate inventories, probe log, browser
  evidence, oracle results, findings, scope log, request log, and a Markdown report per assessment.

---

## The near-miss problem (the interesting part)

Prior continual-learning research warned that **lexical near-miss entities cause knowledge leakage**.
We built a dedicated benchmark and confirmed it — hard.

> **A model that learns "`DOMPurify.sanitize` is safe" will happily call `DOMPvrify.sanitize`,
> `OMPurify.sanitize`, or `sanitizeHtm1` safe too.**

**Measured leakage on the frozen near-miss benchmark:**

| Condition | Near-miss leakage (lower = better) |
|---|---|
| Base model | **1.00** |
| Base + RAG | **1.00** |
| Specialist v1 (single-anchor near-miss training) | **1.00** |
| Specialist v2 (multi-anchor) | **1.00** |
| Specialist v3 (91-record generated, DOMPurify held out) | **1.00** |
| **Live system (execution-authoritative)** | **0.00** |

**The finding:** near-miss sanitizer leakage is *robustly resistant* to supervised fine-tuning at this
scale — so the **frozen promotion gate rejected all three model candidates** (it refuses to ship a model
with an unsolved leakage flaw, no matter how good its other numbers). The **live layer solves the same
problem structurally**: it never infers safety from a name. A sanitizer earns `VERIFIED_SAFE` only on
**exact identity + verified evidence**; anything else stays `UNKNOWN`, and the fake `DOMPurify` is caught
by **execution**, not by reasoning about its name.

This is the project's thesis in one result: **don't trust the model's names — trust the browser's
execution.**

---

## Quick Install

Prerequisites: **macOS on Apple silicon**, Python 3.12 or newer, Git, and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/). MLX model training and inference are
currently Apple-silicon only.

```bash
git clone https://github.com/SecFathy/xss-specialist.git
cd xss-specialist
uv sync
uv run python -m playwright install chromium
uv run pytest -q
```

The 8B base model is converted to 4-bit MLX locally (kept out of git):

```bash
uv run mlx_lm.convert --hf-path ~/.cache/huggingface/hub/models--Qwen--Qwen3-8B/snapshots/<rev> \
    -q --q-bits 4 --q-group-size 64 --mlx-path models/qwen3-8b-4bit
```

> The model/adapters/run outputs are git-ignored. The code, benchmarks, and reports are the artifacts.

---

## How to use

Start with the local acceptance suite. It exercises the scanner against bundled test applications and
does not contact an external target:

```bash
uv run python -m live.livebench
uv run python -m live.final_eval
```

A successful run confirms that the browser oracle and the frozen v2 acceptance gate work in your
environment. Additional component checks are available with:

```bash
uv run python -m live.coverage
uv run python -m live.robustness
uv run python -m live.ablation
```

### Offline research (specialist + benchmarks)

```bash
uv run xss build-benchmark                 # freeze XSSBench (dev/test-locked/generalization/nearmiss/adversarial)
uv run xss corpus                          # write the verified knowledge corpus
uv run xss sft --n 14                      # grounded teacher SFT data
uv run xss train --iters 360 --out models/adapters/xss-v2 --sft data/training/sft_v2.jsonl
uv run python -m evaluation.run --backend mlx --adapter models/adapters/xss-v2 --out runs/E_v2
uv run xss promote --cand runs/E_v2 --base runs/baseline_A_base   # frozen promotion gate
uv run xss kev-route                       # live Kev-4B routing of the corpus
uv run xss adversarial                     # pipeline poisoning suite (0/15 breaches)
uv run xss kill on|off|status              # continual-learning kill switch
```

### Live assessment — authorized external target

External targets are **refused before any network access** unless: the local gate passed **and** you
pass `--authorized-external` **and** you acknowledge authorization with an operator identity.

```bash
uv run python -m live.pilot \
    --target https://target.example.com/app/ \
    --operator "you@org" --assessment-id ENG-2026-001 \
    --acknowledge-authorization \
    --allowed-prefix /app/ --exclude /app/logout \
    --budget 300 --rate 3 \
    --authorized-external
```

Review the generated evidence and Markdown report in
`reports/live_assessments/ENG-2026-001/`.

> Only test targets you are **explicitly authorized** to test (your own systems, an engagement with a
> signed scope, a bug-bounty program's in-scope assets, or a public training sandbox like Google's
> XSS-game). Findings are quarantine-only and never auto-train the specialist.

---

## Repository layout

```
xss_specialist/    core: ontology/schema, prompts, inference (MLX), repro, CLI
knowledge/         verified XSS knowledge corpus (provenance-tagged)
benchmarks/        case generator, frozen XSSBench, XSS-LiveBench-v2 spec
retrieval/         TF-IDF RAG index + independent retrieval eval
kevgate/           frozen zero-shot Kev-4B knowledge-routing gate
training/          grounded teacher SFT + MLX LoRA trainer
verification/      browser oracle (authoritative), poisoning-resistance suite
evaluation/        scorer, frozen promotion gate, paired-bootstrap reports
registry/          versioned adapters, rollback, kill switch, release freeze
consolidation/     "AI-sleep" continual-learning cycle
live/              scope · crawler · probes · executor · oracle glue · sanitizer-id ·
                   findings · pipeline · stored-XSS · coverage · ablation · calibration ·
                   robustness · performance · pilot · local test apps · LiveBench-v2
docs/              ARCHITECTURE, THREAT_MODEL, LIVE_ASSESSMENT, XSSBENCH, CONTINUAL_LEARNING,
                   ROLLBACK, SECURITY_BOUNDARIES, KNOWN_LIMITATIONS, runbook, schema
reports/           final research reports + live-assessment evidence & final report
tests/             22 fast, model-free tests
```

---

## Benchmarks & reproducibility

- **XSSBench** (offline): dev / **locked-test** / generalization / near-miss / adversarial splits, cut by
  *template* (not instance) so held-out sets are structurally novel; contamination-checked at freeze.
- **XSS-LiveBench-v2**: 102 deterministic cases across reflected contexts (HTML/attr/JS/URL/CSS/JSON/
  script-data/template/nested/multi-reflection), a DOM source×sink matrix, encoding/parser stress, a
  large **sanitizer-identity adversarial suite**, a **false-positive torture suite**, multi-step flows,
  and a controlled in-memory stored-XSS workflow.
- **Determinism:** one master seed, independent per-component RNG streams, canonical-JSON hashing of every
  artifact, and an environment manifest recorded with each result. Frozen releases
  (`xss-specialist-live-v1`, `-v2`) hash every component.
- **Integrity rules we follow:** never tune against the locked test; never upgrade `LIKELY → CONFIRMED`
  from model confidence; never infer sanitizer safety from lexical similarity; never let page content
  change control-plane policy; paired evaluation with confidence intervals; negatives reported, not hidden.

---

## Security & boundaries

- **Authorized-use only.** For pentesters, appsec engineers, code reviewers, and researchers working on
  systems they are permitted to test.
- **Non-destructive by construction.** Probes set a benign JS flag (`window.__X[...]`) — no persistence,
  credential/session theft, DoS, phishing, or post-exploitation.
- **Scope is sacred.** Every URL is scope-checked before request and after redirect; out-of-scope is
  blocked and logged. Scope never auto-expands.
- **External refusal.** Non-loopback targets are refused before any network access unless the local
  acceptance gate passed **and** explicit per-target authorization is given.
- **Control-plane isolation.** Page content can never modify scope, budget, oracle logic, promotion
  criteria, registry, KEV config, or training state — verified by a 9-attack suite (**0 breaches**).
- **No autonomous learning from live findings.** Live findings are quarantine-only.

See `docs/SECURITY_BOUNDARIES.md` and `docs/THREAT_MODEL.md`.

---

## Honest limitations

- **Benchmarks are synthetic and local** (102 live cases; small offline corpus). Numbers bound the
  *mechanism and failure modes*, not real-world performance on complex applications.
- **The specialist model was a negative result** — every candidate was gate-rejected on near-miss
  leakage. The live system's quality comes from the **browser oracle**, not the model.
- **Coverage gaps**: SPA/auth flows, POST-body/header/JSON injection, and path parameters are exercised
  only lightly; the context classifier is heuristic (the oracle remains authoritative).
- **A few hard false-positive traps** (dead code, unreachable sinks, CSP-blocked reflection) surface as
  `LIKELY` rather than being dismissed.
- **Not production-ready.** Classified **AUTHORIZED PILOT READY** on synthetic evidence.

---

## Research questions, answered

1. **Can a small specialist beat its base at XSS?** Yes on precision (FPR 0.27→0.00), execution-context
   (0.52→1.00), and accuracy; v2 also beats base on generalization (significant).
2. **RAG vs. parameter adaptation?** RAG lifts recall cheaply but hurts precision on some splits and
   fixes neither context nor entity-binding; adaptation fixes precision/context. Complementary.
3. **Does it generalize?** v1 overfit; **breadth-replay recovered and exceeded** the base.
4. **Can KEV curate knowledge?** Yes — zero-shot Kev-4B cleanly routes stable principles → training and
   volatile advisories → retrieval, as a router, never a truth oracle.
5. **Acquire without forgetting?** Partly — replay preserved skills; naive SFT forgot.
6. **Does continual adaptation cause entity confusion?** **Yes, severely, and it resists SFT** — the
   central negative result.
7. **Do contrastive/near-miss training reduce FPs and leakage?** FPs: yes (→0.00). Leakage: **no**.
8. **Poisoning/injection resistance?** 0/15 attacks reached training.
9. **Smallest useful model?** Not resolved (single 8B studied).
10. **Deployment suitability?** Research prototype; live layer is **authorized-pilot ready**, not production.

---

## Roadmap / blockers to production

1. Real authorized-target pilot evidence (precision/recall on non-synthetic apps).
2. Coverage on SPAs, authenticated flows, POST/JSON/header inputs, path parameters at scale.
3. Reduce hard-trap `LIKELY` false positives (CSP-aware downgrade, reachability analysis) — without
   tuning to eval data.
4. Operator workflow + human-review throughput; a quarantine → offline-verified promotion path.
5. Performance/scale hardening for large sites within request budgets.
6. The open research problem: an inference-time, retrieval-verified sanitizer allow-list to attack the
   near-miss leakage the model can't learn away.

---

## License & credits

- **Code, benchmarks, docs:** Apache-2.0 (see `LICENSE`).
- **KEV / Kev-4B decision model:** used *frozen, zero-shot* as an external dependency, pinned by commit
  and adapter hash in `provenance/kev.json` — [github.com/jaredpalmer/kev](https://github.com/jaredpalmer/kev).
- **Base model:** `Qwen/Qwen3-8B` (Apache-2.0).
- Knowledge corpus distilled from authoritative public references (OWASP, CWE, MDN, W3C, framework docs),
  with license and reference recorded per item.

> Built as a research prototype to study *safe* continual learning and *evidence-backed* XSS assessment.
> If you use it, keep the discipline: **authorized targets only, execution is the authority, and report
> your negatives.**
