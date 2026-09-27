# Executive Summary

**A production-grade *architecture* for an XSS-specialist SLM with KEV-gated continual learning,
built and measured end to end on Apple silicon.** The scientific verdict is nuanced and honest:
parameter adaptation delivers large, real gains in precision, execution-context understanding, and
(with breadth replay) generalization — but does **not** cure near-miss entity-binding leakage, and
the frozen promotion gate therefore **correctly refused to promote any candidate**. That refusal is
the headline safety result: the system will not ship a model with an unsolved leakage flaw, no
matter how good its other numbers.

## What was built (fresh, not reused)
Ontology + provenance schema · 36-item verified corpus (authoritative sources, licensed) ·
deterministic case generator · frozen **XSSBench** (dev/locked-test/generalization/near-miss/
adversarial, hard negatives, contamination-checked) · MLX inference + structured Phase-11 analysis ·
TF-IDF RAG (independently evaluated) · **live frozen Kev-4B routing gate** · grounded teacher SFT ·
MLX LoRA training · **real headless-browser verification oracle** · poisoning-resistant pipeline ·
versioned registry + rollback + kill switch · frozen promotion gate · paired-bootstrap reporting.
13/13 unit tests pass.

## Headline numbers (same frozen XSSBench)
| | dev acc | dev FPR | dev ctx | generalization | near-miss leak |
|---|---|---|---|---|---|
| A base | 0.794 | 0.27 | 0.52 | 0.762 | 1.00 |
| B base+RAG | 0.912 | 0.16 | 0.39 | 0.833 | 1.00 |
| C specialist v1 | 0.941 | **0.00** | **1.00** | 0.595 ↓ | 1.00 |
| E specialist v2 | **1.000** | **0.00** | **1.00** | **0.905** | 1.00 |
| F specialist v3 | 1.000 | 0.00 | 0.90 | 0.714 | 1.00 |

Paired bootstrap (v2 − base): dev **+0.206** [+0.10, +0.31]*, generalization **+0.143** [+0.02,
+0.26]* (\* CI excludes 0). All candidates REJECTED by the gate; **locked test preserved unread**
(no PROMOTE occurred — the pre-registered discipline).

## Answers to the research questions
1. **Better than base?** Yes on precision (FPR 0.27→0.00), execution-context (0.52→1.00), and
   in-distribution accuracy (0.79→1.00); v2 also beats base on generalization (+0.14, sig).
2. **RAG vs adaptation?** RAG raises recall/accuracy cheaply but *worsens* precision on some splits
   and cannot fix context or entity-binding. Adaptation fixes precision and context; the two are
   complementary.
3. **Generalize to novel structures?** v1 over-narrowed (0.595); **breadth replay (v2) recovered it
   to 0.905** — generalization loss from narrow SFT is real but repairable.
4. **KEV as curator?** Yes — zero-shot Kev-4B cleanly routes stable XSS principles → training and
   volatile advisories → retrieval; used as a router, never a truth oracle.
5. **Acquire without forgetting?** Partly — breadth replay preserved skills; naive SFT (v1/v3) forgot.
6. **Leakage / entity confusion?** **Yes, and it is severe and resistant.** Base leakage 1.00;
   neither RAG, nor single-anchor, nor 91-record multi-anchor near-miss training moved it — the model
   labels held-out `OMPurify.sanitize` safe. This is the key negative finding.
7. **Contrastive/hard-negatives reduce FP and leakage without over-abstention?** FP: yes (→0.00, no
   abstention inflation). Leakage: **no** — much harder than false-positive control.
8. **Poisoning/injection resistance?** 15-attack suite, **0 breaches to training**; independent KEV +
   verification + privacy/injection gates, all must agree.
9. **Smallest useful model?** Not resolved — single 8B base studied; size ablation scaffolded.
10. **Deployment suitability?** **RESEARCH PROTOTYPE**, shadow-eligible components; blocked from pilot/
    production by the unsolved leakage property and synthetic-data scope (see production_readiness.md).

## Why this is the right outcome
The objective was never maximum benchmark accuracy — it was a *measurable, auditable, reversible,
safe* system. The gate blocking three strong candidates on a leakage safety criterion, with a
preserved locked test and full lineage in the registry, is exactly that system working as designed.
