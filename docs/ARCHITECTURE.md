# Architecture

A narrow XSS specialist SLM with KEV-gated continual learning. Every path to parameter
adaptation is gated, verified, auditable, reproducible, and reversible. There is **no direct
edge from internet/user input to model weights**.

```
External XSS knowledge (authoritative, licensed)
        │  ingestion + normalization (provenance kept)
        ▼
   KEV knowledge gate   ── kevgate/gate.py (frozen zero-shot Kev-4B decision model)
        │  route ∈ {IGNORE, RAG_ONLY, VERIFY, TRAINING_CANDIDATE, REJECT}
        ▼
   Verification / provenance ── verification/  (independent of KEV and the model)
        │  VERIFIED | CONFLICTING | UNVERIFIED | REJECTED
        ▼
   XSS knowledge store  ── data/verified/  (dedup, contradiction detection, versions)
      ├────────────► RAG        ── retrieval/  (volatile facts stay here, never weights)
      └────────────► Training buffer
                          │  consolidation/  (dedup, cluster, contrastive, hard-neg, replay)
                          ▼
                     SFT / LoRA (MLX) ── training/
                          ▼
                     Candidate XSS SLM (immutable adapter)
                          ▼
                     XSS evaluation ── evaluation/ against frozen XSSBench
                          ▼
                     Promotion gate ── evaluation/promotion.py (frozen criteria)
                          ▼
                     Versioned registry ── registry/ (lineage, rollback, kill switch)
```

## Separation of responsibilities (design principle)

| Component | Decides | Does NOT decide |
|---|---|---|
| KEV gate | whether info deserves further processing | truth |
| Verification | whether a claim is trustworthy enough | relevance/routing |
| RAG | holds volatile/reference knowledge | what enters weights |
| Training | stable, reusable reasoning into weights | truth or deployment |
| Evaluation | whether a candidate is acceptable | deployment scope |
| Deployment controls | whether it reaches users | model quality |

## Base model

`Qwen3-8B`, converted to 4-bit MLX (`models/qwen3-8b-4bit`) for Apple-silicon inference.
Selected for code capability, licensing, MLX/LoRA compatibility, and latency (see
`reports/final/model_comparison.md`). The base model is never modified; specialization is a
separate LoRA adapter.

## KEV

The Kev-4B decision model (LoRA on Qwen3.5-4B-Base) is used **frozen, zero-shot** as a routing
gate only. Raw probabilities are stored; they are never treated as truth. Pinned by commit +
adapter hash in `provenance/kev.json`.

## Reproducibility

`xss_specialist/repro.py`: one master seed, independent named RNG streams per component (adding
a candidate to one stream never perturbs another), canonical JSON hashing, and an environment
manifest recorded with every artifact. See `docs/reproducibility` and `REPRODUCIBILITY_MANIFEST.json`.
