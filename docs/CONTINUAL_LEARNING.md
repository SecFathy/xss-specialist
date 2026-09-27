# Continual Learning ("AI Sleep")

A consolidation cycle turns verified, KEV-approved knowledge into a candidate adapter under
deterministic, reversible controls. It never deploys; deployment is a separate human-approved step.

## Cycle (`consolidation/cycle.py`, Phase 15)
1. **Collect candidates** — route knowledge through KEV; keep only `TRAINING_CANDIDATE` **and**
   `VERIFIED`.
2. **Dedup** by code/claim hash.
3. **Cluster** related items.
4. **Resolve conflicts** — a `CONFLICTING` case (oracle execution ≠ label) is quarantined, never trained.
5. **Contrastive + hard negatives** — each vulnerable case is paired with its safe counterpart;
   near-miss records teach that a look-alike entity name is not establishably safe.
6. **Replay** — a sampled slice of prior skills, drawn from an *independent* RNG stream
   (`consolidation_replay`) so changing the candidate count never perturbs replay or negatives.
7. **Train** candidate LoRA (`training/train.py`) — base untouched, adapter immutable, full config
   + dataset hash recorded.
8. **Evaluate** on frozen XSSBench + leakage + adversarial (`evaluation/`).
9. **Promote / reject** via frozen gate (`evaluation/promotion.py`).

## Determinism
- One master seed; per-component streams (`xss_specialist/repro.py`).
- Dataset construction is versioned and hashed; the same inputs produce the same training file.

## Kill switch (Phase 26)
`registry.set_learning(false)` halts consolidation/training/promotion (each calls
`require_learning_enabled`). Inference, retrieval, and audit logging continue.

## Leakage discipline (Phase 16)
After every candidate, near-miss and unrelated-entity leakage are measured. A candidate is **not**
promoted merely because acquisition improved — the promotion gate requires leakage ≤ 0.30 and no
regression versus baseline.
