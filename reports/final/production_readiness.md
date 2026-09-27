# Production Readiness

Classification: **RESEARCH PROTOTYPE** (shadow-ready components, not production).

Production readiness is not average benchmark accuracy; it requires evidence across the axes below.

| Axis | Evidence | Status |
|---|---|---|
| Privacy | independent privacy filter; sensitive data never enters learning path; 0/15 poisoning breaches | ✅ implemented + tested |
| Verification | independent browser oracle (0 conflicts on in-scope labels) + provenance rules | ✅ implemented |
| Poisoning resistance | 15-attack suite, 0 breaches to training | ✅ tested |
| Leakage controls | near-miss bench + gate criterion (≤0.30) | ⚠️ measured; v1 failed, v2 pending |
| Deterministic data construction | seeded per-component streams; hashed artifacts | ✅ implemented |
| Evaluation | frozen XSSBench, hard negatives, paired bootstrap, locked test | ✅ implemented |
| Monitoring | metrics defined (Phase 27) | ⚠️ defined, not wired to a live dashboard |
| Rollback | registry pointer rollback, no retrain | ✅ implemented |
| Kill switch | learning_enabled flag halts consolidation/train/promote | ✅ implemented + tested |
| Provenance/lineage | registry records base rev, dataset hash, adapter hash, KEV rev, eval, decision | ✅ implemented |
| Deployment safety | shadow→canary stages defined; human approval before promotion | ⚠️ documented, not operated |

## Blockers to higher tiers (explicit)
1. **Generalization/leakage not both cleared** by a promoted candidate yet (v1 rejected; v2 pending).
2. **Corpus & benchmark are synthetic and small** — no real-codebase / repository-level evaluation
   at scale (Phase 19 scaffolded only).
3. **Adversarial evasion detection is weak** (high FNR on obfuscation/mutation).
4. **Monitoring/canary are designed, not operated.**

## Verdict
Suitable for **research** and, once a candidate clears the gate, **shadow** evaluation. Not
controlled-pilot or production until blockers 1–4 are closed with real-data evidence.
