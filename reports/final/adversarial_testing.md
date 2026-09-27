# Adversarial Testing

Two distinct suites.

## 1. Adversarial DETECTION (can the model resist evasion?) — `benchmarks/adversarial.py`
Obfuscated-but-vulnerable cases (aliased sink, mutation XSS, wrong-context encoding, event-handler
setAttribute) plus safe look-alikes.

| Condition | acc | FPR | FNR |
|---|---|---|---|
| A base            | 0.500 | 0.250 | 0.750 |
| B base + RAG      | 0.625 | 0.500 | 0.250 |
| C specialist v1   | 0.625 | 0.000 | 0.750 |
| D specialist + RAG| 0.375 | 0.500 | 0.750 |

Finding: obfuscation/mutation remain hard for all conditions (high FNR); the specialist keeps FPR
low but still misses evasive vulnerable cases. This is a known limitation — adversarial evasion is
the weakest area and needs dedicated training data.

## 2. Pipeline POISONING robustness (Phase 17) — `verification/adversarial_pipeline.py`
15 authorized synthetic attacks trying to push bad knowledge to the weights.

| Attack | Blocked by |
|---|---|
| repeated false claim (×6)   | verification (repetition ≠ evidence) |
| fabricated authority        | provenance-reference check |
| fake citation (attacker domain) | reference allow-list |
| prompt injection in a claim | injection filter |
| private-data injection      | privacy filter |
| near-duplicate poisoning (×5) | dedup + verification |

**Breaches to training: 0 / 15.** A claim reaches training only if KEV routes TRAINING_CANDIDATE
AND verification is VERIFIED AND privacy/injection filters pass — independent gates, all must agree.
No real third-party target is used anywhere.
