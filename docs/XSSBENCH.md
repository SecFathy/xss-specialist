# XSSBench (Phases 3-5)

Frozen synthetic XSS benchmark. Splits cut by TEMPLATE (structural), not instance, so held-out sets are novel shapes. Test is LOCKED (read once per candidate, only with --allow-test). Contamination checked at freeze time.

| split | n | vuln | safe | locked | sha256 |
|---|---|---|---|---|---|
| adversarial | 8 | 4 | 4 | False | c8f48e1fea06 |
| dev | 68 | 31 | 37 | False | ebc8b55adb5f |
| generalization | 42 | 21 | 21 | False | 4dc46c422279 |
| nearmiss | 37 | 36 | 1 | False | deb18bcafd7a |
| test | 29 | 13 | 16 | True | 36003c20c7c7 |

## What each split tests
- **dev** — train-group templates + train names; prompt/threshold development.
- **test [LOCKED]** — train-group, hash-disjoint from dev; final reporting only.
- **generalization** — held-out templates (jQuery, insertAdjacent, wrapper indirection) + unseen identifier bank (Phase 4).
- **nearmiss** — DOMPurify anchor + controlled single-edit perturbations; measures entity-binding leakage (Phase 5).
- **adversarial** — obfuscation, mutation XSS, wrong-context encoding, plus hard negatives (safe-but-scary).

## Metrics
classification acc, vulnerable-class P/R/F1, false-positive rate (safe→vulnerable), false-negative rate, execution-context accuracy, abstention, Brier/ECE calibration, near-miss leakage.

Hard negatives are included in every split: a model that labels everything vulnerable fails on precision/FPR.
