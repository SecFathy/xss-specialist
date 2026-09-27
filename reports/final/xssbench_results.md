# XSSBench Results

All conditions on the same frozen XSSBench (see `docs/XSSBENCH.md`). Full table with all metrics in
`reports/final/model_comparison.md`. Headline accuracy (abstention counts as incorrect):

| split | A base | B +RAG | C spec v1 | D spec+RAG |
|---|---|---|---|---|
| dev            | 0.794 | 0.912 | 0.941 | 0.897 |
| generalization | 0.762 | 0.833 | 0.595 | 0.810 |
| nearmiss (acc) | 0.027 | 0.027 | 0.027 | 0.027 |
| adversarial    | 0.500 | 0.625 | 0.625 | 0.375 |

Key derived metrics:
- **False-positive rate (dev):** A 0.27 → C **0.00** (specialization removes analyst false alarms).
- **Execution-context accuracy (dev):** A 0.52 → C **1.00**.
- **Near-miss leakage:** 1.00 in ALL of A/B/C/D v1 (unsolved by RAG or single-anchor NM training).
- **Generalization:** C regresses vs A (−0.167, 95% CI [−0.31, −0.02], paired) — v1 overfit.

Paired bootstrap (C − A): dev +0.147 [+0.044, +0.265]*, generalization −0.167 [−0.310, −0.024]*,
adversarial +0.125 [0.000, +0.375], near-miss +0.000. (* CI excludes 0.)

Interpretation: v1 specialization is a **precision/context win but a generalization loss** and does
**not** fix entity-binding — so the promotion gate REJECTS v1. v2 (multi-anchor near-miss + breadth
replay, gentler LR) is the corrective candidate; its results and the gate decision are in
`continual_learning.md`. Locked-test numbers are read once, only for the promoted model.
