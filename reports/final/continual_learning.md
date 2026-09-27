# Continual Learning — the candidate iteration record

Every candidate is a gated experiment. The frozen promotion gate (`evaluation/promotion.py`) was
fixed before any candidate and never weakened. Below is the honest reject/fix history.

## v001 — baseline SFT (contrastive pairs + single-anchor near-miss)
| split | acc | FPR | ctx | leak |
|---|---|---|---|---|
| dev | 0.941 | 0.00 | 1.00 | – |
| generalization | 0.595 | 0.00 | 1.00 | – |
| nearmiss | 0.027 | – | 1.00 | 1.00 |

**Gate: REJECT** — failed `generalization` (0.595 < base 0.762 − tol; the model over-narrowed and
under-flagged unseen sinks) and `nearmiss_leakage` (1.0). Wins: dev FPR 0.27→0.00, context 0.52→1.00.

## v002 — + breadth replay + multi-anchor near-miss (gentler LR)
| split | acc | FPR | ctx | leak |
|---|---|---|---|---|
| dev | 1.000 | 0.00 | 1.00 | – |
| generalization | **0.905** | 0.00 | 1.00 | – |
| nearmiss | 0.027 | – | 1.00 | **1.00** |

**Gate: REJECT** — passes everything **except** `nearmiss_leakage` (still 1.0). Breadth replay
(teaching sink-family facts as short records) **fixed the overfit**: generalization 0.595→0.905,
now well above base (0.762). Paired bootstrap E−A on generalization is positive and significant.
But leakage was unmoved: hand-picked multi-anchor perturbations did not instill the general rule.

## v003 — high-volume generated multi-anchor near-miss (DOMPurify perturbations held OUT)
Hypothesis: leakage needs volume + diversity, not token memorization. Trained on generated
single-edit perturbations of 10 *other* sanitizer anchors (≈91 near-miss records); DOMPurify kept
only as a safe anchor, so the frozen DOMPurify single-edits are a genuine transfer test — not taught.

| split | acc | FPR | ctx | leak |
|---|---|---|---|---|
| dev | 1.000 | 0.00 | 0.90 | – |
| generalization | 0.714 | 0.00 | 1.00 | – |
| nearmiss | 0.027 | – | 1.00 | **1.00** |

**Gate: REJECT** — failed `nearmiss_leakage` (1.0, unmoved) AND `generalization` (0.714): the large
near-miss volume re-narrowed the model, undoing part of v2's breadth gain. Leakage did not move even
one point despite 91 near-miss records over 10 anchors with DOMPurify held out — the model still
labels held-out `OMPurify.sanitize` / `DMPurify.sanitize` **safe** at conf 0.85. Near-miss
entity-binding leakage is **robustly resistant** to this SFT approach, and there is a tension
between near-miss volume and generalization.

## Reading
- Parameter adaptation reliably fixes **false positives** and **execution-context** accuracy —
  things RAG did not.
- **Generalization** loss from narrow SFT is real but **recoverable** with breadth replay (v2).
- **Near-miss entity leakage** is the hard, safety-critical failure. It answers RQ6 directly:
  continual adaptation does **not** by itself cure entity confusion; and RQ7: contrastive/near-miss
  training reduces false positives without abstention inflation, but reducing leakage is much harder.
- The gate did its job: it **refused every candidate with unsolved leakage**, regardless of large
  gains elsewhere. That is the intended safety behaviour.
