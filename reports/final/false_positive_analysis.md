# False-Positive Analysis (Phase 18)

A production pentest assistant must not overwhelm analysts. FPR = safe cases labelled vulnerable.
Every split contains hard negatives (framework escaping, contextual encoding, correct sanitizer
use, safe DOM APIs, CSP/Trusted-Types-shaped code).

## Dev split (37 safe / 31 vulnerable)

| Condition | FPR ↓ | recall (vuln) | context acc |
|---|---|---|---|
| A base | 0.270 | 0.871 | 0.52 |
| B base + RAG | 0.162 | 1.000 | 0.39 |
| C specialist v1 | **0.000** | 0.871 | **1.00** |
| D specialist v1 + RAG | **0.000** | 0.774 | 1.00 |

## Findings
1. **The base model over-flags (FPR 0.27).** It calls safe `textContent` / `htmlspecialchars` /
   `json_encode` code vulnerable because a dangerous-looking source is present.
2. **RAG raises recall but also FPR on some splits** (generalization 0.095→0.333, adversarial
   0.25→0.50): more evidence makes the model more willing to flag, trading precision for recall.
3. **Specialization drives dev FPR to 0.00 and context accuracy to 1.00** — the clearest win of
   parameter adaptation: the model learns to recognize *correct* contextual handling as safe, which
   retrieval alone did not achieve.

## Caveat
The v1 FPR win came with a generalization cost (over-conservative on unseen sinks → false
*negatives* rise). Precision and recall must be read together; see `model_comparison.md` and
`continual_learning.md`. No abstention inflation: dev abstention 0.00 across conditions.
