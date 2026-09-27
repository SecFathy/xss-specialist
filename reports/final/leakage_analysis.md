# Leakage Analysis (Phases 5, 16)

## Metric
Near-miss leakage = fraction of PERTURBED cases (sanitizer name is a single-edit look-alike of the
known-safe `DOMPurify`, hence unknown safety) that the model labels **safe** — i.e. knowledge about
`DOMPurify` leaking across the entity boundary to `DOMPvrify`, `DOMPurfy`, etc. Anchor (exact
`DOMPurify.sanitize`) is the paired control; it should stay `safe`.

## Results (frozen near-miss split, 36 perturbations + 1 anchor)

| Condition | leakage ↓ | anchor correct |
|---|---|---|
| A base | 1.00 | ✓ |
| B base + RAG | 1.00 | ✓ |
| C specialist v1 (single-anchor NM training) | 1.00 | ✓ |
| D specialist v1 + RAG | 1.00 | ✓ |

## Findings
1. **The base model leaks completely (1.00).** It treats any `*.sanitize(...)` as safe regardless of
   the exact identifier — it recognizes the *shape* of sanitization, not the specific trusted API.
2. **RAG does not help.** Retrieval surfaces "DOMPurify.sanitize is safe" (k-015), which the model
   then over-applies to look-alikes. Retrieval cannot enforce an entity boundary.
3. **Single-anchor near-miss training (v1) did not transfer.** v1 was trained on `sanitizeHtml`
   perturbations; leakage on the held-out `DOMPurify` family stayed 1.00. Learning "one look-alike
   family is unsafe" is not the same as learning the general rule.

## v2 hypothesis (pre-registered here, before the v2 read)
Multi-anchor near-miss training (DOMPurify + sanitizeHtml + purify.clean, each with perturbations
DISJOINT from the frozen bench) should teach the *principle* — sanitizer safety requires an exact
known name — and transfer to the held-out DOMPurify perturbations. Promotion requires leakage ≤ 0.30
and no generalization regression. Result recorded in `continual_learning.md`.
