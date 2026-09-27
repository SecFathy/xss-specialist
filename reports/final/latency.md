# Latency (Phase 28)

Apple M5 Max, 48 GB, MLX 4-bit Qwen3-8B. Deterministic decoding, ~640 max tokens, structured
analysis output. Mean per-item wall time over dev + generalization + adversarial (steady state,
model warm; excludes cold load ~3 s):

| Condition | s / item |
|---|---|
| A  base                    | 1.89 |
| B  base + RAG              | 2.14 |
| C  specialist (LoRA)       | 2.15 |
| D  specialist + RAG        | 2.35 |

- RAG adds ~0.25 s (TF-IDF retrieve + longer prompt).
- The LoRA adapter adds negligible latency over the base.
- KEV routing gate (Kev-4B, DeltaNet on MLX/MPS): ~2–3 s per knowledge item, first call includes
  warmup. KEV runs offline in the consolidation path, not on the inference hot path, so it does not
  affect analysis latency. Under GPU contention with the 8B specialist, KEV latency degrades and
  should be scheduled off-peak (measured qualitatively; not co-run in these numbers).

Cold start (model load) is reported separately from steady state and never mixed (integrity rule).
