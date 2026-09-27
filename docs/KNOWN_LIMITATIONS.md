# Known Limitations

Honest scope of this research prototype. These do not invalidate the measured findings; they bound
what the findings claim.

## Corpus & data
- The verified corpus is small (~36 authored items) and the cases are **synthetic**, template-based.
  They exercise the ontology and the pipeline, but real-world code is messier. Repository-level and
  real-codebase evaluation (Phase 19) is scaffolded, not run at scale.
- The "teacher" is a **grounded synthesizer over verified ground-truth labels**, not a distilled
  frontier LLM. This removes hallucination risk but means the SFT targets are as good as the
  labels/templates, not a stronger model's reasoning.

## Benchmark
- XSSBench is synthetic and modest in size; confidence intervals are wide. Statistical claims use
  paired bootstrap, but small n limits power. The locked test is small (~29 items).
- Generalization/near-miss splits are structurally novel but still drawn from the same generator
  family; true out-of-distribution generalization is under-tested.

## Verification oracle
- The browser oracle confirms only cases delivered through a decoding source or `window.name` into
  an HTML/JS sink (the faithful-delivery scope). Encoding-dependent and activation-dependent cases
  are honestly reported `UNVERIFIED`, not confirmed. It runs only against local `file://` harnesses.

## KEV
- KEV is used frozen and zero-shot; it was trained on unrelated decision tasks. Its routing is a
  useful signal, not a calibrated XSS relevance judge. Raw probabilities are stored, never treated
  as truth. Latency on Apple silicon is ~2-3 s/item (DeltaNet on MLX).

## Model / compute
- Single base model (Qwen3-8B, 4-bit) on one machine. The model-size ablation (Phase 29) and full
  KEV-gated multi-cycle continual learning (Phase 30 condition E) are scaffolded; headline numbers
  compare A/B/C/D.

## Filters
- Privacy/injection filters are pattern-based defense-in-depth, not complete. Novel encodings can
  evade them; human approval before promotion remains required.
