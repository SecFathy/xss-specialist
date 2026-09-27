# Reproducibility

Every artifact is reproducible from a fixed seed and pinned inputs. See
`REPRODUCIBILITY_MANIFEST.json` for the concrete hashes of this run.

## Determinism
- Master seed `20260927`; per-component RNG streams derived by hashing the component name into the
  seed (`xss_specialist/repro.stream`). Adding a candidate to one stream never perturbs another.
- Deterministic decoding for eval (temperature 0.0, fixed seed).
- Canonical JSON hashing (sorted keys) for corpus, benchmark splits, SFT data, adapters.

## Pinned inputs
- Base model: `Qwen3-8B` → 4-bit MLX (`models/qwen3-8b-4bit`); `config.json` hashed in the
  training record.
- KEV: Kev-4B adapter on `Qwen/Qwen3.5-4B-Base` rev `1001bb4d…`, library commit and adapter
  sha256 pinned in `provenance/kev.json`; used frozen, zero-shot.

## Recorded per result
`split_sha256`, backend name, RAG flag, latency, full metrics, and the environment manifest
(python, platform, package versions, git commit + dirty flag).

## Rebuild
`docs/PRODUCTION_RUNBOOK.md` lists the exact command sequence. `uv.lock` pins dependencies.

## Bug protocol
If a bug is found: document it, determine affected results, preserve the old result, fix, rerun
only what is scientifically justified, explain the change. History is never overwritten.
