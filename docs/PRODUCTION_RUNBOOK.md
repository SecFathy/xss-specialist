# Production Runbook

## Reproduce the study
```bash
uv sync
uv run xss build-benchmark            # freeze XSSBench (Phase 3-5)
uv run xss corpus                     # verified knowledge corpus (Phase 2)
uv run xss sft --n 14                 # teacher SFT data (Phase 9)
uv run xss train --iters 320          # candidate LoRA (Phase 10)
# baselines + candidate eval:
uv run python -m evaluation.run --backend mlx --out runs/baseline_A_base
uv run python -m evaluation.run --backend mlx --rag --out runs/baseline_B_base_rag
uv run python -m evaluation.run --backend mlx --adapter models/adapters/xss-v1 --out runs/C_specialist
uv run python -m evaluation.run --backend mlx --adapter models/adapters/xss-v1 --rag --out runs/D_specialist_rag
uv run python -m evaluation.report --conditions A=runs/baseline_A_base B=runs/baseline_B_base_rag \
    C=runs/C_specialist D=runs/D_specialist_rag --pair A C
```

## Operational commands
- KEV routing:      `uv run xss kev-route`
- Executable verify:`uv run xss verify`
- Poisoning suite:  `uv run xss adversarial`
- Promotion gate:   `uv run xss promote --cand runs/C_specialist --base runs/baseline_A_base`
- Kill switch:      `uv run xss kill on|off|status`

## Locked test
Read at most once per candidate, only with `--allow-test`, and only after a gate PROMOTE. The read
is recorded in the metrics file. Never tune against it.

## Monitoring signals (Phase 27)
precision/recall, false-positive rate, abstention, retrieval Recall@K, KEV score distribution,
verification accept/reject, candidates, promotions/rejections, leakage + near-miss leakage,
poisoning attempts, rollback events, latency p50/p95/p99, memory, drift.

Generate the offline operational dashboard after local or authorized-pilot assessments:

```bash
uv run xss-monitor
open reports/monitoring/dashboard.html
```

The dashboard reads `summary.json` and authorization/review metadata only. It deliberately excludes
request logs, probe payloads, browser evidence, and page content. Dashboard availability does not
constitute an operated canary; a canary requires approved pilot traffic and recorded human review.

## Deployment stages (Phase 22-23)
shadow → 1% → 5% → 25% → 100%, human approval before first promotion, rollback triggers defined
before each stage.
