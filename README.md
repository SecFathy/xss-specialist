# xss-specialist

Production-grade **XSS specialist SLM** with **KEV-gated continual learning** (research prototype).
A narrow expert for authorized security testing and defensive review — deep XSS reasoning
(source/sink/context, encoding/sanitization, DOM/reflected/stored/mutation XSS, framework behaviour,
CSP/Trusted Types, root-cause + remediation), not a generic security chatbot.

```
external XSS knowledge → KEV gate → verification → knowledge store → { RAG | training buffer }
   → consolidation → LoRA → candidate SLM → evaluation → promotion gate → registry (rollback, kill switch)
```
No direct edge from internet/user input to weights. Every path to adaptation is gated, verified,
reproducible, reversible. See `docs/ARCHITECTURE.md` and `docs/SECURITY_BOUNDARIES.md`.

## Quickstart
```bash
uv sync
uv run pytest -q                                   # 13 model-free tests (~0.1s)
uv run xss build-benchmark                         # freeze XSSBench
uv run xss corpus                                  # verified knowledge corpus
uv run xss sft --n 14                              # grounded teacher SFT
uv run xss train --iters 360 --out models/adapters/xss-v2 --sft data/training/sft_v2.jsonl
uv run python -m evaluation.run --backend mlx --adapter models/adapters/xss-v2 --out runs/E_v2
uv run xss promote --cand runs/E_v2 --base runs/baseline_A_base
uv run xss kev-route                               # live Kev-4B routing of the corpus
uv run xss verify                                  # browser oracle over frozen cases
uv run xss adversarial                             # pipeline poisoning suite (0/15 breaches)
uv run xss kill on|off|status                      # kill switch
```

## Result in one line
Parameter adaptation fixed false positives (FPR 0.27→0.00) and execution-context accuracy
(0.52→1.00), and — with breadth replay — beat the base on generalization (0.762→0.905, paired sig).
It did **not** fix near-miss entity-binding leakage (stayed 1.00 across base, RAG, and three
specialist variants), so the **frozen promotion gate rejected all candidates** and the **locked test
was preserved unread**. Full write-up: `reports/final/` (start with `executive_summary.md`).

## Layout
`xss_specialist/` core (schema, repro, prompt, inference, cli) · `knowledge/` corpus ·
`benchmarks/` case gen + XSSBench freeze · `retrieval/` RAG · `kevgate/` KEV routing ·
`training/` teacher + LoRA · `verification/` browser oracle + poisoning suite ·
`evaluation/` scorer + promotion + report · `registry/` versions/rollback/kill switch ·
`consolidation/` sleep cycle · `docs/` · `reports/final/` · `tests/`.

KEV (Kev-4B) is an external dependency used frozen/zero-shot, pinned in `provenance/kev.json`.
For authorized security testing and defensive research only.
