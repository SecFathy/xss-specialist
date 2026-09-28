# Local XSS decision-model improvement workflow

This workflow specializes an already-trained Kev adapter **and pointer head**, rather than
retraining a new decision head from a Qwen base. All artifacts stay local; no publishing step is
included. The historical frozen benchmarks and experimental checkpoint are left unchanged.

## Install

```bash
uv sync --extra decision
uv run --extra decision playwright install chromium
```

The decision extra pins the Kev engine commit and its compatible Torch dependency. Apple Silicon
uses MLX for evaluation/serving and Torch MPS for training. Run one training process at a time.

## Dataset

```bash
uv run --extra decision xss-decision-build-v2 --verify-browser
```

The project-native deterministic generator creates `data/decision/xss-v2-local/`, which is
git-ignored. It does not use an LLM to invent gold labels. An existing output is never overwritten.

- 2,160 fixtures, balanced across `vulnerable`, `safe`, and `unknown`.
- 1,512 train; 216 calibration; 216 development; 216 locked test.
- Nine sink patterns, four input sources, ten structural wrappers, two identifier variants.
- Related verdicts and identifier variants share a group; structural wrappers are held out.
- Every fixture is browser-checked before admission. Unknown cases are checked with both an
  unsafe and a safe completion of the missing dependency. These completions are not model input.
- Half the variants have an identical helper call and sink for all three verdicts: identity
  implementation is vulnerable, context-specific encoding is safe, and an absent implementation
  is unknown. Helper names vary across template groups. No comment reveals an example's label.
- Only code/language enter model state. Labels, verification and grouping remain metadata.

This is **synthetic JavaScript/HTML coverage**, not 2,160 independent real applications. Shared
sink primitives remain across splits. There are no PHP/framework, full stored-workflow, CSP,
Trusted Types or real-codebase guarantees. Safe labels rely on explicit contextual defenses;
one browser probe failing to execute is not, by itself, a safety proof. Old near-miss labels
which equate unknown sanitizer identity with vulnerability are not imported.

## Measure the unchanged parent

```bash
uv run --extra decision xss-decision-evaluate \
  --suite data/decision/xss-v2-local \
  --run jaredpalmer/kev-0.8b@9a45d25eb2ab761841196625383fa1dff0e56c1e \
  --split calibration --backend mlx --out reports/decision_v2/parent_calibration

uv run --extra decision xss-decision-evaluate \
  --suite data/decision/xss-v2-local \
  --run jaredpalmer/kev-0.8b@9a45d25eb2ab761841196625383fa1dff0e56c1e \
  --calibration reports/decision_v2/parent_calibration/temperature.json \
  --backend mlx --out reports/decision_v2/parent_development
```

Reports preserve probabilities, logits, exact model hashes, and the suite manifest hash. Recall
includes every gold vulnerable case, including unknown predictions; abstention cannot inflate it.
The evaluator measures unknown overclaims, false-safe decisions, multiclass Brier/NLL/ECE,
per-context performance, and reversed-choice sensitivity. Calibration fits only on calibration
rows and is bound to the checkpoint hashes, not a portable arbitrary confidence setting.

## Fine-tune

```bash
uv run --extra decision xss-decision-train \
  --suite data/decision/xss-v2-local \
  --out models/xss-decision-0.8b-v2-local-restart --dry-run

uv run --extra decision xss-decision-train \
  --suite data/decision/xss-v2-local \
  --out models/xss-decision-0.8b-v2-local-restart \
  --epochs 1 --batch 8 --accum 1
```

The wrapper derives the base/revision, LoRA targets/rank and head settings from the parent;
upstream Kev checks exact compatibility. Defaults: two epochs, learning rate `2e-5`, batch 4,
accumulation 2 (effective batch 8), permutation KL 0.1 on 30% of records, randomized choice order, seed 0. Use
`--batch 1 --accum 8` on memory-constrained machines. The local 48 GB first-stage run above
uses batch 8/accumulation 1 and saves a checkpoint after one epoch so its development result can
be measured before spending another epoch. If a continuation is warranted, run `--epochs 1
--init-from models/xss-decision-0.8b-v2-local-restart --out models/xss-decision-0.8b-v2-local-restart-e2` and
evaluate it separately. These are initial experiments, not optimized hyperparameters.
Only hash-verified training records are
admitted; every fixture must have passed browser checks. Test labels are not used for training,
calibration, checkpoint selection or promotion.

Fit the candidate's calibration and score development using the same evaluator, substituting
`models/xss-decision-0.8b-v2-local-restart` and new output directories. Compare parent and candidate on
the same suite. The development-only research gate in `xss_decision/promotion.py` rejects
all-safe and unstable candidates. Passing it means eligible for further evaluation, not production
ready or statistically proven better. Independent real-codebase evaluation is still required.

```bash
uv run --extra decision xss-decision-compare \
  --parent reports/decision_v2/parent_development \
  --candidate reports/decision_v2/candidate_restart_development \
  --out reports/decision_v2/comparison_restart.json
```

The comparison pairs identical record IDs and bootstraps whole template groups. The research
gate requires a positive verdict-accuracy improvement interval, alongside absolute recall,
false-alarm, unknown-overclaim and permutation thresholds frozen before training. This remains
evidence about the synthetic development workload, not real-world detection.

## Measured local run (2026-09-28)

One clean epoch was trained from the pinned Kev parent using the corrected suite above:
1,512 records, batch 8, accumulation 1, MPS fp32, 189 optimizer steps, 3,112 seconds
wall time (~52 minutes). The final checkpoint is local and git-ignored at
`models/xss-decision-0.8b-v2-local-restart/`; its adapter SHA-256 is
`84eea1185e6e4b776839f525f0fee763cc6ee5149ca66c9ccb2170725abb5cfa` and pointer-head
SHA-256 is `b3158258853284ede8bb37468917086de6c1311b9df853c15231b386c8fcea68`.
Calibration fit only on the calibration partition produced temperature `0.9267401`.

| Split | Verdict accuracy | Vulnerable recall | False-safe | False alarm | Unknown recall | Unknown overclaim | Context accuracy | Defense accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Development (216) | 0.9722 | 1.0000 | 0.0000 | 0.0833 | 1.0000 | 0.0000 | 0.9769 | 0.9583 |
| Locked test (216, scored once after candidate selection) | 0.9907 | 1.0000 | 0.0000 | 0.0278 | 1.0000 | 0.0000 | 0.9954 | 0.9815 |

The development-only gate returned `RESEARCH_ELIGIBLE` with no failed thresholds.
Template-group paired bootstrap versus the unchanged Kev parent gave verdict-accuracy
delta `+0.7269` (95% CI `[+0.6713, +0.7870]`) and vulnerability-recall delta `+0.9444`
(95% CI `[+0.8889, +0.9861]`). On the locked test, the only two verdict errors were
safe cases predicted vulnerable; there were no missed vulnerable cases. The API was
also smoke-tested locally with the canonical v2 questions: it returned vulnerable /
`dom_html` / `none` for a direct location-hash-to-`innerHTML` example and identified the
actual checkpoint via `/v1/models`.

These are strong results on a small, synthetic, templated JavaScript/HTML suite, not
evidence of accuracy on real applications, production readiness, confirmed browser
execution, or a PortSwigger/GApps lab solve. The candidate has not been evaluated on
independent real repositories or live targets. Do not use the locked-test result to
select more training settings; any further tuning needs a new independent test set.

Reports are local at `reports/decision_v2/candidate_restart_calibration/`,
`candidate_restart_development/`, `comparison_restart.json`, and
`candidate_restart_locked_test/`. The training log is
`models/xss-decision-0.8b-v2-local-restart.training.log`.

## Serve an explicitly selected checkpoint

```bash
uv run --extra decision xss-decision-serve \
  --run models/xss-decision-0.8b-v2-local-restart \
  --calibration reports/decision_v2/candidate_restart_calibration/temperature.json \
  --backend mlx --port 8009
```

Use `verdict` as a `choice` question with `vulnerable`, `safe`, and `unknown`; canonical instructions
are in `xss_decision/questions.py: XSS_QUESTIONS_V2`. Legacy yes/no questions remain supported but
cannot express missing evidence. No API prediction establishes browser-confirmed execution.

```bash
uv run --extra decision python examples/decision_v2_client.py --code-file path/to/example.js
```

The client refuses the heuristic backend, reports the actual loaded checkpoint, and returns
probabilities for verdict/context/defense. It does not submit probes, browse a target or claim a
lab is solved. Keep the code's relevant imports, helper implementations and data flow in the input;
otherwise an unknown verdict may be the correct result.

`live.assess` remains the separate scope-enforced scanner. This workflow does not silently turn
scanner fallback successes into model-only benchmark successes, and does not automatically
replace its probe planner with an unqualified research candidate.
