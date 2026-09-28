---
license: apache-2.0
base_model: Qwen/Qwen3.5-0.8B-Base
library_name: peft
pipeline_tag: text-classification
tags:
  - xss
  - security
  - decision-model
  - research-preview
---

# XSS Decision 0.8B — Kev XSS Specialist v2 (Experimental)

An experimental three-way XSS triage checkpoint built by fine-tuning the Kev-0.8B
decision model. It returns probability distributions for `vulnerable`, `safe`, or
`unknown`, plus context and defense classifications. It does not generate exploit
payloads or execute code. Model predictions are not browser-execution evidence and
must not be used as the sole basis for declaring code safe.

## Status

**Research preview only. Not production-ready.** It passed this repository's frozen
synthetic development gate and was scored once on a separate synthetic locked split.
It has not been evaluated on independent real repositories, live applications, or
PortSwigger labs. The very high benchmark scores should not be interpreted as expected
real-world accuracy: the dataset consists of programmatically generated JavaScript/HTML
fixtures with repeated sink primitives and limited structural variation.

## Lineage and files

- Base: [`Qwen/Qwen3.5-0.8B-Base`](https://huggingface.co/Qwen/Qwen3.5-0.8B-Base), pinned at
  `dc7cdfe2ee4154fa7e30f5b51ca41bfa40174e68`.
- Warm-start parent: [`jaredpalmer/kev-0.8b`](https://github.com/jaredpalmer/kev), pinned at
  `9a45d25eb2ab761841196625383fa1dff0e56c1e`.
- LoRA rank 16, all supported Kev projection targets, pointer head dimension 256.
- The release contains the adapter, pointer head, tokenizer/configuration, calibration,
  training metrics, sanitized provenance, and this card. It does **not** include Qwen base
  weights; those are fetched separately by the serving code.
- Adapter SHA-256: `84eea1185e6e4b776839f525f0fee763cc6ee5149ca66c9ccb2170725abb5cfa`.
- Pointer-head SHA-256: `b3158258853284ede8bb37468917086de6c1311b9df853c15231b386c8fcea68`.
- Training-suite manifest SHA-256: `bffa4bca7f5ff8f6a1425f38aed88a7682f064132251a89f080ccf2a8574b45d`.

## Training

One epoch over 1,512 browser-checked training fixtures, 189 optimizer steps, seed 0,
learning rate `2e-5`, batch 8, accumulation 1, fp32 on Apple MPS; elapsed time was
3,111.56 seconds. All examples were generated locally by deterministic code; no public
repository snippets, real target responses, or model-generated labels were used. The
full suite had 2,160 JavaScript/HTML fixtures split into train/calibration/development/
locked-test partitions by template group. The locked split was not used for training,
calibration, or candidate selection.

Temperature `0.9267400610196151` was fitted only on the 216-case calibration partition
and is bound to this exact checkpoint's hashes.

## Results

Each split has 216 balanced cases (72 per verdict). Recall includes every gold vulnerable
case; a safe/unknown prediction counts as a miss.

| Split | Verdict accuracy | Vulnerable recall | False-safe rate | False-alarm rate | Unknown recall | Unknown overclaim | Context accuracy | Defense accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Development | 97.22% | 100% | 0% | 8.33% | 100% | 0% | 97.69% | 95.83% |
| Locked test (one read, after selection) | 99.07% | 100% | 0% | 2.78% | 100% | 0% | 99.54% | 98.15% |

The development-only gate marked the candidate `RESEARCH_ELIGIBLE`. Paired template-group
bootstrap versus the unchanged Kev parent showed a verdict-accuracy delta of +72.69
percentage points (95% CI +67.13 to +78.70) on this synthetic development set. On the
locked test, two safe fixtures were predicted vulnerable; no vulnerable fixture was
missed. This is not a real-world comparative claim.

## Intended use and limitations

Intended only for defensive research and code-triage experiments by users who can review
the supplied code and verify findings independently. A `safe` answer does not prove the
application safe. A `vulnerable` answer is not a confirmed exploit. Use a browser or other
execution oracle and human review before reporting a finding. `unknown` is appropriate
when source, sanitizer implementation, framework behavior, or sink context is missing.

Coverage is limited to generated JavaScript/HTML examples involving selected DOM/JS sinks,
four synthetic source types, and a small set of wrappers. It does not establish behavior
for PHP, server-side template engines, full frameworks, URL/CSS contexts, CSP, Trusted Types,
stored workflows in real applications, minified/obfuscated programs, or live systems. It
may over- or under-classify code outside this narrow distribution.

Out of scope: automated exploitation, unsupervised vulnerability claims, production release
gating, or replacing static analysis, browser verification, and expert review.

## Local usage

From a compatible checkout of this repository (Python 3.12+):

```bash
uv sync --extra decision
uv run --extra decision xss-decision-serve \
  --run models/xss-decision-0.8b-kev-specialist-v2 \
  --calibration models/xss-decision-0.8b-kev-specialist-v2/temperature.json \
  --backend mlx --port 8009
```

Use the versioned questions `XSS_QUESTIONS_V2` from `xss_decision/questions.py`. Keep
relevant imports, helper definitions, and data flow in the request. The first run downloads
the separately licensed Qwen base model. See `docs/DECISION_MODEL_V2.md` in the source
repository for the evaluation protocol and API client example.

## License and attribution

The adapter and pointer head are released under Apache-2.0. The Qwen base is separately
licensed under Apache-2.0. The Kev engine and parent checkpoint are Apache-2.0; this release
is an independent fine-tune and is not endorsed by Qwen or the Kev authors. See the included
`LICENSE` and upstream model repositories for their notices. The synthetic suite was authored
for this project; it contains no copied application code.
