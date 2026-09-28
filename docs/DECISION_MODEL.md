# XSS Decision Model

The target is a small, calibrated XSS decision model rather than a free-form security chatbot. Its
client contract follows the same useful pattern as Kev: one shared state, independent typed
questions, and probability distributions instead of unsupported prose confidence.

## Stable contract

`POST /v1/systemone` accepts a string or structured state and up to 64 `noul`, `choice`, or `score`
questions. The initial question suite covers vulnerability, XSS family, execution context, existing
defense, and whether browser verification is required.

The server defaults to an explicitly non-learned reference backend. `--run` loads a real Kev
checkpoint with no heuristic fallback. The [v2 improvement workflow](DECISION_MODEL_V2.md) adds
three-way verdicts, browser-checked local fixtures, calibration-only temperature fitting,
checkpoint-backed evaluation and pretrained-Kev warm starts.

An initial local checkpoint now exists at `models/xss-decision-0.8b-experimental/`. It validates the
complete training and serialization path but is rejected for use: vulnerability accuracy is 0.544 on
development and 0.027 on near-miss cases. Its tracked manifest is
`registry/releases/xss-decision-0.8b-experimental.json`; the model files remain git-ignored.

```bash
uv run xss-decision-serve --port 8009
```

```bash
curl -s http://127.0.0.1:8009/v1/systemone \
  -H 'content-type: application/json' \
  -d '{
    "state": {"language":"javascript","code":"out.innerHTML = location.hash"},
    "questions": {
      "vulnerable": {
        "type":"noul",
        "instructions":"Does untrusted input reach an executable XSS sink?"
      },
      "context": {
        "type":"choice",
        "instructions":"What context receives the value?",
        "criteria":{"dom_html":null,"html_text":null,"js_code":null,"safe":null,"unknown":null}
      }
    }
  }'
```

Build pointer-model records from a frozen benchmark split:

```bash
uv run xss-decision-data \
  --source benchmarks/frozen/dev.jsonl \
  --output data/decision/dev.jsonl
```

## Model boundary

The learned model will decide `vulnerable`, `safe`, or `unknown` and return calibrated
probabilities. It must never emit the operational state `CONFIRMED`; only the browser oracle can
establish execution.

## Next milestones

1. Implement the Qwen backbone, rank-16 LoRA, and pointer head.
2. Freeze group-disjoint decision train/development/test suites.
3. Train 0.8B and 4B candidates without reading locked-test labels.
4. Fit temperature calibration on an independent calibration partition.
5. Evaluate near-miss sanitizer binding, option-order sensitivity, calibration, and abstention.
6. Connect the accepted checkpoint to the stable API and publish its model card and hashes.
