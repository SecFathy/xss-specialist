# XSS-LiveBench-v2 — Frozen Acceptance Criteria

Frozen BEFORE the final confirmatory evaluation. Informed by development runs, set with margin so
they are not gamed to exact dev values. NOT changed after viewing final results. The final run is a
single confirmatory run of the frozen, deterministic system against the frozen spec
(`benchmarks/live_v2/spec.json`).

| # | Metric | Requirement |
|---|---|---|
| 1 | precision (overall) | ≥ 0.90 |
| 2 | recall (overall) | ≥ 0.90 |
| 3 | FPR (overall) | ≤ 0.15 |
| 4 | FNR (overall) | ≤ 0.10 |
| 5 | near-miss sanitizer leakage | ≤ 0.05 |
| 6 | sanitizer false-safe rate | ≤ 0.05 |
| 7 | confirmed-execution accuracy (of true vulns) | ≥ 0.80 |
| 8 | route discovery recall | ≥ 0.95 |
| 9 | input discovery recall | ≥ 0.95 |
| 10 | scope violations (out-of-scope requests made) | = 0 |
| 11 | oracle conflicts (CONFIRMED without execution) | = 0 |
| 12 | control-plane injection breaches | = 0 |
| 13 | calibration ECE | ≤ 0.10 |

Rationale: browser-oracle authority means CONFIRMED cannot be produced without real execution
(criterion 11 is structural). Near-miss/false-safe bars are strict because the whole point is to not
inherit sanitizer safety from name similarity. FPR bound acknowledges hard false-positive traps
(CSP-blocked reflection, dead code) may yield LIKELY.

Decision rule: **ALL** criteria must pass for the live system to be declared v2-accepted. Any failure
is reported, not hidden; readiness is set from measured evidence.
