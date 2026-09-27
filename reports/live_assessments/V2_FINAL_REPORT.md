# XSS-LiveBench-v2 — Final Report

Authorized-assessment hardening phase. Existing research untouched (model/XSSBench/KEV/RAG/registry unchanged; **locked XSSBench test unread**; frozen-bench oracle still 0 conflicts; all prior tests pass). All active testing was **local (127.0.0.1) only**; no external target touched.

## 1. Components implemented
v1 release freeze (`live/release.py`); XSS-LiveBench-v2 (102 cases, `live/testapp_v2.py`+`live/livebench.py`); interaction-aware oracle (`verification/browser_oracle.run_probe_on_url`); marker-first + quoted/unquoted + JS-code execution probes (`live/probes.py`); stored-XSS submit→view correlation (`live/stored.py`); crawler+coverage (`live/crawler.py`,`live/coverage.py`); failure attribution + per-context/class/category scoring (`live/livebench.py`); component ablation (`live/ablation.py`); control-plane robustness (`live/robustness.py`); calibration (`live/calibration.py`); performance (`live/performance.py`); frozen acceptance (`reports/live_assessments/V2_ACCEPTANCE.md`); paired final eval (`live/final_eval.py`); authorized pilot mode (`live/pilot.py`).

## 2. Experiments actually executed (all local)
- LiveBench-v2 full pipeline run: 102 cases, 152.5s, 272 requests.
- Final frozen paired eval (v2 vs v1-emulated), 275.4s.
- Coverage, robustness, ablation, calibration, performance runs.
- 22/22 unit tests pass.

## 3. Baseline (v1-emulated) vs v2 — paired
| system | precision | recall | FPR | accuracy |
|---|---|---|---|---|
| v1-emulated | 0.935 | 0.906 | 0.105 | 0.902 |
| **v2** | **0.941** | **1.000** | **0.105** | **0.961** |

Paired bootstrap (v2−v1, per-case accuracy, 5000 resamples): **Δacc +0.059** 95% CI [+0.020, +0.108] (CI excludes 0 → significant). The gain is driven by recall (interaction-aware oracle + JS-code probes + stored correlation catch code-sink and interaction-gated executions v1 missed).

## 4. XSS-LiveBench-v2 results (v2)
precision 0.941 · recall 1.000 · FPR 0.105 · FNR 0.000 · accuracy 0.961 · confirmed-exec 0.938 · context 0.812

## 5. Per-context performance
| context | n | P | R | FPR |
|---|---|---|---|---|
| css | 2 | 1.0 | 1.0 | 0.0 |
| dom_attr | 1 | None | None | 0.0 |
| dom_html | 36 | 1.0 | 1.0 | 0.0 |
| html_attr | 18 | 1.0 | 1.0 | 0.0 |
| html_attr_url | 4 | 1.0 | 1.0 | 0.0 |
| html_text | 25 | 0.625 | 1.0 | 0.15 |
| js_code | 9 | 0.875 | 1.0 | 0.5 |
| js_string | 7 | 1.0 | 1.0 | 0.0 |

## 6. Per-XSS-class performance
| class | n | P | R |
|---|---|---|---|
| dom | 39 | 1.0 | 1.0 |
| reflected | 23 | 1.0 | 1.0 |
| safe | 38 | 0.0 | None |
| stored | 2 | 1.0 | 1.0 |

## 7. Crawler / input-discovery coverage
route recall **1.000**, input recall **1.000**, duplicate rate 0.000, JS routes 102, out-of-scope blocked 0, crawl requests 104.

## 8. Browser-oracle performance
confirmed-execution accuracy 0.938; oracle authoritative for CONFIRMED (no CONFIRMED without real execution). Interaction contribution: {'confirmed_passive': 58, 'confirmed_via_interaction': 2}.

## 9. Near-miss sanitizer results
near-miss leakage **0.0** (21 near-miss cases), sanitizer false-safe **0.0**. Every look-alike sanitizer was caught by EXECUTION; identity verification keeps unknown/near-miss names UNKNOWN and never inherits safety.

## 10. False-positive torture-suite results
fp_torture category: n=16, FPR 0.188 (3 false positives). Remaining FPs are hard traps where dangerous input reflects UNENCODED but does not execute (dead code, unreachable sink, CSP-blocked) — reported as LIKELY, not CONFIRMED.

## 11. Failure-attribution matrix
`{'CONTEXT_CLASSIFICATION_ERROR': 4}` — all remaining misses are CONTEXT_CLASSIFICATION (the LIKELY FPs). No CRAWLER/INPUT/ORACLE/SANITIZER/INTERACTION misses. **The model was not the bottleneck for any case.**

## 12. Ablation (which component contributes)
| config | P | R | FPR |
|---|---|---|---|
| E1_reflection_only | 0.6224489795918368 | 0.953125 | 0.9736842105263158 |
| E2_raw_unencoded | 0.8666666666666667 | 0.40625 | 0.10526315789473684 |
| E3_oracle_execution | 0.9411764705882353 | 1.0 | 0.10526315789473684 |
| E4_interaction_aware | 0.9411764705882353 | 1.0 | 0.10526315789473684 |
| E5_full_identity | 0.9411764705882353 | 1.0 | 0.10526315789473684 |

Interpretation: a naive reflection scanner is FPR≈0.97; encoding-awareness alone gives high precision but low recall; the **browser oracle** is what delivers both precision and recall. System quality comes from the live verification layer, **not** the specialist model.

## 13. Adversarial robustness (control plane)
9 control-plane injection attacks (prompt injection, fake docs/sanitizer descriptions, misleading names, param pollution, redirect chain, error reflection, delayed/long pages): **confirmed-without-execution = 0**, **control plane intact = True**. No page content changed scope/budget/oracle/promotion/registry/KEV state.

## 14. Performance
runtime/case ~1.5s; requests/finding 4.0; RAG retrieve 0.5ms; browser nav (cold) 845.9ms. Bottleneck: browser navigation/execution. KEV/model are offline, not on the hot path.

## 15. Remaining known failure modes
- ~3 hard false-positive traps (dead code / unreachable sink / CSP-blocked) surface as LIKELY.
- Interaction-gated executions occasionally stay LIKELY when the exact event is not derivable.
- Benchmark is synthetic/local (102 cases); no real-application evidence.
- POST-body/header/JSON injection and multi-page auth flows exercised only lightly.
- Context classifier is heuristic (oracle remains authoritative).

## 16. Frozen acceptance-gate decision
**ALL 13 frozen criteria PASS** (see `V2_ACCEPTANCE.md`): precision 0.941≥0.90, recall 1.000≥0.90, FPR 0.105≤0.15, FNR 0.000≤0.10, near-miss leakage 0.0≤0.05, sanitizer false-safe 0.0≤0.05, confirmed-exec 0.938≥0.80, route recall 1.0≥0.95, input recall 1.0≥0.95, scope violations 0, oracle conflicts 0, control-plane breaches 0, ECE 0.041≤0.10.

## 17. Readiness classification
**AUTHORIZED PILOT READY.** The frozen local gate passes on a materially harder 102-case benchmark, with a statistically significant paired improvement over v1, oracle-authoritative CONFIRMED, near-miss leakage 0.0, full scope enforcement, 0 control-plane breaches, and complete evidence artifacts. **NOT CONTROLLED PRODUCTION READY** — all evidence is from a synthetic local application; production requires real-target precision/recall, coverage on complex/auth/SPAs, POST/header/stored breadth, and operator-workflow evidence (Phase 18 collects these in a pilot, without modifying the frozen scanner mid-cohort).

## 18. Next blockers to CONTROLLED PRODUCTION READY
1. Real authorized-target pilot evidence (precision/recall/FPR on non-synthetic apps).
2. Coverage on SPAs, authenticated flows, POST/JSON/header inputs, path parameters at scale.
3. Reduce hard-trap LIKELY FPs (CSP-aware downgrade; reachability analysis) without eval tuning.
4. Operator workflow + human-review throughput; live-finding quarantine→verified-offline promotion path.
5. Scale/perf hardening for large sites within request budgets.
