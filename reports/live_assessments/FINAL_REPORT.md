# Live-Target XSS Assessment — Completion Report

Extension of the `xss-specialist` prototype into an **authorized** live-target XSS assessment
system. Existing research untouched: model/XSSBench/KEV/RAG/registry unchanged, locked test unread,
frozen-bench oracle still 0 conflicts, all prior tests pass.

## What was implemented
- **Scope + enforcement** (`live/scope.py`): allowed hosts/subdomains/prefixes, exclusions, depth &
  request budgets, rate limit, pre-request + post-redirect scope checks, request/blocked logs,
  explicit `authorized_external` gate for non-loopback targets.
- **Crawler + input mapper** (`live/crawler.py`): headless, JS-aware, deterministic BFS; discovers
  links, forms (GET/POST fields), query params, JS-referenced routes; normalized candidate records
  incl. DOM-fragment sources.
- **Marker-first probe planner** (`live/probes.py`): harmless marker then context-tailored,
  non-destructive execution probes (only set `window.__X[marker]`).
- **Headless executor** (`live/executor.py`) + **live oracle** (`verification/browser_oracle.run_probe_on_url`):
  navigates real URLs, per-marker execution sentinel, raw-body reflection with backslash guard.
  **Oracle authoritative for CONFIRMED.**
- **Sanitizer identity verification** (`live/sanitizer_id.py`): exact identity only; near-miss stays
  UNKNOWN and never inherits safety.
- **Finding state machine + correlation** (`live/findings.py`): CONFIRMED / LIKELY / INCONCLUSIVE /
  NOT_VULNERABLE; never CONFIRMED from model confidence.
- **Reporting + evidence preservation** (`live/report.py`): full artifact set per run.
- **Orchestrator** (`live/assess.py`) with external-target refusal until local eval passes AND
  per-target authorization is given.
- **Local vulnerable test app** (`live/testapp.py`) + **evaluation harness** (`live/evaluate.py`)
  with FROZEN acceptance criteria.

## What was actually executed
- Full pipeline run against the local app: 12 routes, 24 candidates, **6 CONFIRMED + 1 LIKELY**,
  0 out-of-scope, artifacts saved to `reports/live_assessments/local_fullpipe/`.
- External-target refusal verified (refused before any network call, TEST-NET-1).
- 18/18 unit tests pass (13 existing + 5 live). Frozen-bench oracle unchanged (0 conflicts).
- **No external target was tested.**

## Local benchmark results (frozen acceptance)
| metric | value | threshold |
|---|---|---|
| precision | 1.00 | ≥ 0.90 ✅ |
| recall | 1.00 | ≥ 0.85 ✅ |
| FPR | 0.00 | ≤ 0.10 ✅ |
| FNR | 0.00 | — |
| context accuracy | 1.00 | — |
| confirmed-execution accuracy | 0.83 | ≥ 0.70 ✅ |
| **near-miss sanitizer leakage** | **0.00** | ≤ 0.00 ✅ |
| requests / finding | ~4.3 | — |
| runtime / route | ~1.2 s | — |

**ACCEPTED = True.** The fake-DOMPurify endpoint was caught by execution, not name reasoning —
directly mitigating the prototype's unsolved near-miss leakage at the assessment layer.

## Remaining failure modes
- Interaction-gated execution (hover/click handlers) → LIKELY, not CONFIRMED.
- POST-body / header / JSON injection probed only when explicitly enabled.
- Heuristic context classifier (oracle stays authoritative).
- SPA/auth-gated coverage limited; stored-XSS only simulated in-memory locally.
- Local benchmark is synthetic and small (11 endpoints); numbers bound the mechanism, not a real app.

## Readiness classification
**AUTHORIZED PILOT READY** — for use against explicitly authorized targets by an operator, with
human review of findings. The measured evidence (P/R 1.0, FPR 0, near-miss leakage 0, oracle-backed
CONFIRMED, enforced scope + budgets, external refusal, full evidence artifacts) supports pilot use.
**NOT** controlled-production ready: evidence is from a synthetic local app only; real-target
precision/recall, coverage on complex apps, POST/header/stored-XSS breadth, and operator workflow
integration remain unproven. Live findings are quarantine-only and never auto-train the specialist.
