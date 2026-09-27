# Live-Target XSS Assessment (authorized)

For **explicitly authorized** security testing only. Runs against `127.0.0.1` first; an external
target is refused until (a) the local acceptance evaluation has PASSED and (b) the operator sets
per-target `authorized_external=True`. Scope never auto-expands. Non-destructive by construction.

## Architecture
```
Target URL + explicit Scope
 → Crawler / route discovery        live/crawler.py   (headless, JS-aware, scope-bounded BFS)
 → Input surface mapper             live/crawler.map_inputs (GET/POST/JSON/path/fragment/DOM)
 → Context classifier               live/pipeline.classify_context (from where a marker lands)
 → Safe probe planner               live/probes.py    (marker-first, then context exec probes)
 → Headless browser executor        live/executor.py
 → Browser verification oracle      verification/browser_oracle.run_probe_on_url (AUTHORITATIVE)
 → Sanitizer identity verification  live/sanitizer_id.py (exact identity; near-miss => UNKNOWN)
 → Finding correlation              live/findings.py  (CONFIRMED/LIKELY/INCONCLUSIVE/NOT_VULNERABLE)
 → Evidence-backed report           live/report.py    (artifacts under reports/live_assessments/)
Orchestrator: live/assess.py        Local eval: live/evaluate.py     Test app: live/testapp.py
```

## Scope enforcement (live/scope.py)
Allowed hosts/subdomains/prefixes, excluded paths, max depth, max requests, rate limit, optional
auth/headers/cookies. Every URL checked BEFORE the request; the final (post-redirect) URL is
re-checked and out-of-scope redirects are blocked and logged. Bounded budget + rate limiter.

## Probes (marker-first, bounded, non-destructive)
Stage 1: a harmless unique MARKER (no metacharacters) to learn reflection + location. Stage 2 only
if reflected: context-tailored EXECUTION probes that do nothing but set `window.__X['<marker>']=1`.
No persistence, no exfiltration, no navigation off-target, no destructive action.

## Authority for CONFIRMED
The **browser oracle** decides CONFIRMED — it navigates the real URL, installs the per-marker
sentinel, and reports whether execution actually fired. Model confidence NEVER upgrades a finding.
Reflection/encoding is judged on the RAW server body (with a backslash guard so escaped quotes don't
false-match), not the re-serialized DOM.

## Sanitizer identity verification (near-miss protection)
The research showed sanitizer/entity-binding leakage is unsolved, so a name that merely RESEMBLES a
known-safe API never inherits its safety. Only an EXACT identity backed by verified evidence yields
VERIFIED_SAFE; a near-miss (edit distance ~1) is flagged and stays UNKNOWN. The fake-DOMPurify test
endpoint is caught by EXECUTION, not by name reasoning.

## Finding states
CONFIRMED (oracle observed execution) · LIKELY (dangerous payload reflected unencoded into a live
context, no execution confirmation) · INCONCLUSIVE (blocked/ambiguous) · NOT_VULNERABLE (encoded /
not reflected / verified-safe sanitizer). Never upgraded to CONFIRMED from model confidence.

## Evidence preservation
Each run writes crawl graph, route/input/candidate inventories, probe log, browser evidence, oracle
results, findings, scope log, request log, summary, and report.md under a NEW directory. Existing
research results are never overwritten. Live findings go to a QUARANTINE note — never auto-trained.

## Authorized-use workflow
1. `python -m live.evaluate` — must PASS frozen acceptance on the local app.
2. Obtain explicit written authorization + scope for the target.
3. `python -m live.assess --target <url> --allowed-prefix /app --authorized-external` (external).
4. Review findings; CONFIRMED are oracle-backed; LIKELY need manual confirmation.

## Limitations
Execution requiring user interaction (hover/click) yields LIKELY not CONFIRMED. POST-body and header
injection probed only when explicitly enabled. Crawler is browser-DOM based; deeply dynamic SPAs or
auth-gated areas may be under-covered. The context classifier is heuristic (oracle remains
authoritative). Stored XSS is simulated in-memory only in the test app; real stored-XSS discovery is
out of current scope.
