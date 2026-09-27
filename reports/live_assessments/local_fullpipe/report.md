# Live XSS Assessment — http://127.0.0.1:8099/

For authorized security testing only. Oracle is authoritative for CONFIRMED; model confidence never upgrades a finding.

## Target summary

- **target:** http://127.0.0.1:8099/
- **routes discovered:** 12
- **js routes discovered:** 12
- **inputs discovered:** 24
- **candidates tested:** 24
- **confirmed:** 6
- **likely:** 1
- **inconclusive:** 0
- **not vulnerable:** 17
- **requests made:** 52
- **out of scope blocked:** 0
- **coverage limitations:** Synthetic/authorized scope only; POST bodies and headers probed only when enabled; execution requiring user interaction (hover/click) may yield LIKELY not CONFIRMED.

## Findings (CONFIRMED / LIKELY)

### F-000 — CONFIRMED (reflected)
- **URL:** http://127.0.0.1:8099/reflect?q=hello
- **Method / Parameter:** GET / `q`
- **Execution context:** html_text
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/reflect?q=%3Cspan%3Exz9606b3a3%3C%2Fspan%3E%3Cimg+src%3Dx+onerror%3D%22window.__X%5B%27xz9606b3a3%27%5D%3D1%22%3E` (marker `xz9606b3a3`, note: html_text img-onerror)
- **Evidence refs:** —

### F-002 — CONFIRMED (reflected)
- **URL:** http://127.0.0.1:8099/reflect_js?q=hello
- **Method / Parameter:** GET / `q`
- **Execution context:** js_string
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/reflect_js?q=xz61ab09d0%22%3Bwindow.__X%5B%27xz61ab09d0%27%5D%3D1%3B%2F%2F` (marker `xz61ab09d0`, note: js string breakout)
- **Evidence refs:** —

### F-006 — CONFIRMED (reflected)
- **URL:** http://127.0.0.1:8099/nearmiss?q=hello
- **Method / Parameter:** GET / `q`
- **Execution context:** html_text
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/nearmiss?q=%3Cspan%3Exzc2e31db0%3C%2Fspan%3E%3Cimg+src%3Dx+onerror%3D%22window.__X%5B%27xzc2e31db0%27%5D%3D1%22%3E` (marker `xzc2e31db0`, note: html_text img-onerror)
- **Evidence refs:** —

### F-010 — CONFIRMED (reflected)
- **URL:** http://127.0.0.1:8099/store?q=hello
- **Method / Parameter:** GET / `q`
- **Execution context:** html_text
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/store?q=%3Cspan%3Exzb3719516%3C%2Fspan%3E%3Cimg+src%3Dx+onerror%3D%22window.__X%5B%27xzb3719516%27%5D%3D1%22%3E` (marker `xzb3719516`, note: html_text img-onerror)
- **Evidence refs:** —

### F-011 — CONFIRMED (reflected)
- **URL:** http://127.0.0.1:8099/reflect
- **Method / Parameter:** GET / `q`
- **Execution context:** html_text
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/reflect?q=%3Cspan%3Exzd5bf2ebc%3C%2Fspan%3E%3Cimg+src%3Dx+onerror%3D%22window.__X%5B%27xzd5bf2ebc%27%5D%3D1%22%3E` (marker `xzd5bf2ebc`, note: html_text img-onerror)
- **Evidence refs:** —

### F-020 — CONFIRMED (dom)
- **URL:** http://127.0.0.1:8099/dom?q=hello
- **Method / Parameter:** GET / `#`
- **Execution context:** dom_html
- **Source → Sink:** URL fragment (DOM) → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/dom?q=hello#<span>xz90d3977d</span><img src=x onerror="window.__X['xz90d3977d']=1">` (marker `xz90d3977d`, note: html_text img-onerror)
- **Evidence refs:** —

### F-001 — LIKELY (reflected)
- **URL:** http://127.0.0.1:8099/reflect_attr?q=hello
- **Method / Parameter:** GET / `q`
- **Execution context:** html_attr
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** not-executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.60
- **Impact:** Untrusted input reaches a live context without verified-safe encoding.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `http://127.0.0.1:8099/reflect_attr?q=xz46e37086` (marker `xz46e37086`, note: harmless reflection marker)
- **Evidence refs:** —

## All candidate outcomes

| finding | status | url | param | context | browser |
|---|---|---|---|---|---|
| F-000 | CONFIRMED | http://127.0.0.1:8099/reflect?q=hello | `q` | html_text | executed |
| F-002 | CONFIRMED | http://127.0.0.1:8099/reflect_js?q=hello | `q` | js_string | executed |
| F-006 | CONFIRMED | http://127.0.0.1:8099/nearmiss?q=hello | `q` | html_text | executed |
| F-010 | CONFIRMED | http://127.0.0.1:8099/store?q=hello | `q` | html_text | executed |
| F-011 | CONFIRMED | http://127.0.0.1:8099/reflect | `q` | html_text | executed |
| F-020 | CONFIRMED | http://127.0.0.1:8099/dom?q=hello | `#` | dom_html | executed |
| F-001 | LIKELY | http://127.0.0.1:8099/reflect_attr?q=hello | `q` | html_attr | not-executed |
| F-003 | NOT_VULNERABLE | http://127.0.0.1:8099/encoded?q=hello | `q` | html_text | not-executed |
| F-004 | NOT_VULNERABLE | http://127.0.0.1:8099/json_script?q=hello | `q` | js_string | not-executed |
| F-005 | NOT_VULNERABLE | http://127.0.0.1:8099/sanitized?q=hello | `q` | html_text | not-executed |
| F-007 | NOT_VULNERABLE | http://127.0.0.1:8099/dom?q=hello | `q` | unknown | not-executed |
| F-008 | NOT_VULNERABLE | http://127.0.0.1:8099/dom_safe?q=hello | `q` | unknown | not-executed |
| F-009 | NOT_VULNERABLE | http://127.0.0.1:8099/fp_trap?q=hello | `q` | html_attr | not-executed |
| F-012 | NOT_VULNERABLE | http://127.0.0.1:8099/ | `#` | unknown | not-executed |
| F-013 | NOT_VULNERABLE | http://127.0.0.1:8099/reflect?q=hello | `#` | unknown | not-executed |
| F-014 | NOT_VULNERABLE | http://127.0.0.1:8099/reflect_attr?q=hello | `#` | unknown | not-executed |
| F-015 | NOT_VULNERABLE | http://127.0.0.1:8099/reflect_js?q=hello | `#` | unknown | not-executed |
| F-016 | NOT_VULNERABLE | http://127.0.0.1:8099/encoded?q=hello | `#` | unknown | not-executed |
| F-017 | NOT_VULNERABLE | http://127.0.0.1:8099/json_script?q=hello | `#` | unknown | not-executed |
| F-018 | NOT_VULNERABLE | http://127.0.0.1:8099/sanitized?q=hello | `#` | unknown | not-executed |
| F-019 | NOT_VULNERABLE | http://127.0.0.1:8099/nearmiss?q=hello | `#` | unknown | not-executed |
| F-021 | NOT_VULNERABLE | http://127.0.0.1:8099/dom_safe?q=hello | `#` | dom_html | not-executed |
| F-022 | NOT_VULNERABLE | http://127.0.0.1:8099/fp_trap?q=hello | `#` | unknown | not-executed |
| F-023 | NOT_VULNERABLE | http://127.0.0.1:8099/store?q=hello | `#` | unknown | not-executed |
