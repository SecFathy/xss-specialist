# Live XSS Assessment — https://0a440055033904578164c086002b003f.web-security-academy.net/

**Benchmark result:** SOLVED — Reflected XSS into HTML context with nothing encoded.

For authorized security testing only. Oracle is authoritative for CONFIRMED; model confidence never upgrades a finding.

## Target summary

- **target:** https://0a440055033904578164c086002b003f.web-security-academy.net/
- **routes discovered:** 2
- **js routes discovered:** 2
- **inputs discovered:** 10
- **candidates tested:** 10
- **confirmed:** 1
- **likely:** 0
- **inconclusive:** 0
- **not vulnerable:** 9
- **requests made:** 22
- **out of scope blocked:** 0
- **coverage limitations:** Synthetic/authorized scope only; POST bodies and headers probed only when enabled; execution requiring user interaction (hover/click) may yield LIKELY not CONFIRMED.

## Findings (CONFIRMED / LIKELY)

### F-001 — CONFIRMED (reflected)
- **URL:** https://0a440055033904578164c086002b003f.web-security-academy.net/
- **Method / Parameter:** GET / `search`
- **Execution context:** html_text
- **Source → Sink:** GET parameter → —
- **Existing sanitizer:** none observed
- **Sanitizer identity verification:** none observed
- **Browser verification:** executed (oracle-authoritative for CONFIRMED)
- **Confidence:** 0.99
- **Impact:** Executable script in the page origin: session/DOM access, action-on-behalf.
- **Remediation:** Contextual output encoding at the sink; use a verified-safe sanitizer (exact known API) or a safe DOM API (textContent).
- **Reproduction:** `https://0a440055033904578164c086002b003f.web-security-academy.net/?search=%3Cspan%3Exza81f39cd%3C%2Fspan%3E%3Cimg+src%3Dx+onerror%3D%22window.__X%5B%27xza81f39cd%27%5D%3D1%22%3E` (marker `xza81f39cd`, note: html_text img-onerror)
- **Evidence refs:** —

## All candidate outcomes

| finding | status | url | param | context | browser |
|---|---|---|---|---|---|
| F-001 | CONFIRMED | https://0a440055033904578164c086002b003f.web-security-academy.net/ | `search` | html_text | executed |
| F-000 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post?postId=3 | `postId` | unknown | not-executed |
| F-002 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `csrf` | unknown | not-executed |
| F-003 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `postId` | unknown | not-executed |
| F-004 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `comment` | unknown | not-executed |
| F-005 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `name` | unknown | not-executed |
| F-006 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `email` | unknown | not-executed |
| F-007 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post/comment | `website` | unknown | not-executed |
| F-008 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/ | `#` | unknown | not-executed |
| F-009 | NOT_VULNERABLE | https://0a440055033904578164c086002b003f.web-security-academy.net/post?postId=3 | `#` | unknown | not-executed |
