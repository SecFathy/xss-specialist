# PortSwigger Web Security Academy Results

This ledger records authorized PortSwigger lab benchmarks completed with the repository's scoped
assessment pipeline. A lab is recorded as solved only when the intended vulnerability is confirmed
by browser execution evidence.

| Date | Lab | Result | Finding | Requests | Evidence |
|---|---|---|---|---:|---|
| 2026-09-28 | Reflected XSS into HTML context with nothing encoded | SOLVED | Reflected XSS in GET `search`; `html_text`; browser execution confirmed | 22 | [`portswigger-reflected-xss-html-001/report.md`](portswigger-reflected-xss-html-001/report.md) |

## Result 001

- **Lab:** Reflected XSS into HTML context with nothing encoded
- **Target instance:** `0a440055033904578164c086002b003f.web-security-academy.net`
- **Assessment ID:** `portswigger-reflected-xss-html-001`
- **Status:** SOLVED
- **Confirmed finding:** `F-001`
- **Vulnerable input:** GET parameter `search`
- **Execution context:** `html_text`
- **Verification:** raw reflection and browser-observed JavaScript sentinel execution
- **Scope:** the supplied lab host only
- **Requests made:** 22
- **Out-of-scope requests:** 0

The target URL is an ephemeral Academy instance. The preserved local evidence, rather than continued
target availability, is the record of this result.
