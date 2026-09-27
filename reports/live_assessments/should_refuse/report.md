# Live XSS Assessment — http://example.com/

For authorized security testing only. Oracle is authoritative for CONFIRMED; model confidence never upgrades a finding.

## Target summary

- **target:** http://example.com/
- **routes discovered:** 1
- **js routes discovered:** 0
- **inputs discovered:** 1
- **candidates tested:** 1
- **confirmed:** 0
- **likely:** 0
- **inconclusive:** 0
- **not vulnerable:** 1
- **requests made:** 2
- **out of scope blocked:** 0
- **coverage limitations:** Synthetic/authorized scope only; POST bodies and headers probed only when enabled; execution requiring user interaction (hover/click) may yield LIKELY not CONFIRMED.

## Findings (CONFIRMED / LIKELY)

## All candidate outcomes

| finding | status | url | param | context | browser |
|---|---|---|---|---|---|
| F-000 | NOT_VULNERABLE | http://example.com/ | `#` | unknown | not-executed |
