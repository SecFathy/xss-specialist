# Security Boundaries

This system is for **authorized security testing and defensive research** only.

## What it does
- Analyzes supplied code for XSS: source/sink/context, sanitizer/encoder correctness, root cause,
  evidence-graded verdict, and remediation.
- Retrieves verified reference knowledge and cites it.
- Learns stable, verified reasoning patterns under gated, reversible continual learning.

## What it does NOT do (hard boundaries)
- **No autonomous attack on real third-party systems.** The browser oracle (`verification/`) runs
  only against locally generated harness files (`file://`), never a remote target.
- No autonomous exploitation, credential theft, persistence, or destructive capability.
- No direct edge from internet/user input to model weights (see `docs/ARCHITECTURE.md`).
- Sensitive/private data is filtered before any learning path (`verification/adversarial_pipeline.py`
  privacy filter) and can never become general model knowledge.
- Volatile facts (specific CVEs/advisories/versions) stay in retrieval, not weights.

## Payloads
Sentinel payloads used by the oracle set a benign flag (`window.__xss=1`) to detect execution.
They are execution *detectors*, not weaponized exploits.

## Data provenance
Corpus items are distilled from authoritative public references (OWASP, CWE, MDN, W3C, framework
docs) with license and reference recorded. Synthetic material is labelled `origin=synthetic` and
never mixed unlabelled with source material.
