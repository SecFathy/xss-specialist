# Threat Model (the learning pipeline)

The specialist analyzes untrusted code and ingests external knowledge. The adversary's goal is to
corrupt the model — push a false or malicious "fact" into the weights, or make the detector
unreliable. Assets to protect: verified knowledge store, training data, promoted weights.

## Attacker capabilities (assumed)
- Can submit arbitrary knowledge items / write-ups for ingestion.
- Can craft code samples for analysis (including prompt-injection-laced comments).
- Cannot modify the frozen benchmark, the registry, or the code.

## Attacks and defenses (tested — `verification/adversarial_pipeline.py`, Phase 17)

| Attack | Defense | Result |
|---|---|---|
| Repeated false claim | repetition ≠ evidence; verification requires a resolvable authoritative reference | not verified → not trained |
| Fabricated authority ("OWASP-verified" in text) | verification checks the *provenance reference*, not the claim text | not verified |
| Fake citation to attacker domain | reference allow-list (OWASP/CWE/MDN/W3C) | not verified |
| Prompt injection in a claim | independent injection filter | rejected |
| Private/secret data injection | independent privacy filter (keys/PII/passwords) | rejected |
| Near-duplicate poisoning | dedup + still fails verification | not trained |

A claim reaches training only if **all** independent gates agree: KEV routes `TRAINING_CANDIDATE`
**and** verification is `VERIFIED` **and** the privacy/injection filters pass. Measured breaches to
training in the current suite: **0 / 15**.

## Benchmark integrity
- Locked test read at most once per candidate, only via `--allow-test`.
- Training data hash-checked disjoint from every frozen split at build time.
- Contamination check at benchmark-freeze time aborts on any cross-split code overlap.

## Residual risks
- The reference allow-list is a coarse proxy for authority; a compromised authoritative source
  would pass. Mitigation: human approval before promotion (Phase 22).
- The privacy/injection filters are pattern-based and can miss novel encodings; they are a
  defense-in-depth layer, not a sole control.
