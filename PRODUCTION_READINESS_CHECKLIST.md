# Production Readiness Checklist

- [x] Ontology + provenance schema (source vs synthetic separated)
- [x] Verified knowledge corpus with references
- [x] Frozen XSSBench (dev/test-locked/generalization/nearmiss/adversarial), hard negatives
- [x] Contamination check at freeze; training data hash-disjoint from all splits
- [x] Baselines measured before specialization (A base, B base+RAG)
- [x] Retrieval evaluated independently (Recall@K / MRR / nDCG)
- [x] Teacher SFT grounded in verified labels, all labelled synthetic
- [x] LoRA training reproducible (dataset hash, base rev, config, seed, runtime)
- [x] KEV routing gate (frozen zero-shot), raw probs stored, not treated as truth
- [x] Independent verification (browser oracle: 0 conflicts in scope)
- [x] Pipeline poisoning suite: 0/15 breaches to training
- [x] Privacy + injection filters (independent)
- [x] Frozen promotion gate (does not rubber-stamp: v1 REJECTED)
- [x] Versioned registry with lineage
- [x] Rollback without retraining
- [x] Kill switch (halts learning, keeps inference/audit)
- [x] Paired-bootstrap significance; locked test read-once discipline
- [x] Reproducibility manifest
- [ ] Candidate that clears the full gate (v1/v2/v3 rejected on near-miss leakage; new approach required)
- [ ] Real-codebase / repository-level evaluation at scale
- [ ] Adversarial-evasion detection hardened
- [x] Offline operational monitoring dashboard (summary metadata only; no sensitive evidence ingestion)
- [ ] Operated canary with approved pilot traffic and recorded human review
- [ ] Human-in-the-loop promotion operated in a pilot

## Kev-based decision model v2 (local research)

This is separate from the historical generative-model and live-scanner checklist above.
The scanner's successful probes do not establish learned-model accuracy.

- [x] Real checkpoint-backed API with explicit identity; no heuristic fallback on load errors
- [x] Three-way vulnerable/safe/unknown decision contract
- [x] New versioned train/calibration/development/test suite; historical frozen files unchanged
- [x] Related variants grouped; structural wrappers held out across partitions
- [x] 2,160 synthetic JavaScript/HTML fixtures checked in a local browser with no conflicts
- [x] Missing-helper cases admit both safe and unsafe completions; neither completion enters model input
- [x] Pretrained Kev-0.8B adapter and pointer head loaded with matching architecture and pinned base
- [x] Unchanged-parent development baseline measured before candidate training
- [x] Calibration-only temperature fitting, bound to checkpoint hashes
- [x] Model-only recall, false-safe/false-alarm, unknown-overclaim and permutation evaluation
- [x] Paired template-group bootstrap and pre-training research gate
- [ ] Trained candidate meets the independent development research gate
- [ ] Selected candidate scored once on the locked test
- [ ] Independent real-codebase coverage, including URL contexts and framework/server-side flows
- [ ] Learned model drives an authorized live-lab workflow without manual/fallback attribution
- [ ] Production-qualified model (synthetic scores alone are insufficient)

Workflow: [Decision Model v2](docs/DECISION_MODEL_V2.md). Model files, generated datasets and
evaluation artifacts remain local and git-ignored. No GitHub push or release is part of this cycle.
