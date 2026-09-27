# Methodology

## Research question
Can a small specialist model reach deep XSS competence through domain knowledge, grounded SFT,
RAG, LoRA adaptation, KEV-based knowledge gating, independent verification, deterministic
continual-learning data construction, rigorous specialist evaluation, and promotion controls —
and does that competence generalize without knowledge leakage?

## Design
- **Ontology first** (Phase 1): controlled vocabularies for families, contexts, data-flow roles,
  defenses; records `KnowledgeItem` and `XSSCase` carry provenance and epistemic tags.
- **Corpus** (Phase 2): authored, provenance-bearing, factual claims from authoritative public
  references; `origin=source` vs `origin=synthetic` never mixed unlabelled.
- **Benchmark before training** (Phases 3-5): XSSBench frozen with dev / locked-test /
  generalization / near-miss / adversarial splits, hard negatives in every split, contamination
  checked at freeze.
- **Baselines** (Phases 6-7): base SLM, base+RAG measured before specialization.
- **Retrieval** (Phase 8): TF-IDF (word + char n-gram) retriever, evaluated independently
  (Recall@K/MRR/nDCG) with authored gold relevance.
- **Teacher/SFT** (Phase 9): grounded synthesizer over verified labels + citations; contrastive
  pairs + near-miss records; all labelled synthetic; hash-checked disjoint from all frozen splits.
- **Training** (Phase 10): LoRA on 4-bit MLX Qwen3-8B; base untouched; immutable adapter; full
  config + dataset hash recorded.
- **KEV gate** (Phases 12-13): frozen zero-shot Kev-4B decision model routes each item; raw
  probabilities stored, never treated as truth.
- **Verification** (Phase 14): independent — a real headless-browser oracle confirms executable
  DOM labels; knowledge claims require resolvable authoritative provenance.
- **Evaluation** (Phases 16-20): leakage, adversarial pipeline, false-positive control; frozen
  promotion gate.

## Statistics
Conditions compared on the *same* frozen items. Accuracy differences use a paired bootstrap (5000
resamples, per-split RNG stream) 95% CI; "better" is claimed only when the CI excludes 0. No
threshold is tuned on the locked test; the locked test is read once, after a gate PROMOTE.

## Integrity controls
Fixed master seed + independent per-component RNG streams; canonical JSON hashing of every
artifact; environment manifest recorded per result; contamination checks; no silent removal of
failed examples; negative results recorded, not hidden.
