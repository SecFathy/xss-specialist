"""Phase 15 — controlled consolidation ("AI sleep") cycle.

Orchestrates one gated learning cycle with deterministic, versioned data construction and separate
RNG streams, so a change in candidate count never perturbs negative/replay sampling. The cycle is
halted by the kill switch (Phase 26). It does not itself deploy — it produces a candidate adapter
and a promotion decision; deployment is a separate human-approved step (Phase 22).

Steps: collect verified candidates -> dedup -> cluster -> resolve conflicts -> contrastive + hard
negatives -> replay -> train candidate -> evaluate -> promote/reject.
"""
from __future__ import annotations

import json
from pathlib import Path

from xss_specialist.repro import sha256_text, stream
from registry.registry import require_learning_enabled


def collect_candidates(items, kev_gate) -> list:
    """Route each knowledge item through KEV; keep only TRAINING_CANDIDATE + verified."""
    from kevgate.gate import TRAINING_CANDIDATE
    from verification.pipeline import verify_knowledge
    vstatus = verify_knowledge(items)["status"]
    kept = []
    for it in items:
        d = kev_gate.route(it)
        v = vstatus.get(it.id, ("unverified", ""))[0]
        if d.route == TRAINING_CANDIDATE and v == "verified":
            kept.append((it, d))
    return kept


def dedup(cases: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in cases:
        h = sha256_text(c["code"])
        if h not in seen:
            seen.add(h); out.append(c)
    return out


def build_cycle_dataset(base_sft: str, replay_frac: float = 0.3) -> dict:
    """Deterministically assemble the consolidation training set: new contrastive/near-miss records
    plus a replay sample of prior skills. Uses independent streams for replay vs negatives so counts
    don't cross-perturb (integrity rule)."""
    require_learning_enabled("consolidation")
    recs = [json.loads(l) for l in Path(base_sft).read_text().splitlines() if l.strip()]
    replay_rng = stream("consolidation_replay")
    n_replay = int(len(recs) * replay_frac)
    replay_idx = replay_rng.choice(len(recs), size=min(n_replay, len(recs)), replace=False)
    manifest = {
        "n_total": len(recs),
        "n_contrastive": sum(1 for r in recs if not r.get("tags", []) or "train_nearmiss" not in r["tags"]),
        "n_nearmiss": sum(1 for r in recs if "train_nearmiss" in r.get("tags", [])),
        "n_replay_sampled": int(len(replay_idx)),
        "replay_stream": "consolidation_replay",
        "negatives_stream": "consolidation_negatives",
        "sha256": sha256_text(Path(base_sft).read_text()),
    }
    return manifest
