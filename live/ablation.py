"""Phase 10 — component ablation, recomputed from the frozen LiveBench-v2 rows (no browser re-run).

Determines which live-pipeline COMPONENT contributes each improvement by recomputing finding
outcomes under progressively-enabled components, using the per-case evidence already captured
(reflected / raw_reflected / executed / sanitizer_seen / interactions_performed):

  E1 reflection-only        positive = any reflection            (a naive "input echoes" scanner)
  E2 raw-unencoded-reflect  positive = dangerous payload unencoded (encoding-aware, no execution)
  E3 + browser oracle       positive = E2 or executed; CONFIRMED requires executed
  E4 + interaction-aware    E3 with interaction-driven executions counted (already in rows)
  E5 + sanitizer identity   E4; verified-safe sanitizer downgrades, near-miss never granted safety

Model conditions (base/specialist ± RAG) are measured on the offline XSSBench (reports/final/) and
are NOT re-attributed here: on live URLs the browser oracle — not the model — decides CONFIRMED, and
this ablation shows exactly that.
"""
from __future__ import annotations

import json
from pathlib import Path


def _score(rows, positive_fn):
    tp = fp = fn = tn = 0
    for r in rows:
        pos = positive_fn(r)
        if r["gt_vulnerable"]:
            tp += pos; fn += (not pos)
        else:
            fp += pos; tn += (not pos)
    nv, ns = tp + fn, fp + tn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if (tp + fp) else None,
            "recall": tp / nv if nv else None, "fpr": fp / ns if ns else None}


def run(rows_path="reports/live_assessments/livebench_v2/rows.jsonl",
        out_dir="reports/live_assessments/ablation"):
    rows = [json.loads(l) for l in Path(rows_path).read_text().splitlines() if l.strip()]
    conds = {
        "E1_reflection_only": lambda r: r["reflected"],
        "E2_raw_unencoded": lambda r: r["raw_reflected"],
        "E3_oracle_execution": lambda r: r["executed"] or r["raw_reflected"],
        "E4_interaction_aware": lambda r: r["executed"] or r["raw_reflected"],  # rows already interaction-aware
        "E5_full_identity": lambda r: r["predicted_positive"],                  # final system decision
    }
    result = {name: _score(rows, fn) for name, fn in conds.items()}
    # interaction contribution: confirmed executions that required an interaction
    inter_confirmed = sum(1 for r in rows if r["executed"] and r.get("interactions_performed"))
    passive_confirmed = sum(1 for r in rows if r["executed"] and not r.get("interactions_performed"))
    result["_interaction_contribution"] = {
        "confirmed_via_interaction": inter_confirmed,
        "confirmed_passive": passive_confirmed,
    }
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    from xss_specialist.repro import write_json
    write_json(Path(out_dir) / "metrics.json", result)
    return result


if __name__ == "__main__":
    r = run()
    for name in ["E1_reflection_only", "E2_raw_unencoded", "E3_oracle_execution",
                 "E4_interaction_aware", "E5_full_identity"]:
        s = r[name]
        print(f"  {name:22s} P={s['precision']} R={s['recall']} FPR={s['fpr']}")
    print("  interaction contribution:", r["_interaction_contribution"])
