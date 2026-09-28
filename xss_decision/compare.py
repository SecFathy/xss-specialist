"""Paired, template-group bootstrap comparison on the same development suite."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from xss_decision.evaluate import summarize
from xss_decision.promotion import research_gate


def paired_comparison(parent_rows: list[dict], candidate_rows: list[dict], samples=1000, seed=0):
    parent = {r["_meta"]["id"]: r for r in parent_rows}
    candidate = {r["_meta"]["id"]: r for r in candidate_rows}
    if len(parent) != len(parent_rows) or len(candidate) != len(candidate_rows) or parent.keys() != candidate.keys():
        raise ValueError("Comparison requires unique matching record IDs")
    grouped = {}
    for rid, row in parent.items():
        other = candidate[rid]
        if row["questions"] != other["questions"] or row["_meta"]["group_id"] != other["_meta"]["group_id"]:
            raise ValueError("Gold questions or groups differ")
        grouped.setdefault(row["_meta"]["group_id"], []).append(rid)
    groups = list(grouped)
    if not groups or samples < 100: raise ValueError("Need non-empty groups and at least 100 bootstrap draws")
    def values(ids):
        a = summarize([parent[rid] for rid in ids]); b = summarize([candidate[rid] for rid in ids])
        return {"verdict_accuracy": b["per_question_accuracy"]["verdict"] - a["per_question_accuracy"]["verdict"],
                "vulnerability_recall": b["vulnerability_recall"] - a["vulnerability_recall"]}
    point = values(list(parent)); deltas = {k: [] for k in point}; rng = np.random.default_rng(seed)
    for _ in range(samples):
        ids = [rid for i in rng.integers(0, len(groups), len(groups)) for rid in grouped[groups[i]]]
        for key, delta in values(ids).items(): deltas[key].append(delta)
    return {"n_records": len(parent), "n_groups": len(groups), "bootstrap_samples": samples, "seed": seed,
            "deltas": {key: {"candidate_minus_parent": point[key],
                             "ci95": [float(v) for v in np.quantile(vals, [.025, .975])]} for key, vals in deltas.items()},
            "note": "Template-group bootstrap on a synthetic development suite; not a real-site guarantee."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parent", required=True); ap.add_argument("--candidate", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--samples", type=int, default=1000)
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists(): raise ValueError("Refusing to overwrite comparison")
    parent = Path(args.parent); candidate = Path(args.candidate)
    a = json.loads((parent / "report.json").read_text()); b = json.loads((candidate / "report.json").read_text())
    if a["suite_manifest_sha256"] != b["suite_manifest_sha256"] or a["split"] != b["split"] or a["split"] != "development":
        raise ValueError("Checkpoint selection compares the same development suite only")
    comparison = paired_comparison(json.loads((parent / "rows.json").read_text()),
                                   json.loads((candidate / "rows.json").read_text()), samples=args.samples)
    comparison["research_gate"] = research_gate(b, a, comparison)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(comparison, indent=2) + "\n")
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__": main()
