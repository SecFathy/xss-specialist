"""Phase 30-32 — comparison report.

Reads condition run directories, emits markdown tables per split, and computes a paired bootstrap
95% CI on the accuracy difference between two conditions (same items, so pairing is valid). No
"better" claim is made without the CI. The locked test is included only if its metrics exist AND
were produced by an explicit --allow-test read (recorded in the metrics).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from xss_specialist.repro import stream

SPLITS = ["dev", "generalization", "nearmiss", "adversarial"]
METRICS = [("accuracy_all", "acc"), ("f1_vuln", "F1"), ("false_positive_rate", "FPR"),
           ("false_negative_rate", "FNR"), ("context_accuracy", "ctx"),
           ("abstention_rate", "abst")]


def _correct_vector(run_dir, split):
    """Per-item correctness (1/0) for paired bootstrap, aligned by id."""
    f = Path(run_dir) / split / "predictions.jsonl"
    if not f.exists():
        return None
    rows = [json.loads(l) for l in f.read_text().splitlines() if l.strip()]
    vec = {}
    for r in rows:
        gold = r["gold_vulnerable"]
        pred = r["pred"]
        correct = (pred == "vulnerable" and gold) or (pred == "safe" and not gold)
        vec[r["id"]] = 1 if correct else 0
    return vec


def paired_bootstrap(run_a, run_b, split, n=5000):
    va, vb = _correct_vector(run_a, split), _correct_vector(run_b, split)
    if not va or not vb:
        return None
    ids = sorted(set(va) & set(vb))
    if not ids:
        return None
    a = np.array([va[i] for i in ids]); b = np.array([vb[i] for i in ids])
    diff = b.mean() - a.mean()
    rng = stream(f"bootstrap:{split}")
    idx = rng.integers(0, len(ids), size=(n, len(ids)))
    boots = b[idx].mean(1) - a[idx].mean(1)
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {"delta": float(diff), "ci95": [float(lo), float(hi)], "n": len(ids)}


def table(conditions: dict, splits=SPLITS) -> str:
    lines = []
    for split in splits:
        lines.append(f"\n### {split}\n")
        header = "| Condition | " + " | ".join(m[1] for m in METRICS)
        if split == "nearmiss":
            header += " | leak | anchor"
        lines.append(header + " |")
        lines.append("|" + "---|" * (len(METRICS) + 1 + (2 if split == "nearmiss" else 0)))
        for label, run_dir in conditions.items():
            f = Path(run_dir) / split / "metrics.json"
            if not f.exists():
                continue
            m = json.loads(f.read_text())
            row = f"| {label} | " + " | ".join(
                f"{m.get(k):.3f}" if m.get(k) is not None else "-" for k, _ in METRICS)
            if split == "nearmiss":
                nm = m.get("nearmiss", {})
                row += f" | {nm.get('leakage_rate', float('nan')):.3f} | {nm.get('anchor_correct')}"
            lines.append(row + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conditions", nargs="+", required=True,
                    help="label=run_dir pairs, e.g. A=runs/baseline_A_base")
    ap.add_argument("--out", default="reports/final/model_comparison.md")
    ap.add_argument("--pair", nargs=2, help="two labels to paired-bootstrap")
    a = ap.parse_args()
    conditions = dict(kv.split("=", 1) for kv in a.conditions)
    md = ["# XSS Specialist — Model Comparison\n",
          "Same frozen XSSBench for every condition. Metrics: acc, vulnerable-class F1, "
          "false-positive rate (safe called vulnerable), false-negative rate, execution-context "
          "accuracy, abstention. Near-miss adds leakage (lower better) and anchor correctness.\n"]
    md.append(table(conditions))
    if a.pair:
        la, lb = a.pair
        md.append(f"\n## Paired bootstrap: {lb} − {la} (accuracy Δ, 95% CI)\n")
        md.append("| split | Δacc | 95% CI | n |")
        md.append("|---|---|---|---|")
        for s in SPLITS:
            r = paired_bootstrap(conditions[la], conditions[lb], s)
            if r:
                sig = "" if (r["ci95"][0] <= 0 <= r["ci95"][1]) else " *"
                md.append(f"| {s} | {r['delta']:+.3f}{sig} | [{r['ci95'][0]:+.3f}, {r['ci95'][1]:+.3f}] | {r['n']} |")
        md.append("\n\\* CI excludes 0 (significant at 95%).")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(md) + "\n")
    print(f"report -> {a.out}")
    print("\n".join(md))


if __name__ == "__main__":
    main()
