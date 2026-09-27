"""Phase 13 — confidence calibration of the live finding classifier.

Uses the LiveBench-v2 rows (finding status -> a confidence proxy) and ground truth to check whether
the SYSTEM's confidence tracks correctness, bucketed. This is the assessment system's confidence, not
the LLM's — and browser execution (CONFIRMED) is never overridden by model confidence. Reports
accuracy per confidence bucket, false-safe confidence, false-positive confidence, and ECE.
"""
from __future__ import annotations

import json
from pathlib import Path

# map finding status to a positive-class confidence (system-level, not LLM)
STATUS_CONF = {"CONFIRMED": 0.99, "LIKELY": 0.6, "INCONCLUSIVE": 0.3, "NOT_VULNERABLE": 0.08}


def run(rows_path="reports/live_assessments/livebench_v2/rows.jsonl",
        out_dir="reports/live_assessments/calibration"):
    rows = [json.loads(l) for l in Path(rows_path).read_text().splitlines() if l.strip()]
    buckets = {}
    briers = []
    false_safe_confs, false_pos_confs = [], []
    for r in rows:
        conf = STATUS_CONF.get(r["status"], 0.5)
        p_pos = conf  # confidence that it IS vulnerable
        y = 1 if r["gt_vulnerable"] else 0
        pred_pos = r["predicted_positive"]
        # for a negative prediction, confidence-in-prediction = 1 - p_pos
        conf_in_pred = p_pos if pred_pos else (1 - p_pos)
        correct = (pred_pos == bool(y))
        b = round(conf_in_pred * 10) / 10
        buckets.setdefault(b, []).append(1 if correct else 0)
        briers.append((p_pos - y) ** 2)
        if (not pred_pos) and y == 1:            # false safe (missed vuln)
            false_safe_confs.append(conf_in_pred)
        if pred_pos and y == 0:                  # false positive
            false_pos_confs.append(conf_in_pred)
    n = len(rows)
    ece = sum((len(v) / n) * abs(sum(v) / len(v) - b) for b, v in buckets.items())
    metrics = {
        "n": n,
        "accuracy_by_confidence_bucket": {str(b): {"n": len(v), "accuracy": sum(v) / len(v)}
                                          for b, v in sorted(buckets.items())},
        "ece": ece,
        "brier": sum(briers) / n,
        "mean_false_safe_confidence": (sum(false_safe_confs) / len(false_safe_confs))
                                      if false_safe_confs else None,
        "n_false_safe": len(false_safe_confs),
        "mean_false_positive_confidence": (sum(false_pos_confs) / len(false_pos_confs))
                                          if false_pos_confs else None,
        "n_false_positive": len(false_pos_confs),
        "note": "System confidence from finding status; browser CONFIRMED never overridden by LLM.",
    }
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    from xss_specialist.repro import write_json
    write_json(Path(out_dir) / "metrics.json", metrics)
    return metrics


if __name__ == "__main__":
    m = run()
    print(f"ECE={m['ece']:.3f} Brier={m['brier']:.3f} "
          f"false_safe(n={m['n_false_safe']})={m['mean_false_safe_confidence']} "
          f"false_pos(n={m['n_false_positive']})={m['mean_false_positive_confidence']}")
    for b, s in m["accuracy_by_confidence_bucket"].items():
        print(f"  conf~{b}: n={s['n']} acc={s['accuracy']:.3f}")
