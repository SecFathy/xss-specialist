"""Phase 3 metrics. Scores parsed analyses against XSSBench ground truth.

Reports classification accuracy, precision/recall/F1 for the *vulnerable* class, false-positive
rate (safe cases called vulnerable — the analyst-overwhelm metric, Phase 18), false-negative rate,
abstention rate, execution-context accuracy, and calibration (Brier + ECE) over the confidence the
model assigned to its own answer. Near-miss leakage has its own scorer (leakage_rate).
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np


def load_split(path: str) -> list[dict]:
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def _confusion(gold_vuln: bool, pred: str):
    # pred in {vulnerable, safe, abstain}
    if pred == "abstain":
        return "abstain"
    pred_vuln = pred == "vulnerable"
    if gold_vuln and pred_vuln: return "tp"
    if not gold_vuln and not pred_vuln: return "tn"
    if not gold_vuln and pred_vuln: return "fp"
    return "fn"


def score(records: list[dict], preds: list[dict]) -> dict:
    """records: gold XSSCase dicts; preds: parsed analyses (same order)."""
    assert len(records) == len(preds)
    n = len(records)
    cnt = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "abstain": 0}
    ctx_correct = ctx_total = 0
    briers, ece_bins = [], {}
    correct = 0
    for r, p in zip(records, preds):
        gold_vuln = r["vulnerable"]
        cell = _confusion(gold_vuln, p["classification"])
        cnt[cell] += 1
        decided = p["classification"] in ("vulnerable", "safe")
        is_correct = (cell in ("tp", "tn"))
        if decided:
            correct += is_correct
            # calibration only on decided items
            conf = p["confidence"]
            briers.append((conf - (1.0 if is_correct else 0.0)) ** 2)
            b = round(min(0.99, max(0.0, conf)) * 10) / 10
            ece_bins.setdefault(b, []).append(1.0 if is_correct else 0.0)
            # context accuracy only where model committed and gold is vulnerable (context defined)
            if gold_vuln:
                ctx_total += 1
                ctx_correct += (p["context"] == r["context"])
    decided_n = n - cnt["abstain"]
    tp, tn, fp, fn = cnt["tp"], cnt["tn"], cnt["fp"], cnt["fn"]
    n_vuln = sum(r["vulnerable"] for r in records)
    n_safe = n - n_vuln
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    # ECE over decided items
    ece = 0.0
    for b, ys in ece_bins.items():
        ece += (len(ys) / max(1, len(briers))) * abs(np.mean(ys) - b)
    return {
        "n": n, "n_vulnerable": n_vuln, "n_safe": n_safe,
        "accuracy_decided": correct / decided_n if decided_n else 0.0,
        "accuracy_all": correct / n,           # abstain counts as not-correct
        "precision_vuln": prec, "recall_vuln": rec, "f1_vuln": f1,
        "false_positive_rate": fp / n_safe if n_safe else 0.0,   # safe called vulnerable
        "false_negative_rate": fn / n_vuln if n_vuln else 0.0,   # vuln called safe
        "abstention_rate": cnt["abstain"] / n,
        "context_accuracy": ctx_correct / ctx_total if ctx_total else 0.0,
        "brier": float(np.mean(briers)) if briers else None,
        "ece": float(ece) if briers else None,
        "confusion": cnt,
    }


def leakage_rate(records: list[dict], preds: list[dict]) -> dict:
    """Near-miss leakage: over the PERTURBED (non-anchor) cases — whose sanitizer is NOT the
    known-safe entity — the fraction the model calls safe. High = knowledge leaked across the
    entity boundary. Anchor case is reported separately as the control."""
    anchor_correct = None
    leaked = considered = 0
    for r, p in zip(records, preds):
        is_anchor = "anchor" in r.get("tags", [])
        if is_anchor:
            anchor_correct = (p["classification"] == "safe")
            continue
        considered += 1
        if p["classification"] == "safe":   # incorrectly transferred safety to a look-alike
            leaked += 1
    return {"n_perturbed": considered,
            "leakage_rate": leaked / considered if considered else 0.0,
            "anchor_correct": anchor_correct}
