"""Local live-assessment evaluation harness.

Runs the FULL live pipeline against `live/testapp.py` on 127.0.0.1 and scores findings against the
app's GROUND_TRUTH. A positive detection = finding status in {CONFIRMED, LIKELY}. Reports precision,
recall, FPR, FNR, context accuracy, confirmed-execution accuracy (of the truly-vulnerable, how many
reached CONFIRMED), near-miss sanitizer leakage (did the fake-DOMPurify endpoint get called safe?),
requests-per-finding, and runtime.

Acceptance criteria are FROZEN here (before any external target). External targets are refused until
a run meets them.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from live.pipeline import assess_candidate
from live.scope import Enforcer, Scope
from live.testapp import GROUND_TRUTH, serve
from xss_specialist.repro import write_json

# Delivery per endpoint: DOM endpoints take the payload in the fragment.
_DELIVERY = {"/dom": "hash", "/dom_safe": "hash"}

FROZEN_ACCEPTANCE = {
    "min_precision": 0.90,
    "min_recall": 0.85,
    "max_fpr": 0.10,
    "max_nearmiss_leakage": 0.0,      # the fake-DOMPurify endpoint must NOT be called safe
    "min_confirmed_exec_accuracy": 0.70,
}


def _candidates(base="http://127.0.0.1:8099"):
    cands = []
    for path in GROUND_TRUTH:
        cands.append({"url": base + path, "param": "q", "method": "GET",
                      "context": "unknown", "delivery": _DELIVERY.get(path, "query"),
                      "input_type": "GET parameter", "gt_path": path})
    return cands


def run(out_dir="reports/live_assessments/local_eval", port=8099):
    srv = serve(port=port)
    time.sleep(0.4)
    enf = Enforcer(Scope(base_url=f"http://127.0.0.1:{port}/", allowed_prefixes=["/"],
                         max_requests=500, rate_limit_rps=50))
    t0 = time.time()
    rows = []
    try:
        for i, cand in enumerate(_candidates(f"http://127.0.0.1:{port}")):
            r = assess_candidate(cand, enf, fid=f"L-{i:03d}")
            f = r["finding"]
            gt_vuln, gt_ctx, _ = GROUND_TRUTH[cand["gt_path"]]
            positive = f.status in ("CONFIRMED", "LIKELY")
            rows.append({"path": cand["gt_path"], "status": f.status, "predicted_positive": positive,
                         "gt_vulnerable": gt_vuln, "confirmed": f.status == "CONFIRMED",
                         "context_pred": f.context, "context_gt": gt_ctx,
                         "sanitizer_verification": f.sanitizer_verification,
                         "browser_result": f.browser_result})
    finally:
        runtime = time.time() - t0
        srv.shutdown()

    tp = sum(r["predicted_positive"] and r["gt_vulnerable"] for r in rows)
    fp = sum(r["predicted_positive"] and not r["gt_vulnerable"] for r in rows)
    fn = sum(not r["predicted_positive"] and r["gt_vulnerable"] for r in rows)
    tn = sum(not r["predicted_positive"] and not r["gt_vulnerable"] for r in rows)
    n_vuln = tp + fn
    n_safe = fp + tn
    ctx_ok = sum(r["context_pred"] == r["context_gt"] for r in rows if r["gt_vulnerable"])
    confirmed_of_vuln = sum(r["confirmed"] and r["gt_vulnerable"] for r in rows)
    # near-miss leakage: was the fake-DOMPurify endpoint (vulnerable) missed / called safe?
    nm = next((r for r in rows if r["path"] == "/nearmiss"), None)
    nm_leak = 0.0 if (nm and nm["predicted_positive"]) else 1.0

    metrics = {
        "n": len(rows), "n_vulnerable": n_vuln, "n_safe": n_safe,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / n_vuln if n_vuln else 0.0,
        "fpr": fp / n_safe if n_safe else 0.0,
        "fnr": fn / n_vuln if n_vuln else 0.0,
        "context_accuracy": ctx_ok / n_vuln if n_vuln else 0.0,
        "confirmed_exec_accuracy": confirmed_of_vuln / n_vuln if n_vuln else 0.0,
        "nearmiss_leakage": nm_leak,
        "requests_made": enf.requests_made,
        "requests_per_finding": enf.requests_made / max(1, tp + fp),
        "runtime_s": round(runtime, 1),
        "runtime_per_route_s": round(runtime / max(1, len(rows)), 2),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }
    passed = (metrics["precision"] >= FROZEN_ACCEPTANCE["min_precision"]
              and metrics["recall"] >= FROZEN_ACCEPTANCE["min_recall"]
              and metrics["fpr"] <= FROZEN_ACCEPTANCE["max_fpr"]
              and metrics["nearmiss_leakage"] <= FROZEN_ACCEPTANCE["max_nearmiss_leakage"]
              and metrics["confirmed_exec_accuracy"] >= FROZEN_ACCEPTANCE["min_confirmed_exec_accuracy"])
    metrics["acceptance"] = FROZEN_ACCEPTANCE
    metrics["ACCEPTED"] = bool(passed)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "metrics.json", metrics)
    (out / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return metrics, rows


if __name__ == "__main__":
    m, rows = run()
    for r in rows:
        print(f"  {r['path']:14s} status={r['status']:14s} gt_vuln={r['gt_vulnerable']!s:5s} "
              f"ctx {r['context_pred']}/{r['context_gt']}")
    print(json.dumps({k: v for k, v in m.items() if k not in ("acceptance",)}, indent=2))
    print("ACCEPTED:", m["ACCEPTED"])
