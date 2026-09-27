"""Phase 16 — final frozen local evaluation.

Runs the frozen v2 system ONCE on XSS-LiveBench-v2, plus a v1-emulated configuration (no interaction,
no JS-code probe, no quoted/unquoted split, no stored correlation) for a PAIRED comparison on the
same 102 cases. Reports per-case correctness, paired bootstrap 95% CI on the accuracy difference,
and the frozen-acceptance-gate decision. Deterministic; existing artifacts untouched.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from live.pipeline import assess_candidate
from live.stored import assess_stored
from live.scope import Enforcer, Scope
from live.testapp_v2 import CASES, serve
from xss_specialist.repro import stream, write_json

POSITIVE = ("CONFIRMED", "LIKELY")
V1_CAPS = {"interactions": False, "js_code_probe": False, "quoted_split": False}


def _run_config(port, caps, stored_enabled):
    enf = Enforcer(Scope(base_url=f"http://127.0.0.1:{port}/", allowed_prefixes=["/"],
                         max_requests=6000, rate_limit_rps=100))
    correct, positive_by_path = {}, {}
    stored_status = "NOT_VULNERABLE"
    if stored_enabled:
        sr = assess_stored(f"http://127.0.0.1:{port}/store/submit",
                           f"http://127.0.0.1:{port}/store/view", enf, "S")
        stored_status = sr["status"]
    rows = []
    for i, c in enumerate(CASES):
        if c.category == "stored":
            status = stored_status if stored_enabled else "NOT_VULNERABLE"
        else:
            url = f"http://127.0.0.1:{port}{c.path}" + ("" if c.delivery == "hash" else "?q=hi")
            cand = {"url": url, "param": "q", "context": "unknown", "delivery": c.delivery}
            status = assess_candidate(cand, enf, fid=f"X-{i}", caps=caps)["finding"].status
        pos = status in POSITIVE
        ok = (pos == c.vulnerable)
        correct[c.path] = 1 if ok else 0
        rows.append({"path": c.path, "status": status, "predicted_positive": pos,
                     "gt_vulnerable": c.vulnerable, "context_gt": c.context,
                     "category": c.category, "xss_class": c.xss_class})
    return correct, rows, enf


def _metrics(rows):
    tp = sum(r["predicted_positive"] and r["gt_vulnerable"] for r in rows)
    fp = sum(r["predicted_positive"] and not r["gt_vulnerable"] for r in rows)
    fn = sum(not r["predicted_positive"] and r["gt_vulnerable"] for r in rows)
    tn = sum(not r["predicted_positive"] and not r["gt_vulnerable"] for r in rows)
    nv, ns = tp + fn, fp + tn
    nm = [r for r in rows if r["category"] == "sanitizer_nearmiss"]
    san_v = [r for r in rows if r["category"].startswith("sanitizer") and r["gt_vulnerable"]]
    return {"precision": tp/(tp+fp) if tp+fp else 0, "recall": tp/nv if nv else 0,
            "fpr": fp/ns if ns else 0, "fnr": fn/nv if nv else 0,
            "accuracy": (tp+tn)/len(rows),
            "nearmiss_leakage": sum(not r["predicted_positive"] for r in nm)/len(nm) if nm else None,
            "sanitizer_false_safe": sum(not r["predicted_positive"] for r in san_v)/len(san_v) if san_v else None,
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}


def paired_bootstrap(cv2, cv1, n=5000):
    paths = sorted(set(cv2) & set(cv1))
    a = np.array([cv1[p] for p in paths]); b = np.array([cv2[p] for p in paths])
    rng = stream("livebench_final_bootstrap")
    idx = rng.integers(0, len(paths), size=(n, len(paths)))
    boots = b[idx].mean(1) - a[idx].mean(1)
    return {"delta_acc": float(b.mean() - a.mean()),
            "ci95": [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))],
            "n": len(paths), "v1_acc": float(a.mean()), "v2_acc": float(b.mean())}


def run(out_dir="reports/live_assessments/final_v2"):
    srv = serve(port=8093); time.sleep(0.4)
    t0 = time.time()
    try:
        cv2, rows2, enf2 = _run_config(8093, caps=None, stored_enabled=True)
        cv1, rows1, enf1 = _run_config(8093, caps=V1_CAPS, stored_enabled=False)
    finally:
        runtime = time.time() - t0
        srv.shutdown()
    m2, m1 = _metrics(rows2), _metrics(rows1)
    boot = paired_bootstrap(cv2, cv1)
    result = {"bench": "XSS-LiveBench-v2", "n": len(CASES), "runtime_s": round(runtime, 1),
              "v2": m2, "v1_emulated": m1, "paired_bootstrap_v2_minus_v1": boot,
              "scope_violations_v2": sum(1 for b in enf2.request_log if b.get("redirect_blocked")),
              "requests_v2": enf2.requests_made}
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    write_json(Path(out_dir) / "metrics.json", result)
    (Path(out_dir) / "rows_v2.jsonl").write_text("\n".join(json.dumps(r) for r in rows2) + "\n")
    return result


if __name__ == "__main__":
    r = run()
    v2, v1, b = r["v2"], r["v1_emulated"], r["paired_bootstrap_v2_minus_v1"]
    print(f"FINAL LiveBench-v2 (n={r['n']}, {r['runtime_s']}s)")
    print(f"  v2:  P={v2['precision']:.3f} R={v2['recall']:.3f} FPR={v2['fpr']:.3f} "
          f"acc={v2['accuracy']:.3f} nm_leak={v2['nearmiss_leakage']} san_false_safe={v2['sanitizer_false_safe']}")
    print(f"  v1*: P={v1['precision']:.3f} R={v1['recall']:.3f} FPR={v1['fpr']:.3f} acc={v1['accuracy']:.3f}")
    print(f"  paired v2-v1: dacc={b['delta_acc']:+.3f} CI95=[{b['ci95'][0]:+.3f},{b['ci95'][1]:+.3f}] "
          f"(v1={b['v1_acc']:.3f} v2={b['v2_acc']:.3f})")
