"""XSS-LiveBench-v2 — freeze, run, score.

freeze(): export the deterministic case spec (paths + ground truth + delivery) to a versioned,
hashed JSON. run(): stand up the local app, assess each case through the FULL live pipeline, score
overall + per-context + per-xss-class + per-category, compute the coverage funnel (Phase 8), near-miss
leakage, sanitizer false-safe rate, confirmed-execution accuracy, and a failure-attribution matrix
(Phase 9). Deterministic, local-only. Existing artifacts untouched.
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path

from live.pipeline import assess_candidate
from live.scope import Enforcer, Scope
from live.testapp_v2 import CASES, serve
from xss_specialist.repro import sha256_json, sha256_text, write_json

BENCH_DIR = Path("benchmarks/live_v2")
POSITIVE = ("CONFIRMED", "LIKELY")


def freeze(out=BENCH_DIR):
    spec = [{"path": c.path, "vulnerable": c.vulnerable, "context": c.context,
             "xss_class": c.xss_class, "category": c.category, "delivery": c.delivery,
             "interaction": c.interaction, "note": c.note} for c in CASES]
    # contamination / dedup check: every path unique
    paths = [s["path"] for s in spec]
    assert len(paths) == len(set(paths)), "duplicate case paths"
    out.mkdir(parents=True, exist_ok=True)
    h = sha256_json(spec)
    write_json(out / "spec.json", {"version": "XSS-LiveBench-v2", "n": len(spec),
                                   "sha256": h, "cases": spec})
    return {"n": len(spec), "sha256": h}


def _attribute_miss(row) -> str:
    """Assign a primary failure class to a scored miss (Phase 9)."""
    gt_vuln = row["gt_vulnerable"]
    if gt_vuln and not row["predicted_positive"]:            # false negative
        if row["category"].startswith("sanitizer") and row.get("sanitizer_seen"):
            return "SANITIZER_IDENTITY_ERROR"
        if not row["reflected"]:
            return "PROBE_GENERATION_ERROR" if row["delivery"] == "query" else "UNSUPPORTED_FLOW"
        if row["raw_reflected"] and not row["executed"]:
            return "INTERACTION_MISSING" if row["interaction"] != "none" else "BROWSER_ORACLE_ERROR"
        if row["reflected"] and not row["raw_reflected"]:
            return "CONTEXT_CLASSIFICATION_ERROR"
        return "UNSUPPORTED_FLOW"
    if not gt_vuln and row["predicted_positive"]:            # false positive
        return "CONTEXT_CLASSIFICATION_ERROR"
    return "OTHER"


def run(port=8098, out_dir="reports/live_assessments/livebench_v2", max_requests=4000):
    freeze()
    srv = serve(port=port)
    time.sleep(0.4)
    enf = Enforcer(Scope(base_url=f"http://127.0.0.1:{port}/", allowed_prefixes=["/"],
                         max_requests=max_requests, rate_limit_rps=100))
    rows = []
    funnel = Counter()
    t0 = time.time()
    try:
        # stored cases are assessed as one correlated submit->view flow (Phase 12)
        from live.stored import assess_stored
        stored_status = "NOT_VULNERABLE"
        if any(c.category == "stored" for c in CASES):
            sr = assess_stored(f"http://127.0.0.1:{port}/store/submit",
                               f"http://127.0.0.1:{port}/store/view", enf, "L-stored")
            stored_status = sr["status"]
        for i, c in enumerate(CASES):
            if c.category == "stored":
                positive = stored_status in POSITIVE
                rows.append({"path": c.path, "status": stored_status,
                             "predicted_positive": positive, "gt_vulnerable": c.vulnerable,
                             "confirmed": stored_status == "CONFIRMED",
                             "context_pred": c.context, "context_gt": c.context,
                             "xss_class": c.xss_class, "category": c.category,
                             "delivery": c.delivery, "interaction": c.interaction,
                             "reflected": True, "raw_reflected": True,
                             "executed": stored_status == "CONFIRMED", "sanitizer_seen": False,
                             "interactions_performed": []})
                funnel["inputs_analyzed"] += 1; funnel["inputs_probed"] += 1
                funnel["reflections_observed"] += 1; funnel["execution_attempted"] += 1
                funnel["CONFIRMED"] += int(stored_status == "CONFIRMED")
                funnel["LIKELY"] += int(stored_status == "LIKELY")
                continue
            base = f"http://127.0.0.1:{port}{c.path}"
            url = base + ("" if c.delivery == "hash" else "?q=hi")
            cand = {"url": url, "param": "q", "method": "GET", "context": "unknown",
                    "delivery": c.delivery, "input_type": "GET parameter"}
            funnel["inputs_analyzed"] += 1
            r = assess_candidate(cand, enf, fid=f"L-{i:03d}")
            f = r["finding"]
            reflected = bool(r["marker_ev"].get("reflected_html") or r["marker_ev"].get("reflected_dom"))
            raw = any(e.get("raw_reflected") for e in r["exec_evs"])
            executed = any(e.get("executed") for e in r["exec_evs"])
            funnel["inputs_probed"] += 1
            funnel["reflections_observed"] += int(reflected)
            funnel["execution_attempted"] += int(bool(r["exec_evs"]))
            funnel["LIKELY"] += int(f.status == "LIKELY")
            funnel["CONFIRMED"] += int(f.status == "CONFIRMED")
            rows.append({"path": c.path, "status": f.status,
                         "predicted_positive": f.status in POSITIVE,
                         "gt_vulnerable": c.vulnerable, "confirmed": f.status == "CONFIRMED",
                         "context_pred": f.context, "context_gt": c.context,
                         "xss_class": c.xss_class, "category": c.category,
                         "delivery": c.delivery, "interaction": c.interaction,
                         "reflected": reflected, "raw_reflected": raw, "executed": executed,
                         "sanitizer_seen": bool(f.existing_sanitizer),
                         "interactions_performed": [ip for e in r["exec_evs"]
                                                    for ip in e.get("interactions_performed", [])]})
    finally:
        runtime = time.time() - t0
        srv.shutdown()

    for r in rows:
        r["failure_class"] = _attribute_miss(r) if (
            r["predicted_positive"] != r["gt_vulnerable"]) else None

    def agg(subset):
        tp = sum(x["predicted_positive"] and x["gt_vulnerable"] for x in subset)
        fp = sum(x["predicted_positive"] and not x["gt_vulnerable"] for x in subset)
        fn = sum(not x["predicted_positive"] and x["gt_vulnerable"] for x in subset)
        tn = sum(not x["predicted_positive"] and not x["gt_vulnerable"] for x in subset)
        nv, ns = tp + fn, fp + tn
        return {"n": len(subset), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": tp / (tp + fp) if (tp + fp) else None,
                "recall": tp / nv if nv else None,
                "fpr": fp / ns if ns else None, "fnr": fn / nv if nv else None}

    overall = agg(rows)
    vuln = [r for r in rows if r["gt_vulnerable"]]
    overall["context_accuracy"] = (sum(r["context_pred"] == r["context_gt"] for r in vuln)
                                   / len(vuln)) if vuln else None
    overall["confirmed_exec_accuracy"] = (sum(r["confirmed"] for r in vuln) / len(vuln)) if vuln else None
    # near-miss sanitizer metrics
    nm = [r for r in rows if r["category"] == "sanitizer_nearmiss"]
    overall["nearmiss_cases"] = len(nm)
    overall["nearmiss_leakage"] = (sum(not r["predicted_positive"] for r in nm) / len(nm)) if nm else None
    san = [r for r in rows if r["category"].startswith("sanitizer")]
    san_vuln = [r for r in san if r["gt_vulnerable"]]
    overall["sanitizer_false_safe_rate"] = (sum(not r["predicted_positive"] for r in san_vuln)
                                            / len(san_vuln)) if san_vuln else None

    by_context = {k: agg([r for r in rows if r["context_gt"] == k])
                  for k in sorted({r["context_gt"] for r in rows})}
    by_class = {k: agg([r for r in rows if r["xss_class"] == k])
                for k in sorted({r["xss_class"] for r in rows})}
    by_category = {k: agg([r for r in rows if r["category"] == k])
                   for k in sorted({r["category"] for r in rows})}
    failure_matrix = dict(Counter(r["failure_class"] for r in rows if r["failure_class"]))

    metrics = {
        "bench": "XSS-LiveBench-v2", "n": len(rows),
        "overall": overall, "by_context": by_context, "by_xss_class": by_class,
        "by_category": by_category, "failure_matrix": failure_matrix,
        "coverage_funnel": dict(funnel),
        "requests_made": enf.requests_made,
        "requests_per_finding": enf.requests_made / max(1, overall["tp"] + overall["fp"]),
        "runtime_s": round(runtime, 1), "runtime_per_case_s": round(runtime / max(1, len(rows)), 2),
        "spec_sha256": json.loads((BENCH_DIR / "spec.json").read_text())["sha256"],
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "metrics.json", metrics)
    (out / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return metrics, rows


if __name__ == "__main__":
    m, rows = run()
    o = m["overall"]
    print(f"LiveBench-v2 n={m['n']} spec={m['spec_sha256'][:12]}")
    print(f"  precision={o['precision']:.3f} recall={o['recall']:.3f} fpr={o['fpr']:.3f} "
          f"fnr={o['fnr']:.3f} ctx={o['context_accuracy']:.3f} confirmed_exec={o['confirmed_exec_accuracy']:.3f}")
    print(f"  nearmiss_leakage={o['nearmiss_leakage']} sanitizer_false_safe={o['sanitizer_false_safe_rate']}")
    print(f"  requests/finding={m['requests_per_finding']:.2f} runtime/case={m['runtime_per_case_s']}s")
    print("  failure_matrix:", m["failure_matrix"])
    print("  funnel:", m["coverage_funnel"])
