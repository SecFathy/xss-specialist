"""Phase 7 — crawler / input-discovery coverage, measured separately from vulnerability detection.

Runs the crawler against the local app and compares discovered routes/inputs to ground truth (the
app's own case registry), reporting route recall, input recall, duplicate rate, out-of-scope blocked,
crawl requests, depth, and JS-route discovery. Discovery is scored independently of classification.
"""
from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import urlparse

from live.crawler import crawl, map_inputs
from live.scope import Enforcer, Scope
from live.testapp_v2 import CASES, serve
from xss_specialist.repro import write_json


def run(port=8095, out_dir="reports/live_assessments/coverage"):
    srv = serve(port=port)
    time.sleep(0.4)
    enf = Enforcer(Scope(base_url=f"http://127.0.0.1:{port}/", allowed_prefixes=["/"],
                         max_depth=2, max_requests=2000, rate_limit_rps=100))
    t0 = time.time()
    try:
        cr = crawl(enf)
        cands = map_inputs(cr)
    finally:
        runtime = time.time() - t0
        srv.shutdown()

    gt_paths = {c.path for c in CASES}
    discovered_paths = {urlparse(r["url"]).path for r in cr["routes"]}
    # inputs: every case is reachable from the index (?q=) or is a hash/DOM route
    discovered_input_paths = {urlparse(c["url"]).path for c in cands}
    route_recall = len(discovered_paths & gt_paths) / len(gt_paths)
    input_recall = len(discovered_input_paths & gt_paths) / len(gt_paths)
    # duplicates: candidates sharing normalized (path,param,delivery)
    from collections import Counter
    keys = Counter((urlparse(c["url"]).path, c["param"], c["delivery"]) for c in cands)
    dup_rate = sum(v - 1 for v in keys.values()) / max(1, len(cands))

    metrics = {
        "gt_routes": len(gt_paths),
        "routes_discovered": len(cr["routes"]),
        "route_recall": route_recall,
        "inputs_discovered": len(cands),
        "input_recall": input_recall,
        "js_routes_discovered": len(cr["js_routes"]),
        "duplicate_rate": dup_rate,
        "out_of_scope_blocked": len(enf.blocked_log),
        "crawl_requests": enf.requests_made,
        "max_depth": enf.scope.max_depth,
        "runtime_s": round(runtime, 1),
        "missed_routes": sorted(gt_paths - discovered_paths)[:20],
    }
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    write_json(Path(out_dir) / "metrics.json", metrics)
    return metrics


if __name__ == "__main__":
    m = run()
    print(f"route_recall={m['route_recall']:.3f} input_recall={m['input_recall']:.3f} "
          f"dup_rate={m['duplicate_rate']:.3f} js_routes={m['js_routes_discovered']} "
          f"blocked={m['out_of_scope_blocked']} crawl_requests={m['crawl_requests']}")
    if m["missed_routes"]:
        print("missed (first 20):", m["missed_routes"])
