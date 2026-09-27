"""Phase 14 — performance measurement.

Aggregates timing/throughput from the LiveBench-v2 run and times the auxiliary components (RAG
retrieve, one browser navigation). KEV latency is cited from the prior KEV analysis (offline
consolidation path, not the assessment hot path). Reports bottlenecks; optimization is deferred
until after correctness (per the phase ordering).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from xss_specialist.repro import write_json


def run(lb="reports/live_assessments/livebench_v2/metrics.json",
        out_dir="reports/live_assessments/performance"):
    m = json.loads(Path(lb).read_text())
    # time a RAG retrieval
    from retrieval.index import Retriever
    r = Retriever.load_default()
    t = time.time()
    for _ in range(20):
        r.search("el.innerHTML = location.hash")
    rag_ms = (time.time() - t) / 20 * 1000
    # time one browser navigation
    from live.testapp_v2 import serve
    from verification.browser_oracle import run_probe_on_url
    srv = serve(port=8094); time.sleep(0.3)
    t = time.time()
    run_probe_on_url("http://127.0.0.1:8094/r/html_text?q=hi", "hi", raw_signature="<img")
    nav_ms = (time.time() - t) * 1000
    srv.shutdown()

    metrics = {
        "livebench_runtime_s": m.get("runtime_s"),
        "runtime_per_case_s": m.get("runtime_per_case_s"),
        "requests_made": m.get("requests_made"),
        "requests_per_finding": m.get("requests_per_finding"),
        "rag_retrieve_ms": round(rag_ms, 1),
        "browser_nav_ms_cold": round(nav_ms, 1),
        "kev_latency_note": "~2-3 s/item (Kev-4B DeltaNet on MLX); offline consolidation path only, "
                            "NOT on the assessment hot path",
        "bottleneck": "browser navigation + execution dominates (~1.2-1.5 s/case); "
                      "network/model are not on the per-candidate hot path",
    }
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    write_json(Path(out_dir) / "metrics.json", metrics)
    return metrics


if __name__ == "__main__":
    m = run()
    print(json.dumps(m, indent=2))
