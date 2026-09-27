"""Phase 12 — controlled stored-XSS workflow (local only unless explicitly authorized).

A stored-XSS candidate has a submit step and a separate retrieval/view step. We inject a unique
execution payload at submit, then load the view URL and let the oracle check whether that payload
executes there — correlating the original input with later execution. CONFIRMED still requires
browser execution at the view step. Non-destructive; against external targets only when the operator
explicitly enables stored testing in an approved, non-destructive plan.
"""
from __future__ import annotations

from live.executor import _embed
from live.probes import new_marker
from live.scope import Enforcer
from verification.browser_oracle import run_probe_on_url


def assess_stored(submit_url: str, view_url: str, enforcer: Enforcer, fid: str,
                  submit_param: str = "q", delivery: str = "query", timeout_ms: int = 4000) -> dict:
    """Submit an execution payload, then verify at the view step. Returns a finding-like dict."""
    marker = new_marker()
    payload = f"<img src=x onerror=\"window.__X['{marker}']=1\">"
    sig = "<img src=x onerror="
    submit = _embed(submit_url, submit_param, payload, delivery)
    ok, reason = enforcer.check(submit, kind="stored_submit")
    if not ok:
        return {"finding_id": fid, "status": "INCONCLUSIVE", "reason": reason, "xss_class": "stored"}
    # submit (store) — the value is persisted server-side; we don't need execution here
    s_ev = run_probe_on_url(submit, marker, delivery=delivery, param=submit_param,
                            timeout_ms=timeout_ms, raw_signature=sig)
    enforcer.note_request(submit, final_url=s_ev.get("final_url") or submit, status=s_ev.get("status"),
                          kind="stored_submit")
    # view (retrieve) — check whether the stored payload executes when rendered to a viewer
    ok, reason = enforcer.check(view_url, kind="stored_view")
    if not ok:
        return {"finding_id": fid, "status": "INCONCLUSIVE", "reason": reason, "xss_class": "stored"}
    v_ev = run_probe_on_url(view_url, marker, delivery="query", param=submit_param,
                            timeout_ms=timeout_ms, raw_signature=sig,
                            interactions=["hover", "click"])
    enforcer.note_request(view_url, final_url=v_ev.get("final_url") or view_url,
                          status=v_ev.get("status"), kind="stored_view")
    executed = bool(v_ev.get("executed"))
    raw_at_view = bool(v_ev.get("raw_reflected"))
    if executed:
        status = "CONFIRMED"
    elif raw_at_view:
        status = "LIKELY"
    else:
        status = "NOT_VULNERABLE"
    return {"finding_id": fid, "status": status, "xss_class": "stored",
            "submit_url": submit, "view_url": view_url, "marker": marker,
            "executed_at_view": executed, "raw_at_view": raw_at_view,
            "correlated": executed or raw_at_view}


if __name__ == "__main__":
    import time
    from live.testapp_v2 import serve
    from live.scope import Scope
    srv = serve(port=8096); time.sleep(0.3)
    enf = Enforcer(Scope(base_url="http://127.0.0.1:8096/", allowed_prefixes=["/"], rate_limit_rps=100))
    r = assess_stored("http://127.0.0.1:8096/store/submit", "http://127.0.0.1:8096/store/view",
                      enf, "S-000")
    srv.shutdown()
    print(r["status"], "executed_at_view=", r["executed_at_view"], "correlated=", r["correlated"])
