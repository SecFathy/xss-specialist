"""Live-assessment orchestrator.

assess_candidate: marker probe -> (if reflected) context classification from where the marker landed
-> context-tailored execution probes -> sanitizer identity -> correlated finding. The oracle is
authoritative for CONFIRMED. The specialist model may be attached for advisory context analysis, but
it never sets the finding state.

assess_target: run assess_candidate over a candidate list (from the crawler/mapper or a seed list),
under one Enforcer, collecting all evidence for the report.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from live.executor import execute, _embed
from live.findings import correlate
from live.probes import Probe, plan, new_marker
from live.sanitizer_id import verify_identity
from verification.browser_oracle import run_probe_on_url


def classify_context(html_src: str, marker: str) -> str:
    """Where did the marker land? Classify the reflection context from surrounding source."""
    idx = html_src.find(marker)
    if idx < 0:
        return "dom_html" if marker else "unknown"
    before = html_src[max(0, idx - 80):idx]
    after = html_src[idx + len(marker):idx + len(marker) + 40]
    # inside <script>...marker...</script> ?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script>")
    if last_script_open > last_script_close:
        return "js_string"
    # inside an attribute value?  ...attr="....marker   or  attr=....marker
    tag_open = before.rfind("<")
    tag_close = before.rfind(">")
    if tag_open > tag_close:  # we're inside a tag
        # quoted vs unquoted attribute
        seg = before[tag_open:]
        if re.search(r'=\s*"[^"]*$', seg) or re.search(r"=\s*'[^']*$", seg):
            return "html_attr"
        if re.search(r'=\s*[^"\'\s]*$', seg):
            return "html_attr"
        return "html_attr"
    if before.rstrip().endswith("<!--") or "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
        return "html_comment"
    return "html_text"


def assess_candidate(candidate: dict, enforcer, fid: str, timeout_ms: int = 4000) -> dict:
    """Full per-candidate flow. Returns {finding, marker_ev, exec_evs}."""
    # 1) marker probe
    mp = plan(candidate, "marker")[0]
    marker_ev = execute(candidate, mp, enforcer, timeout_ms)
    reflected = bool(marker_ev.get("reflected_html") or marker_ev.get("reflected_dom"))

    # 2) context: classify from WHERE the marker landed (source window captured by the oracle)
    ctx = candidate.get("context", "unknown")
    if reflected and (ctx == "unknown"):
        if marker_ev.get("reflected_dom") and not marker_ev.get("reflected_html"):
            ctx = "dom_html"     # appears only after JS ran -> a DOM sink wrote it
        else:
            win = marker_ev.get("context_window", "")
            ctx = classify_context(win, mp.marker) if win else "html_text"
        candidate = {**candidate, "context": ctx}

    # 3) execution probes (only if reflected)
    exec_evs = []
    if reflected:
        for pr in plan(candidate, "exec"):
            e = execute(candidate, pr, enforcer, timeout_ms)
            exec_evs.append(e)
            if e.get("executed"):
                break  # one confirmed execution is enough

    # 4) sanitizer identity (from an observed name, if any)
    san_name = candidate.get("observed_sanitizer", "")
    sv = verify_identity(san_name) if san_name else None

    # 5) correlate -> finding (oracle authoritative)
    finding = correlate(candidate, marker_ev, exec_evs, sv, fid)
    return {"finding": finding, "marker_ev": marker_ev, "exec_evs": exec_evs}


def assess_target(candidates: list, enforcer, prefix: str = "F") -> dict:
    results = []
    for i, cand in enumerate(candidates):
        if enforcer.budget_left() <= 0:
            break
        r = assess_candidate(cand, enforcer, fid=f"{prefix}-{i:03d}")
        results.append(r)
    return {"results": results, "requests": enforcer.requests_made,
            "blocked": enforcer.blocked_log}
