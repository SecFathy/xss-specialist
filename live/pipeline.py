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
        seg = before[tag_open:]
        if re.search(r'=\s*"[^"]*$', seg) or re.search(r"=\s*'[^']*$", seg):
            return "html_attr"            # quoted attribute value
        return "html_attr_unquoted"       # unquoted attribute value
    if before.rstrip().endswith("<!--") or "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
        return "html_comment"
    return "html_text"


def assess_candidate(candidate: dict, enforcer, fid: str, timeout_ms: int = 4000,
                     caps: dict | None = None) -> dict:
    """Full per-candidate flow. Returns {finding, marker_ev, exec_evs}.
    caps (all default True) toggle v2 capabilities for ablation/baseline emulation:
    interactions, js_code_probe, quoted_split."""
    caps = caps or {}
    cap_interactions = caps.get("interactions", True)
    cap_jscode = caps.get("js_code_probe", True)
    cap_quoted_split = caps.get("quoted_split", True)
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
            if not cap_quoted_split and ctx == "html_attr_unquoted":
                ctx = "html_attr"   # v1 did not distinguish quoted vs unquoted
        candidate = {**candidate, "context": ctx}

    # 3) derive bounded interactions from the reflection context (Phase 3)
    if "interactions" not in candidate:
        win = marker_ev.get("context_window", "") or ""
        acts = []
        m = re.search(r"on(\w+)\s*=", win)
        if m:
            ev_name = m.group(1).lower()
            acts = {"mouseover": ["hover"], "focus": ["focus"], "click": ["click"],
                    "mouseenter": ["hover"], "keyup": ["focus"], "keydown": ["focus"]}.get(
                        ev_name, ["hover", "focus", "click"])
        elif ctx in ("html_attr_url",) or "href=" in win or "src=" in win:
            acts = ["click"]
        elif ctx in ("html_attr",):
            acts = ["hover", "focus", "click"]
        elif ctx in ("dom_html", "dom_attr"):
            acts = ["hashnav"]
        candidate = {**candidate, "interactions": acts if cap_interactions else []}

    # 4) execution probes
    exec_evs = []
    if reflected:
        for pr in plan(candidate, "exec"):
            e = execute(candidate, pr, enforcer, timeout_ms)
            exec_evs.append(e)
            if e.get("executed"):
                break  # one confirmed execution is enough
    # code sinks (eval/Function/string-timer/script-element/event-handler) consume input as CODE and
    # never reflect it — try a harmless JS-execution probe for DOM/query candidates even if nothing
    # reflected. Confirmation is by the sentinel only.
    if cap_jscode and not any(e.get("executed") for e in exec_evs):
        from live.probes import js_code_probe
        jp = js_code_probe(candidate.get("delivery", "query"))
        je = execute(candidate, jp, enforcer, timeout_ms)
        exec_evs.append(je)

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
