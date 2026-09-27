"""Phase 14 — independent executable verification for DOM XSS cases.

This is a genuine, model-independent oracle: it renders a case's code in a headless browser with a
sentinel payload and checks whether script ACTUALLY executes (window.__xss set). It does not ask any
LLM; it observes real browser behaviour. Used to confirm the ground-truth `vulnerable` label of the
DOM-family synthetic cases (verified => the label is trustworthy; a mismatch is CONFLICTING and the
case is quarantined, never trained on). Repetition is never evidence — only execution is.

Only DOM cases whose source is a URL fragment/search and whose sink is an HTML/JS sink are
executable here; others return UNVERIFIED (out of this oracle's scope) rather than a false claim.
"""
from __future__ import annotations

import json
from pathlib import Path

# sentinel payload: fires only if the string is parsed as HTML (img onerror) — the DOM XSS signal.
PAYLOAD = "<img src=x onerror=\"window.__xss=1\">"


_ELEM_NAMES = ["el", "node", "container", "target", "box", "out", "slot", "view"]


def _harness(case_code: str) -> str:
    # Drive the source via the real URL hash/query (set by verify_dom_case). Bind every element
    # identifier the generator uses to the in-document #out node, so an HTML sink actually parses
    # the payload and connected-image onerror fires. `const $` shims a minimal jQuery-like html/text
    # so jQuery-shaped cases execute too.
    binds = "var " + ", ".join(_ELEM_NAMES) + ";\n"
    binds += "".join(f"{n} = document.getElementById('out');\n" for n in _ELEM_NAMES)
    shim = ("function $(sel){var n=document.getElementById('out');"
            "return {html:function(v){n.innerHTML=v;},text:function(v){n.textContent=v;}};}\n")
    return f"""<!doctype html><html><head><meta charset=utf-8></head><body>
<div id="out"></div>
<script>window.__xss=0;
{binds}{shim}try {{
{case_code}
}} catch(e) {{ window.__xss_err = String(e); }}
</script></body></html>"""


def verify_dom_case(case: dict, payload: str = PAYLOAD, timeout_ms: int = 3000) -> dict:
    """Returns {status, executed, expected_vulnerable, scope}. status in
    VERIFIED / CONFLICTING / UNVERIFIED."""
    code = case["code"]
    if case["language"] not in ("javascript",):
        return {"status": "UNVERIFIED", "scope": "non_js"}
    # Faithful delivery scope: the payload reaches the sink undistorted only through a decoding
    # source (decodeURIComponent / URLSearchParams) or window.name. A bare location.hash.slice is
    # percent-encoded by the browser, and href/setAttribute sinks need user activation a headless
    # div cannot supply — both are out of this oracle's scope (UNVERIFIED), not label conflicts.
    decodes = ("decodeURIComponent" in code) or ("URLSearchParams" in code)
    windowname = "window.name" in code
    if not (decodes or windowname):
        return {"status": "UNVERIFIED", "scope": "encoding_or_activation_limited"}
    if ".href" in code and "innerHTML" not in code:
        return {"status": "UNVERIFIED", "scope": "needs_activation"}
    if "setAttribute" in code:
        return {"status": "UNVERIFIED", "scope": "needs_activation"}
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return {"status": "UNVERIFIED", "scope": f"playwright_unavailable:{e}"}

    # context-appropriate payload: a JS sink (eval/Function) needs JS, an HTML sink needs markup,
    # a URL sink needs a javascript: URL activated by a click.
    is_js_sink = "eval(" in code or "Function(" in code
    is_url_sink = ".href" in code and "innerHTML" not in code
    if is_js_sink:
        payload = "window.__xss=1"
    elif is_url_sink:
        payload = "javascript:window.__xss=1"
    html = _harness(code)
    tmp = Path("data/verified/_harness.html")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(html, encoding="utf-8")
    # drive the source: URL fragment / query carry the payload
    import urllib.parse as up
    frag = up.quote(payload)
    url = tmp.resolve().as_uri() + (f"?q={frag}&next={frag}#{frag}"
                                    if "location.search" in code else f"#{frag}")
    executed = None
    err = None
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            # window.name source: set it before navigation
            if "window.name" in code:
                page.goto("about:blank")
                page.evaluate(f"window.name = {json.dumps(payload)}")
            page.goto(url, wait_until="load", timeout=timeout_ms)
            page.wait_for_timeout(200)
            # URL/href sinks execute only on activation: click the anchor if one was set.
            if is_url_sink:
                try:
                    page.eval_on_selector("#out", "n => n.click && n.click()")
                    page.wait_for_timeout(150)
                except Exception:
                    pass
            executed = bool(page.evaluate("window.__xss === 1"))
            err = page.evaluate("window.__xss_err || null")
        finally:
            browser.close()
    expected = case["vulnerable"]
    status = "VERIFIED" if executed == expected else "CONFLICTING"
    return {"status": status, "executed": executed, "expected_vulnerable": expected,
            "scope": "in_scope", "js_error": err}


def verify_split(split_path: str, limit: int | None = None) -> dict:
    recs = [json.loads(l) for l in Path(split_path).read_text().splitlines() if l.strip()]
    if limit:
        recs = recs[:limit]
    results = {"VERIFIED": 0, "CONFLICTING": 0, "UNVERIFIED": 0, "conflicts": []}
    for r in recs:
        res = verify_dom_case(r)
        results[res["status"]] += 1
        if res["status"] == "CONFLICTING":
            results["conflicts"].append({"id": r["id"], **res})
    return results


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/frozen/dev.jsonl"
    lim = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    print(json.dumps(verify_split(path, lim), indent=2))
