"""Deterministic, scope-bounded crawler + input-surface mapper.

Uses the headless browser (so JS-rendered links/routes are seen) to fetch each in-scope page, then
extracts links, forms (GET/POST fields), query parameters, and JavaScript-referenced routes. BFS by
depth, deduplicated by a normalized route key, honouring the Enforcer's budget/rate/scope. Every
requested URL is logged; out-of-scope links are blocked, never fetched.

The input-surface mapper turns discovered routes/forms into normalized candidate records the pipeline
can probe.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

from live.scope import Enforcer

_JS_ROUTE = re.compile(r"""["'](/[A-Za-z0-9_\-/]{1,80}(?:\?[^"']*)?)["']""")


def _norm_route(url: str) -> str:
    """Normalize for dedup: drop fragment, sort params, blank param values (route shape, not values)."""
    p = urlparse(url)
    q = sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True))
    return urlunparse(p._replace(query="&".join(q), fragment=""))


def crawl(enforcer: Enforcer, seed: str | None = None, timeout_ms: int = 4000) -> dict:
    """Returns {routes, forms, links, js_routes, graph}. Deterministic BFS."""
    from playwright.sync_api import sync_playwright
    scope = enforcer.scope
    start = seed or scope.base_url
    seen: set[str] = set()
    routes: list[dict] = []
    forms: list[dict] = []
    graph: list[dict] = []
    js_routes: set[str] = set()
    q = deque([(start, 0)])

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            context = browser.new_context(extra_http_headers=scope.extra_headers or {})
            if scope.cookies:
                try:
                    context.add_cookies(scope.cookies)
                except Exception:
                    pass
            page = context.new_page()
            while q:
                url, depth = q.popleft()
                key = _norm_route(url)
                if key in seen:
                    continue
                ok, reason = enforcer.check(url, kind="crawl", depth=depth)
                if not ok:
                    continue
                seen.add(key)
                try:
                    resp = page.goto(url, wait_until="load", timeout=timeout_ms)
                except Exception:
                    enforcer.note_request(url, status=None, kind="crawl", depth=depth)
                    continue
                final = page.url
                enforcer.note_request(url, final_url=final, status=resp.status if resp else None,
                                      kind="crawl", depth=depth)
                routes.append({"url": url, "final_url": final, "depth": depth,
                               "status": resp.status if resp else None})
                # links
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
                for h in hrefs or []:
                    if not h:
                        continue
                    nxt = urljoin(final, h)
                    ins, _ = scope.in_scope(nxt)
                    graph.append({"from": url, "to": nxt, "in_scope": ins})
                    if ins and _norm_route(nxt) not in seen and depth + 1 <= scope.max_depth:
                        q.append((nxt, depth + 1))
                # forms
                fdefs = page.eval_on_selector_all("form", """els => els.map(f => ({
                    action: f.getAttribute('action') || '', method: (f.getAttribute('method')||'get').toLowerCase(),
                    fields: Array.from(f.querySelectorAll('input,textarea,select'))
                        .map(i => ({name: i.getAttribute('name'), type: i.getAttribute('type')||'text'}))
                        .filter(i => i.name)}))""")
                for f in fdefs or []:
                    forms.append({"page": final, "action": urljoin(final, f["action"] or final),
                                  "method": f["method"], "fields": f["fields"]})
                # JS-referenced routes (from page HTML/scripts)
                try:
                    body = resp.text() if resp else ""
                except Exception:
                    body = ""
                for m in _JS_ROUTE.findall(body):
                    cand = urljoin(final, m)
                    if scope.in_scope(cand)[0]:
                        js_routes.add(_norm_route(cand))
        finally:
            browser.close()
    return {"routes": routes, "forms": forms, "graph": graph, "js_routes": sorted(js_routes)}


def map_inputs(crawl_result: dict) -> list[dict]:
    """Normalized candidate records from discovered routes, query params, and forms."""
    cands: list[dict] = []
    seen = set()

    def add(url, param, method, itype, delivery, content_type="", source="", auth="none"):
        key = (_norm_route(url), param, method, delivery)
        if key in seen:
            return
        seen.add(key)
        cands.append({"url": url, "param": param, "method": method, "input_type": itype,
                      "delivery": delivery, "content_type": content_type, "discovery_source": source,
                      "auth_state": auth, "context": "unknown"})

    for r in crawl_result["routes"]:
        for k, _ in parse_qsl(urlparse(r["url"]).query, keep_blank_values=True):
            add(r["url"], k, "GET", "GET parameter", "query", source="crawl-link")
    for jr in crawl_result["js_routes"]:
        for k, _ in parse_qsl(urlparse(jr).query, keep_blank_values=True):
            add(jr, k, "GET", "GET parameter", "query", source="js-route")
    for f in crawl_result["forms"]:
        for field in f["fields"]:
            delivery = "query" if f["method"] == "get" else "form"
            add(f["action"], field["name"], f["method"].upper(), "POST form field" if f["method"] == "post"
                else "GET parameter", delivery, source="form")
    # DOM-source candidates: every route is also a DOM candidate (hash-delivered)
    for r in crawl_result["routes"]:
        add(r["url"], "#", "GET", "URL fragment (DOM)", "hash", source="dom-source")
    return cands
