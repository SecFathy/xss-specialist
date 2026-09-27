"""XSS-LiveBench-v2 local test application (stdlib only; 127.0.0.1 only).

A data-driven set of >100 endpoints spanning reflected contexts, DOM source/sink matrices, encoding
& parser stress, a large sanitizer-identity adversarial suite, a false-positive torture suite, a few
multi-step flows, and a controlled in-memory stored-XSS workflow. Each endpoint is one benchmark
case with ground truth. Nothing persists to disk; stored cases keep state in a process-local dict.

Ground truth per case: vulnerable(bool), context, xss_class(reflected|dom|stored|safe), category,
delivery(query|hash), interaction(none|hover|click|focus|submit|hashnav), note.
"""
from __future__ import annotations

import html
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = "<!doctype html><html><head><meta charset=utf-8><title>vulnapp2</title>{csp}</head><body>{body}</body></html>"


@dataclass
class Case:
    path: str
    vulnerable: bool
    context: str
    xss_class: str
    category: str
    render: object            # fn(v)->str  (v = decoded query value)
    delivery: str = "query"
    interaction: str = "none"
    note: str = ""
    csp: str = ""


CASES: list[Case] = []
_STORE: dict[str, str] = {}


def _c(path, vuln, ctx, cls, cat, render, delivery="query", interaction="none", note="", csp=""):
    CASES.append(Case(path, vuln, ctx, cls, cat, render, delivery, interaction, note, csp))


def esc(s):  # HTML entity encode
    return html.escape(s, quote=True)


def js_str_safe(s):  # JSON + <>& escaping for inline script string
    return json.dumps(s).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


# ---------------------------------------------------------------- reflected contexts
def _reflected():
    _c("/r/html_text", True, "html_text", "reflected", "reflected",
       lambda v: f"<div>Hello {v}</div>")
    _c("/r/html_text_safe", False, "html_text", "safe", "reflected",
       lambda v: f"<div>Hello {esc(v)}</div>")
    _c("/r/attr_quoted", True, "html_attr", "reflected", "reflected",
       lambda v: f'<input value="{v}">')
    _c("/r/attr_quoted_safe", False, "html_attr", "safe", "reflected",
       lambda v: f'<input value="{esc(v)}">')
    _c("/r/attr_unquoted", True, "html_attr", "reflected", "reflected",
       lambda v: f"<div class={v}>x</div>", interaction="hover")
    # entity-encoding does NOT protect an UNQUOTED attribute (no metachar needed for onX= injection);
    # the genuinely-safe form quotes the attribute.
    _c("/r/attr_unquoted_safe", False, "html_attr", "safe", "reflected",
       lambda v: f'<div class="{esc(v)}">x</div>')
    _c("/r/js_string", True, "js_string", "reflected", "reflected",
       lambda v: f'<script>var s = "{v}";</script>')
    _c("/r/js_string_safe", False, "js_string", "safe", "reflected",
       lambda v: f"<script>var s = {js_str_safe(v)};</script>")
    _c("/r/js_expr", True, "js_code", "reflected", "reflected",
       lambda v: f"<script>var n = {v};</script>")
    _c("/r/js_expr_safe", False, "js_code", "safe", "reflected",
       lambda v: f"<script>var n = {json.dumps(v)};</script>")
    _c("/r/url_href", True, "html_attr_url", "reflected", "reflected",
       lambda v: f'<a id=lnk href="{v}">go</a>', interaction="click")
    _c("/r/url_href_safe", False, "html_attr_url", "safe", "reflected",
       lambda v: (f'<a id=lnk href="{v}">go</a>' if v.startswith(("http://", "https://", "/"))
                  else '<a id=lnk href="#">go</a>'), interaction="click")
    _c("/r/css", True, "css", "reflected", "reflected",
       lambda v: f"<style>body{{background:{v}}}</style><div>x</div>")
    _c("/r/css_safe", False, "css", "safe", "reflected",
       lambda v: f"<style>body{{background:{esc(v)}}}</style><div>x</div>")
    _c("/r/json_in_html", True, "js_string", "reflected", "reflected",
       lambda v: f'<script>var cfg = {{"name":"{v}"}};</script>')
    _c("/r/json_in_html_safe", False, "js_string", "safe", "reflected",
       lambda v: f"<script>var cfg = {json.dumps({'name': v}).replace('<','\\u003c')};</script>")
    _c("/r/script_data", True, "js_code", "reflected", "reflected",
       lambda v: f"<script>/* {v} */ var ok=1;</script>", note="script-data comment breakout")
    _c("/r/script_data_safe", False, "js_code", "safe", "reflected",
       lambda v: f"<script>/* {esc(v).replace('*/','')} */ var ok=1;</script>")
    _c("/r/template", True, "html_text", "reflected", "reflected",
       lambda v: f"<template id=t><div>{v}</div></template><script>"
                 "document.body.appendChild(document.getElementById('t').content.cloneNode(true))</script>")
    _c("/r/nested_attr_js", True, "html_attr", "reflected", "reflected",
       lambda v: f'<div data-x="{v}" onclick="run()">c</div>', interaction="click")
    _c("/r/multi_reflection", True, "html_text", "reflected", "reflected",
       lambda v: f"<div>{v}</div><span title='{v}'>{v}</span>", note="same input reflected 3x")
    _c("/r/multi_reflection_safe", False, "html_text", "safe", "reflected",
       lambda v: f"<div>{esc(v)}</div><span title='{esc(v)}'>{esc(v)}</span>")


# ---------------------------------------------------------------- DOM source/sink matrix
def _dom():
    sources = {
        "hash": "decodeURIComponent(location.hash.slice(1))",
        "search": "new URLSearchParams(location.search).get('q')",
        "referrer": "document.referrer",
        "url": "document.URL",
    }
    sinks_vuln = {
        "innerHTML": "o.innerHTML = SRC;",
        "outerHTML": "o.outerHTML = '<div>'+SRC+'</div>';",
        "insertAdjacentHTML": "o.insertAdjacentHTML('beforeend', SRC);",
        "docwrite": "document.write(SRC);",
        "eval": "try{eval(SRC)}catch(e){}",
    }
    # only hash/search deliver undistorted payloads in a headless run; use hash for exec ones
    for sink, code in sinks_vuln.items():
        src_expr = sources["hash"]
        js = code.replace("SRC", src_expr)
        _c(f"/dom/{sink}", True, "dom_html" if sink != "eval" else "js_code", "dom", "dom",
           (lambda js=js: (lambda v: f'<div id=out></div><script>var o=document.getElementById("out");{js}</script>'))(),
           delivery="hash", note=f"hash -> {sink}")
    # safe sinks
    _c("/dom/textContent", False, "dom_html", "safe", "dom",
       lambda v: '<div id=out></div><script>var o=document.getElementById("out");'
                 'o.textContent = decodeURIComponent(location.hash.slice(1));</script>', delivery="hash")
    _c("/dom/setattr_safe", False, "dom_attr", "safe", "dom",
       lambda v: '<div id=out></div><script>var o=document.getElementById("out");'
                 'o.setAttribute("title", decodeURIComponent(location.hash.slice(1)));</script>', delivery="hash")
    # multi-step: source -> transform -> transform -> sink
    _c("/dom/multistep", True, "dom_html", "dom", "dom_multistep",
       lambda v: '<div id=out></div><script>'
                 'function t1(x){return x.trim()} function t2(x){return "<b>"+x+"</b>"}'
                 'var s=decodeURIComponent(location.hash.slice(1));'
                 'document.getElementById("out").innerHTML=t2(t1(s));</script>', delivery="hash",
       note="source->trim->wrap->innerHTML")
    _c("/dom/settimeout", True, "js_code", "dom", "dom",
       lambda v: '<script>setTimeout(decodeURIComponent(location.hash.slice(1)), 10);</script>',
       delivery="hash", note="string timer")


# ---------------------------------------------------------------- encoding / parser stress
def _encoding():
    # double-encoded: server decodes once; a single-encoded payload becomes text -> safe here
    _c("/enc/double", False, "html_text", "safe", "encoding",
       lambda v: f"<div>{esc(v)}</div>", note="double-encoded input stays inert")
    # server html-encodes but client decodes then innerHTML -> VULN (multi-decode)
    _c("/enc/client_decode", True, "dom_html", "dom", "encoding",
       lambda v: f'<div id=raw hidden>{esc(v)}</div><div id=out></div>'
                 '<script>var t=document.getElementById("raw").textContent;'
                 'document.getElementById("out").innerHTML=t;</script>',
       note="server-encoded then client textContent->innerHTML re-parses")
    # unicode escape in JS string -> safe if properly json-encoded
    _c("/enc/js_unicode_safe", False, "js_string", "safe", "encoding",
       lambda v: f"<script>var s={js_str_safe(v)};</script>")
    # backslash: value placed in JS string with only quote-escaping (backslash breaks it) -> VULN
    _c("/enc/backslash_js", True, "js_string", "reflected", "encoding",
       lambda v: '<script>var s = "' + v.replace('"', '\\"') + '";</script>',
       note="quote-escaped only; trailing backslash escapes the escape")
    _c("/enc/entity_text_safe", False, "html_text", "safe", "encoding",
       lambda v: f"<div>{esc(v)}</div>", note="entities render as text")


# ---------------------------------------------------------------- sanitizer identity adversarial
def _sanitizers():
    def wrap(sanitizer_js, safe):
        # a page that 'sanitizes' with the named function then innerHTMLs the result
        return lambda v: ('<div id=out></div><script>'
                          f'{sanitizer_js}'
                          'var s=decodeURIComponent(location.hash.slice(1));'
                          'document.getElementById("out").innerHTML=clean(s);</script>')
    # real DOMPurify-equivalent (strips tags) -> SAFE
    _c("/san/real_strip", False, "dom_html", "safe", "sanitizer",
       wrap('function clean(x){var d=document.createElement("div");d.textContent=x;return d.innerHTML;}', True),
       delivery="hash", note="real escaping sanitizer")
    # fake DOMPurify no-op -> VULN (trap)
    _c("/san/fake_dompurify", True, "dom_html", "dom", "sanitizer",
       wrap('var DOMPurify={sanitize:function(x){return x;}};function clean(x){return DOMPurify.sanitize(x);}', False),
       delivery="hash", note="fake DOMPurify no-op")
    # near-miss names, all no-op -> VULN
    for nm in ["DOMPvrify", "DOMPurfy", "DomPurify", "DOMPurify2", "D0MPurify", "DOMPurifyy"]:
        _c(f"/san/nearmiss_{nm}", True, "dom_html", "dom", "sanitizer_nearmiss",
           wrap(f'var {nm}={{sanitize:function(x){{return x;}}}};function clean(x){{return {nm}.sanitize(x);}}', False),
           delivery="hash", note=f"near-miss sanitizer {nm} (no-op)")
    # same function name from another package, no-op -> VULN
    _c("/san/other_pkg_sanitize", True, "dom_html", "dom", "sanitizer_nearmiss",
       wrap('function sanitize(x){return x;}function clean(x){return sanitize(x);}', False),
       delivery="hash", note="generic sanitize() no-op")
    # correct sanitizer then unsafe DOM manipulation afterward -> VULN
    _c("/san/correct_then_unsafe", True, "dom_html", "dom", "sanitizer",
       lambda v: ('<div id=out></div><script>'
                  'function clean(x){var d=document.createElement("div");d.textContent=x;return d.innerHTML;}'
                  'var s=decodeURIComponent(location.hash.slice(1));'
                  'var c=clean(s); document.getElementById("out").innerHTML=c+decodeURIComponent(location.hash.slice(1));</script>'),
       delivery="hash", note="sanitized value concatenated with raw source")
    # sanitize in wrong context: html-escape then put in JS -> VULN
    _c("/san/wrong_context", True, "js_string", "reflected", "sanitizer",
       lambda v: f'<script>var s = "{esc(v)}";</script>' if False else
                 f'<script>var s = "{v.replace(chr(34), "&quot;")}";</script>',
       note="html-entity encode used for a JS-string context")
    # sanitize then decode -> VULN
    _c("/san/sanitize_then_decode", True, "dom_html", "dom", "sanitizer",
       lambda v: ('<div id=out></div><script>'
                  'function clean(x){var d=document.createElement("div");d.textContent=x;return d.innerHTML;}'
                  'var s=decodeURIComponent(location.hash.slice(1));'
                  'var c=clean(s); document.getElementById("out").innerHTML=(new DOMParser())'
                  '.parseFromString(c,"text/html").body.textContent;</script>'),
       delivery="hash", note="sanitized then decoded back before sink")


# ---------------------------------------------------------------- false-positive torture
def _fp_torture():
    fp = [
        ("comment", lambda v: f"<!-- user: {esc(v)} --><div>ok</div>", "payload inside comment"),
        ("encoded_text", lambda v: f"<div>{esc(v)}</div>", "encoded payload as text"),
        ("docs", lambda v: f"<pre>Example: {esc(v)}</pre>", "example in documentation"),
        ("code_snippet", lambda v: f"<code>{esc(v)}</code>", "code snippet"),
        ("textarea", lambda v: f"<textarea>{esc(v)}</textarea>", "textarea content"),
        ("json_text", lambda v: f'<script type="application/json">{js_str_safe(v)}</script>', "json data block"),
        ("noexec_text", lambda v: f"<div>script-like: {esc(v)}</div>", "non-executable text"),
        ("sanitized_html", lambda v: f"<div>{esc(v)}</div>", "correctly sanitized"),
        ("textcontent_js", lambda v: '<div id=o></div><script>document.getElementById("o")'
                                     '.textContent=decodeURIComponent(location.hash.slice(1))</script>', "safe textContent"),
        ("dead_code", lambda v: f"<script>if(false){{eval({json.dumps(v)})}}</script><div>ok</div>", "dead code path"),
        ("unreachable_sink", lambda v: f"<script>function never(){{document.body.innerHTML={json.dumps(v)}}}</script>", "sink never called"),
        ("safe_after_transform", lambda v: f"<div>{esc(v.replace('<','').replace('>',''))}</div>", "stripped then shown"),
    ]
    for name, render, note in fp:
        delivery = "hash" if name in ("textcontent_js",) else "query"
        _c(f"/fp/{name}", False, "html_text", "safe", "fp_torture", render, delivery=delivery, note=note)
    # CSP-blocked execution: reflects raw but CSP forbids inline -> not executable
    _c("/fp/csp_blocked", False, "html_text", "safe", "fp_torture",
       lambda v: f"<div>{v}</div>", note="raw reflection but CSP blocks inline scripts",
       csp='<meta http-equiv="Content-Security-Policy" content="script-src \'none\'">')


# ---------------------------------------------------------------- stored (in-memory)
def _stored():
    _c("/store/submit", True, "html_text", "stored", "stored",
       lambda v: (_STORE.__setitem__("note", v) or f"<div>saved</div>"), note="submit step")
    _c("/store/view", True, "html_text", "stored", "stored",
       lambda v: f"<div>note: {_STORE.get('note','')}</div>", note="retrieval/view step")


def _expand():
    # DOM matrix: search-delivered (URLSearchParams decodes -> live) across sinks
    dom_sinks = {
        "innerHTML": "o.innerHTML=S;", "outerHTML": "o.outerHTML='<i>'+S+'</i>';",
        "insertAdjacentHTML": "o.insertAdjacentHTML('beforeend',S);",
        "docwrite": "document.write(S);", "Function": "try{Function(S)()}catch(e){}",
        "eventhandler": "o.setAttribute('onclick',S);o.click&&o.click();",
    }
    for sink, code in dom_sinks.items():
        js = code.replace("S", "new URLSearchParams(location.search).get('q')")
        _c(f"/dom/search_{sink}", True, "dom_html" if "HTML" in sink or "write" in sink else "js_code",
           "dom", "dom",
           (lambda js=js: (lambda v: f'<div id=out></div><script>var o=document.getElementById("out");{js}</script>'))(),
           delivery="query", interaction="click" if sink == "eventhandler" else "none",
           note=f"search -> {sink}")
    # script element construction sink
    _c("/dom/script_construct", True, "js_code", "dom", "dom",
       lambda v: '<script>var s=document.createElement("script");'
                 's.text=new URLSearchParams(location.search).get("q");document.body.appendChild(s);</script>',
       delivery="query", note="dynamic <script>.text")
    # reflected attribute variants
    for attr in ["title", "alt", "data-x", "placeholder", "aria-label"]:
        _c(f"/r/attrq_{attr}", True, "html_attr", "reflected", "reflected",
           (lambda a=attr: (lambda v: f'<input {a}="{v}">'))())
        _c(f"/r/attrq_{attr}_safe", False, "html_attr", "safe", "reflected",
           (lambda a=attr: (lambda v: f'<input {a}="{esc(v)}">'))())
    # event-handler attribute reflection (needs interaction)
    for ev, itn in [("onmouseover", "hover"), ("onfocus", "focus"), ("onclick", "click")]:
        _c(f"/r/evattr_{ev}", True, "html_attr", "reflected", "reflected",
           (lambda e=ev: (lambda v: f'<input id=t {e}="{v}" value=x autofocus>'))(),
           interaction=itn, note=f"reflection into {ev}")
    # img src / iframe src url sinks
    _c("/r/img_src", True, "html_attr_url", "reflected", "reflected",
       lambda v: f'<img src="{v}" onerror="1">', note="img src")
    _c("/r/img_src_safe", False, "html_attr_url", "safe", "reflected",
       lambda v: f'<img src="{esc(v)}" alt=x>')
    # more near-miss sanitizer edits (all no-op -> vuln)
    for nm in ["DOMPurlfy", "DOMPur1fy", "DMOPurify", "DOMPurifyClean", "purifyDOM",
               "DOMPurify_", "_DOMPurify", "DOMPurifi", "DOMSanitize", "sanitizeDOM",
               "xssClean", "htmlSanitize", "DOMpurify", "domPurify"]:
        _c(f"/san/nm2_{nm}", True, "dom_html", "dom", "sanitizer_nearmiss",
           (lambda n=nm: (lambda v: '<div id=out></div><script>'
                          f'var {n}={{sanitize:function(x){{return x;}}}};'
                          f'document.getElementById("out").innerHTML={n}.sanitize('
                          'decodeURIComponent(location.hash.slice(1)));</script>'))(),
           delivery="hash", note=f"near-miss {nm} no-op")
    # more FP torture
    _c("/fp/svg_text", False, "html_text", "safe", "fp_torture",
       lambda v: f"<svg><text>{esc(v)}</text></svg>", note="svg text encoded")
    _c("/fp/attr_name_pos", False, "html_text", "safe", "fp_torture",
       lambda v: f"<div>{esc(v)}</div><!-- {esc(v)} -->", note="encoded in two inert spots")
    _c("/fp/meta_refresh_safe", False, "html_text", "safe", "fp_torture",
       lambda v: f"<div>{esc(v)}</div>", note="looks navigational, encoded")


for _f in (_reflected, _dom, _encoding, _sanitizers, _fp_torture, _stored, _expand):
    _f()

BY_PATH = {c.path: c for c in CASES}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        v = (q.get("q") or q.get("name") or [""])[0]
        if path in ("/", "/index.html"):
            links = "".join(f'<li><a href="{c.path}?q=hi">{c.path}</a></li>' for c in CASES)
            body = f"<h1>vulnapp2</h1><ul>{links}</ul>"
            return self._send(PAGE.format(csp="", body=body))
        c = BY_PATH.get(path)
        if not c:
            return self._send(PAGE.format(csp="", body="not found"), status=404)
        try:
            body = c.render(v)
        except Exception as e:
            body = f"<div>err {html.escape(str(e))}</div>"
        return self._send(PAGE.format(csp=c.csp, body=body))

    def _send(self, body, status=200):
        b = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def serve(host="127.0.0.1", port=8098) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    print(f"vulnapp2: {len(CASES)} cases "
          f"(vuln={sum(c.vulnerable for c in CASES)} safe={sum(not c.vulnerable for c in CASES)})")
    from collections import Counter
    print("by category:", dict(Counter(c.category for c in CASES)))
    print("by context:", dict(Counter(c.context for c in CASES)))
