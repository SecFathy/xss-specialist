"""Phase 13 — local intentionally-vulnerable XSS test application (stdlib only, no new deps).

Runs on 127.0.0.1 for authorized local evaluation ONLY. The live pipeline must pass against this app
before any external target is considered. Endpoints deliberately span the ground-truth matrix:

  /reflect        reflected XSS in HTML text (VULN)
  /reflect_attr   reflected into an unquoted attribute (VULN)
  /reflect_js     reflected into a <script> JS string (VULN)
  /encoded        reflected but HTML-encoded (SAFE)
  /json_script    reflected into <script> via json.dumps (SAFE)
  /sanitized      reflected via a real allow-list sanitizer (SAFE)
  /nearmiss       reflected via a fake 'DOMPurify'-looking sanitizer that does nothing (VULN, trap)
  /dom            DOM XSS: reads location.hash into innerHTML (VULN)
  /dom_safe       reads location.hash into textContent (SAFE)
  /fp_trap        echoes input inside a comment / non-executing spot (SAFE, false-positive trap)
  /store          stored-style: keeps last value in memory (process-local, NOT persisted) (VULN)

Ground truth is exported as GROUND_TRUTH for the evaluator. Nothing here persists to disk.
"""
from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# (path, vulnerable, context, note) — ground truth for the local benchmark.
GROUND_TRUTH = {
    "/reflect":      (True,  "html_text",   "unencoded reflection"),
    "/reflect_attr": (True,  "html_attr",   "unquoted attribute"),
    "/reflect_js":   (True,  "js_string",   "script string context"),
    "/encoded":      (False, "html_text",   "html-encoded"),
    "/json_script":  (False, "js_string",   "json_encode into script"),
    "/sanitized":    (False, "html_text",   "real allow-list sanitizer"),
    "/nearmiss":     (True,  "html_text",   "fake DOMPurify no-op (trap)"),
    "/dom":          (True,  "dom_html",    "location.hash -> innerHTML"),
    "/dom_safe":     (False, "dom_html",    "location.hash -> textContent"),
    "/fp_trap":      (False, "html_text",   "echoed inside HTML comment"),
    "/store":        (True,  "html_text",   "stored-style in-memory reflection"),
}

_STORE = {"v": ""}


def _real_sanitizer(s: str) -> str:
    # allow-list: strip everything but a few inline tags' text; here just entity-encode (safe).
    return html.escape(s, quote=True)


def _fake_dompurify(s: str) -> str:
    # LOOKS like a sanitizer, does nothing — the near-miss trap. Name resemblance != safety.
    return s


PAGE = "<!doctype html><html><head><meta charset=utf-8><title>vulnapp</title></head><body>{body}</body></html>"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, body: str, ctype="text/html; charset=utf-8", status=200):
        b = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = parse_qs(u.query)
        v = (q.get("q") or q.get("name") or [""])[0]
        if path == "/" or path == "/index.html":
            links = "".join(f'<li><a href="{p}?q=hello">{p}</a></li>' for p in GROUND_TRUTH)
            return self._send(PAGE.format(body=f"<h1>vulnapp</h1><ul>{links}</ul>"
                                          '<form action="/reflect" method="get">'
                                          '<input name="q"><button>go</button></form>'))
        if path == "/reflect":
            return self._send(PAGE.format(body=f"<div>Hello {v}</div>"))
        if path == "/reflect_attr":
            return self._send(PAGE.format(body=f"<div class={v}>x</div>"))
        if path == "/reflect_js":
            return self._send(PAGE.format(body=f"<script>var s = \"{v}\";</script>"))
        if path == "/encoded":
            return self._send(PAGE.format(body=f"<div>Hello {html.escape(v, quote=True)}</div>"))
        if path == "/json_script":
            return self._send(PAGE.format(body=f"<script>var s = {json.dumps(v)};</script>"))
        if path == "/sanitized":
            return self._send(PAGE.format(body=f"<div>{_real_sanitizer(v)}</div>"))
        if path == "/nearmiss":
            return self._send(PAGE.format(body=f"<div>{_fake_dompurify(v)}</div>"))
        if path == "/dom":
            return self._send(PAGE.format(body='<div id=out></div>'
                '<script>document.getElementById("out").innerHTML = decodeURIComponent(location.hash.slice(1));</script>'))
        if path == "/dom_safe":
            return self._send(PAGE.format(body='<div id=out></div>'
                '<script>document.getElementById("out").textContent = decodeURIComponent(location.hash.slice(1));</script>'))
        if path == "/fp_trap":
            return self._send(PAGE.format(body=f"<!-- user said: {html.escape(v)} --><div>ok</div>"))
        if path == "/store":
            if v:
                _STORE["v"] = v
            return self._send(PAGE.format(body=f"<div>last: {_STORE['v']}</div>"))
        return self._send(PAGE.format(body="not found"), status=404)


def serve(host="127.0.0.1", port=8099) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    s = serve()
    print(f"vulnapp on http://127.0.0.1:8099  ({len(GROUND_TRUTH)} endpoints)")
    import time
    while True:
        time.sleep(3600)
