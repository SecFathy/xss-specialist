"""Headless browser executor: delivers a planned probe to an in-scope URL and records browser
evidence via the authoritative oracle (`verification.browser_oracle.run_probe_on_url`).

Delivery embeds the probe payload into the candidate's parameter — as a query value, a URL fragment,
or (for forms) a query value against the form action. Scope is enforced before every navigation and
the final (post-redirect) URL is checked; out-of-scope is blocked and never executed.
"""
from __future__ import annotations

from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from live.probes import Probe
from live.scope import Enforcer
from verification.browser_oracle import run_probe_on_url


def _embed(url: str, param: str, value: str, delivery: str) -> str:
    p = urlparse(url)
    if delivery == "hash":
        return urlunparse(p._replace(fragment=value))
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


def execute(candidate: dict, probe: Probe, enforcer: Enforcer, timeout_ms: int = 4000) -> dict:
    """Deliver one probe. Returns a browser-evidence record; the oracle's `executed` is authoritative."""
    url = _embed(candidate["url"], candidate.get("param", "q"), probe.payload, probe.delivery)
    ok, reason = enforcer.check(url, kind=probe.kind)
    if not ok:
        return {"blocked": True, "reason": reason, "marker": probe.marker, "url": url}
    ev = run_probe_on_url(url, probe.marker, delivery=probe.delivery,
                          param=candidate.get("param", "q"), timeout_ms=timeout_ms,
                          extra_headers=enforcer.scope.extra_headers or None,
                          cookies=enforcer.scope.cookies or None,
                          raw_signature=probe.raw_signature)
    enforcer.note_request(url, final_url=ev.get("final_url") or url, status=ev.get("status"),
                          kind=probe.kind)
    return {"blocked": False, "probe_kind": probe.kind, "probe_note": probe.note,
            "context": probe.context, "delivery": probe.delivery,
            "param": candidate.get("param", "q"), **ev}
