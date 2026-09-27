"""Marker-first, bounded, non-destructive probe planner.

Every probe carries a unique random marker. Stage 1 is always a harmless MARKER probe (no HTML/JS
metacharacters) to learn whether and where input is reflected. Only if a marker reflects do we plan
context-tailored EXECUTION probes, and those do nothing but set a per-marker flag on `window.__X`
(no persistence, no exfiltration, no navigation off-target, no destructive action).

The execution sentinel is the same idea the existing oracle uses (`window.__xss`), generalized to a
per-probe token so many candidates can be told apart. The browser oracle — not the model — decides
whether execution actually happened.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field


def new_marker() -> str:
    return "xz" + secrets.token_hex(4)


@dataclass
class Probe:
    marker: str
    kind: str            # "marker" | "exec"
    context: str         # target context this probe is shaped for
    payload: str
    delivery: str        # "query" | "hash" | "form"
    note: str = ""
    raw_signature: str = ""   # dangerous literal that must reflect UNENCODED for the payload to be live


def _signature(payload: str) -> str:
    """The dangerous fragment that must survive unencoded for the browser to parse the injection.
    If the response HTML-encodes it (&lt;img…), the signature won't be found -> not live."""
    for anchor in ("javascript:", '"><', "</script>", "<img", "onmouseover=", '";'):
        i = payload.find(anchor)
        if i >= 0:
            return payload[i:i + 24]
    return payload[:20]


# Execution payloads by context. Each only sets window.__X['<MARKER>']=1 on execution.
def _exec_payloads(marker: str, context: str) -> list[tuple[str, str]]:
    hit = f"window.__X['{marker}']=1"
    img = f"<img src=x onerror=\"{hit}\">"
    out = []
    if context in ("html_text", "unknown", "dom_html"):
        out.append((f"<span>{marker}</span>{img}", "html_text img-onerror"))
    if context in ("html_attr", "html_attr_quoted", "unknown"):
        # break out of a quoted attribute (needs an UNENCODED quote to work -> good discriminator)
        out.append((f"\"><img src=x onerror=\"{hit}\">", "quoted(dq) attr breakout"))
        out.append((f"'><img src=x onerror='{hit}'>", "quoted(sq) attr breakout"))
    if context in ("html_attr_unquoted",):
        # unquoted attribute: no metachar needed, an event handler alone injects
        out.append((f"{marker} onmouseover={hit} x", "unquoted attr handler"))
    if context in ("js_string", "unknown"):
        out.append((f"{marker}\";{hit};//", "js string breakout"))
        out.append((f"{marker}</script><img src=x onerror=\"{hit}\">", "script close + img"))
    if context in ("url", "html_attr_url"):
        out.append((f"javascript:{hit}", "javascript: url"))
    if context in ("dom_html",):
        out.append((img, "dom innerHTML img-onerror"))
    if not out:
        out.append((img, "default img-onerror"))
    return out


def js_code_probe(delivery: str) -> "Probe":
    """A harmless JS-EXECUTION probe for code sinks (eval/Function/string-timer/script-element/
    event-handler) that consume input as code and do NOT reflect it. Confirmation is by the
    sentinel, not reflection. Non-destructive: only sets window.__X[marker]."""
    m = new_marker()
    payload = f"window.__X['{m}']=1"
    return Probe(marker=m, kind="exec", context="js_code", payload=payload, delivery=delivery,
                 note="js-code execution probe", raw_signature="")


def plan(candidate: dict, stage: str = "marker") -> list[Probe]:
    """candidate: {url, param, method, content_type, context, input_type, delivery}.
    stage 'marker' -> one marker probe; stage 'exec' -> context execution probes."""
    ctx = candidate.get("context", "unknown")
    delivery = candidate.get("delivery", "query")
    if stage == "marker":
        m = new_marker()
        return [Probe(marker=m, kind="marker", context=ctx, payload=m, delivery=delivery,
                      note="harmless reflection marker")]
    probes = []
    for payload, note in _exec_payloads(new_marker(), ctx):
        m = payload.split("'")[1] if "window.__X['" in payload else new_marker()
        probes.append(Probe(marker=m, kind="exec", context=ctx, payload=payload,
                            delivery=delivery, note=note, raw_signature=_signature(payload)))
    return probes
