"""Deterministic XSS case generator.

A *template* is a code shape with a hole for untrusted data reaching a sink, plus a matched
SAFE counterpart (correct encoder / safe sink / framework escaping) — the hard negative that
stops a "label everything vulnerable" model from scoring. Each template is parameterised by
identifiers drawn from wordbanks, so the same shape yields many lexically distinct cases; this
powers the generalization split (unseen names) and the near-miss split (edit-distance-controlled
entity perturbations).

Splits are cut by TEMPLATE, not by instance, so the held-out/generalization sets are structurally
novel, never a renamed training row. All draws come from named repro streams so counts in one
split never perturb another (integrity rule).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from xss_specialist.repro import stream
from xss_specialist.schema import (
    Context as C, Defense as D, Family as F, FlowNode, Origin, Provenance, Role as R, XSSCase,
)

_SYN = Provenance(source="template", title="synthetic XSS case", reference="benchmarks/cases.py",
                  origin=Origin.SYNTHETIC)

# Wordbanks for identifier variation. Disjoint 'train' vs 'holdout' names give the
# generalization split truly unseen tokens.
VARS_TRAIN = ["userInput", "data", "value", "param", "q", "name", "comment", "msg"]
VARS_HOLD = ["payload", "field", "token", "note", "term", "author", "body", "tag"]
ELEMS = ["el", "node", "container", "target", "box", "out", "slot", "view"]
SRC_URL = ["location.hash", "location.search", "document.referrer", "window.name"]


@dataclass
class Template:
    id: str
    language: str
    family: F
    context: C
    sink_name: str
    source_name: str
    # builders take (var, elem, src) -> code string
    vuln: Callable[[str, str, str], str]
    safe: Callable[[str, str, str], str]
    safe_sink: str
    safe_defense: D
    root_cause: str
    remediation: str
    group: str  # "train" or "holdout" (structural generalization split)


def _templates() -> list[Template]:
    T = []
    T.append(Template(
        "dom_innerhtml", "javascript", F.DOM, C.DOM_HTML, "innerHTML", "location.hash",
        vuln=lambda v, e, s: f"const {v} = decodeURIComponent({s}.slice(1));\n{e}.innerHTML = {v};",
        safe=lambda v, e, s: f"const {v} = decodeURIComponent({s}.slice(1));\n{e}.textContent = {v};",
        safe_sink="textContent", safe_defense=D.SAFE_DOM_API,
        root_cause="URL fragment written to innerHTML, which parses HTML.",
        remediation="Use textContent, or sanitize with DOMPurify before innerHTML.", group="train"))
    T.append(Template(
        "doc_write", "javascript", F.DOM, C.DOM_HTML, "document.write", "location.search",
        vuln=lambda v, e, s: f"const {v} = new URLSearchParams({s}).get('q');\ndocument.write({v});",
        safe=lambda v, e, s: f"const {v} = new URLSearchParams({s}).get('q');\n{e}.textContent = {v};",
        safe_sink="textContent", safe_defense=D.SAFE_DOM_API,
        root_cause="Query parameter passed to document.write, an HTML-parsing sink.",
        remediation="Write via textContent or a sanitizer; avoid document.write.", group="train"))
    T.append(Template(
        "reflected_html", "php", F.REFLECTED, C.HTML_TEXT, "echo", "$_GET",
        vuln=lambda v, e, s: f"$${v} = $_GET['q'];\necho \"<div>\" . $${v} . \"</div>\";",
        safe=lambda v, e, s: f"$${v} = $_GET['q'];\necho \"<div>\" . htmlspecialchars($${v}, ENT_QUOTES) . \"</div>\";",
        safe_sink="htmlspecialchars", safe_defense=D.CONTEXTUAL_ENCODING,
        root_cause="Request parameter echoed into HTML text without encoding.",
        remediation="HTML-encode with htmlspecialchars(..., ENT_QUOTES).", group="train"))
    T.append(Template(
        "react_dsih", "jsx", F.TEMPLATE, C.DOM_HTML, "dangerouslySetInnerHTML", "props",
        vuln=lambda v, e, s: f"function {e}({{ {v} }}) {{\n  return <div dangerouslySetInnerHTML={{{{ __html: {v} }}}} />;\n}}",
        safe=lambda v, e, s: f"function {e}({{ {v} }}) {{\n  return <div>{{{v}}}</div>;\n}}",
        safe_sink="{child}", safe_defense=D.FRAMEWORK_ESCAPING,
        root_cause="Untrusted prop passed to dangerouslySetInnerHTML, bypassing React escaping.",
        remediation="Render as a text child, or sanitize before setting __html.", group="train"))
    T.append(Template(
        "js_eval", "javascript", F.DOM, C.JS_CODE, "eval", "location.hash",
        vuln=lambda v, e, s: f"const {v} = {s}.slice(1);\neval({v});",
        safe=lambda v, e, s: f"const {v} = {s}.slice(1);\n{e}.textContent = {v};",
        safe_sink="textContent", safe_defense=D.SAFE_DOM_API,
        root_cause="URL fragment passed to eval, executing attacker JS.",
        remediation="Never eval untrusted input; parse data with JSON.parse if structured.", group="train"))
    T.append(Template(
        "attr_href", "javascript", F.DOM, C.HTML_ATTR_URL, "href", "location.search",
        vuln=lambda v, e, s: f"const {v} = new URLSearchParams({s}).get('next');\n{e}.href = {v};",
        safe=lambda v, e, s: (f"const {v} = new URLSearchParams({s}).get('next');\n"
                              f"if (/^https?:\\/\\//.test({v})) {e}.href = {v};"),
        safe_sink="scheme allow-list", safe_defense=D.INPUT_CONSTRAINT,
        root_cause="Anchor href set to attacker URL; a javascript: scheme executes on click.",
        remediation="Allow-list http/https schemes before assigning href.", group="train"))
    # --- Held-out structural shapes (generalization split): different wrappers / flow ---
    T.append(Template(
        "jquery_html", "javascript", F.DOM, C.DOM_HTML, "$.html", "location.hash",
        vuln=lambda v, e, s: f"var {v} = {s}.substring(1);\n$('#{e}').html({v});",
        safe=lambda v, e, s: f"var {v} = {s}.substring(1);\n$('#{e}').text({v});",
        safe_sink=".text()", safe_defense=D.SAFE_DOM_API,
        root_cause="jQuery .html() parses HTML; fed a URL fragment.",
        remediation="Use .text() for untrusted strings.", group="holdout"))
    T.append(Template(
        "insert_adjacent", "javascript", F.DOM, C.DOM_HTML, "insertAdjacentHTML", "window.name",
        vuln=lambda v, e, s: f"const {v} = {s};\n{e}.insertAdjacentHTML('beforeend', {v});",
        safe=lambda v, e, s: f"const {v} = {s};\n{e}.insertAdjacentText('beforeend', {v});",
        safe_sink="insertAdjacentText", safe_defense=D.SAFE_DOM_API,
        root_cause="insertAdjacentHTML parses HTML; fed window.name.",
        remediation="Use insertAdjacentText for untrusted content.", group="holdout"))
    T.append(Template(
        "wrapped_render", "javascript", F.DOM, C.DOM_HTML, "innerHTML", "document.referrer",
        # wrapper function indirection -> tests source/sink distance & flow tracking
        vuln=lambda v, e, s: (f"function render({v}, {e}) {{ {e}.innerHTML = {v}; }}\n"
                              f"render({s}, document.getElementById('out'));"),
        safe=lambda v, e, s: (f"function render({v}, {e}) {{ {e}.textContent = {v}; }}\n"
                              f"render({s}, document.getElementById('out'));"),
        safe_sink="textContent", safe_defense=D.SAFE_DOM_API,
        root_cause="Referrer flows through a wrapper into innerHTML.",
        remediation="Sink to textContent inside the wrapper.", group="holdout"))
    return T


def _case_from(t: Template, v: str, e: str, vulnerable: bool, idx: int) -> XSSCase:
    src = t.source_name
    code = (t.vuln if vulnerable else t.safe)(v, e, src)
    flow = [
        FlowNode(R.SOURCE, src, C.URL if "location" in src or "referrer" in src or "name" in src else C.HTML_TEXT),
        FlowNode(R.SINK, t.sink_name if vulnerable else t.safe_sink, t.context,
                 safe=None if vulnerable else True),
    ]
    if not vulnerable and t.safe_defense in (D.CONTEXTUAL_ENCODING, D.INPUT_CONSTRAINT):
        flow.insert(1, FlowNode(R.ENCODER if t.safe_defense == D.CONTEXTUAL_ENCODING else R.SANITIZER,
                                t.safe_sink, t.context, safe=True))
    return XSSCase(
        id=f"{t.id}-{'v' if vulnerable else 's'}-{idx:03d}",
        code=code, language=t.language, family=t.family if vulnerable else F.SAFE,
        vulnerable=vulnerable, context=t.context, flow=flow,
        existing_defense=D.NONE if vulnerable else t.safe_defense,
        root_cause=t.root_cause if vulnerable else "",
        remediation=t.remediation if vulnerable else "",
        tags=[t.group, t.id], provenance=_SYN,
    )


def generate(n_per_template: int = 6, group: str | None = None,
             names: str = "train") -> list[XSSCase]:
    """Generate paired (vuln, safe) cases. `group` filters template group;
    `names` selects the identifier wordbank (train vs holdout for generalization)."""
    rng = stream(f"cases:{group}:{names}")
    vbank = VARS_TRAIN if names == "train" else VARS_HOLD
    out: list[XSSCase] = []
    for t in _templates():
        if group and t.group != group:
            continue
        for i in range(n_per_template):
            v = vbank[rng.integers(0, len(vbank))]
            e = ELEMS[rng.integers(0, len(ELEMS))]
            out.append(_case_from(t, v, e, True, i))
            out.append(_case_from(t, v, e, False, i))
    return out


if __name__ == "__main__":
    import json
    cs = generate()
    print(f"{len(cs)} cases; vuln={sum(c.vulnerable for c in cs)} safe={sum(not c.vulnerable for c in cs)}")
    print(json.dumps(cs[0].to_dict(), indent=2)[:600])
