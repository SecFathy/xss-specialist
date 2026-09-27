"""Adversarial DETECTION cases: genuinely vulnerable code that is easy to miss (obfuscation,
mutation XSS, indirection), plus safe code that superficially looks dangerous. A specialist must
keep both recall (catch the evasive ones) and precision (not flag the safe look-alikes).

(Pipeline-level adversarial robustness — poisoning, injection into the learning pipeline — is a
separate suite under verification/ and gate/, per Phase 17.)
"""
from __future__ import annotations

from xss_specialist.schema import (
    Context as C, Defense as D, Family as F, FlowNode, Origin, Provenance, Role as R, XSSCase,
)

_SYN = Provenance(source="template", title="adversarial XSS case", reference="benchmarks/adversarial.py",
                  origin=Origin.SYNTHETIC)


def _c(id, lang, fam, vuln, ctx, flow, defense, rc="", rem="", tags=(), *, code):
    return XSSCase(id=id, code=code, language=lang, family=fam, vulnerable=vuln, context=ctx,
                   flow=flow, existing_defense=defense, root_cause=rc, remediation=rem,
                   tags=["adversarial", *tags], provenance=_SYN)


def generate() -> list[XSSCase]:
    S = lambda name, ctx=C.URL: FlowNode(R.SOURCE, name, ctx)
    K = lambda name, ctx, safe=None: FlowNode(R.SINK, name, ctx, safe=safe)
    cases = [
        # 1. Vulnerable but obfuscated: sink reached via bracket property + alias
        _c("adv-alias-innerhtml", "javascript", F.DOM, True, C.DOM_HTML,
           [S("location.hash"), K("innerHTML", C.DOM_HTML)],
           D.NONE, "innerHTML reached via a computed property alias.",
           "Sink to textContent regardless of how the property is referenced.", tags=["obfuscation"],
           code="const p = 'inner' + 'HTML';\nel[p] = location.hash.slice(1);"),
        # 2. Mutation XSS: sanitized string re-parsed differently
        _c("adv-mxss-reparse", "javascript", F.MUTATION, True, C.DOM_HTML,
           [S("userInput", C.HTML_TEXT), FlowNode(R.SANITIZER, "naiveStrip", C.DOM_HTML, safe=False),
            K("innerHTML", C.DOM_HTML)],
           D.SANITIZATION, "Hand-rolled tag stripper leaves markup that the parser mutates into active content.",
           "Use DOMPurify; do not regex-strip then re-insert as HTML.", tags=["mutation"],
           code="const clean = userInput.replace(/<script>/gi,'');\nel.innerHTML = clean;"),
        # 3. Safe but scary-looking: innerHTML with a static string literal (no untrusted data)
        _c("adv-safe-static", "javascript", F.SAFE, False, C.DOM_HTML,
           [K("innerHTML", C.DOM_HTML, safe=True)],
           D.NONE, "", "", tags=["hard_negative"],
           code="el.innerHTML = '<b>Welcome</b>';  // static literal, no user data"),
        # 4. Safe: value goes to innerHTML but is number-coerced first
        _c("adv-safe-coerced", "javascript", F.SAFE, False, C.DOM_HTML,
           [S("location.hash"), FlowNode(R.TRANSFORM, "Number", C.DOM_HTML, safe=True),
            K("innerHTML", C.DOM_HTML, safe=True)],
           D.INPUT_CONSTRAINT, "", "", tags=["hard_negative"],
           code="const n = Number(location.hash.slice(1));\nif (!Number.isNaN(n)) el.innerHTML = n;"),
        # 5. Vulnerable: encoded for wrong context (HTML-encoded then put in <script>)
        _c("adv-wrongctx-script", "php", F.REFLECTED, True, C.JS_CODE,
           [S("$_GET", C.HTML_TEXT), FlowNode(R.ENCODER, "htmlspecialchars", C.HTML_TEXT, safe=False),
            K("<script>", C.JS_CODE)],
           D.CONTEXTUAL_ENCODING, "HTML-encoding does not neutralize a JS-string context inside <script>.",
           "Use a JS-string/JSON encoder for script context, not htmlspecialchars.", tags=["wrong_context"],
           code="<script>var q = \"<?php echo htmlspecialchars($_GET['q']); ?>\";</script>"),
        # 6. Safe: correct context encoding (JSON-encoded into script)
        _c("adv-safe-json-script", "php", F.SAFE, False, C.JS_CODE,
           [S("$_GET", C.HTML_TEXT), FlowNode(R.ENCODER, "json_encode", C.JS_CODE, safe=True),
            K("<script>", C.JS_CODE, safe=True)],
           D.CONTEXTUAL_ENCODING, "", "", tags=["hard_negative"],
           code="<script>var q = <?php echo json_encode($_GET['q']); ?>;</script>"),
        # 7. Vulnerable: setAttribute on an event handler
        _c("adv-setattr-onclick", "javascript", F.DOM, True, C.DOM_ATTR,
           [S("location.search"), K("setAttribute(onclick)", C.JS_CODE)],
           D.NONE, "setAttribute on an on* handler injects executable JS.",
           "Never set event-handler attributes from untrusted data.", tags=["event_handler"],
           code="const v = new URLSearchParams(location.search).get('x');\nel.setAttribute('onclick', v);"),
        # 8. Safe: setAttribute on a benign attribute
        _c("adv-safe-setattr-title", "javascript", F.SAFE, False, C.DOM_ATTR,
           [S("location.search"), K("setAttribute(title)", C.DOM_ATTR, safe=True)],
           D.SAFE_DOM_API, "", "", tags=["hard_negative"],
           code="const v = new URLSearchParams(location.search).get('x');\nel.setAttribute('title', v);"),
    ]
    return cases


if __name__ == "__main__":
    cs = generate()
    print(f"{len(cs)} adversarial cases; vuln={sum(c.vulnerable for c in cs)} "
          f"hard_neg={sum('hard_negative' in c.tags for c in cs)}")
