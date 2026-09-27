"""Phase 2 — seed XSS knowledge corpus.

Authored, provenance-bearing, factual claims about XSS. Every item is Origin.SOURCE
(distilled from authoritative public references: OWASP Cheat Sheets, CWE, MDN, W3C/WHATWG,
framework security docs). Claims are stable reasoning facts, not volatile advisories —
volatile items (specific CVEs, version-specific advisories) are marked volatile=True and
routed to RAG rather than weights (Phase 13).

This module is the single source of the corpus so it versions and hashes deterministically.
Run `python -m knowledge.seed_corpus > data/verified/corpus.jsonl` (the CLI does this).
"""
from __future__ import annotations

import json
import sys

from xss_specialist.schema import (
    Context as C, Defense as D, Family as F, KnowledgeItem, Origin, Provenance,
    VerifyStatus as V,
)

_OWASP = lambda title, ref: Provenance(source="OWASP", title=title, reference=ref,
                                        license="CC-BY-SA", origin=Origin.SOURCE)
_CWE = lambda title, ref: Provenance(source="CWE", title=title, reference=ref, origin=Origin.SOURCE)
_MDN = lambda title, ref: Provenance(source="MDN", title=title, reference=ref,
                                      license="CC-BY-SA", origin=Origin.SOURCE)
_W3C = lambda title, ref: Provenance(source="W3C", title=title, reference=ref, origin=Origin.SOURCE)
_FW = lambda src, title, ref: Provenance(source=src, title=title, reference=ref, origin=Origin.SOURCE)


def _k(i, claim, *, fams=(), ctxs=(), defs=(), prov, conf=0.9, volatile=False, tags=()):
    return KnowledgeItem(
        id=f"k-{i:03d}", claim=claim,
        families=list(fams), contexts=list(ctxs), defenses=list(defs),
        provenance=prov, verify_status=V.VERIFIED, confidence=conf,
        volatile=volatile, tags=list(tags),
    )


def build() -> list[KnowledgeItem]:
    P_XSS = _OWASP("Cross Site Scripting Prevention Cheat Sheet",
                   "cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
    P_DOM = _OWASP("DOM based XSS Prevention Cheat Sheet",
                   "cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html")
    P_CSP = _OWASP("Content Security Policy Cheat Sheet",
                   "cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html")
    items = [
        _k(1, "XSS occurs when untrusted input reaches an output context and is interpreted "
              "as active content (script) rather than inert data.", fams=[F.REFLECTED, F.STORED, F.DOM],
           prov=_CWE("CWE-79: Improper Neutralization of Input During Web Page Generation",
                     "cwe.mitre.org/data/definitions/79.html")),
        _k(2, "Reflected XSS occurs when the injected script is echoed back in the immediate HTTP "
              "response to a request and is not stored on the server.", fams=[F.REFLECTED], prov=P_XSS),
        _k(3, "Stored XSS occurs when the injected payload is persisted (database, file, log) and "
              "later served to other users.", fams=[F.STORED], prov=P_XSS),
        _k(4, "DOM-based XSS occurs entirely client-side: a script reads a source (e.g. location.hash) "
              "and writes it to a dangerous sink without the server rendering the payload.",
           fams=[F.DOM], ctxs=[C.DOM_HTML], prov=P_DOM),
        _k(5, "The correct output encoding is determined by the context the data lands in; HTML-entity "
              "encoding that stops HTML-text injection does not stop injection inside a JavaScript string.",
           ctxs=[C.HTML_TEXT, C.JS_STRING], defs=[D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(6, "In HTML text context, encoding <, >, &, \", ' to entities prevents breaking out of text "
              "into markup.", ctxs=[C.HTML_TEXT], defs=[D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(7, "In an HTML attribute value, unquoted attributes are dangerous because whitespace or "
              "event-handler attributes can be injected without needing a quote character.",
           ctxs=[C.HTML_ATTR], defs=[D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(8, "element.innerHTML and outerHTML parse their string as HTML, so assigning untrusted data "
              "to them is a DOM XSS sink.", ctxs=[C.DOM_HTML], fams=[F.DOM], prov=P_DOM),
        _k(9, "element.textContent and element.innerText treat their value as text, not markup, so they "
              "are safe DOM sinks for untrusted data.", ctxs=[C.DOM_HTML], defs=[D.SAFE_DOM_API], prov=P_DOM),
        _k(10, "document.write and document.writeln parse their argument as HTML and are DOM XSS sinks.",
           ctxs=[C.DOM_HTML], fams=[F.DOM], prov=P_DOM),
        _k(11, "eval, Function, setTimeout/setInterval with a string argument, and similar APIs execute "
               "their string as JavaScript and are code-execution sinks.", ctxs=[C.JS_CODE], fams=[F.DOM], prov=P_DOM),
        _k(12, "Setting an anchor's href or an iframe's src to a javascript: URL executes script when "
               "activated; URL-scheme allow-listing (http/https only) prevents this.",
           ctxs=[C.HTML_ATTR_URL, C.URL], defs=[D.INPUT_CONSTRAINT], prov=P_XSS),
        _k(13, "location.hash, location.search, document.referrer, window.name and postMessage data are "
               "attacker-controllable DOM sources.", fams=[F.DOM], ctxs=[C.URL], prov=P_DOM),
        _k(14, "Mutation XSS (mXSS) arises when the browser's HTML parser re-serializes and re-parses "
               "markup so that a payload considered safe by a sanitizer becomes active after mutation.",
           fams=[F.MUTATION], prov=_OWASP("XSS Filter Evasion Cheat Sheet",
               "cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html")),
        _k(15, "A robust defense against DOM sinks that require HTML is to sanitize with a well-maintained "
               "library (e.g. DOMPurify) configured for the target context, rather than hand-rolled regexes.",
           defs=[D.SANITIZATION], fams=[F.DOM], prov=_FW("DOMPurify", "DOMPurify README",
               "github.com/cure53/DOMPurify")),
        _k(16, "Blocklist / regex filtering of tags or keywords is unreliable against XSS because of the "
               "many equivalent encodings and parser quirks; allow-list and contextual encoding are preferred.",
           defs=[D.SANITIZATION, D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(17, "Content Security Policy can mitigate XSS impact by restricting script sources; a strict "
               "nonce- or hash-based CSP without 'unsafe-inline' blocks injected inline scripts.",
           defs=[D.CSP], prov=P_CSP),
        _k(18, "'unsafe-inline' in a CSP script-src negates most of CSP's XSS protection because it "
               "re-permits inline scripts and event handlers.", defs=[D.CSP], prov=P_CSP),
        _k(19, "Trusted Types (require-trusted-types-for 'script') forces DOM injection sinks to receive a "
               "typed, policy-vetted value, eliminating most DOM XSS sink misuse.",
           defs=[D.TRUSTED_TYPES], fams=[F.DOM], prov=_W3C("Trusted Types",
               "w3c.github.io/trusted-types/dist/spec/")),
        _k(20, "React escapes string children by default, so {userInput} rendered as text is safe; the "
               "danger is dangerouslySetInnerHTML, which bypasses that escaping.",
           fams=[F.TEMPLATE], defs=[D.FRAMEWORK_ESCAPING], prov=_FW("React", "React docs: dangerouslySetInnerHTML",
               "react.dev/reference/react-dom/components/common")),
        _k(21, "Angular sanitizes interpolated and bound values by default; bypassSecurityTrustHtml and "
               "similar APIs disable that protection and reintroduce XSS risk.",
           fams=[F.TEMPLATE], defs=[D.FRAMEWORK_ESCAPING], prov=_FW("Angular", "Angular security guide",
               "angular.dev/best-practices/security")),
        _k(22, "Vue's v-html directive renders raw HTML and bypasses Vue's default text escaping, so it is "
               "a template XSS sink for untrusted data.", fams=[F.TEMPLATE], prov=_FW("Vue", "Vue security guide",
               "vuejs.org/guide/best-practices/security")),
        _k(23, "In a JavaScript string literal context, HTML-entity encoding is ineffective; the value must "
               "be JavaScript-string escaped (\\xHH / \\uHHHH) or, better, passed as data via JSON.",
           ctxs=[C.JS_STRING], defs=[D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(24, "Reflecting untrusted data inside a <script> block is dangerous even when HTML-encoded, "
               "because the HTML parser does not decode entities inside script content.",
           ctxs=[C.JS_CODE], prov=P_DOM),
        _k(25, "For URL context, values placed into a query string or path must be URL-encoded, and the "
               "scheme must be validated to prevent javascript:/data: execution.",
           ctxs=[C.URL, C.HTML_ATTR_URL], defs=[D.CONTEXTUAL_ENCODING, D.INPUT_CONSTRAINT], prov=P_XSS),
        _k(26, "Server-side reflection of a request parameter into HTML without encoding is the canonical "
               "reflected XSS root cause.", fams=[F.REFLECTED], ctxs=[C.HTML_TEXT], prov=P_XSS),
        _k(27, "encodeURIComponent protects data placed in a URL query value but does NOT make it safe to "
               "place in HTML or JavaScript contexts.", ctxs=[C.URL], defs=[D.CONTEXTUAL_ENCODING], prov=P_DOM),
        _k(28, "setAttribute for a non-event, non-URL attribute (e.g. class, title) treats the value as text "
               "and does not execute script, unlike setting on* handler attributes.",
           ctxs=[C.DOM_ATTR], defs=[D.SAFE_DOM_API], prov=P_DOM),
        _k(29, "Assigning to an element's on* event-handler property or attribute with untrusted data is a "
               "code-execution sink.", ctxs=[C.DOM_ATTR, C.JS_CODE], fams=[F.DOM], prov=P_DOM),
        _k(30, "insertAdjacentHTML parses HTML like innerHTML and is a DOM XSS sink; insertAdjacentText is "
               "the safe counterpart.", ctxs=[C.DOM_HTML], fams=[F.DOM], prov=P_DOM),
        _k(31, "jQuery's $(html) / .html() / .append(html) parse and insert HTML, making them DOM XSS sinks "
               "when passed untrusted strings.", ctxs=[C.DOM_HTML], fams=[F.DOM],
           prov=_FW("jQuery", "jQuery API: jQuery( html )", "api.jquery.com/jQuery/")),
        _k(32, "A correct fix generally combines contextual output encoding at the sink with input validation "
               "as defense in depth, not input validation alone.", defs=[D.CONTEXTUAL_ENCODING, D.INPUT_CONSTRAINT],
           prov=P_XSS),
        _k(33, "template literals or DOM text APIs that never parse HTML are structurally safe; the safest "
               "remediation removes the HTML-parsing sink rather than trying to clean the input.",
           defs=[D.ARCHITECTURAL, D.SAFE_DOM_API], prov=P_DOM),
        _k(34, "Double-encoding and mixed-context reflection (data flowing through two contexts, e.g. HTML "
               "attribute then JavaScript) require encoding for the innermost executing context.",
           ctxs=[C.HTML_ATTR, C.JS_STRING], defs=[D.CONTEXTUAL_ENCODING], prov=P_XSS),
        _k(35, "A value that is HTML-encoded then inserted with textContent is doubly safe but may display "
               "literal entities; encoding must match the sink to be both safe and correct.",
           ctxs=[C.HTML_TEXT, C.DOM_HTML], defs=[D.CONTEXTUAL_ENCODING, D.SAFE_DOM_API], prov=P_XSS),
        # Volatile example: routed to RAG, never to weights.
        _k(36, "Specific published CVE advisories for XSS in named product versions are volatile facts that "
               "should be retrieved, not memorized into model weights.", volatile=True,
           prov=_CWE("KEV/CVE advisories are time-varying", "www.cve.org"), conf=0.7,
           tags=["volatile", "advisory"]),
    ]
    return items


def main():
    for it in build():
        sys.stdout.write(json.dumps(it.to_dict(), ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
