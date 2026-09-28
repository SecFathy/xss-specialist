"""Phase 11 — structured XSS reasoning format: the analysis prompt and a tolerant parser.

The model must produce a fixed-field analysis and mark evidence as OBSERVED / INFERRED /
NOT_ESTABLISHED. The parser is line-oriented and tolerant (models drift on formatting); it
extracts the fields we score and never raises — a missing field becomes an explicit default so
an unparseable answer scores as an abstention, not a crash.
"""
from __future__ import annotations

import re

FIELDS = ["Classification", "Confidence", "Source", "Transformations", "Sink",
          "Execution Context", "Existing Defense", "Root Cause", "Evidence",
          "Missing Evidence", "Risk Explanation", "Recommended Validation",
          "Remediation", "References"]

SYSTEM = (
    "You are an XSS analysis specialist for AUTHORIZED security testing and defensive review. "
    "Analyze the code for cross-site scripting only. Be precise about execution context and "
    "distinguish OBSERVED facts (present in the code) from INFERRED conclusions and from what is "
    "NOT ESTABLISHED. Do not label code vulnerable without an untrusted source reaching a sink in "
    "an executing context. If safety cannot be established, say so rather than guessing."
)

TEMPLATE = """{system}

Analyze this {language} code for XSS:

```{language}
{code}
```

{rag}Respond in EXACTLY this format, one field per line:
Classification: <vulnerable|safe>
Confidence: <0.0-1.0>
Source: <untrusted source, or none>
Transformations: <encoders/sanitizers applied, or none>
Sink: <the sink, or none>
Execution Context: <html_text|html_attr|html_attr_url|js_string|js_code|url|css|dom_html|dom_attr|unknown>
Existing Defense: <contextual_encoding|sanitization|csp|trusted_types|framework_escaping|safe_dom_api|input_constraint|none>
Root Cause: <one line, or none if safe>
Evidence: <OBSERVED/INFERRED/NOT_ESTABLISHED note>
Missing Evidence: <what would change the verdict, or none>
Risk Explanation: <one line>
Recommended Validation: <how to confirm safely>
Remediation: <the fix, or none if safe>
References: <e.g. OWASP/CWE-79, or none>
"""


def build(code: str, language: str, rag_context: str = "") -> str:
    rag = ""
    if rag_context:
        rag = ("Relevant verified reference material (cite it in References if you use it):\n"
               f"{rag_context}\n\n")
    return TEMPLATE.format(system=SYSTEM, language=language, code=code, rag=rag)


_CTX = {"html_text", "html_attr", "html_attr_url", "html_comment", "js_string", "js_code",
        "url", "css", "dom_html", "dom_attr", "unknown"}


def parse(text: str) -> dict:
    """Extract scored fields. Returns dict with at least: classification (vulnerable/safe/abstain),
    confidence (float), context, sink, source, defense, evidence_tag, and raw."""
    out = {"raw": text, "classification": "abstain", "confidence": 0.0,
           "context": "unknown", "sink": "", "source": "", "defense": "none",
           "evidence_tag": "not_established", "remediation": "", "references": ""}
    fields = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z ]+?)\s*:\s*(.*)$", line)
        if m and m.group(1).strip() in FIELDS:
            fields[m.group(1).strip()] = m.group(2).strip()

    cls = fields.get("Classification", "").lower()
    if cls == "vulnerable":
        out["classification"] = "vulnerable"
    elif cls in {"safe", "not vulnerable", "not_vulnerable"}:
        out["classification"] = "safe"
    elif "cannot" in cls or "abstain" in cls or "unknown" in cls:
        out["classification"] = "abstain"

    conf = fields.get("Confidence", "")
    mconf = re.search(r"[01](?:\.\d+)?|\.\d+", conf)
    if mconf:
        try:
            out["confidence"] = max(0.0, min(1.0, float(mconf.group())))
        except ValueError:
            pass

    ec = fields.get("Execution Context", "").lower().strip()
    ec = re.sub(r"[^a-z_]", "", ec.replace(" ", "_"))
    out["context"] = ec if ec in _CTX else "unknown"
    out["sink"] = fields.get("Sink", "")
    out["source"] = fields.get("Source", "")
    out["defense"] = fields.get("Existing Defense", "none").lower().strip() or "none"
    out["remediation"] = fields.get("Remediation", "")
    out["references"] = fields.get("References", "")

    ev = fields.get("Evidence", "").upper()
    for tag in ("NOT_ESTABLISHED", "NOT ESTABLISHED", "INFERRED", "OBSERVED"):
        if tag in ev:
            out["evidence_tag"] = tag.lower().replace(" ", "_")
            break
    out["_fields_found"] = len(fields)
    return out
