"""Finding state machine + correlation.

Each candidate ends in exactly one state:
  CONFIRMED      — browser oracle observed execution (window.__X[marker] set). Authoritative.
  LIKELY         — strong source/context/sink + reflection evidence, but no execution confirmation.
  INCONCLUSIVE   — reflected but context/oracle ambiguous, or blocked before completion.
  NOT_VULNERABLE — reflected-and-encoded or not reflected, no execution, no strong path.

A finding is NEVER upgraded to CONFIRMED from model confidence. Only the oracle upgrades it.
Sanitizer identity contributes to NOT_VULNERABLE only when VERIFIED_SAFE; UNKNOWN/near-miss never
downgrades a positive.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CONFIRMED, LIKELY, INCONCLUSIVE, NOT_VULNERABLE = \
    "CONFIRMED", "LIKELY", "INCONCLUSIVE", "NOT_VULNERABLE"


@dataclass
class Finding:
    finding_id: str
    status: str
    xss_class: str
    url: str
    method: str
    parameter: str
    source: str = ""
    transformations: str = ""
    sink: str = ""
    context: str = ""
    existing_sanitizer: str = ""
    sanitizer_verification: str = ""     # VERIFIED_SAFE | UNKNOWN | near-miss note
    browser_result: str = ""             # executed / not-executed / blocked
    reproduction: dict = field(default_factory=dict)
    confidence: float = 0.0
    impact: str = ""
    remediation: str = ""
    evidence_refs: list = field(default_factory=list)


def correlate(candidate: dict, marker_ev: dict, exec_evs: list, sanitizer_verdict,
              fid: str) -> Finding:
    """Fold the marker probe + execution probes + sanitizer identity into one finding."""
    reflected = bool(marker_ev.get("reflected_html") or marker_ev.get("reflected_dom"))
    executed = any(e.get("executed") for e in exec_evs)
    # a harmless marker reflecting is NOT evidence of XSS; the dangerous payload must survive UNENCODED
    raw_live = any(e.get("raw_reflected") for e in exec_evs)
    blocked = marker_ev.get("blocked") or (bool(exec_evs) and all(e.get("blocked") for e in exec_evs))
    ctx = candidate.get("context", "unknown")
    dom = ctx in ("dom_html", "dom_attr")
    xss_class = "dom" if dom else ("reflected" if reflected else "unknown")

    san_status = getattr(sanitizer_verdict, "status", "") if sanitizer_verdict else ""
    san_name = getattr(sanitizer_verdict, "observed_name", "") if sanitizer_verdict else ""
    san_note = getattr(sanitizer_verdict, "note", "") if sanitizer_verdict else ""

    if executed:
        status, conf = CONFIRMED, 0.99          # oracle observed execution — authoritative
    elif raw_live and san_status != "VERIFIED_SAFE":
        # dangerous payload survived unencoded into a live context, no execution confirmation yet
        status, conf = LIKELY, 0.6
    elif blocked:
        status, conf = INCONCLUSIVE, 0.2
    elif reflected and not raw_live:
        # input echoes but dangerous chars are encoded / not present -> not exploitable here
        status, conf = NOT_VULNERABLE, 0.12
    else:
        status, conf = NOT_VULNERABLE, 0.1

    winning = next((e for e in exec_evs if e.get("executed")), marker_ev)
    return Finding(
        finding_id=fid, status=status, xss_class=xss_class,
        url=candidate["url"], method=candidate.get("method", "GET"),
        parameter=candidate.get("param", "q"),
        source=candidate.get("source_name", candidate.get("input_type", "")),
        sink=candidate.get("sink", ""), context=ctx,
        existing_sanitizer=san_name,
        sanitizer_verification=f"{san_status}: {san_note}" if san_status else "none observed",
        browser_result="executed" if executed else ("blocked" if blocked else "not-executed"),
        reproduction={"requested_url": winning.get("requested_url"),
                      "final_url": winning.get("final_url"), "status": winning.get("status"),
                      "marker": winning.get("marker"), "probe_note": winning.get("probe_note"),
                      "console": winning.get("console", [])[:3]},
        confidence=conf,
        impact=("Executable script in the page origin: session/DOM access, action-on-behalf."
                if status == CONFIRMED else
                "Untrusted input reaches a live context without verified-safe encoding."
                if status == LIKELY else "No executable path established."),
        remediation="Contextual output encoding at the sink; use a verified-safe sanitizer "
                    "(exact known API) or a safe DOM API (textContent).",
        evidence_refs=[getattr(sanitizer_verdict, "evidence_id", "")] if getattr(sanitizer_verdict, "evidence_id", "") else [],
    )
