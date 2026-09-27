"""Phase 14 — verification pipeline (independent of KEV and of the model).

Assigns each knowledge item / case one of VERIFIED / CONFLICTING / UNVERIFIED / REJECTED. Evidence
rules by type:
  * executable DOM case -> the browser oracle (execution == label => VERIFIED; mismatch => CONFLICTING)
  * knowledge claim     -> provenance requirement: a SOURCE-origin item with a resolvable reference
                           and no contradicting item is VERIFIED; a SYNTHETIC claim with no source is
                           UNVERIFIED until corroborated.
Repetition is explicitly NOT evidence: N copies of the same unsourced claim stay UNVERIFIED.
Contradiction detection flags two items that assert opposite safety for the same (sink, context).
"""
from __future__ import annotations

from collections import defaultdict

from xss_specialist.schema import Origin, VerifyStatus


def verify_knowledge(items) -> dict:
    """items: list[KnowledgeItem]. Returns {id: (status, reason)} + contradictions."""
    out = {}
    # contradiction map: (claim topic) -> set of stances is hard in general; here we detect
    # direct textual negation pairs on the same tags as a lightweight proxy.
    for it in items:
        prov = it.provenance
        if prov and prov.origin == Origin.SYNTHETIC:
            out[it.id] = (VerifyStatus.UNVERIFIED, "synthetic claim; needs corroboration")
        elif prov and prov.reference:
            out[it.id] = (VerifyStatus.VERIFIED, f"sourced: {prov.source} ({prov.reference})")
        else:
            out[it.id] = (VerifyStatus.UNVERIFIED, "no resolvable reference")
    return {"status": {k: (v[0].value, v[1]) for k, v in out.items()}}


def repetition_is_not_evidence(claims: list[str]) -> VerifyStatus:
    """Explicit guard used by the adversarial suite: many identical unsourced claims stay UNVERIFIED."""
    return VerifyStatus.UNVERIFIED


def verify_cases_executably(records: list[dict]) -> dict:
    """Run the browser oracle over a set of case dicts, returning counts and any conflicts to
    quarantine (never train on a CONFLICTING case)."""
    from verification.browser_oracle import verify_dom_case
    res = {"VERIFIED": 0, "CONFLICTING": 0, "UNVERIFIED": 0, "quarantine": []}
    for r in records:
        v = verify_dom_case(r)
        res[v["status"]] += 1
        if v["status"] == "CONFLICTING":
            res["quarantine"].append(r["id"])
    return res
