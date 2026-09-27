"""Exact sanitizer-identity verification (near-miss protection).

The research showed sanitizer/entity-binding leakage is unsolved: a name resembling a known-safe API
must NEVER inherit its safety. So a sanitizer observed in code/response is assigned a security
property only when its EXACT identity is supported by verified local/RAG evidence. Otherwise it is
UNKNOWN and contributes no safety — the finding relies on the browser oracle instead.
"""
from __future__ import annotations

from dataclasses import dataclass

# Exact known-safe identities, keyed by exact token, backed by verified corpus knowledge ids.
KNOWN_SAFE = {
    "DOMPurify.sanitize": "k-015",
    "textContent": "k-009",
    "innerText": "k-009",
    "htmlspecialchars": "k-006",
    "json_encode": "k-023",
    "encodeURIComponent": "k-027",
    "insertAdjacentText": "k-030",
}


@dataclass
class SanitizerVerdict:
    observed_name: str
    exact_match: bool
    status: str            # "VERIFIED_SAFE" | "UNKNOWN"
    evidence_id: str = ""
    nearest_known: str = ""
    note: str = ""


def _edit1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    # crude edit-distance<=1 check
    if a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    diff = 0
    while i < len(short) and j < len(long):
        if short[i] != long[j]:
            diff += 1
            j += 1
            if diff > 1:
                return False
        else:
            i += 1
            j += 1
    return True


def verify_identity(observed_name: str, retriever=None) -> SanitizerVerdict:
    """Exact-match only. A near-miss (edit distance ~1 to a known name) is explicitly flagged and
    stays UNKNOWN — it does NOT inherit the neighbour's safety."""
    name = (observed_name or "").strip()
    if name in KNOWN_SAFE:
        return SanitizerVerdict(name, True, "VERIFIED_SAFE", evidence_id=KNOWN_SAFE[name],
                                note="exact identity matches verified safe API")
    # find a near-miss neighbour purely to WARN (never to grant safety)
    nearest = ""
    for known in KNOWN_SAFE:
        kcore = known.split(".")[-1]
        ncore = name.split(".")[-1]
        if _edit1(kcore, ncore) or _edit1(known, name):
            nearest = known
            break
    note = ("near-miss to a known-safe name; identity NOT established, safety NOT inherited"
            if nearest else "unrecognized sanitizer; no verified evidence")
    return SanitizerVerdict(name, False, "UNKNOWN", nearest_known=nearest, note=note)


if __name__ == "__main__":
    for n in ["DOMPurify.sanitize", "DOMPvrify.sanitize", "sanitizeHtml", "textContent", "totallyFake"]:
        v = verify_identity(n)
        print(f"{n:22s} -> {v.status:12s} exact={v.exact_match} near={v.nearest_known!r} | {v.note}")
