"""Phase 5 — near-miss / entity-binding benchmark.

Prior continual-learning work found lexical near-miss entities cause knowledge leakage: a fact
learned about entity A gets mis-attributed to a look-alike A'. Here the anchor entity is a
KNOWN-SAFE sanitizer, `DOMPurify.sanitize`. We perturb the name with controlled single edits and
build a case that pipes untrusted data through the *perturbed* (hence unknown-safety) sanitizer
into innerHTML.

Ground truth: only the exact anchor is an established safe sanitizer. A case using a near-miss
name (e.g. `DOMPurify.sanitize`) is NOT establishably safe, so a correct model must not call it
safe. Leakage rate = fraction of perturbed cases the model labels safe (knowledge transferred
across the entity boundary). The anchor (unperturbed) case is the paired control.

Perturbation metadata (edit type, edit distance, position, shared prefix/suffix length) is kept
on each case so leakage can be sliced by how close the near-miss is.
"""
from __future__ import annotations

from xss_specialist.repro import stream
from xss_specialist.schema import (
    Context as C, Defense as D, Family as F, FlowNode, Origin, Provenance, Role as R, XSSCase,
)

ANCHOR = "DOMPurify"
_SYN = Provenance(source="template", title="near-miss entity case", reference="benchmarks/nearmiss.py",
                  origin=Origin.SYNTHETIC)

_VOWELS = "aeiou"


def _perturb(name: str, rng) -> list[dict]:
    """All controlled single-edit perturbations of `name`, with metadata."""
    out = []
    n = len(name)
    # substitution (incl. vowel/consonant), at each position
    for i, ch in enumerate(name):
        repl = "y" if ch == "i" else ("i" if ch == "y" else ("v" if ch == "u" else "x"))
        if repl == ch:
            repl = "z"
        w = name[:i] + repl + name[i + 1:]
        out.append(dict(name=w, edit="substitution", pos=i, dist=1))
    # deletion
    for i in range(n):
        out.append(dict(name=name[:i] + name[i + 1:], edit="deletion", pos=i, dist=1))
    # insertion
    for i in range(n + 1):
        out.append(dict(name=name[:i] + "x" + name[i:], edit="insertion", pos=i, dist=1))
    # transposition of adjacent chars
    for i in range(n - 1):
        if name[i] != name[i + 1]:
            out.append(dict(name=name[:i] + name[i + 1] + name[i] + name[i + 2:],
                            edit="transposition", pos=i, dist=1))
    # dedup, drop identity
    seen, uniq = set(), []
    for p in out:
        if p["name"] != name and p["name"] not in seen:
            seen.add(p["name"]); uniq.append(p)
    return uniq


def _shared(a: str, b: str) -> tuple[int, int]:
    p = 0
    for x, y in zip(a, b):
        if x == y: p += 1
        else: break
    s = 0
    for x, y in zip(reversed(a), reversed(b)):
        if x == y: s += 1
        else: break
    return p, s


def _case(entity: str, is_anchor: bool, meta: dict, idx: int) -> XSSCase:
    code = (f"import {ANCHOR} from 'dompurify';\n"
            f"const clean = {entity}.sanitize(location.hash.slice(1));\n"
            f"el.innerHTML = clean;")
    # anchor: sanitizer is known-safe -> SAFE; near-miss: unknown -> vulnerable (not establishable safe)
    vulnerable = not is_anchor
    flow = [
        FlowNode(R.SOURCE, "location.hash", C.URL),
        FlowNode(R.SANITIZER, f"{entity}.sanitize", C.DOM_HTML, safe=True if is_anchor else None),
        FlowNode(R.SINK, "innerHTML", C.DOM_HTML),
    ]
    pfx, sfx = _shared(entity, ANCHOR)
    return XSSCase(
        id=("nm-anchor" if is_anchor else f"nm-{meta['edit']}-{meta['pos']}") + f"-{idx:03d}",
        code=code, language="javascript",
        family=F.SAFE if is_anchor else F.DOM, vulnerable=vulnerable, context=C.DOM_HTML,
        flow=flow, existing_defense=D.SANITIZATION if is_anchor else D.NONE,
        root_cause="" if is_anchor else f"'{entity}.sanitize' is not the known-safe {ANCHOR} API; safety not established.",
        remediation="" if is_anchor else f"Use the exact {ANCHOR}.sanitize API, or textContent.",
        tags=["nearmiss", "anchor" if is_anchor else "perturbed",
              meta.get("edit", "anchor")], provenance=_SYN,
    )


def generate(max_perturbations: int = 40) -> list[XSSCase]:
    rng = stream("nearmiss")
    cases = [_case(ANCHOR, True, {"edit": "anchor", "pos": -1, "dist": 0}, 0)]
    perts = _perturb(ANCHOR, rng)
    # attach shared-affix metadata, then take a deterministic sample
    for p in perts:
        p["prefix"], p["suffix"] = _shared(p["name"], ANCHOR)
    perts = sorted(perts, key=lambda p: (p["edit"], p["pos"]))[:max_perturbations]
    for i, p in enumerate(perts):
        cases.append(_case(p["name"], False, p, i))
    return cases


if __name__ == "__main__":
    cs = generate()
    print(f"{len(cs)} near-miss cases (1 anchor + {len(cs)-1} perturbed)")
    for c in cs[:4]:
        print(c.id, "| vuln=", c.vulnerable, "|", c.code.splitlines()[1])
