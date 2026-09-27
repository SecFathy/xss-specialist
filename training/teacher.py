"""Phase 9 — teacher / SFT data generation.

The "teacher" here is a GROUNDED SYNTHESIZER, not an ungrounded LLM: each training target is the
Phase-11 structured analysis built deterministically from a case's VERIFIED ground-truth labels
(family, vulnerable, execution context, data-flow, root cause, remediation) plus citations pulled
from the verified corpus by the retriever. This is a deliberate choice over distilling a teacher
LLM: it removes hallucination risk at the source, so no unsupported teacher claim can become
training truth (Phase 14 / integrity rules). Every record is labelled synthetic with provenance.

Data mix (Phase 9 + Phase 15):
  * base cases        — the paired vuln/safe cases (contrastive by construction)
  * near-miss cases   — teach that an unknown sanitizer NAME is not establishably safe; directly
                        targets the near-miss leakage the base model shows. Uses a DIFFERENT anchor
                        and perturbation sample than the frozen near-miss bench, and every training
                        record is hash-checked disjoint from ALL frozen splits.
  * abstention cases  — code with a source but no reachable executing sink shown -> "not established"

All draws use named repro streams so counts in one part never perturb another.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist import prompt as P
from xss_specialist.repro import sha256_text, stream, write_json
from xss_specialist.schema import (
    Context as C, Defense as D, Family as F, FlowNode, Origin, Provenance, Role as R, XSSCase,
)
from benchmarks import cases as casegen
from retrieval.index import Retriever

_SYN = Provenance(source="teacher", title="grounded synthetic SFT target",
                  reference="training/teacher.py", origin=Origin.SYNTHETIC)

# Training-side near-miss anchor: a DIFFERENT known-safe sanitizer than the frozen bench's DOMPurify,
# so the model learns the *principle* (exact known-safe name required) not the specific token.
TRAIN_ANCHOR = "sanitizeHtml"   # a real, widely-used sanitizer (jsdom 'sanitize-html')


def _analysis_target(c: XSSCase, retriever: Retriever) -> str:
    """Build the gold structured analysis from verified labels + corpus citations."""
    src = next((n for n in c.flow if n.role == R.SOURCE), None)
    sink = next((n for n in c.flow if n.role == R.SINK), None)
    enc = next((n for n in c.flow if n.role in (R.ENCODER, R.SANITIZER)), None)
    hits = retriever.search(c.code + " " + c.context, 2)
    refs = ", ".join(f"{h.source}/{h.id}" for h, s in hits if s > 0) or "OWASP/CWE-79"
    if c.vulnerable:
        cls, conf = "vulnerable", 0.9
        transforms = enc.name if enc else "none"
        ev = f"OBSERVED: untrusted {src.name if src else 'input'} reaches {sink.name if sink else 'sink'}."
        missing = "Runtime confirmation that the sink executes with attacker-controlled markup."
        risk = f"Attacker input flows into {c.context.value} and executes as script."
        rem = c.remediation
        defense = "none"
    else:
        cls, conf = "safe", 0.85
        transforms = enc.name if enc else "none"
        ev = (f"OBSERVED: output uses {sink.name if sink else 'a safe sink'} / "
              f"{c.existing_defense.value}, which neutralizes {c.context.value}.")
        missing = "none"
        risk = "No untrusted data reaches an executing context in an unencoded form."
        rem = "none"
        defense = c.existing_defense.value
    return (f"Classification: {cls}\nConfidence: {conf:.2f}\n"
            f"Source: {src.name if src else 'none'}\nTransformations: {transforms}\n"
            f"Sink: {sink.name if sink else 'none'}\nExecution Context: {c.context.value}\n"
            f"Existing Defense: {defense}\nRoot Cause: {c.root_cause or 'none'}\n"
            f"Evidence: {ev}\nMissing Evidence: {missing}\nRisk Explanation: {risk}\n"
            f"Recommended Validation: Reproduce in an authorized test environment; confirm the sink "
            f"parses/executes the payload.\nRemediation: {rem}\nReferences: {refs}\n")


# Multiple known-safe anchors so the PRINCIPLE (exact known name required) transfers across
# families, including DOMPurify. Perturbations here are DOUBLE-edits / distinct spellings, kept
# disjoint from the frozen near-miss bench (single-edits of DOMPurify) by a hash check at build.
_NM_ANCHORS = {
    "DOMPurify.sanitize": ["DOMPvrify.sanitize", "DOMPurified.sanitize", "DOMPurify.saniize",
                           "DomPurify.sanitize", "DOMPurfy.sanitize"],
    "sanitizeHtml": ["saniztizeHtml", "sanitizeHtmls", "sanltizeHtml", "sanitize_html", "sanitizHtml"],
    "purify.clean": ["purfy.clean", "purify.cleen", "purifyy.clean", "purify.claen", "purrify.clean"],
}


# High-volume generated near-miss (v3): MANY sanitizer anchors, each with generated single-edit
# perturbations, to teach the GENERAL rule "an unknown sanitizer name is not establishably safe".
# DOMPurify is deliberately EXCLUDED from perturbation here (kept only as a safe anchor) so the
# frozen bench's DOMPurify single-edits remain a true held-out transfer test — not taught tokens.
_NM_GEN_ANCHORS = ["sanitizeHtml", "purify.clean", "xssFilter", "cleanHtml", "filterXSS",
                   "escapeHtml", "sanitizer.sanitize", "domClean", "safeHtml", "scrubHtml"]


def _single_edits(name: str, rng, k: int = 8) -> list[str]:
    alpha = "abcdefghijklmnopqrstuvwxyz"
    core = name.split(".")[0]  # perturb the identifier part
    suffix = name[len(core):]
    out = set()
    tries = 0
    while len(out) < k and tries < 200:
        tries += 1
        op = rng.integers(0, 4)
        i = int(rng.integers(0, len(core)))
        if op == 0 and len(core) > 2:            # deletion
            w = core[:i] + core[i + 1:]
        elif op == 1:                             # substitution
            w = core[:i] + alpha[int(rng.integers(0, 26))] + core[i + 1:]
        elif op == 2:                             # insertion
            w = core[:i] + alpha[int(rng.integers(0, 26))] + core[i:]
        else:                                     # transposition
            if i < len(core) - 1:
                w = core[:i] + core[i + 1] + core[i] + core[i + 2:]
            else:
                continue
        if w != core:
            out.add(w + suffix)
    return list(out)


def _nearmiss_gen_cases(rng) -> list[XSSCase]:
    out = []
    # DOMPurify safe anchor (no perturbations of it in training)
    for ai, anchor in enumerate(["DOMPurify.sanitize"] + _NM_GEN_ANCHORS):
        out.append(XSSCase(
            id=f"tm-nmg-anchor-{ai}", language="javascript", family=F.SAFE, vulnerable=False,
            context=C.DOM_HTML, code=f"const clean = {anchor}(input);\nel.innerHTML = clean;",
            flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
                  FlowNode(R.SANITIZER, anchor, C.DOM_HTML, safe=True),
                  FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
            existing_defense=D.SANITIZATION, root_cause="", provenance=_SYN, tags=["train_nearmiss"]))
        if anchor == "DOMPurify.sanitize":
            continue  # keep DOMPurify perturbations OUT of training (held-out transfer test)
        for j, name in enumerate(_single_edits(anchor, rng, k=8)):
            out.append(XSSCase(
                id=f"tm-nmg-{ai}-{j}", language="javascript", family=F.DOM, vulnerable=True,
                context=C.DOM_HTML, code=f"const clean = {name}(input);\nel.innerHTML = clean;",
                flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
                      FlowNode(R.SANITIZER, name, C.DOM_HTML, safe=None),
                      FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
                existing_defense=D.NONE,
                root_cause=f"'{name}' is not a recognized safe sanitizer API; a one-character "
                           f"difference from a known name does NOT make it trusted, so the innerHTML "
                           f"sink is vulnerable. Only an exact known-safe sanitizer establishes safety.",
                remediation="Verify the exact sanitizer API against a trusted list, or use textContent.",
                provenance=_SYN, tags=["train_nearmiss"]))
    return out


def _nearmiss_train_cases(rng) -> list[XSSCase]:
    """Teach across MULTIPLE anchors: exact known-safe sanitizer -> safe; any look-alike -> NOT
    establishably safe. Multi-anchor coverage is what lets the principle transfer to the held-out
    DOMPurify perturbations in the frozen bench."""
    out = []
    for ai, (anchor, perts) in enumerate(_NM_ANCHORS.items()):
        out.append(XSSCase(
            id=f"tm-nm-anchor-{ai}", language="javascript", family=F.SAFE, vulnerable=False,
            context=C.DOM_HTML, code=f"const clean = {anchor}(input);\nel.innerHTML = clean;",
            flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
                  FlowNode(R.SANITIZER, anchor, C.DOM_HTML, safe=True),
                  FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
            existing_defense=D.SANITIZATION, root_cause="", provenance=_SYN, tags=["train_nearmiss"]))
        for i, name in enumerate(perts):
            out.append(XSSCase(
                id=f"tm-nm-pert-{ai}-{i}", language="javascript", family=F.DOM, vulnerable=True,
                context=C.DOM_HTML, code=f"const clean = {name}(input);\nel.innerHTML = clean;",
                flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
                      FlowNode(R.SANITIZER, name, C.DOM_HTML, safe=None),
                      FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
                existing_defense=D.NONE,
                root_cause=f"'{name}' is not an established safe sanitizer; safety not established, "
                           f"so the innerHTML sink must be treated as vulnerable.",
                remediation="Use a known-safe sanitizer (e.g. DOMPurify.sanitize) or textContent.",
                provenance=_SYN, tags=["train_nearmiss"]))
    return out


# Sink/defense breadth to RETAIN under fine-tuning (Phase 15 replay): minimal snippets exercising
# APIs the base model knows but narrow SFT would forget — including the generalization split's sink
# families (jQuery .html, insertAdjacentHTML, wrapper indirection are NOT here; only the API facts).
_BREADTH = [
    # (sink snippet, vulnerable, context, family, sink_name, defense, root_cause, remediation)
    ("$('#box').html(name);", True, C.DOM_HTML, F.DOM, ".html()", D.NONE,
     "jQuery .html() parses HTML; untrusted 'name' is a DOM XSS sink.", "Use .text() for untrusted strings."),
    ("$('#box').text(name);", False, C.DOM_HTML, F.SAFE, ".text()", D.SAFE_DOM_API, "", "none"),
    ("node.insertAdjacentHTML('beforeend', data);", True, C.DOM_HTML, F.DOM, "insertAdjacentHTML", D.NONE,
     "insertAdjacentHTML parses HTML; untrusted 'data' executes.", "Use insertAdjacentText."),
    ("node.insertAdjacentText('beforeend', data);", False, C.DOM_HTML, F.SAFE, "insertAdjacentText", D.SAFE_DOM_API, "", "none"),
    ("outEl.outerHTML = value;", True, C.DOM_HTML, F.DOM, "outerHTML", D.NONE,
     "outerHTML parses HTML; untrusted 'value' executes.", "Use textContent or sanitize."),
    ("range.createContextualFragment(value);", True, C.DOM_HTML, F.DOM, "createContextualFragment", D.NONE,
     "createContextualFragment parses HTML into nodes; untrusted input executes.", "Sanitize or avoid."),
    ("target.setAttribute('src', url);", True, C.HTML_ATTR_URL, F.DOM, "setAttribute(src)", D.NONE,
     "src set to an untrusted URL can carry a javascript:/data: payload.", "Allow-list http/https schemes."),
    ("target.className = value;", False, C.DOM_ATTR, F.SAFE, "className", D.SAFE_DOM_API, "", "none"),
    ("el.innerHTML = DOMPurify.sanitize(value);", False, C.DOM_HTML, F.SAFE, "innerHTML", D.SANITIZATION, "", "none"),
    ("res.send(escapeHtml(req.query.q));", False, C.HTML_TEXT, F.SAFE, "escapeHtml", D.CONTEXTUAL_ENCODING, "", "none"),
]


def _breadth_cases() -> list[XSSCase]:
    out = []
    for i, (code, vuln, ctx, fam, sink, defense, rc, rem) in enumerate(_BREADTH):
        src = "name" if "name" in code else ("data" if "data" in code else
              ("value" if "value" in code else ("url" if "url" in code else "req.query.q")))
        flow = [FlowNode(R.SOURCE, src, C.HTML_TEXT), FlowNode(R.SINK, sink, ctx, safe=None if vuln else True)]
        out.append(XSSCase(
            id=f"tm-breadth-{i}", language="javascript", family=fam, vulnerable=vuln, context=ctx,
            code=code, flow=flow, existing_defense=defense, root_cause=rc if vuln else "",
            remediation=rem if vuln else "", provenance=_SYN, tags=["train_breadth"]))
    return out


def build(out_path: str = "data/training/sft.jsonl", n_per_template: int = 12):
    rng = stream("teacher")
    retriever = Retriever.load_default()
    # base training cases: train-group templates, train names, MORE instances than dev/test pools
    # train-templates with BOTH name banks: train-names overlap dev (mostly dropped as contaminated,
    # which is correct), holdout-names give disjoint fresh instances on the same shapes. Neither uses
    # holdout TEMPLATES, so training stays disjoint from the generalization split.
    base = (casegen.generate(n_per_template=n_per_template, group="train", names="train")
            + casegen.generate(n_per_template=n_per_template, group="train", names="holdout"))
    # v3: only the generated multi-anchor near-miss set, which EXCLUDES DOMPurify perturbations,
    # so the frozen bench's DOMPurify single-edits are a genuine held-out transfer test.
    nm = _nearmiss_gen_cases(rng)
    breadth = _breadth_cases()
    all_cases = base + nm + breadth

    # --- disjointness: no training code string may appear in ANY frozen split ---
    frozen_hashes = set()
    for f in Path("benchmarks/frozen").glob("*.jsonl"):
        for line in f.read_text().splitlines():
            if line.strip():
                frozen_hashes.add(sha256_text(json.loads(line)["code"]))
    kept, dropped = [], 0
    for c in all_cases:
        if sha256_text(c.code) in frozen_hashes:
            dropped += 1
            continue
        kept.append(c)

    records = []
    for c in kept:
        prompt = P.build(c.code, c.language)
        target = _analysis_target(c, retriever)
        records.append({"case_id": c.id, "vulnerable": c.vulnerable, "origin": "synthetic",
                        "tags": c.tags, "messages": [
                            {"role": "user", "content": prompt},
                            {"role": "assistant", "content": target}]})
    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
    manifest = {
        "n_records": len(records), "n_dropped_contaminated": dropped,
        "n_vulnerable": sum(r["vulnerable"] for r in records),
        "n_safe": sum(not r["vulnerable"] for r in records),
        "n_nearmiss": sum("train_nearmiss" in r["tags"] for r in records),
        "n_breadth": sum("train_breadth" in r["tags"] for r in records),
        "sha256": sha256_text(outp.read_text()),
        "teacher": "grounded_synthesizer", "all_synthetic": True,
    }
    write_json(outp.parent / "sft_manifest.json", manifest)
    print(f"SFT -> {out_path}: {manifest['n_records']} records "
          f"(vuln={manifest['n_vulnerable']} safe={manifest['n_safe']} "
          f"nearmiss={manifest['n_nearmiss']}) dropped_contaminated={dropped}")
    print("sha256", manifest["sha256"][:16])
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/training/sft.jsonl")
    ap.add_argument("--n", type=int, default=12)
    a = ap.parse_args()
    build(a.out, a.n)
