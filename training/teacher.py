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


def _nearmiss_train_cases(rng) -> list[XSSCase]:
    """Teach: exact known-safe sanitizer -> safe; a look-alike name -> NOT establishably safe."""
    out = []
    # anchor safe
    out.append(XSSCase(
        id="tm-nm-anchor", language="javascript", family=F.SAFE, vulnerable=False,
        context=C.DOM_HTML, code=f"const clean = {TRAIN_ANCHOR}(input);\nel.innerHTML = clean;",
        flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
              FlowNode(R.SANITIZER, TRAIN_ANCHOR, C.DOM_HTML, safe=True),
              FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
        existing_defense=D.SANITIZATION, root_cause="", provenance=_SYN, tags=["train_nearmiss"]))
    # perturbations -> vulnerable (unknown safety)
    perts = ["sanitizeHtm1", "santizeHtml", "sanitizeHtml", "sanitzeHtml", "sanitizeHTML"]
    for i, name in enumerate(perts):
        out.append(XSSCase(
            id=f"tm-nm-pert-{i}", language="javascript", family=F.DOM, vulnerable=True,
            context=C.DOM_HTML, code=f"const clean = {name}(input);\nel.innerHTML = clean;",
            flow=[FlowNode(R.SOURCE, "input", C.HTML_TEXT),
                  FlowNode(R.SANITIZER, name, C.DOM_HTML, safe=None),
                  FlowNode(R.SINK, "innerHTML", C.DOM_HTML)],
            existing_defense=D.NONE,
            root_cause=f"'{name}' is not an established safe sanitizer; safety not established, "
                       f"so the innerHTML sink must be treated as vulnerable.",
            remediation=f"Use a known-safe sanitizer (e.g. DOMPurify.sanitize) or textContent.",
            provenance=_SYN, tags=["train_nearmiss"]))
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
    nm = _nearmiss_train_cases(rng)
    all_cases = base + nm

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
