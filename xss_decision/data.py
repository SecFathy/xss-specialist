"""Convert frozen XSSBench cases into pointer-model decision records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_decision.questions import DEFAULT_QUESTIONS


def case_to_record(case: dict) -> dict:
    family = case["family"]
    context = case["context"]
    defense = case.get("existing_defense", "none")
    labels = {
        "vulnerable": "yes" if case["vulnerable"] else "no",
        "family": family,
        "context": context,
        "defense": defense,
        # Model confidence never confirms XSS; executable cases go to the oracle.
        "needs_browser_verification": "yes" if case["vulnerable"] else "no",
    }
    questions = []
    for qid, spec in DEFAULT_QUESTIONS.items():
        options = ["no", "yes"] if spec["type"] == "noul" else list(spec["criteria"])
        questions.append({
            "id": qid,
            "type": spec["type"],
            "instr": spec["instructions"],
            "options": options,
            "label": options.index(labels[qid]),
        })
    return {
        "id": case["id"],
        "state": f'language: {case["language"]}\ncode:\n{case["code"]}',
        "questions": questions,
        "metadata": {
            "split_origin": case.get("provenance", {}).get("origin", "unknown"),
            "knowledge_version": case.get("knowledge_version", "v1"),
        },
    }


def case_to_labelled_request(case: dict) -> dict:
    """Kev-compatible labelled API request used by the pointer-head trainer."""
    labels = {
        "vulnerable": bool(case["vulnerable"]),
        "family": case["family"],
        "context": case["context"],
        "defense": case.get("existing_defense", "none"),
        "needs_browser_verification": bool(case["vulnerable"]),
    }
    questions = {}
    for qid, spec in DEFAULT_QUESTIONS.items():
        question = {"type": spec["type"], "instructions": spec["instructions"],
                    "label": labels[qid], "src": f"xss_{qid}"}
        if spec["type"] != "noul":
            question["criteria"] = spec["criteria"]
        questions[qid] = question
    return {
        "state": {"language": case["language"], "code": case["code"]},
        "questions": questions,
        "_meta": {"id": case["id"], "group_id": case["id"], "source": "xssbench",
                  "split": case.get("split", "legacy_export"), "variant": "clean"},
    }
def build(source: str | Path, output: str | Path, output_format: str = "internal",
          purpose: str = "evaluation") -> int:
    source, output = Path(source), Path(output)
    if source.stem == "test":
        raise ValueError("Do not export locked-test labels into decision training files")
    manifest_path = source.parent / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        for split, info in manifest.get("splits", {}).items():
            if info.get("file") == source.name and (split == "test" or info.get("locked")):
                raise ValueError("Refusing to read a locked-test partition")
    if purpose == "training" and source.stem != "train":
        raise ValueError("Training export requires a train partition, not a development/evaluation split")
    convert = case_to_labelled_request if output_format == "kev" else case_to_record
    records = [convert(json.loads(line)) for line in source.read_text().splitlines() if line]
    if output_format == "kev":
        for record in records:
            record["_meta"]["split"] = source.stem
            record["_meta"]["purpose"] = purpose
    if output.exists():
        raise ValueError(f"Refusing to overwrite decision export: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
    return len(records)


def main() -> None:
    ap = argparse.ArgumentParser(prog="xss-decision-data")
    ap.add_argument("--source", default="benchmarks/frozen/dev.jsonl")
    ap.add_argument("--output", default="data/decision/dev.jsonl")
    ap.add_argument("--format", choices=["internal", "kev"], default="internal")
    ap.add_argument("--purpose", choices=["evaluation", "training"], default="evaluation")
    args = ap.parse_args()
    print(f"wrote {build(args.source, args.output, args.format, args.purpose)} decision records -> {args.output}")


if __name__ == "__main__":
    main()
