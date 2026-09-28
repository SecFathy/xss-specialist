"""Model-only evaluation: three-way decisions, calibration and permutation tests."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np


def read_partition(suite: str | Path, split: str, *, allow_test: bool = False) -> list[dict]:
    root = Path(suite)
    manifest = json.loads((root / "manifest.json").read_text())
    info = manifest["splits"][split]
    if (split == "test" or info.get("locked")) and not allow_test:
        raise ValueError("Locked test is not a search set; select a checkpoint first and pass --allow-test explicitly.")
    path = root / info["file"]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != info["sha256"]:
        raise ValueError(f"Hash mismatch for {path}")
    rows = [json.loads(line) for line in raw.decode().splitlines() if line]
    if len(rows) != info["n"] or any(r["_meta"]["split"] != split for r in rows):
        raise ValueError("Partition count or split provenance mismatch")
    return rows


def summarize(rows: list[dict]) -> dict:
    if not rows:
        raise ValueError("Cannot evaluate zero rows")
    cells = Counter(); golds = Counter(); per_context = defaultdict(Counter)
    nll = []; brier = []; bins = defaultdict(list); qcorrect = Counter(); qtotal = Counter()
    for row in rows:
        for qid, q in row["questions"].items():
            p = row["prediction"]["probabilities"][qid]
            if not p or any(not math.isfinite(v) or v < 0 for v in p.values()) or abs(sum(p.values()) - 1) > 1e-4:
                raise ValueError("Invalid probability distribution")
            y = str(q["label"]).lower() if q["type"] == "noul" else str(q["label"])
            pred = max(p, key=p.get)
            qcorrect[qid] += pred == y; qtotal[qid] += 1
            nll.append(-math.log(max(p[y], 1e-12)))
            brier.append(sum((v - float(k == y)) ** 2 for k, v in p.items()))
            conf = max(p.values()); bins[min(9, int(conf * 10))].append((conf, float(pred == y)))
            if qid == "verdict":
                golds[y] += 1; cells[f"{y}->{pred}"] += 1
                context = row["questions"].get("context", {}).get("label", "unknown")
                per_context[context]["n"] += 1; per_context[context]["correct"] += pred == y
    n = sum(golds.values())
    if not n:
        raise ValueError("The v2 evaluator requires a three-way verdict question")
    vuln = golds["vulnerable"]; safe = golds["safe"]; unknown = golds["unknown"]
    known_decided = sum(cells[f"{y}->{p}"] for y in ("safe", "vulnerable") for p in ("safe", "vulnerable"))
    correct_decided = cells["safe->safe"] + cells["vulnerable->vulnerable"]
    return {
        "n": n, "gold_counts": dict(golds), "confusion": dict(cells),
        "per_question_accuracy": {k: qcorrect[k] / qtotal[k] for k in qtotal},
        "vulnerability_recall": cells["vulnerable->vulnerable"] / vuln if vuln else None,
        "false_safe_rate": cells["vulnerable->safe"] / vuln if vuln else None,
        "vulnerable_abstention_rate": cells["vulnerable->unknown"] / vuln if vuln else None,
        "false_alarm_rate": cells["safe->vulnerable"] / safe if safe else None,
        "unknown_recall": cells["unknown->unknown"] / unknown if unknown else None,
        "unknown_overclaim_rate": (cells["unknown->safe"] + cells["unknown->vulnerable"]) / unknown if unknown else None,
        "known_coverage": known_decided / (safe + vuln) if safe + vuln else None,
        "known_selective_error": 1 - correct_decided / known_decided if known_decided else None,
        "nll": float(np.mean(nll)), "brier_multiclass": float(np.mean(brier)),
        "ece": sum(len(v) * abs(np.mean([p for p, _ in v]) - np.mean([ok for _, ok in v])) for v in bins.values()) / len(nll),
        "per_context_verdict_accuracy": {k: v["correct"] / v["n"] for k, v in per_context.items()},
        "per_context_counts": {k: v["n"] for k, v in per_context.items()},
    }


def permuted(record: dict) -> dict:
    return {**record, "questions": {qid: {**q, "criteria": dict(reversed(list(q["criteria"].items())))}
            if q["type"] == "choice" else q for qid, q in record["questions"].items()}}


def evaluate(records: list[dict], predictor, permutation_limit: int = 30) -> tuple[list[dict], dict]:
    rows = []; flips = Counter(); totals = Counter(); shifts = defaultdict(float)
    # Avoid testing only the first sink family in a template-ordered JSONL.
    ranked = sorted(range(len(records)), key=lambda i: hashlib.sha256(records[i]["_meta"]["id"].encode()).hexdigest())
    selected = []; families = set(); groups = set()
    for i in ranked:
        family = records[i]["_meta"].get("sink_family", "unspecified")
        if family not in families and len(selected) < permutation_limit:
            selected.append(i); families.add(family); groups.add(records[i]["_meta"]["group_id"])
    for i in ranked:
        group = records[i]["_meta"]["group_id"]
        if group not in groups and len(selected) < permutation_limit:
            selected.append(i); groups.add(group)
    selected = set(selected)
    for i, record in enumerate(records):
        pred = predictor(record)
        row = {"_meta": record["_meta"], "questions": record["questions"], "prediction": pred}
        if i in selected:
            alt = predictor(permuted(record))
            row["permuted_prediction"] = alt
            for qid, q in record["questions"].items():
                if q["type"] != "choice": continue
                a = pred["probabilities"][qid]; b = alt["probabilities"][qid]
                flips[qid] += max(a, key=a.get) != max(b, key=b.get); totals[qid] += 1
                shifts[qid] = max(shifts[qid], max(abs(a[k] - b[k]) for k in a))
        rows.append(row)
        if (i + 1) % 50 == 0: print(f"evaluated {i + 1}/{len(records)} records", flush=True)
    report = summarize(rows)
    report["permutation"] = {k: {"n": totals[k], "flip_rate": flips[k] / totals[k], "max_probability_shift": shifts[k]} for k in totals}
    return rows, report


def fit_temperature(rows: list[dict]) -> dict:
    """One scalar temperature fitted ONLY on the calibration partition."""
    if not rows or any(r["_meta"]["split"] != "calibration" for r in rows):
        raise ValueError("Temperature fit requires calibration-only rows")
    examples = []
    for r in rows:
        old_t = r["prediction"]["inference_temperature"]
        for qid, q in r["questions"].items():
            z = r["prediction"]["logits"][qid]
            keys = list(z); y = str(q["label"]).lower() if q["type"] == "noul" else str(q["label"])
            examples.append((np.array([z[k] * old_t for k in keys]), keys.index(y)))
    def loss(t):
        losses = []
        for z, y in examples:
            z = z / t; top = z.max()
            losses.append(float(top + np.log(np.exp(z - top).sum()) - z[y]))
        return float(np.mean(losses))
    grid = np.exp(np.linspace(math.log(0.2), math.log(10), 200))
    best = min([1.0, *map(float, grid)], key=loss)
    return {"temperature": best, "n_questions": len(examples), "nll_raw": loss(1), "nll_fitted": loss(best),
            "fit_split": "calibration", "note": "Calibration-set fit is not an unseen-data accuracy guarantee."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True); ap.add_argument("--run", required=True)
    ap.add_argument("--split", choices=["calibration", "development", "test"], default="development")
    ap.add_argument("--out", required=True); ap.add_argument("--device", default="mps")
    ap.add_argument("--backend", choices=["auto", "mlx", "torch"], default="auto")
    ap.add_argument("--temperature", type=float); ap.add_argument("--allow-test", action="store_true")
    ap.add_argument("--calibration", help="Apply a fitted calibration-only temperature for this checkpoint")
    ap.add_argument("--permutation-limit", type=int, default=30)
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists(): raise ValueError(f"Refusing to overwrite evaluation directory: {out}")
    records = read_partition(args.suite, args.split, allow_test=args.allow_test)
    from xss_decision.learned import LearnedBackend
    predictor = LearnedBackend(args.run, args.device, args.backend, args.temperature, calibration=args.calibration)
    rows, report = evaluate(records, predictor.predict, args.permutation_limit)
    report.update({"model": predictor.details, "split": args.split,
                   "suite_manifest_sha256": hashlib.sha256((Path(args.suite) / "manifest.json").read_bytes()).hexdigest()})
    out.mkdir(parents=True)
    (out / "rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.split == "calibration":
        fit = fit_temperature(rows)
        fit.update(checkpoint_signature=predictor.details["checkpoint_signature"],
                   suite_manifest_sha256=report["suite_manifest_sha256"])
        (out / "temperature.json").write_text(json.dumps(fit, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
