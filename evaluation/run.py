"""Run a backend over an XSSBench split and score it. Writes per-item predictions and a metrics
summary under runs/<name>/<split>/ with the split's frozen hash recorded, so a result is always
traceable to the exact benchmark version it was measured on.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from xss_specialist import prompt as P
from xss_specialist.inference import GenConfig, get_backend
from xss_specialist.repro import sha256_json, write_json
from evaluation.scorer import leakage_rate, load_split, score


def run_split(backend, split_path: str, out_dir: str, rag=None, max_items: int | None = None):
    records = load_split(split_path)
    if max_items:
        records = records[:max_items]
    preds, raws = [], []
    t0 = time.time()
    for i, r in enumerate(records):
        rag_ctx = rag.context_for(r) if rag else ""
        prompt = P.build(r["code"], r["language"], rag_ctx)
        text = backend.generate(prompt, GenConfig())
        parsed = P.parse(text)
        preds.append(parsed)
        raws.append({"id": r["id"], "gold_vulnerable": r["vulnerable"],
                     "pred": parsed["classification"], "conf": parsed["confidence"],
                     "context_gold": r["context"], "context_pred": parsed["context"],
                     "fields_found": parsed.get("_fields_found", 0)})
    dt = time.time() - t0
    split_name = Path(split_path).stem
    metrics = score(records, preds)
    metrics["latency_s_per_item"] = dt / max(1, len(records))
    metrics["backend"] = backend.name
    metrics["split"] = split_name
    metrics["split_sha256"] = sha256_json(records)
    metrics["rag"] = bool(rag)
    if split_name == "nearmiss":
        metrics["nearmiss"] = leakage_rate(records, preds)
    out = Path(out_dir) / split_name
    out.mkdir(parents=True, exist_ok=True)
    (out / "predictions.jsonl").write_text(
        "\n".join(json.dumps(x) for x in raws) + "\n", encoding="utf-8")
    write_json(out / "metrics.json", metrics)
    return metrics


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="mock", choices=["mock", "mlx"])
    ap.add_argument("--model", default="models/qwen3-8b-4bit")
    ap.add_argument("--adapter", default="")
    ap.add_argument("--splits", nargs="+",
                    default=["dev", "generalization", "nearmiss", "adversarial"])
    ap.add_argument("--frozen", default="benchmarks/frozen")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rag", action="store_true")
    ap.add_argument("--max-items", type=int, default=None)
    ap.add_argument("--allow-test", action="store_true",
                    help="required to touch the LOCKED test split")
    a = ap.parse_args()
    if "test" in a.splits and not a.allow_test:
        raise SystemExit("Refusing to read LOCKED test split without --allow-test (integrity rule).")
    backend = get_backend(a.backend, a.model, a.adapter)
    rag = None
    if a.rag:
        from retrieval.index import Retriever
        rag = Retriever.load_default()
    print(f"backend={backend.name} rag={a.rag}")
    for s in a.splits:
        m = run_split(backend, f"{a.frozen}/{s}.jsonl", a.out, rag=rag, max_items=a.max_items)
        extra = ""
        if s == "nearmiss":
            extra = f" leak={m['nearmiss']['leakage_rate']:.2f} anchor_ok={m['nearmiss']['anchor_correct']}"
        print(f"  {s:15s} acc={m['accuracy_all']:.3f} F1={m['f1_vuln']:.3f} "
              f"FPR={m['false_positive_rate']:.3f} FNR={m['false_negative_rate']:.3f} "
              f"abst={m['abstention_rate']:.2f} ctx={m['context_accuracy']:.2f}"
              f" brier={m['brier'] if m['brier'] is None else round(m['brier'],3)}{extra}")


if __name__ == "__main__":
    main()
