"""Unified CLI. Thin wrappers over the phase modules so the whole study runs from one entrypoint.

  xss build-benchmark            freeze XSSBench (Phase 3-5)
  xss corpus                     write the verified knowledge corpus (Phase 2)
  xss sft [--n N]                build teacher SFT data (Phase 9)
  xss train [...]                train a candidate LoRA (Phase 10)
  xss eval --backend ... --out   evaluate a backend on splits (Phase 6-7)
  xss kev-route                  route the corpus through KEV (Phase 12-13)
  xss verify                     run the browser oracle over frozen cases (Phase 14)
  xss adversarial                run the pipeline poisoning suite (Phase 17)
  xss promote --cand R --base R  run the promotion gate (Phase 20)
  xss kill on|off|status         kill switch (Phase 26)
  xss report ...                 build the comparison report (Phase 30-32)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_metrics(run_dir, splits):
    out = {}
    for s in splits:
        f = Path(run_dir) / s / "metrics.json"
        if f.exists():
            out[s] = json.loads(f.read_text())
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="xss")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build-benchmark")
    sub.add_parser("corpus")
    p = sub.add_parser("sft"); p.add_argument("--n", type=int, default=14)
    p = sub.add_parser("train")
    for k, d, t in [("iters", 320, int), ("batch", 4, int), ("lr", 1e-4, float),
                    ("layers", 8, int), ("rank", 16, int)]:
        p.add_argument(f"--{k}", type=t, default=d)
    p.add_argument("--out", default="models/adapters/xss-v1")
    sub.add_parser("kev-route")
    sub.add_parser("verify")
    sub.add_parser("adversarial")
    p = sub.add_parser("promote"); p.add_argument("--cand", required=True); p.add_argument("--base", required=True)
    p = sub.add_parser("kill"); p.add_argument("state", choices=["on", "off", "status"])

    a = ap.parse_args(argv)
    splits = ["dev", "generalization", "nearmiss", "adversarial"]

    if a.cmd == "build-benchmark":
        from benchmarks.build import build; build()
    elif a.cmd == "corpus":
        from knowledge.seed_corpus import build as bc
        recs = [i.to_dict() for i in bc()]
        Path("data/verified").mkdir(parents=True, exist_ok=True)
        Path("data/verified/corpus.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs) + "\n")
        print(f"corpus: {len(recs)} verified items -> data/verified/corpus.jsonl")
    elif a.cmd == "sft":
        from training.teacher import build; build(n_per_template=a.n)
    elif a.cmd == "train":
        from training.train import train
        train(adapter_out=a.out, iters=a.iters, batch=a.batch, lr=a.lr, num_layers=a.layers, rank=a.rank)
    elif a.cmd == "kev-route":
        from kevgate.gate import KevGate
        from knowledge.seed_corpus import build as bc
        g = KevGate()
        counts = {}
        for it in bc():
            d = g.route(it); counts[d.route] = counts.get(d.route, 0) + 1
            print(f"{it.id} {d.route:18s} {d.reason}")
        print("routes:", counts)
    elif a.cmd == "verify":
        from verification.browser_oracle import verify_split
        for s in splits:
            r = verify_split(f"benchmarks/frozen/{s}.jsonl")
            print(s, {k: v for k, v in r.items() if k != "conflicts"})
    elif a.cmd == "adversarial":
        from verification.adversarial_pipeline import run
        r = run(); print(f"attacks={r['n_attacks']} breaches={r['breaches']}")
    elif a.cmd == "promote":
        from evaluation.promotion import evaluate
        d = evaluate(_load_metrics(a.cand, splits), _load_metrics(a.base, splits))
        print(json.dumps(d, indent=2))
    elif a.cmd == "kill":
        import registry.registry as reg
        if a.state == "status":
            print("learning_enabled =", reg.learning_enabled())
        else:
            reg.set_learning(a.state == "on")
            print("learning_enabled ->", reg.learning_enabled())


if __name__ == "__main__":
    main()
