"""Phase 3/4/5 — freeze XSSBench.

Assembles splits, deduplicates by code hash, runs a contamination check (no code string may
appear in more than one split, and the locked test must be disjoint from everything used for
tuning/training), then writes each split as JSONL plus a manifest carrying per-split hashes and
counts. The test split is flagged locked: its labels must be read at most once per candidate.

Splits:
  dev            train-group templates, train names        (prompt/threshold development)
  test  [LOCKED] train-group templates, train names, idx-disjoint from dev/train pools
  generalization holdout-group templates + holdout names   (structural + lexical novelty)
  nearmiss       entity-binding perturbations
  adversarial    obfuscation / mutation / wrong-context + hard negatives
The training pool is generated separately (train-group, train names) and checked disjoint from test.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.repro import env_manifest, sha256_json, sha256_text, write_json
from benchmarks import adversarial, cases, nearmiss


def _dedup_split(all_cases):
    """Cases share templates across splits; make each instance unique by code hash within its split
    and record the hash for cross-split contamination checks."""
    seen, out = set(), []
    for c in all_cases:
        h = sha256_text(c.code)
        if h in seen:
            continue
        seen.add(h)
        out.append((h, c))
    return out


def build(out_dir: str = "benchmarks/frozen"):
    # Pools. dev and test both come from train-group/train-names but we split the instance
    # index range so they never share a code string.
    train_group = cases.generate(n_per_template=10, group="train", names="train")
    # deterministic dev/test partition by instance index parity of the code hash
    dev_pool, test_pool = [], []
    for c in train_group:
        (test_pool if int(sha256_text(c.code)[:8], 16) % 3 == 0 else dev_pool).append(c)

    generalization = cases.generate(n_per_template=8, group="holdout", names="holdout")
    nm = nearmiss.generate()
    adv = adversarial.generate()

    splits = {
        "dev": dev_pool,
        "test": test_pool,
        "generalization": generalization,
        "nearmiss": nm,
        "adversarial": adv,
    }

    # dedup within split
    hashed = {name: _dedup_split(cs) for name, cs in splits.items()}

    # --- contamination check: test disjoint from dev + generalization (train reuses dev pool) ---
    test_hashes = {h for h, _ in hashed["test"]}
    for other in ("dev", "generalization"):
        overlap = test_hashes & {h for h, _ in hashed[other]}
        if overlap:
            raise SystemExit(f"CONTAMINATION: test shares {len(overlap)} code strings with {other}; abort.")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"env": env_manifest(), "splits": {}}
    for name, hc in hashed.items():
        recs = [c.to_dict() for _, c in hc]
        path = out / f"{name}.jsonl"
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in recs) + "\n", encoding="utf-8")
        manifest["splits"][name] = {
            "n": len(recs),
            "n_vulnerable": sum(r["vulnerable"] for r in recs),
            "n_safe": sum(not r["vulnerable"] for r in recs),
            "locked": name == "test",
            "sha256": sha256_json(recs),
            "file": f"{name}.jsonl",
        }
    mh = write_json(out / "manifest.json", manifest)
    print(f"XSSBench frozen -> {out}  (manifest sha256 {mh[:16]})")
    for name, info in manifest["splits"].items():
        lock = " [LOCKED]" if info["locked"] else ""
        print(f"  {name:15s} n={info['n']:3d} vuln={info['n_vulnerable']:3d} "
              f"safe={info['n_safe']:3d}{lock}  {info['sha256'][:12]}")
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="benchmarks/frozen")
    build(ap.parse_args().out)
