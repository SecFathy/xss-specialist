"""Reproducible, train-partition-only warm starts using the upstream Kev trainer."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from xss_decision.evaluate import read_partition


def target_mode(targets: list[str]) -> str:
    dense = {"q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"}
    hybrid = {"in_proj_qkv", "in_proj_z", "in_proj_a", "in_proj_b", "out_proj"}
    modes = {"all": dense | hybrid, "dense": dense,
             "attn": {"q_proj", "k_proj", "v_proj", "o_proj"} | hybrid,
             "qv": {"q_proj", "v_proj"}}
    return next((mode for mode, modules in modes.items() if set(targets) == modules), "unsupported")


def plan(suite: str, init_from: str, out: str, *, epochs=2, lr=2e-5,
         device="mps", seed=0, perm_kl=0.1, batch=4, accum=2) -> dict:
    if epochs < 1 or not 0 < lr <= 2e-5 or perm_kl < 0:
        raise ValueError("Warm starts require epochs >= 1, 0 < lr <= 2e-5, perm_kl >= 0")
    if min(batch, accum) < 1: raise ValueError("Batch and accumulation must be positive")
    if Path(out).exists(): raise ValueError(f"Refusing to overwrite checkpoint: {out}")
    root = Path(suite).resolve(); records = read_partition(root, "train")
    if any("verdict" not in r["questions"] for r in records):
        raise ValueError("Only the corrected three-way dataset is accepted for this training path")
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema_version") != "xss-decision-v2":
        raise ValueError("Expected a versioned xss-decision-v2 suite")
    if manifest.get("verification", {}).get("checked", 0) != manifest["stats"]["records"]:
        raise ValueError("Every fixture must pass the browser check before training")
    if any(r["_meta"].get("browser_status") != "PASS" for r in records):
        raise ValueError("Training partition contains unverified fixtures")
    seen_groups = set()
    for info in manifest["splits"].values():
        groups = set(info["group_ids"])
        if groups & seen_groups: raise ValueError("Template groups overlap across partitions")
        seen_groups |= groups
    from kev.checkpoint import Checkpoint
    parent = Checkpoint(init_from)
    adapter = json.loads(Path(parent.file("adapter_config.json")).read_text())
    mode = target_mode(adapter["target_modules"])
    if mode == "unsupported": raise ValueError("Unsupported adapter target set; refusing a partial warm start")
    if not parent.meta.base_revision: raise ValueError("Parent checkpoint must pin its base revision")
    command = [sys.executable, "-m", "kev.train", "--data", str(root / manifest["splits"]["train"]["file"]),
               "--base", parent.meta.base, "--base_revision", parent.meta.base_revision,
               "--init_from", parent.path, "--lora", str(parent.meta.lora),
               "--head_dim", str(parent.meta.head_dim), "--lora_targets", mode,
               "--lora_placement", parent.meta.lora_placement,
               "--option_isolation", str(int(parent.meta.option_isolation)),
               "--special_embeddings", str(int(parent.meta.special_embeddings)),
               "--weights_dtype", parent.meta.weights_dtype,
               "--epochs", str(epochs), "--lr", str(lr), "--batch", str(batch), "--accum", str(accum),
               "--dtype", "fp32", "--checkpointing", "1", "--device", device,
               "--p_none", "0", "--p_none_distract", "0", "--p_distract", "0",
               "--perm_kl", str(perm_kl), "--perm_frac", "0.3", "--max_state", "1024",
               "--seed", str(seed), "--out", str(Path(out).resolve())]
    return {"command": command, "suite_manifest_sha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest(),
            "research_gate_sha256": hashlib.sha256(Path(__file__).with_name("promotion.py").read_bytes()).hexdigest(),
            "train_records": len(records), "init_requested": init_from, "init_resolved": parent.path,
            "parent_adapter_sha256": hashlib.sha256(Path(parent.file("adapter_model.safetensors")).read_bytes()).hexdigest(),
            "parent_head_sha256": hashlib.sha256(Path(parent.file("head.pt")).read_bytes()).hexdigest(),
            "test_read": False, "scope": "Local research candidate; no promotion or publication."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--init-from", default="jaredpalmer/kev-0.8b@9a45d25eb2ab761841196625383fa1dff0e56c1e")
    ap.add_argument("--epochs", type=int, default=2); ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--device", choices=["cpu", "mps", "cuda"], default="mps")
    ap.add_argument("--seed", type=int, default=0); ap.add_argument("--perm-kl", type=float, default=0.1)
    ap.add_argument("--batch", type=int, default=4); ap.add_argument("--accum", type=int, default=2)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    p = plan(args.suite, args.init_from, args.out, epochs=args.epochs, lr=args.lr,
             device=args.device, seed=args.seed, perm_kl=args.perm_kl, batch=args.batch, accum=args.accum)
    print(json.dumps(p, indent=2), flush=True)
    if args.dry_run: return
    log_path = Path(str(Path(args.out)) + ".training.log")
    if log_path.exists(): raise ValueError(f"Refusing to overwrite training log: {log_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as log:
        process = subprocess.Popen(p["command"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="", flush=True); log.write(line); log.flush()
        if process.wait(): raise RuntimeError(f"Training failed; see {log_path}")
    Path(args.out, "xss_training_provenance.json").write_text(json.dumps(p, indent=2) + "\n")


if __name__ == "__main__": main()
