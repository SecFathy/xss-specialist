"""Phase 10 — train the XSS specialist LoRA on MLX.

Splits the SFT data deterministically, writes it in mlx-lm's chat format, runs `mlx_lm.lora`, and
records an immutable training record (dataset hash, base model + revision, adapter config, seed,
runtime) so the candidate adapter is fully reproducible and reversible. The base model is never
modified; the adapter is a separate artifact.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from xss_specialist.repro import env_manifest, sha256_file, sha256_text, stream, write_json


def _split(sft_path: str, data_dir: str, valid_frac: float = 0.15):
    recs = [json.loads(l) for l in Path(sft_path).read_text().splitlines() if l.strip()]
    rng = stream("train_split")
    idx = rng.permutation(len(recs))
    n_valid = max(2, int(len(recs) * valid_frac))
    valid_ids = set(idx[:n_valid].tolist())
    dd = Path(data_dir)
    dd.mkdir(parents=True, exist_ok=True)
    train, valid = [], []
    for i, r in enumerate(recs):
        row = {"messages": r["messages"]}
        (valid if i in valid_ids else train).append(row)
    (dd / "train.jsonl").write_text("\n".join(json.dumps(r) for r in train) + "\n")
    (dd / "valid.jsonl").write_text("\n".join(json.dumps(r) for r in valid) + "\n")
    return len(train), len(valid)


def train(model="models/qwen3-8b-4bit", sft="data/training/sft.jsonl",
          adapter_out="models/adapters/xss-v1", iters=300, batch=4, lr=1e-4,
          num_layers=8, rank=16, seed=0):
    data_dir = "data/training/mlx"
    n_train, n_valid = _split(sft, data_dir)
    Path(adapter_out).mkdir(parents=True, exist_ok=True)
    lora_cfg = {
        "model": model, "train": True, "data": data_dir, "adapter_path": adapter_out,
        "iters": iters, "batch_size": batch, "learning_rate": lr, "num_layers": num_layers,
        "seed": seed, "steps_per_report": 25, "steps_per_eval": 100, "save_every": 100,
        "max_seq_length": 1024,
        "lora_parameters": {"rank": rank, "scale": 20.0, "dropout": 0.0},
    }
    cfg_path = Path(adapter_out) / "lora_config.yaml"
    import yaml
    cfg_path.write_text(yaml.safe_dump(lora_cfg))
    t0 = time.time()
    cmd = [sys.executable, "-m", "mlx_lm", "lora", "--config", str(cfg_path)]
    print("running:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(proc.stdout[-3000:])
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-3000:])
        raise SystemExit(f"mlx_lm.lora failed rc={proc.returncode}")
    dt = time.time() - t0
    adapter_file = Path(adapter_out) / "adapters.safetensors"
    record = {
        "base_model": model,
        "base_config_sha256": sha256_file(Path(model) / "config.json"),
        "sft_path": sft, "sft_sha256": sha256_text(Path(sft).read_text()),
        "n_train": n_train, "n_valid": n_valid,
        "lora_config": lora_cfg,
        "adapter_sha256": sha256_file(adapter_file) if adapter_file.exists() else None,
        "runtime_s": round(dt, 1), "env": env_manifest(),
    }
    write_json(Path(adapter_out) / "training_record.json", record)
    print(f"\nadapter -> {adapter_out}  ({dt:.0f}s, {n_train} train / {n_valid} valid)")
    print("adapter_sha256", record["adapter_sha256"][:16] if record["adapter_sha256"] else "MISSING")
    return record


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=300)
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--layers", type=int, default=8)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--out", default="models/adapters/xss-v1")
    a = ap.parse_args()
    train(adapter_out=a.out, iters=a.iters, batch=a.batch, lr=a.lr,
          num_layers=a.layers, rank=a.rank)
