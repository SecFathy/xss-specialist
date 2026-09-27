"""Reproducibility primitives: deterministic per-component RNG streams, content hashing,
and an environment manifest. Every artifact-producing step records its inputs' hashes so
an unrelated pipeline change can never silently alter training examples (integrity rule).
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import numpy as np

# Master seed for the whole study. Component streams derive from it deterministically,
# so adding a candidate to one stream never perturbs sampling in another.
MASTER_SEED = 20260927


def stream(component: str, master: int = MASTER_SEED) -> np.random.Generator:
    """A named, independent RNG stream. `component` is hashed into the seed so
    e.g. 'negatives' and 'replay' never share draws even as counts change."""
    h = int.from_bytes(hashlib.sha256(f"{master}:{component}".encode()).digest()[:8], "big")
    return np.random.default_rng(h)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8"))


def sha256_json(obj: Any) -> str:
    """Canonical hash of a JSON-able object: sorted keys, no whitespace drift."""
    return sha256_text(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git(*args: str) -> str | None:
    try:
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return None


def env_manifest() -> dict:
    """Snapshot of the reproducibility-relevant environment."""
    try:
        import importlib.metadata as md
        pkgs = {n: md.version(n) for n in
                ("mlx-lm", "numpy", "scikit-learn", "transformers", "playwright", "statsmodels")}
    except Exception:
        pkgs = {}
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "master_seed": MASTER_SEED,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "packages": pkgs,
    }


def write_json(path: str | Path, obj: Any) -> str:
    """Write canonical JSON, return its content hash."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
    p.write_text(text, encoding="utf-8")
    return sha256_text(text)
