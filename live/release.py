"""Phase 1 — freeze a reproducible release of the live-assessment system.

Hashes every component that defines the system's behaviour (code, model/adapter, prompts, KEV pin,
RAG corpus, sanitizer DB, thresholds, benchmark) into a single manifest under registry/releases/.
Every later change is evaluated against the frozen baseline. Does not modify any existing artifact.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from xss_specialist.repro import env_manifest, sha256_file, sha256_text, write_json

# Files whose content defines system behaviour.
COMPONENT_FILES = {
    "prompt": "xss_specialist/prompt.py",
    "inference": "xss_specialist/inference.py",
    "schema": "xss_specialist/schema.py",
    "rag_index": "retrieval/index.py",
    "kev_gate": "kevgate/gate.py",
    "oracle": "verification/browser_oracle.py",
    "crawler": "live/crawler.py",
    "input_mapper": "live/crawler.py",
    "probe_planner": "live/probes.py",
    "executor": "live/executor.py",
    "finding_classifier": "live/findings.py",
    "sanitizer_id": "live/sanitizer_id.py",
    "scope_rules": "live/scope.py",
    "pipeline": "live/pipeline.py",
    "testapp": "live/testapp.py",
}


def _maybe(path: str):
    p = Path(path)
    return sha256_file(p) if p.exists() else None


def build(tag: str = "xss-specialist-live-v1", out_dir="registry/releases") -> dict:
    comp = {}
    for name, path in COMPONENT_FILES.items():
        h = _maybe(path)
        comp[name] = {"path": path, "sha256": h}
    # model + adapters
    models = {}
    for label, p in [("base_config", "models/qwen3-8b-4bit/config.json"),
                     ("adapter_v1", "models/adapters/xss-v1/adapters.safetensors"),
                     ("adapter_v2", "models/adapters/xss-v2/adapters.safetensors"),
                     ("adapter_v3", "models/adapters/xss-v3/adapters.safetensors")]:
        models[label] = _maybe(p)
    # KEV pin, sanitizer DB, thresholds, benchmarks
    extras = {}
    if Path("provenance/kev.json").exists():
        extras["kev_pin"] = json.loads(Path("provenance/kev.json").read_text())
    from live.sanitizer_id import KNOWN_SAFE
    extras["sanitizer_db_sha256"] = sha256_text(json.dumps(KNOWN_SAFE, sort_keys=True))
    from live.evaluate import FROZEN_ACCEPTANCE
    extras["live_v1_acceptance"] = FROZEN_ACCEPTANCE
    from live.findings import CONFIRMED, LIKELY   # noqa
    # frozen XSSBench (offline) checksum, without reading its labels beyond hashing bytes
    bench = {}
    fz = Path("benchmarks/frozen/manifest.json")
    if fz.exists():
        bench["xssbench_manifest_sha256"] = sha256_file(fz)
    lb = Path("reports/live_assessments/local_eval/metrics.json")
    if lb.exists():
        bench["live_v1_local_eval_sha256"] = sha256_file(lb)

    manifest = {
        "tag": tag,
        "git_commit": env_manifest().get("git_commit"),
        "env": env_manifest(),
        "components": comp,
        "models": models,
        "extras": extras,
        "benchmarks": bench,
    }
    manifest["release_sha256"] = sha256_text(json.dumps(
        {"components": comp, "models": models, "extras": extras, "benchmarks": bench},
        sort_keys=True))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / f"{tag}.json", manifest)
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="xss-specialist-live-v1")
    a = ap.parse_args()
    m = build(a.tag)
    print(f"release {m['tag']} -> registry/releases/{m['tag']}.json")
    print("release_sha256", m["release_sha256"][:16], "| git", (m["git_commit"] or "")[:12])
    print("components hashed:", sum(1 for c in m["components"].values() if c["sha256"]))
    print("models hashed:", sum(1 for v in m["models"].values() if v))
