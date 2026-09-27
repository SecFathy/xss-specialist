"""Phase 24/25/26 — versioned model registry, rollback, and kill switch.

The registry is an append-only JSON log of adapter versions. Each entry records full lineage
(parent, base revision, dataset hash, adapter hash, KEV revision, eval results, promotion decision,
deployment status) so any deployed behaviour traces back to a training example and its verified
source. Rollback restores a prior version's pointer without retraining. The kill switch is a single
persisted flag that halts consolidation/training/promotion while leaving inference and audit intact.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from xss_specialist.repro import write_json

REGISTRY_PATH = Path("registry/registry.json")
STATE_PATH = Path("registry/state.json")


@dataclass
class Version:
    version: str
    parent: str | None
    base_model: str
    base_revision: str
    adapter_path: str
    adapter_sha256: str | None
    dataset_sha256: str
    kev_revision: str
    eval_results: dict = field(default_factory=dict)
    promotion: str = "candidate"     # candidate | promoted | rejected
    deployment: str = "none"         # none | shadow | canary | production
    created: float = field(default_factory=time.time)
    notes: str = ""


class Registry:
    def __init__(self, path: Path = REGISTRY_PATH):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text()) if self.path.exists() else \
            {"versions": [], "current": None, "rollback_target": None}

    def _save(self):
        write_json(self.path, self.data)

    def add(self, v: Version) -> str:
        assert all(x["version"] != v.version for x in self.data["versions"]), f"dup {v.version}"
        self.data["versions"].append(asdict(v))
        self._save()
        return v.version

    def get(self, version: str) -> dict | None:
        return next((x for x in self.data["versions"] if x["version"] == version), None)

    def promote(self, version: str, deployment: str = "shadow"):
        v = self.get(version)
        assert v, version
        v["promotion"] = "promoted"
        v["deployment"] = deployment
        self.data["rollback_target"] = self.data["current"]   # remember prior good
        self.data["current"] = version
        self._save()

    def reject(self, version: str, reason: str = ""):
        v = self.get(version); assert v, version
        v["promotion"] = "rejected"; v["notes"] = reason
        self._save()

    def rollback(self) -> str | None:
        """Restore the previous current version without retraining."""
        target = self.data.get("rollback_target")
        if target is None:
            return None
        self.data["current"], self.data["rollback_target"] = target, self.data["current"]
        self._save()
        return target

    def current_adapter(self) -> str | None:
        cur = self.data.get("current")
        v = self.get(cur) if cur else None
        return v["adapter_path"] if v else None


# --- Kill switch (Phase 26) ---------------------------------------------------

def _state() -> dict:
    return json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else {"learning_enabled": True}


def learning_enabled() -> bool:
    return bool(_state().get("learning_enabled", True))


def set_learning(enabled: bool):
    s = _state(); s["learning_enabled"] = bool(enabled)
    write_json(STATE_PATH, s)


def require_learning_enabled(stage: str):
    """Gate used by consolidation/training/promotion. Inference never calls this."""
    if not learning_enabled():
        raise SystemExit(f"KILL SWITCH ACTIVE: {stage} blocked (learning_enabled=false). "
                         f"Inference and audit continue; consolidation/training/promotion halted.")
