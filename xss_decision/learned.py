"""Checkpoint-backed Kev inference. No heuristic fallback on load/inference errors."""
from __future__ import annotations

import threading
import time
import hashlib
import json
import math
from pathlib import Path

from xss_decision.schema import DecisionRequest


def canonical_state(value):
    """Canonicalize object keys, never ordered lists or choice criteria.

    Use the same operation before training export and serving. Choice order is
    preserved deliberately so permutation sensitivity can be measured honestly.
    """
    if isinstance(value, dict):
        return {k: canonical_state(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [canonical_state(v) for v in value]
    return value


class LearnedBackend:
    def __init__(self, run: str, device: str = "mps", backend: str = "auto",
                 temperature: float | None = None, calibration: str | None = None):
        try:
            from kev.checkpoint import Checkpoint, LoadOptions
        except ImportError as exc:
            raise RuntimeError("Kev is required: install the project's decision extra.") from exc
        checkpoint = Checkpoint(run)
        signature = {name: hashlib.sha256(Path(checkpoint.file(name)).read_bytes()).hexdigest()
                     for name in ("head.pt", "adapter_model.safetensors")}
        if calibration:
            fitted = json.loads(Path(calibration).read_text())
            if fitted.get("fit_split") != "calibration" or fitted.get("checkpoint_signature") != signature:
                raise ValueError("Calibration must come from this exact checkpoint's calibration-only evaluation")
            if temperature is not None: raise ValueError("Use either explicit temperature or a calibration file")
            temperature = fitted["temperature"]
        if temperature is not None and (not math.isfinite(temperature) or temperature <= 0):
            raise ValueError("Temperature must be finite and positive")
        self.tok, self.model = checkpoint.load(device, LoadOptions(backend=backend, temperature=temperature))
        self.model.eval()
        self.model_name = f"xss-decision:{Path(checkpoint.path).name}"
        self.lock = threading.Lock()
        self.details = {
            "name": self.model_name, "checkpoint": run,
            "resolved_checkpoint": checkpoint.path, "base": checkpoint.meta.base,
            "base_revision": checkpoint.meta.base_revision,
            "checkpoint_signature": signature, "calibration_file": calibration,
            "temperature": float(self.model.head.temperature),
            "backend": getattr(self.model, "backend", "torch"),
            "description": "Learned Kev pointer model; predictions are not browser execution evidence.",
        }

    def predict(self, payload: dict) -> dict:
        import torch
        from kev.api import SystemOneRequest, to_record
        started = time.perf_counter()
        payload = {"state": canonical_state(payload["state"]), "questions": {
            qid: {k: v for k, v in q.items() if k in {"type", "instructions", "criteria"}}
            for qid, q in payload["questions"].items()}}
        rec, meta = to_record(SystemOneRequest.model_validate(payload))
        with self.lock, torch.no_grad():
            enc = self.model.encode(self.tok, rec, strict=True, max_state=8192, max_branch=8192)
            logits = self.model.forward(enc)
            probabilities = [torch.softmax(z, -1).float().cpu().tolist() for z in logits]
            zs = [z.float().cpu().tolist() for z in logits]
        return {
            "probabilities": {m["id"]: dict(zip(m["keys"], p)) for m, p in zip(meta, probabilities)},
            "logits": {m["id"]: dict(zip(m["keys"], z)) for m, z in zip(meta, zs)},
            "inference_temperature": float(self.model.head.temperature),
            "input_tokens": len(enc["ids"]), "latency_ms": (time.perf_counter() - started) * 1000,
        }

    def answer(self, request: DecisionRequest) -> dict:
        from kev.api import SystemOneRequest, output_tokens, to_answers, to_record
        payload = request.model_dump(exclude={"model"})
        result = self.predict(payload)
        _, meta = to_record(SystemOneRequest.model_validate(payload))
        ps = [[result["probabilities"][m["id"]][k] for k in m["keys"]] for m in meta]
        answers = to_answers(ps, meta)
        return {"model": self.model_name, "answers": answers,
                "usage": {"input_tokens": result["input_tokens"], "output_tokens": output_tokens(self.tok, answers)},
                "latency_ms": result["latency_ms"]}
