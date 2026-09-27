"""Inference backends. MLXBackend runs a local MLX model (+ optional LoRA adapter). MockBackend
is a deterministic rule-based stand-in so the whole pipeline and its tests run with no model
(used in CI and for dry runs). Both expose `generate(prompt) -> str`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache


@dataclass
class GenConfig:
    max_tokens: int = 640
    temp: float = 0.0          # deterministic decoding for reproducible eval
    seed: int = 0


class MockBackend:
    """Deterministic heuristic 'model'. Not a real LLM — it exists so the pipeline is testable
    offline. It reads the code out of the prompt and applies a few keyword rules to emit a
    structured analysis in the Phase-11 format. Its accuracy is intentionally modest."""
    name = "mock"

    VULN_SINKS = ("innerHTML", "outerHTML", "document.write", "eval(", ".html(",
                  "insertAdjacentHTML", "dangerouslySetInnerHTML", "setAttribute('onclick'",
                  "setAttribute(\"onclick\"")
    SAFE_MARKERS = ("textContent", "innerText", "htmlspecialchars", "json_encode",
                    "insertAdjacentText", ".text(", "Number(", "https?:")

    def generate(self, prompt: str, cfg: GenConfig | None = None) -> str:
        code = _extract_code(prompt)
        low = code
        vuln = any(s in low for s in self.VULN_SINKS)
        safe = any(re.search(re.escape(m).replace("https\\?", "https?"), low) for m in self.SAFE_MARKERS)
        # sanitizer must be exactly DOMPurify to count as safe (near-miss discipline)
        if "sanitize" in low and "DOMPurify.sanitize" not in low:
            vuln, safe = True, False
        verdict = "vulnerable" if (vuln and not safe) else "safe"
        conf = 0.7 if (vuln ^ safe) else 0.5
        return _fmt(verdict, conf,
                    source="location/param" if "location" in low or "_GET" in low or "props" in low else "unknown",
                    sink="innerHTML/eval/write" if vuln else "textContent/encoder",
                    ctx="dom_html")


class MLXBackend:
    """Local MLX generation. Loads once, caches. Optional adapter_path for a LoRA."""
    def __init__(self, model_path: str, adapter_path: str | None = None):
        self.model_path = model_path
        self.adapter_path = adapter_path
        self.name = f"mlx:{model_path.split('/')[-1]}" + (f"+{adapter_path.split('/')[-1]}" if adapter_path else "")
        self._model = None
        self._tok = None

    def _load(self):
        if self._model is None:
            from mlx_lm import load
            self._model, self._tok = load(
                self.model_path,
                adapter_path=self.adapter_path,
                tokenizer_config={"trust_remote_code": True},
            )
        return self._model, self._tok

    def generate(self, prompt: str, cfg: GenConfig | None = None) -> str:
        import mlx.core as mx
        from mlx_lm import generate as mlx_generate
        from mlx_lm.sample_utils import make_sampler
        cfg = cfg or GenConfig()
        model, tok = self._load()
        mx.random.seed(cfg.seed)
        msgs = [{"role": "user", "content": prompt}]
        text = tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False,
                                       enable_thinking=False)
        sampler = make_sampler(temp=cfg.temp)
        return mlx_generate(model, tok, prompt=text, max_tokens=cfg.max_tokens,
                            sampler=sampler, verbose=False)


def _extract_code(prompt: str) -> str:
    m = re.search(r"```[a-zA-Z]*\n(.*?)```", prompt, re.S)
    return m.group(1) if m else prompt


def _fmt(verdict, conf, source, sink, ctx):
    return (f"Classification: {verdict}\nConfidence: {conf:.2f}\n"
            f"Source: {source}\nTransformations: none\nSink: {sink}\n"
            f"Execution Context: {ctx}\nExisting Defense: none\n"
            f"Root Cause: heuristic\nEvidence: OBSERVED sink in code\n"
            f"Missing Evidence: none\nRisk Explanation: heuristic\n"
            f"Recommended Validation: manual review\nRemediation: contextual encoding / safe sink\n"
            f"References: internal\n")


@lru_cache(maxsize=4)
def get_backend(kind: str, model_path: str = "", adapter_path: str = "") -> object:
    if kind == "mock":
        return MockBackend()
    if kind == "mlx":
        return MLXBackend(model_path, adapter_path or None)
    raise ValueError(f"unknown backend {kind}")
