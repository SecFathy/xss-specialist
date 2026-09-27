"""Decision backend contract and deterministic CI reference implementation."""
from __future__ import annotations

import re
import time

from xss_decision.schema import DecisionRequest, state_text


def _normalized(weights: list[float]) -> list[float]:
    total = sum(weights)
    return [round(x / total, 6) for x in weights]


class HeuristicBackend:
    """Non-learned reference backend. It validates the API; it is not the released SLM."""
    model_name = "xss-decision-mock"

    def answer(self, request: DecisionRequest) -> dict:
        started = time.perf_counter()
        text = state_text(request.state)
        low = text.lower()
        unsafe_sink = any(x in low for x in
                          ("innerhtml", "outerhtml", "document.write", "eval(",
                           "insertadjacenthtml", "dangerouslysetinnerhtml"))
        untrusted = any(x in low for x in
                        ("location.", "urlsearchparams", "_get", "request.", "req.", "props"))
        exact_safe = any(x in text for x in ("textContent", "innerText", "DOMPurify.sanitize"))
        vulnerable = unsafe_sink and untrusted and not exact_safe
        answers = {}
        for qid, q in request.questions.items():
            if q.type == "noul":
                yes = 0.92 if vulnerable else 0.08
                if "browser" in (qid + " " + q.instructions).lower():
                    yes = 0.95 if vulnerable else 0.2
                answers[qid] = {"type": "noul", "noul": yes}
                continue
            options = list(q.criteria or [])
            chosen = self._choice(qid, q.instructions, options, low, vulnerable)
            weights = [0.7 if x == chosen else 0.3 / max(1, len(options) - 1) for x in options]
            probs = _normalized(weights)
            if q.type == "choice":
                answers[qid] = {"type": "choice", "choice": chosen,
                                "confidence": round(max(probs), 6),
                                "probabilities": dict(zip(options, probs))}
            else:
                score = sum(i * p for i, p in enumerate(probs))
                answers[qid] = {"type": "score", "score": round(score, 6),
                                "confidence": round(max(probs), 6),
                                "legend": {str(i): x for i, x in enumerate(options)},
                                "probabilities": {str(i): p for i, p in enumerate(probs)}}
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        return {"model": request.model, "answers": answers,
                "usage": {"input_tokens": len(re.findall(r"\S+", text)),
                          "output_tokens": len(answers)}, "latency_ms": elapsed}

    @staticmethod
    def _choice(qid: str, instructions: str, options: list[str], low: str,
                vulnerable: bool) -> str:
        subject = (qid + " " + instructions).lower()
        preferences = []
        if "context" in subject:
            preferences = ["dom_html" if "innerhtml" in low else "js_code" if "eval(" in low else "unknown"]
        elif "family" in subject:
            preferences = ["dom" if "location." in low else "reflected" if vulnerable else "safe"]
        elif "defense" in subject:
            preferences = ["safe_dom_api" if "textcontent" in low else
                           "sanitization" if "dompurify.sanitize" in low else "none"]
        elif vulnerable:
            preferences = ["high", "vulnerable", "yes"]
        else:
            preferences = ["none", "safe", "no", "unknown"]
        return next((x for x in preferences if x in options), options[0])

