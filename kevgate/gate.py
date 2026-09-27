"""Phase 12/13 — KEV as the knowledge-routing gate (frozen, zero-shot).

KEV is the Kev-4B *decision model* (a LoRA on Qwen3.5-4B-Base that answers typed questions about a
state document in one forward pass). We use it, unmodified, to ROUTE each candidate knowledge item
— not to decide truth. For each item we ask a fixed set of boolean (Noul) questions; KEV returns a
probability per question. We store the RAW probabilities and apply a deterministic routing rule.

Design boundaries the spec insists on:
  * KEV decides whether info deserves further processing, not whether it is true.
  * Raw probabilities are stored; verification (separate module) decides trust.
  * Volatile items are pushed to RAG, never to training.
  * Zero-shot, frozen: we do NOT fine-tune KEV.

Routes (Phase 13): IGNORE, RAG_ONLY, VERIFY, TRAINING_CANDIDATE, REJECT.
Loads the local kev-4b adapter via the third-party `kev` library (pinned by commit in provenance).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# third-party KEV, pinned by commit (see provenance/kev.json).
_KEV_REPO = Path(__file__).resolve().parents[2] / "adaptive-ai" / "third_party" / "kev"
_KEV_MODEL = Path(__file__).resolve().parents[2] / "adaptive-ai" / "models" / "kev-4b"

ROUTING_QUESTIONS = {
    "relevant_xss": "Is this text specifically about cross-site scripting (XSS): sources, sinks, "
                    "execution contexts, sanitization, encoding, CSP, or XSS remediation?",
    "reusable": "Does this state a general, reusable security principle that applies beyond one "
                "specific application or incident?",
    "volatile": "Is this a time-varying fact tied to a specific product version, CVE, or advisory "
                "that would go out of date?",
    "needs_verification": "Would a security engineer need to independently verify this claim before "
                          "relying on it, because it is specific or could be wrong?",
}

# Decision routes.
IGNORE, RAG_ONLY, VERIFY, TRAINING_CANDIDATE, REJECT = \
    "IGNORE", "RAG_ONLY", "VERIFY", "TRAINING_CANDIDATE", "REJECT"


@dataclass
class KevDecision:
    item_id: str
    probs: dict          # raw KEV probabilities per question (NOT truth)
    route: str
    reason: str
    kev_revision: str = ""


@dataclass
class KevGate:
    """Lazy in-process KEV. thresholds are the routing rule; all frozen and versioned."""
    thr_relevant: float = 0.5
    thr_reusable: float = 0.5
    thr_volatile: float = 0.5
    thr_verify: float = 0.5
    _server: object = field(default=None, repr=False)
    revision: str = ""

    def _load(self):
        if self._server is not None:
            return self._server
        if str(_KEV_REPO) not in sys.path:
            sys.path.insert(0, str(_KEV_REPO))
        import torch
        from dataclasses import replace
        from kev.checkpoint import Checkpoint, LoadOptions
        from kev.serve import Server
        try:
            from kev.device import default_device
            dev = default_device()
        except Exception:
            dev = "mps" if torch.backends.mps.is_available() else "cpu"
        opts = LoadOptions()
        if dev == "mps":
            opts = replace(opts, dtype=torch.bfloat16, attn="sdpa", backend="auto")
        ck = Checkpoint(str(_KEV_MODEL))
        tok, model = ck.load(dev, opts)
        self._server = Server(ck, tok, model, dev)
        try:
            self.revision = ck.release_date()
        except Exception:
            self.revision = "local"
        return self._server

    def _ask(self, state_text: str) -> dict:
        srv = self._load()
        sys.path.insert(0, str(_KEV_REPO)) if str(_KEV_REPO) not in sys.path else None
        from kev.api import SystemOneRequest
        questions = {k: {"type": "noul", "instructions": v} for k, v in ROUTING_QUESTIONS.items()}
        req = SystemOneRequest(state=state_text, questions=questions)
        ans = srv.answer(req)["answers"]
        # Noul answer = p(true); shape depends on kev.api.to_answers
        # Noul answer is p(true) under key "noul" (kev.api.to_answers).
        return {k: float(ans[k]["noul"]) for k in ROUTING_QUESTIONS}

    def route(self, item) -> KevDecision:
        """item: KnowledgeItem. Returns a routing decision with raw probs stored."""
        state = f"{item.claim}\n\n(source: {item.provenance.source} — {item.provenance.title})" \
            if item.provenance else item.claim
        p = self._ask(state)
        route, reason = self._rule(p, item)
        return KevDecision(item_id=item.id, probs=p, route=route, reason=reason,
                           kev_revision=self.revision)

    def _rule(self, p: dict, item) -> tuple[str, str]:
        if p["relevant_xss"] < self.thr_relevant:
            return IGNORE, f"not XSS-relevant (p={p['relevant_xss']:.2f})"
        if p["volatile"] >= self.thr_volatile or item.volatile:
            return RAG_ONLY, f"volatile (p={p['volatile']:.2f}) -> retrieval, not weights"
        if p["needs_verification"] >= self.thr_verify and item.verify_status.value != "verified":
            return VERIFY, f"needs verification (p={p['needs_verification']:.2f})"
        if p["reusable"] >= self.thr_reusable:
            return TRAINING_CANDIDATE, (f"reusable XSS principle (reuse={p['reusable']:.2f}, "
                                        f"relevant={p['relevant_xss']:.2f})")
        return RAG_ONLY, "relevant but not clearly reusable -> retrieval"
