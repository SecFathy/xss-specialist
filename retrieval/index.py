"""Phase 8 — XSS retrieval layer.

A compact, dependency-light retriever over the verified knowledge corpus. Embeddings are
TF-IDF character+word n-grams (deterministic, no network, no model download) with cosine
similarity — enough to measure the *effect* of retrieval on the specialist and to evaluate
retrieval quality itself (Recall@K etc.). Each chunk keeps source identity, section, date and
verification status so the model can cite evidence and volatile facts stay routed to RAG.

Swappable: the Retriever interface (context_for, search) is all the eval/runner needs, so a
stronger embedder can drop in later without touching callers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from knowledge.seed_corpus import build as build_corpus


@dataclass
class Chunk:
    id: str
    text: str
    source: str
    reference: str
    verify_status: str
    volatile: bool
    tags: list


class Retriever:
    def __init__(self, chunks: list[Chunk], top_k: int = 3):
        self.chunks = chunks
        self.top_k = top_k
        texts = [c.text for c in chunks]
        # word n-grams for prose match + char n-grams so code tokens (innerHTML, htmlspecialchars)
        # still retrieve when the corpus phrases them slightly differently.
        self._vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True, min_df=1)
        self._cvec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=1)
        self._mat = self._vec.fit_transform(texts)
        self._cmat = self._cvec.fit_transform(texts)

    @classmethod
    def load_default(cls, top_k: int = 3) -> "Retriever":
        chunks = []
        for it in build_corpus():
            chunks.append(Chunk(
                id=it.id, text=it.claim, source=it.provenance.source,
                reference=it.provenance.reference, verify_status=it.verify_status.value,
                volatile=it.volatile, tags=it.tags,
            ))
        return cls(chunks, top_k=top_k)

    def search(self, query: str, k: int | None = None) -> list[tuple[Chunk, float]]:
        k = k or self.top_k
        sims = (0.6 * cosine_similarity(self._vec.transform([query]), self._mat)[0]
                + 0.4 * cosine_similarity(self._cvec.transform([query]), self._cmat)[0])
        order = np.argsort(-sims)[:k]
        return [(self.chunks[i], float(sims[i])) for i in order]

    def context_for(self, record: dict) -> str:
        """Retrieval context for a case: query on its code plus context/family hints."""
        query = record["code"] + " " + record.get("context", "") + " " + record.get("language", "")
        hits = self.search(query)
        lines = []
        for c, s in hits:
            if s <= 0:
                continue
            lines.append(f"- [{c.source}] {c.text} (ref: {c.reference})")
        return "\n".join(lines)


if __name__ == "__main__":
    r = Retriever.load_default()
    for q in ["el.innerHTML = location.hash", "htmlspecialchars echo $_GET",
              "DOMPurify sanitize innerHTML"]:
        print("Q:", q)
        for c, s in r.search(q):
            print(f"   {s:.3f} {c.id} {c.text[:70]}")
