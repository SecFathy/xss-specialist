"""Phase 8 — retrieval quality, evaluated independently of the model.

Gold relevance is authored per case *template* (the sink/family determines which corpus claims
support a correct analysis). We report Recall@K, Precision@K, MRR and nDCG over the frozen splits.
This measures the retriever alone; its effect on the model is measured by baseline B vs A.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from retrieval.index import Retriever

# Relevance map: substring found in a case id/tags -> set of supporting corpus item ids.
RELEVANCE = {
    "dom_innerhtml": {"k-008", "k-009", "k-004", "k-013"},
    "doc_write": {"k-010", "k-009", "k-004"},
    "reflected_html": {"k-002", "k-006", "k-026"},
    "react_dsih": {"k-020"},
    "js_eval": {"k-011", "k-013"},
    "attr_href": {"k-012", "k-025"},
    "jquery_html": {"k-031", "k-008"},
    "insert_adjacent": {"k-030", "k-009"},
    "wrapped_render": {"k-008", "k-009", "k-004"},
    "nm": {"k-015", "k-008"},          # near-miss: DOMPurify sanitizer + innerHTML sink
    "adv-mxss": {"k-014", "k-016", "k-015"},
    "adv-wrongctx": {"k-023", "k-024", "k-005"},
    "adv-setattr": {"k-029", "k-028"},
    "adv-alias": {"k-008", "k-009"},
    "adv-safe-json": {"k-023", "k-024"},
}


def _gold(record: dict) -> set:
    rid = record["id"]
    tags = record.get("tags", [])
    for key, ids in RELEVANCE.items():
        if key in rid or key in tags:
            return ids
    return set()


def evaluate(frozen="benchmarks/frozen", splits=("dev", "generalization", "nearmiss", "adversarial"),
             k=3):
    r = Retriever.load_default(top_k=k)
    per_split = {}
    for s in splits:
        recs = [json.loads(l) for l in Path(f"{frozen}/{s}.jsonl").read_text().splitlines() if l.strip()]
        recalls, precs, rrs, ndcgs, scored = [], [], [], [], 0
        for rec in recs:
            gold = _gold(rec)
            if not gold:
                continue
            scored += 1
            hits = r.search(rec["code"] + " " + rec.get("context", ""), k)
            ranked = [c.id for c, _ in hits]
            rel = [1 if cid in gold else 0 for cid in ranked]
            recalls.append(sum(rel) / len(gold))
            precs.append(sum(rel) / k)
            rr = 0.0
            for i, x in enumerate(rel):
                if x:
                    rr = 1.0 / (i + 1); break
            rrs.append(rr)
            dcg = sum(x / math.log2(i + 2) for i, x in enumerate(rel))
            idcg = sum(1 / math.log2(i + 2) for i in range(min(len(gold), k)))
            ndcgs.append(dcg / idcg if idcg else 0.0)
        n = max(1, len(recalls))
        per_split[s] = {
            "scored_cases": scored,
            f"recall@{k}": sum(recalls) / n, f"precision@{k}": sum(precs) / n,
            "mrr": sum(rrs) / n, f"ndcg@{k}": sum(ndcgs) / n,
        }
    return per_split


if __name__ == "__main__":
    res = evaluate()
    for s, m in res.items():
        print(f"{s:15s}", {k: round(v, 3) if isinstance(v, float) else v for k, v in m.items()})
