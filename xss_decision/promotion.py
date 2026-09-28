"""Development-only research gate; never claims production or lab execution."""
from __future__ import annotations


RESEARCH_THRESHOLDS = {
    "vulnerability_recall_min": 0.8,
    "false_alarm_rate_max": 0.1,
    "unknown_overclaim_rate_max": 0.2,
    "verdict_accuracy_min": 0.75,
    "context_accuracy_min": 0.75,
    "permutation_flip_rate_max": 0.1,
}


def research_gate(candidate: dict, baseline: dict, comparison: dict | None = None) -> dict:
    """Thresholds must be frozen before candidate evaluation. Test is untouched.

    Passing is an eligibility check for independent evaluation, not a statistical
    claim of generalization: real-code and live-model tests remain necessary.
    """
    failed = []
    if candidate.get("split") != "development" or baseline.get("split") != "development":
        failed.append("development_only_selection")
    if not candidate.get("suite_manifest_sha256") or candidate.get("suite_manifest_sha256") != baseline.get("suite_manifest_sha256"):
        failed.append("same_suite_required")
    for metric, threshold, higher in [
        ("vulnerability_recall", RESEARCH_THRESHOLDS["vulnerability_recall_min"], True),
        ("false_alarm_rate", RESEARCH_THRESHOLDS["false_alarm_rate_max"], False),
        ("unknown_overclaim_rate", RESEARCH_THRESHOLDS["unknown_overclaim_rate_max"], False),
    ]:
        value = candidate.get(metric)
        if value is None or (value < threshold if higher else value > threshold): failed.append(metric)
    for qid in ("verdict", "context"):
        value = candidate.get("per_question_accuracy", {}).get(qid)
        if value is None or value < RESEARCH_THRESHOLDS[f"{qid}_accuracy_min"]: failed.append(f"{qid}_accuracy")
    permutation = candidate.get("permutation", {})
    if not permutation or any(v["n"] < 30 or v["flip_rate"] > RESEARCH_THRESHOLDS["permutation_flip_rate_max"] for v in permutation.values()):
        failed.append("permutation_stability")
    a = candidate.get("per_question_accuracy", {}).get("verdict", 0)
    b = baseline.get("per_question_accuracy", {}).get("verdict", 0)
    if a <= b: failed.append("no_verdict_improvement_over_parent")
    ci = (comparison or {}).get("deltas", {}).get("verdict_accuracy", {}).get("ci95")
    if not ci or ci[0] <= 0: failed.append("no_positive_paired_verdict_interval")
    return {"status": "REJECTED" if failed else "RESEARCH_ELIGIBLE", "failed": failed,
            "thresholds": RESEARCH_THRESHOLDS, "production_ready": False,
            "note": "No production release, statistical improvement claim, or confirmed XSS is established by this gate."}
