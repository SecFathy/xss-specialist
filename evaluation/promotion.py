"""Phase 20 — frozen promotion gate.

A candidate adapter is PROMOTED only if it clears every criterion below, measured against the
CANDIDATE's own eval and the baseline it must not regress. Criteria are frozen here (not tuned to
a candidate) and evaluated with exact evidence. The gate never silently weakens: a failed criterion
returns REJECT with the offending metric named.

Criteria (on dev + generalization + nearmiss + adversarial; the LOCKED test is read once, after a
gate PROMOTE, for the final report only):
  1. dev accuracy            >= baseline dev accuracy            (no in-distribution regression)
  2. generalization accuracy >= baseline - 0.02                  (structural generalization holds)
  3. near-miss leakage       <= 0.30  AND  <= baseline leakage    (entity binding improved)
  4. false-positive rate (dev+adversarial safe) <= baseline FPR  (fewer analyst false alarms)
  5. adversarial accuracy    >= baseline                         (no robustness regression)
  6. abstention rate (dev)   <= 0.25                              (not abstaining its way to safety)
"""
from __future__ import annotations

FROZEN = {
    "gen_tolerance": 0.02,
    "max_leakage": 0.30,
    "max_abstention": 0.25,
}


def _acc(m):  return m["accuracy_all"]
def _fpr(m):  return m["false_positive_rate"]
def _leak(m): return m.get("nearmiss", {}).get("leakage_rate", 1.0)


def evaluate(candidate: dict, baseline: dict) -> dict:
    """candidate/baseline: {split_name: metrics_dict}. Returns decision + per-criterion evidence."""
    checks = []

    def chk(name, ok, detail):
        checks.append({"criterion": name, "pass": bool(ok), "detail": detail})

    c_dev, b_dev = candidate["dev"], baseline["dev"]
    c_gen, b_gen = candidate["generalization"], baseline["generalization"]
    c_nm, b_nm = candidate["nearmiss"], baseline["nearmiss"]
    c_adv, b_adv = candidate["adversarial"], baseline["adversarial"]

    chk("dev_no_regression", _acc(c_dev) >= _acc(b_dev) - 1e-9,
        f"cand {_acc(c_dev):.3f} vs base {_acc(b_dev):.3f}")
    chk("generalization", _acc(c_gen) >= _acc(b_gen) - FROZEN["gen_tolerance"],
        f"cand {_acc(c_gen):.3f} vs base {_acc(b_gen):.3f} (tol {FROZEN['gen_tolerance']})")
    chk("nearmiss_leakage", _leak(c_nm) <= FROZEN["max_leakage"] and _leak(c_nm) <= _leak(b_nm) + 1e-9,
        f"cand leak {_leak(c_nm):.3f} vs base {_leak(b_nm):.3f} (max {FROZEN['max_leakage']})")
    # FPR over safe cases in dev + adversarial (analyst false alarms)
    chk("false_positive", _fpr(c_dev) <= _fpr(b_dev) + 1e-9 and _fpr(c_adv) <= _fpr(b_adv) + 1e-9,
        f"dev cand {_fpr(c_dev):.3f}/base {_fpr(b_dev):.3f}; adv cand {_fpr(c_adv):.3f}/base {_fpr(b_adv):.3f}")
    chk("adversarial", _acc(c_adv) >= _acc(b_adv) - 1e-9,
        f"cand {_acc(c_adv):.3f} vs base {_acc(b_adv):.3f}")
    chk("abstention", c_dev["abstention_rate"] <= FROZEN["max_abstention"],
        f"dev abstention {c_dev['abstention_rate']:.3f} (max {FROZEN['max_abstention']})")

    passed = all(c["pass"] for c in checks)
    return {"decision": "PROMOTE" if passed else "REJECT",
            "checks": checks,
            "failed": [c["criterion"] for c in checks if not c["pass"]]}
