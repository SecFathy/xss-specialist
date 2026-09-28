import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from xss_decision.evaluate import evaluate, fit_temperature, read_partition, summarize
from xss_decision.learned import canonical_state
from xss_decision.questions import XSS_QUESTIONS_V2
from xss_decision.schema import Question
from xss_decision.serve import app
from xss_decision.train import target_mode
from xss_decision.data import build
from xss_decision.promotion import research_gate
from xss_decision.dataset import fixtures, validate_structure, freeze
from xss_decision.compare import paired_comparison
from xss_specialist.prompt import parse


def record(label="vulnerable", split="development"):
    return {"state": {"code": "untrusted data", "language": "javascript"},
            "_meta": {"id": "one", "group_id": "one", "split": split},
            "questions": {"verdict": {**XSS_QUESTIONS_V2["verdict"], "label": label}}}


def prediction(p):
    import math
    return {"probabilities": {"verdict": p}, "logits": {"verdict": {k: math.log(v) for k, v in p.items()}},
            "inference_temperature": 1.0, "latency_ms": 1}


def test_parser_exact_classification():
    assert parse("Classification: not vulnerable")["classification"] == "safe"
    assert parse("Classification: maybe vulnerable")["classification"] == "abstain"
    assert parse("Classification: vulnerable")["classification"] == "vulnerable"


def test_unknown_is_not_a_negative_and_abstention_does_not_inflate_recall():
    p = prediction({"vulnerable": .1, "safe": .1, "unknown": .8})
    m = summarize([{**record(label), "prediction": p} for label in ["vulnerable", "safe", "unknown"]])
    assert m["vulnerability_recall"] == 0
    assert m["vulnerable_abstention_rate"] == 1
    assert m["unknown_recall"] == 1
    assert m["known_coverage"] == 0 and m["known_selective_error"] is None


def test_all_safe_fails_recall():
    p = prediction({"vulnerable": .1, "safe": .8, "unknown": .1})
    m = summarize([{**record(label), "prediction": p} for label in ["vulnerable", "safe", "unknown"]])
    assert m["vulnerability_recall"] == 0 and m["false_safe_rate"] == 1
    assert m["unknown_overclaim_rate"] == 1


def test_temperature_never_fits_development_or_test():
    p = prediction({"vulnerable": .1, "safe": .8, "unknown": .1})
    with pytest.raises(ValueError, match="calibration-only"):
        fit_temperature([{**record(), "prediction": p}])
    result = fit_temperature([{**record(split="calibration"), "prediction": p}])
    assert result["nll_fitted"] <= result["nll_raw"]


def test_locked_test_rejected_before_file_read(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"splits": {"test": {"locked": True, "file": "MISSING"}}}))
    with pytest.raises(ValueError, match="Locked test"):
        read_partition(tmp_path, "test")


def test_partition_hash_checked(tmp_path):
    raw = json.dumps(record(split="train")).encode() + b"\n"
    (tmp_path / "train.jsonl").write_bytes(raw)
    info = {"n": 1, "file": "train.jsonl", "sha256": hashlib.sha256(raw).hexdigest()}
    (tmp_path / "manifest.json").write_text(json.dumps({"splits": {"train": info}}))
    assert len(read_partition(tmp_path, "train")) == 1
    (tmp_path / "train.jsonl").write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="Hash mismatch"):
        read_partition(tmp_path, "train")


def test_permutation_maps_probabilities_by_key():
    def predictor(r):
        return prediction({k: .8 if k == "vulnerable" else .1 for k in r["questions"]["verdict"]["criteria"]})
    rows, m = evaluate([record()], predictor)
    assert m["permutation"]["verdict"]["flip_rate"] == 0
    assert m["permutation"]["verdict"]["max_probability_shift"] == 0


def test_canonical_state_keeps_list_order():
    assert list(canonical_state({"z": 1, "a": 2})) == ["a", "z"]
    assert canonical_state(["z", "a"]) == ["z", "a"]


def test_noul_and_choice_limits():
    with pytest.raises(ValueError): Question(type="noul", criteria=["yes", "no"])
    with pytest.raises(ValueError): Question(type="noul", criteria={"maybe": None})
    with pytest.raises(ValueError): Question(type="choice", criteria={str(i): None for i in range(256)})


def test_checkpoint_identity_not_caller_model(monkeypatch):
    class Fake:
        details = {"name": "learned-checkpoint", "backend": "test"}
        def answer(self, request):
            return {"model": "learned-checkpoint", "answers": {}, "usage": {"input_tokens": 0, "output_tokens": 0}, "latency_ms": 0}
    monkeypatch.setattr(app.state, "backend", Fake())
    client = TestClient(app)
    assert client.get("/v1/models").json()["models"][0]["name"] == "learned-checkpoint"
    assert client.post("/v1/systemone", json={"state": "x", "model": "fake", "questions": {"q": {"type": "noul"}}}).json()["model"] == "learned-checkpoint"


def test_mock_reports_its_actual_identity():
    from xss_decision.backend import HeuristicBackend
    from xss_decision.schema import DecisionRequest
    response = HeuristicBackend().answer(DecisionRequest(state="x", model="fake-learned", questions={"q": {"type": "noul"}}))
    assert response["model"] == "xss-decision-mock"


def test_warm_start_targets_must_match():
    assert target_mode(["q_proj", "v_proj"]) == "qv"
    assert target_mode(["nonexistent"]) == "unsupported"


def test_export_does_not_read_locked_or_train_on_dev(tmp_path):
    with pytest.raises(ValueError, match="locked-test"):
        build(tmp_path / "test.jsonl", tmp_path / "out.jsonl")
    with pytest.raises(ValueError, match="train partition"):
        build(tmp_path / "dev.jsonl", tmp_path / "out.jsonl", purpose="training")


def test_research_gate_never_promotes_all_safe_or_missing_metrics():
    result = research_gate({"split": "development", "vulnerability_recall": 0}, {"split": "development"})
    assert result["status"] == "REJECTED"
    assert "vulnerability_recall" in result["failed"]
    assert result["production_ready"] is False


def test_v2_balanced_and_group_disjoint():
    rows = fixtures()
    stats = validate_structure(rows)
    assert stats["records"] == 2160 and stats["groups"] == 360
    groups = {}
    for r in rows:
        m = r["_meta"]
        groups.setdefault(m["group_id"], set()).add(m["split"])
        if r["questions"]["verdict"]["label"] == "unknown":
            assert f"function {m['helper']}" not in r["state"]["code"]
            assert r["questions"]["defense"]["label"] == "unknown"
            assert "implementation was not supplied" not in r["state"]["code"]
        if r["questions"]["defense"]["label"] == "safe_dom_api":
            assert r["questions"]["context"]["label"] == "html_text"
        assert "label" not in r["state"] and "__xssDecisionExecuted" not in r["state"]["code"]
    assert all(len(v) == 1 for v in groups.values())
    for split in stats["counts"]:
        labels = [r["questions"]["verdict"]["label"] for r in rows if r["_meta"]["split"] == split]
        assert labels.count("safe") == labels.count("vulnerable") == labels.count("unknown")
    by_group = {}
    for r in rows:
        if r["_meta"]["id"].split("/")[-2] == "userValue":
            by_group.setdefault(r["_meta"]["group_id"], {})[r["questions"]["verdict"]["label"]] = r
    for trio in by_group.values():
        assert set(trio) == {"vulnerable", "safe", "unknown"}
        # Only helper implementation, not sink or source flow, changes.
        bodies = [r["state"]["code"].split("const box =", 1)[1] for r in trio.values()]
        assert len(set(bodies)) == 1
        assert len({r["_meta"]["helper"] for r in trio.values()}) == 1


def test_freeze_is_immutable_and_admits_no_conflicts(tmp_path):
    root = tmp_path / "suite"
    freeze(fixtures(), root)
    assert len(read_partition(root, "development")) == 216
    with pytest.raises(ValueError, match="Locked test"):
        read_partition(root, "test")
    with pytest.raises(ValueError, match="overwrite"):
        freeze(fixtures(), root)
    with pytest.raises(ValueError, match="Conflicting"):
        freeze(fixtures(), tmp_path / "bad", {"conflicts": [{}]})


def test_paired_bootstrap_requires_same_ids_and_labels():
    a = {**record(), "prediction": prediction({"vulnerable": .1, "safe": .8, "unknown": .1})}
    b = {**record(), "prediction": prediction({"vulnerable": .8, "safe": .1, "unknown": .1})}
    result = paired_comparison([a], [b], samples=100)
    assert result["deltas"]["verdict_accuracy"]["candidate_minus_parent"] == 1
    assert result["n_groups"] == 1
    with pytest.raises(ValueError, match="matching record IDs"):
        paired_comparison([a], [])
