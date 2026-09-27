import json

from fastapi.testclient import TestClient

from xss_decision.data import case_to_labelled_request, case_to_record
from xss_decision.questions import DEFAULT_QUESTIONS
from xss_decision.serve import app


def _case(vulnerable=True):
    return {
        "id": "case-1", "language": "javascript",
        "code": "out.innerHTML = location.hash" if vulnerable else "out.textContent = location.hash",
        "family": "dom" if vulnerable else "safe", "vulnerable": vulnerable,
        "context": "dom_html", "existing_defense": "none" if vulnerable else "safe_dom_api",
        "provenance": {"origin": "synthetic"}, "knowledge_version": "v1",
    }


def test_case_conversion_produces_pointer_labels():
    record = case_to_record(_case())
    questions = {q["id"]: q for q in record["questions"]}
    assert questions["vulnerable"]["options"] == ["no", "yes"]
    assert questions["vulnerable"]["label"] == 1
    assert questions["family"]["options"][questions["family"]["label"]] == "dom"
    assert questions["context"]["options"][questions["context"]["label"]] == "dom_html"

    labelled = case_to_labelled_request(_case())
    assert labelled["questions"]["vulnerable"]["label"] is True
    assert labelled["questions"]["family"]["label"] == "dom"
    assert labelled["questions"]["context"]["criteria"]["dom_html"] is None


def test_decision_api_returns_typed_probabilities():
    client = TestClient(app)
    response = client.post("/v1/systemone", json={
        "state": {"language": "javascript", "code": "out.innerHTML = location.hash"},
        "questions": DEFAULT_QUESTIONS,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["answers"]["vulnerable"]["noul"] > 0.9
    context = body["answers"]["context"]
    assert context["choice"] == "dom_html"
    assert abs(sum(context["probabilities"].values()) - 1.0) < 1e-5
    assert response.headers["x-request-id"]


def test_decision_api_rejects_invalid_choice():
    response = TestClient(app).post("/v1/systemone", json={
        "state": "code", "questions": {"context": {"type": "choice"}}
    })
    assert response.status_code == 422
