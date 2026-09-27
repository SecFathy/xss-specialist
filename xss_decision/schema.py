"""Stable request/response contract for the XSS decision model."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class Question(BaseModel):
    type: Literal["noul", "choice", "score"]
    instructions: str = ""
    criteria: dict[str, str | None] | list[str] | None = None

    @model_validator(mode="after")
    def validate_criteria(self):
        if self.type == "choice" and not isinstance(self.criteria, dict):
            raise ValueError("choice criteria must be an option-to-description object")
        if self.type == "score" and not isinstance(self.criteria, list):
            raise ValueError("score criteria must be an ordered list")
        if self.type != "noul" and not self.criteria:
            raise ValueError(f"{self.type} requires at least one criterion")
        return self


class DecisionRequest(BaseModel):
    state: Any
    model: str = "xss-decision-latest"
    questions: dict[str, Question] = Field(min_length=1, max_length=64)


class Usage(BaseModel):
    input_tokens: int
    output_tokens: int


class DecisionResponse(BaseModel):
    model: str
    answers: dict[str, dict]
    usage: Usage
    latency_ms: float


def state_text(state: Any) -> str:
    """Serialize structured state deterministically for model input and audit logs."""
    if isinstance(state, str):
        return state
    import json
    return json.dumps(state, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

