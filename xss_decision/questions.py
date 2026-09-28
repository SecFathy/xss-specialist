"""Canonical XSS questions used for training, evaluation, and the playground."""
from __future__ import annotations

from xss_specialist.schema import Context, Defense, Family


DEFAULT_QUESTIONS = {
    "vulnerable": {
        "type": "noul",
        "instructions": "Does untrusted input reach an executable cross-site scripting sink?",
    },
    "family": {
        "type": "choice",
        "instructions": "Which XSS family best describes this case?",
        "criteria": {x.value: None for x in Family},
    },
    "context": {
        "type": "choice",
        "instructions": "What execution or output context receives the untrusted value?",
        "criteria": {x.value: None for x in Context},
    },
    "defense": {
        "type": "choice",
        "instructions": "What is the primary existing defense?",
        "criteria": {x.value: None for x in Defense},
    },
    "needs_browser_verification": {
        "type": "noul",
        "instructions": "Is browser execution evidence required before calling this finding confirmed?",
    },
}

# Versioned separately: historical boolean checkpoints and frozen benchmarks keep
# their original contract. Missing evidence is not a negative or positive label.
XSS_QUESTIONS_V2 = {
    "verdict": {
        "type": "choice",
        "instructions": "Using only the supplied evidence, classify the XSS data flow. Do not assume missing implementations are safe or unsafe.",
        "criteria": {
            "vulnerable": "Attacker-controlled input can reach an executable sink without an effective defense in this context.",
            "safe": "The supplied complete flow establishes an effective defense or a non-executable sink.",
            "unknown": "The evidence is insufficient to establish either vulnerability or safety.",
        },
    },
    "context": DEFAULT_QUESTIONS["context"],
    "defense": {
        "type": "choice",
        "instructions": "Which effective defense is established for this specific sink context? Select unknown when the relevant implementation is missing.",
        "criteria": {**{x.value: None for x in Defense}, "unknown": "Effectiveness cannot be established from the evidence."},
    },
}
