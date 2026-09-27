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

