"""Phase 1 — XSS knowledge ontology (machine-readable).

Two layers:
  * the *ontology* — the controlled vocabularies the whole system reasons over
    (families, contexts, data-flow roles, defenses);
  * the record schemas — KnowledgeItem (a provenance-bearing claim) and
    XSSCase (a code sample with a labelled data-flow), which every benchmark
    item and training example is an instance of.

Everything is a plain dataclass with `to_dict`/`from_dict` so records serialize to
canonical JSON and hash stably (see repro.sha256_json).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


# --- Controlled vocabularies -------------------------------------------------

class Family(str, Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM = "dom"
    MUTATION = "mutation"          # mXSS
    TEMPLATE = "template"          # framework/template injection surface
    CLIENT_INJECTION = "client_injection"
    SAFE = "safe"                  # hard negative: not vulnerable


class Context(str, Enum):
    """Execution / output context the untrusted data lands in."""
    HTML_TEXT = "html_text"
    HTML_ATTR = "html_attr"
    HTML_ATTR_URL = "html_attr_url"        # href/src style attributes
    HTML_COMMENT = "html_comment"
    JS_STRING = "js_string"
    JS_CODE = "js_code"                     # e.g. inside a script block / eval sink
    URL = "url"
    CSS = "css"
    DOM_HTML = "dom_html"                   # innerHTML/outerHTML family
    DOM_ATTR = "dom_attr"
    UNKNOWN = "unknown"


class Role(str, Enum):
    """Role of a node in the data-flow graph of a case."""
    SOURCE = "source"
    TRANSFORM = "transform"        # arbitrary transformation (may be unsafe)
    SANITIZER = "sanitizer"        # intends to remove dangerous constructs
    ENCODER = "encoder"            # contextual output encoding
    DECODER = "decoder"
    PARSER = "parser"
    SINK = "sink"


class Defense(str, Enum):
    CONTEXTUAL_ENCODING = "contextual_encoding"
    SANITIZATION = "sanitization"
    CSP = "csp"
    TRUSTED_TYPES = "trusted_types"
    FRAMEWORK_ESCAPING = "framework_escaping"
    SAFE_DOM_API = "safe_dom_api"
    INPUT_CONSTRAINT = "input_constraint"
    ARCHITECTURAL = "architectural"
    NONE = "none"


class Verdict(str, Enum):
    """Epistemic status of a claim in an analysis, per Phase 11."""
    OBSERVED = "observed"          # present in the supplied code/evidence
    INFERRED = "inferred"          # reasoned from observed facts
    NOT_ESTABLISHED = "not_established"


class VerifyStatus(str, Enum):
    VERIFIED = "verified"
    CONFLICTING = "conflicting"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


class Origin(str, Enum):
    """Keeps factual source material and model-generated material strictly separate (Phase 2)."""
    SOURCE = "source"              # extracted from an authoritative document
    SYNTHETIC = "synthetic"        # generated for the project (teacher / templates)


# --- Provenance --------------------------------------------------------------

@dataclass
class Provenance:
    source: str                    # e.g. "OWASP", "CWE", "MDN", "template:v1"
    title: str = ""
    reference: str = ""            # URL or citation
    section: str = ""
    date: str = ""                 # ISO; volatile facts belong in RAG, not weights
    license: str = ""
    origin: Origin = Origin.SOURCE

    def to_dict(self) -> dict:
        d = asdict(self)
        d["origin"] = self.origin.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Provenance":
        d = dict(d)
        d["origin"] = Origin(d.get("origin", "source"))
        return cls(**d)


# --- Data-flow node ----------------------------------------------------------

@dataclass
class FlowNode:
    role: Role
    name: str                      # symbol / API, e.g. "location.hash", "innerHTML", "DOMPurify.sanitize"
    context: Context = Context.UNKNOWN
    safe: Optional[bool] = None    # for sanitizer/encoder: does it neutralize *this* context?

    def to_dict(self) -> dict:
        return {"role": self.role.value, "name": self.name,
                "context": self.context.value, "safe": self.safe}

    @classmethod
    def from_dict(cls, d: dict) -> "FlowNode":
        return cls(role=Role(d["role"]), name=d["name"],
                   context=Context(d.get("context", "unknown")), safe=d.get("safe"))


# --- Core records ------------------------------------------------------------

@dataclass
class XSSCase:
    """A code sample plus its ground-truth labelled data-flow. The unit of the
    benchmark and of teacher-generated training examples."""
    id: str
    code: str
    language: str                  # "html", "javascript", "jsx", "php", ...
    family: Family
    vulnerable: bool
    context: Context               # execution context at the sink
    flow: list[FlowNode] = field(default_factory=list)
    existing_defense: Defense = Defense.NONE
    root_cause: str = ""
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    provenance: Optional[Provenance] = None
    # Optional executable oracle (Phase used by verification / benchmark labels):
    # a URL param / payload that demonstrates execution in a headless browser.
    poc_payload: str = ""
    knowledge_version: str = "v1"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "code": self.code, "language": self.language,
            "family": self.family.value, "vulnerable": self.vulnerable,
            "context": self.context.value, "flow": [n.to_dict() for n in self.flow],
            "existing_defense": self.existing_defense.value,
            "root_cause": self.root_cause, "remediation": self.remediation,
            "tags": self.tags,
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "poc_payload": self.poc_payload, "knowledge_version": self.knowledge_version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "XSSCase":
        return cls(
            id=d["id"], code=d["code"], language=d["language"],
            family=Family(d["family"]), vulnerable=d["vulnerable"],
            context=Context(d["context"]),
            flow=[FlowNode.from_dict(n) for n in d.get("flow", [])],
            existing_defense=Defense(d.get("existing_defense", "none")),
            root_cause=d.get("root_cause", ""), remediation=d.get("remediation", ""),
            tags=d.get("tags", []),
            provenance=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
            poc_payload=d.get("poc_payload", ""),
            knowledge_version=d.get("knowledge_version", "v1"),
        )


@dataclass
class KnowledgeItem:
    """A single, provenance-bearing XSS claim. Lives in the knowledge store; may be
    routed to RAG only, or become a training candidate (Phase 13)."""
    id: str
    claim: str
    families: list[Family] = field(default_factory=list)
    contexts: list[Context] = field(default_factory=list)
    defenses: list[Defense] = field(default_factory=list)
    provenance: Optional[Provenance] = None
    verify_status: VerifyStatus = VerifyStatus.UNVERIFIED
    confidence: float = 0.0
    volatile: bool = False         # true => prefer RAG, keep out of weights
    tags: list[str] = field(default_factory=list)
    knowledge_version: str = "v1"

    def to_dict(self) -> dict:
        return {
            "id": self.id, "claim": self.claim,
            "families": [f.value for f in self.families],
            "contexts": [c.value for c in self.contexts],
            "defenses": [d.value for d in self.defenses],
            "provenance": self.provenance.to_dict() if self.provenance else None,
            "verify_status": self.verify_status.value, "confidence": self.confidence,
            "volatile": self.volatile, "tags": self.tags,
            "knowledge_version": self.knowledge_version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KnowledgeItem":
        return cls(
            id=d["id"], claim=d["claim"],
            families=[Family(x) for x in d.get("families", [])],
            contexts=[Context(x) for x in d.get("contexts", [])],
            defenses=[Defense(x) for x in d.get("defenses", [])],
            provenance=Provenance.from_dict(d["provenance"]) if d.get("provenance") else None,
            verify_status=VerifyStatus(d.get("verify_status", "unverified")),
            confidence=d.get("confidence", 0.0), volatile=d.get("volatile", False),
            tags=d.get("tags", []), knowledge_version=d.get("knowledge_version", "v1"),
        )


# Convenience: the full ontology as data, for docs generation and validation.
ONTOLOGY = {
    "families": [e.value for e in Family],
    "contexts": [e.value for e in Context],
    "roles": [e.value for e in Role],
    "defenses": [e.value for e in Defense],
    "verdicts": [e.value for e in Verdict],
    "verify_status": [e.value for e in VerifyStatus],
    "origins": [e.value for e in Origin],
}
