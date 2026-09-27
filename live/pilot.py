"""Phase 17/18 — authorized pilot mode.

A pilot requires an explicit, complete authorization record and refuses external targets before any
network access unless every gate is satisfied: local acceptance PASSED, `--authorized-external`, an
authorization acknowledgement, an operator identity, and an assessment id. Human review stays
mandatory; live findings are quarantine-only and never auto-train. Evidence (Phase 18) is preserved
by `live.report.save_assessment` plus the pilot authorization record.
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from live.assess import local_eval_passed
from live.scope import Scope


@dataclass
class PilotAuthorization:
    target: str
    operator_identity: str
    assessment_id: str
    authorization_acknowledged: bool
    allowed_hosts: list = field(default_factory=list)
    allowed_subdomains: list = field(default_factory=list)
    allowed_prefixes: list = field(default_factory=list)
    excluded_paths: list = field(default_factory=list)
    request_budget: int = 300
    rate_limit_rps: float = 3.0
    auth_config: dict = field(default_factory=dict)
    allowed_test_classes: list = field(default_factory=lambda: ["reflected", "dom"])
    stored_xss_permitted: bool = False


def _is_loopback(url):
    return (urlparse(url).hostname or "") in ("127.0.0.1", "localhost", "::1")


def authorize(auth: PilotAuthorization, authorized_external: bool) -> Scope:
    """Validate all gates and build a Scope, or refuse BEFORE any network access."""
    if not auth.authorization_acknowledged:
        raise SystemExit("REFUSED: authorization not acknowledged.")
    if not auth.operator_identity or not auth.assessment_id:
        raise SystemExit("REFUSED: operator identity and assessment id are required.")
    if not _is_loopback(auth.target):
        if not local_eval_passed():
            raise SystemExit("REFUSED: external pilot requires a PASSED local acceptance evaluation.")
        if not authorized_external:
            raise SystemExit("REFUSED: external target requires --authorized-external.")
    scope = Scope(base_url=auth.target, allowed_hosts=list(auth.allowed_hosts),
                  allowed_subdomains=list(auth.allowed_subdomains),
                  allowed_prefixes=auth.allowed_prefixes or None,
                  excluded_paths=list(auth.excluded_paths),
                  max_requests=auth.request_budget, rate_limit_rps=auth.rate_limit_rps,
                  auth=dict(auth.auth_config), authorized_external=authorized_external)
    return scope


def run_pilot(auth: PilotAuthorization, authorized_external: bool = False):
    from live.assess import run_assessment
    scope = authorize(auth, authorized_external)
    saved = run_assessment(scope, auth.assessment_id)
    # persist the authorization record alongside the evidence (Phase 18)
    Path(saved["dir"]).mkdir(parents=True, exist_ok=True)
    (Path(saved["dir"]) / "authorization.json").write_text(json.dumps(asdict(auth), indent=2))
    (Path(saved["dir"]) / "HUMAN_REVIEW_REQUIRED.txt").write_text(
        "Every finding requires human review before disclosure/action. Live findings are "
        "quarantine-only and MUST NOT auto-train the specialist.\n")
    return saved


def main():
    ap = argparse.ArgumentParser(prog="xss-pilot")
    ap.add_argument("--target", required=True)
    ap.add_argument("--operator", required=True)
    ap.add_argument("--assessment-id", required=True)
    ap.add_argument("--acknowledge-authorization", action="store_true")
    ap.add_argument("--allowed-prefix", action="append", default=[])
    ap.add_argument("--allowed-subdomain", action="append", default=[])
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--budget", type=int, default=300)
    ap.add_argument("--rate", type=float, default=3.0)
    ap.add_argument("--stored-xss", action="store_true")
    ap.add_argument("--authorized-external", action="store_true")
    a = ap.parse_args()
    auth = PilotAuthorization(
        target=a.target, operator_identity=a.operator, assessment_id=a.assessment_id,
        authorization_acknowledged=a.acknowledge_authorization,
        allowed_subdomains=a.allowed_subdomain, allowed_prefixes=a.allowed_prefix,
        excluded_paths=a.exclude, request_budget=a.budget, rate_limit_rps=a.rate,
        stored_xss_permitted=a.stored_xss)
    saved = run_pilot(auth, a.authorized_external)
    print(json.dumps(saved["summary"], indent=2))
    print("evidence ->", saved["dir"])


if __name__ == "__main__":
    main()
