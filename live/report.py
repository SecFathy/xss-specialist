"""Evidence-backed reporting + artifact preservation for a live assessment.

Writes everything reproducibly under reports/live_assessments/<name>/ WITHOUT touching existing
research results: crawl graph, route/input/candidate inventories, probe log, browser evidence,
findings, scope log, request log, and a markdown report with per-finding schema + target summary.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from xss_specialist.repro import write_json


def _finding_md(f) -> str:
    return "\n".join([
        f"### {f.finding_id} — {f.status} ({f.xss_class})",
        f"- **URL:** {f.url}",
        f"- **Method / Parameter:** {f.method} / `{f.parameter}`",
        f"- **Execution context:** {f.context}",
        f"- **Source → Sink:** {f.source or '—'} → {f.sink or '—'}",
        f"- **Existing sanitizer:** {f.existing_sanitizer or 'none observed'}",
        f"- **Sanitizer identity verification:** {f.sanitizer_verification}",
        f"- **Browser verification:** {f.browser_result} (oracle-authoritative for CONFIRMED)",
        f"- **Confidence:** {f.confidence:.2f}",
        f"- **Impact:** {f.impact}",
        f"- **Remediation:** {f.remediation}",
        f"- **Reproduction:** `{f.reproduction.get('requested_url','')}` "
        f"(marker `{f.reproduction.get('marker','')}`, note: {f.reproduction.get('probe_note','')})",
        f"- **Evidence refs:** {', '.join(x for x in f.evidence_refs if x) or '—'}",
        "",
    ])


def save_assessment(name, scope, enforcer, crawl_result, candidates, assess_result,
                    base_dir="reports/live_assessments") -> dict:
    out = Path(base_dir) / name
    out.mkdir(parents=True, exist_ok=True)
    findings = [r["finding"] for r in assess_result["results"]]

    # inventories + logs (JSON/JSONL artifacts)
    write_json(out / "scope.json", {k: v for k, v in scope.__dict__.items()})
    write_json(out / "crawl_graph.json", crawl_result.get("graph", []))
    write_json(out / "route_inventory.json", crawl_result.get("routes", []))
    write_json(out / "js_routes.json", crawl_result.get("js_routes", []))
    write_json(out / "input_inventory.json", crawl_result.get("forms", []))
    write_json(out / "candidate_inventory.json", candidates)
    (out / "request_log.jsonl").write_text(
        "\n".join(json.dumps(r) for r in enforcer.request_log) + "\n")
    (out / "scope_blocked.jsonl").write_text(
        "\n".join(json.dumps(b) for b in enforcer.blocked_log) + "\n")
    # probe log + browser evidence
    probe_log, browser_ev = [], []
    for r in assess_result["results"]:
        for ev in [r["marker_ev"]] + r["exec_evs"]:
            probe_log.append({"finding": r["finding"].finding_id,
                              "kind": ev.get("probe_kind", "marker"),
                              "note": ev.get("probe_note", ""), "url": ev.get("requested_url"),
                              "reflected_html": ev.get("reflected_html"),
                              "raw_reflected": ev.get("raw_reflected"),
                              "executed": ev.get("executed"), "blocked": ev.get("blocked")})
            browser_ev.append({"finding": r["finding"].finding_id, **{k: ev.get(k) for k in
                              ("requested_url", "final_url", "status", "reflected_html",
                               "reflected_dom", "raw_reflected", "executed", "console")}})
    (out / "probe_log.jsonl").write_text("\n".join(json.dumps(p) for p in probe_log) + "\n")
    (out / "browser_evidence.jsonl").write_text("\n".join(json.dumps(b) for b in browser_ev) + "\n")
    (out / "findings.jsonl").write_text("\n".join(json.dumps(asdict(f)) for f in findings) + "\n")

    # summary counts
    def n(s): return sum(1 for f in findings if f.status == s)
    summary = {
        "target": scope.base_url,
        "routes_discovered": len(crawl_result.get("routes", [])),
        "js_routes_discovered": len(crawl_result.get("js_routes", [])),
        "inputs_discovered": len(candidates),
        "candidates_tested": len(findings),
        "confirmed": n("CONFIRMED"), "likely": n("LIKELY"),
        "inconclusive": n("INCONCLUSIVE"), "not_vulnerable": n("NOT_VULNERABLE"),
        "requests_made": enforcer.requests_made,
        "out_of_scope_blocked": len(enforcer.blocked_log),
        "coverage_limitations": "Synthetic/authorized scope only; POST bodies and headers probed only "
                                "when enabled; execution requiring user interaction (hover/click) may "
                                "yield LIKELY not CONFIRMED.",
    }
    write_json(out / "summary.json", summary)

    # markdown report
    md = [f"# Live XSS Assessment — {scope.base_url}", "",
          "For authorized security testing only. Oracle is authoritative for CONFIRMED; model "
          "confidence never upgrades a finding.", "",
          "## Target summary", ""]
    for k, v in summary.items():
        md.append(f"- **{k.replace('_',' ')}:** {v}")
    md += ["", "## Findings (CONFIRMED / LIKELY)", ""]
    ranked = sorted(findings, key=lambda f: {"CONFIRMED": 0, "LIKELY": 1, "INCONCLUSIVE": 2,
                                             "NOT_VULNERABLE": 3}[f.status])
    for f in ranked:
        if f.status in ("CONFIRMED", "LIKELY"):
            md.append(_finding_md(f))
    md += ["## All candidate outcomes", "",
           "| finding | status | url | param | context | browser |", "|---|---|---|---|---|---|"]
    for f in ranked:
        md.append(f"| {f.finding_id} | {f.status} | {f.url} | `{f.parameter}` | {f.context} | {f.browser_result} |")
    (out / "report.md").write_text("\n".join(md) + "\n")
    return {"dir": str(out), "summary": summary}
