"""Offline operational dashboard for authorized live assessments.

The dashboard reads summary and authorization metadata only. It intentionally does not ingest
probe payloads, browser evidence, request logs, or page content. This keeps operational monitoring
separate from potentially sensitive assessment evidence.
"""
from __future__ import annotations

import argparse
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from xss_specialist.repro import write_json


def _read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def collect(base_dir: str | Path = "reports/live_assessments") -> list[dict]:
    """Collect valid assessment summaries without reading detailed evidence artifacts."""
    root = Path(base_dir)
    rows = []
    if not root.exists():
        return rows
    for summary_path in sorted(root.glob("*/summary.json")):
        summary = _read_json(summary_path)
        if not summary or not summary.get("target"):
            continue
        authorization = _read_json(summary_path.parent / "authorization.json") or {}
        findings = sum(int(summary.get(k, 0) or 0) for k in
                       ("confirmed", "likely", "inconclusive", "not_vulnerable"))
        rows.append({
            "assessment_id": authorization.get("assessment_id", summary_path.parent.name),
            "target": summary["target"],
            "operator": authorization.get("operator_identity", "local/non-pilot"),
            "authorized_pilot": bool(authorization.get("authorization_acknowledged")),
            "human_review_recorded": (summary_path.parent / "HUMAN_REVIEW_REQUIRED.txt").exists(),
            "requests": int(summary.get("requests_made", 0) or 0),
            "candidates": int(summary.get("candidates_tested", findings) or 0),
            "confirmed": int(summary.get("confirmed", 0) or 0),
            "likely": int(summary.get("likely", 0) or 0),
            "inconclusive": int(summary.get("inconclusive", 0) or 0),
            "blocked": int(summary.get("out_of_scope_blocked", 0) or 0),
        })
    return rows


def metrics(rows: list[dict]) -> dict:
    total_candidates = sum(r["candidates"] for r in rows)
    total_inconclusive = sum(r["inconclusive"] for r in rows)
    return {
        "assessments": len(rows),
        "authorized_pilots": sum(r["authorized_pilot"] for r in rows),
        "requests": sum(r["requests"] for r in rows),
        "candidates": total_candidates,
        "confirmed": sum(r["confirmed"] for r in rows),
        "likely": sum(r["likely"] for r in rows),
        "inconclusive": total_inconclusive,
        "out_of_scope_blocked": sum(r["blocked"] for r in rows),
        "inconclusive_rate": (total_inconclusive / total_candidates if total_candidates else 0.0),
        "pilots_missing_review_record": sum(
            r["authorized_pilot"] and not r["human_review_recorded"] for r in rows),
    }


def _render(snapshot: dict) -> str:
    m = snapshot["metrics"]
    cards = "".join(
        f'<section><strong>{html.escape(label)}</strong><span>{html.escape(str(value))}</span></section>'
        for label, value in (
            ("Assessments", m["assessments"]), ("Authorized pilots", m["authorized_pilots"]),
            ("Requests", m["requests"]), ("Candidates", m["candidates"]),
            ("Confirmed", m["confirmed"]), ("Likely", m["likely"]),
            ("Inconclusive rate", f'{m["inconclusive_rate"]:.1%}'),
            ("Scope blocks", m["out_of_scope_blocked"]),
        ))
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in (
            r["assessment_id"], r["target"], r["operator"],
            "yes" if r["authorized_pilot"] else "no", r["requests"], r["candidates"],
            r["confirmed"], r["likely"], r["inconclusive"], r["blocked"],
            "yes" if r["human_review_recorded"] else "no")) + "</tr>"
        for r in snapshot["assessments"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>XSS Specialist Operations</title><style>
body{{font:14px system-ui,sans-serif;margin:2rem;color:#172033;background:#f5f7fa}}
h1{{margin-bottom:.25rem}} .note{{color:#526174}} .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:2rem 0}}
section{{background:white;border:1px solid #dce2ea;border-radius:8px;padding:1rem}} section span{{display:block;font-size:1.6rem;margin-top:.4rem}}
.table{{overflow:auto}} table{{border-collapse:collapse;width:100%;background:white}} th,td{{padding:.7rem;border:1px solid #dce2ea;text-align:left;white-space:nowrap}} th{{background:#eaf0f6}}
</style></head><body><h1>XSS Specialist Operations</h1>
<p class="note">Generated {html.escape(snapshot['generated_at'])}. Summary metadata only; detailed assessment evidence is intentionally excluded.</p>
<div class="cards">{cards}</div><div class="table"><table><thead><tr>
<th>Assessment</th><th>Target</th><th>Operator</th><th>Pilot</th><th>Requests</th><th>Candidates</th><th>Confirmed</th><th>Likely</th><th>Inconclusive</th><th>Blocked</th><th>Review record</th>
</tr></thead><tbody>{body}</tbody></table></div></body></html>"""


def build(base_dir: str | Path = "reports/live_assessments",
          out_dir: str | Path = "reports/monitoring") -> dict:
    rows = collect(base_dir)
    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics(rows),
        "assessments": rows,
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "snapshot.json", snapshot)
    (out / "dashboard.html").write_text(_render(snapshot))
    return snapshot


def main() -> None:
    ap = argparse.ArgumentParser(prog="xss-monitor")
    ap.add_argument("--assessments", default="reports/live_assessments")
    ap.add_argument("--out", default="reports/monitoring")
    args = ap.parse_args()
    snapshot = build(args.assessments, args.out)
    print(json.dumps(snapshot["metrics"], indent=2))
    print("dashboard ->", Path(args.out) / "dashboard.html")


if __name__ == "__main__":
    main()
