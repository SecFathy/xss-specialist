"""Versioned, deterministic local XSS fixtures; no LLM-generated gold labels.

Different structural wrappers are held out by partition. Identifier variants and
all three verdicts of a template stay together. This is a synthetic research
suite, not a substitute for independent real-codebase or live-lab evaluation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path

from xss_decision.learned import canonical_state
from xss_decision.questions import XSS_QUESTIONS_V2


HTML_ESCAPE = "function encodeHtml(s) { return String(s).replace(/[&<>\"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c])); }"
HELPER_NAMES = ("scrubInput", "cleanValue", "normalizeInput", "filterValue", "transformText", "sanitizeContent")


def helper_name(group: str) -> str:
    return HELPER_NAMES[int(hashlib.sha256(group.encode()).hexdigest(), 16) % len(HELPER_NAMES)]


def helper_definition(name: str, sink: str, safe: bool) -> str:
    if not safe:
        return f"function {name}(value) {{ return value; }}"
    if sink in {"eval", "function"}:
        return f"function {name}(value) {{ return JSON.stringify(value); }}"
    return HTML_ESCAPE + f"\nfunction {name}(value) {{ return encodeHtml(value); }}"
SOURCES = {
    "query": "new URLSearchParams(location.search).get('q') || ''",
    "fragment": "decodeURIComponent(location.hash.slice(1))",
    "window_name": "window.name",
    "stored": "localStorage.getItem('message') || ''",
}
WRAPPERS = [
    ("direct", "train", "BODY"),
    ("block", "train", "{ BODY }"),
    ("iife", "train", "(() => { BODY })();"),
    ("named_fn", "train", "function renderOutput() { BODY } renderOutput();"),
    ("arrow_fn", "train", "const renderOutput = () => { BODY }; renderOutput();"),
    ("object_method", "train", "const renderer = { run() { BODY } }; renderer.run();"),
    ("try_finally", "train", "try { BODY } finally { window.renderFinished = true; }"),
    ("loop_once", "calibration", "for (let iteration = 0; iteration < 1; iteration++) { BODY }"),
    ("record_arg", "development", "function display(record) { const VALUE = record.content; BODY } display({content: SOURCE});"),
    ("class_method", "test", "class OutputView { display() { BODY } } new OutputView().display();"),
]
SINKS = {
    "inner_html": ("dom_html", "box.innerHTML = VALUE;", "box.textContent = VALUE;", "safe_dom_api"),
    "outer_html": ("dom_html", "box.outerHTML = VALUE;", "box.textContent = VALUE;", "safe_dom_api"),
    "document_write": ("html_text", "document.open(); document.write(VALUE); document.close();", "document.open(); document.write(encodeHtml(VALUE)); document.close();", "contextual_encoding"),
    "adjacent_html": ("dom_html", "box.insertAdjacentHTML('beforeend', VALUE);", "box.insertAdjacentText('beforeend', VALUE);", "safe_dom_api"),
    "eval": ("js_code", "eval(VALUE);", "eval(JSON.stringify(VALUE));", "contextual_encoding"),
    "function": ("js_code", "new Function(VALUE)();", "new Function(JSON.stringify(VALUE))();", "contextual_encoding"),
    "html_text": ("html_text", "box.innerHTML = '<p>' + VALUE + '</p>';", "box.innerHTML = '<p>' + encodeHtml(VALUE) + '</p>';", "contextual_encoding"),
    "html_attribute": ("html_attr", "box.innerHTML = '<input value=\"' + VALUE + '\">';", "box.innerHTML = '<input value=\"' + encodeHtml(VALUE) + '\">';", "contextual_encoding"),
    "stored_html": ("dom_html", "localStorage.setItem('saved', VALUE); box.innerHTML = localStorage.getItem('saved');", "localStorage.setItem('saved', VALUE); box.textContent = localStorage.getItem('saved');", "safe_dom_api"),
}


def fixtures() -> list[dict]:
    records = []
    for sink, (context, unsafe, safe, defense) in SINKS.items():
        for source_name, source in SOURCES.items():
            for wrapper, split, shape in WRAPPERS:
                group = f"v2/{sink}/{source_name}/{wrapper}"
                helper = helper_name(group)
                for alias in ("userValue", "messageValue"):
                    for verdict in ("vulnerable", "safe", "unknown"):
                        paired_helper = alias == "userValue" or verdict == "unknown"
                        if paired_helper:
                            # The sink and callsite are identical across the three labels.
                            # Only the supplied helper implementation changes; unknown
                            # omits it. A name alone is never the ground-truth rule.
                            body = f"const transformed = {helper}({alias});\n" + unsafe.replace("VALUE", "transformed")
                            pre = "" if verdict == "unknown" else helper_definition(helper, sink, verdict == "safe")
                            effective_defense = "unknown" if verdict == "unknown" else "contextual_encoding" if verdict == "safe" else "none"
                        else:
                            operation = safe if verdict == "safe" else unsafe
                            body = operation.replace("VALUE", alias)
                            pre = HTML_ESCAPE if verdict == "safe" and "encodeHtml" in operation else ""
                            effective_defense = defense if verdict == "safe" else "none"
                        if wrapper == "record_arg":
                            rendered = shape.replace("BODY", body).replace("VALUE", alias).replace("SOURCE", source)
                        else:
                            rendered = f"const {alias} = {source};\n" + shape.replace("BODY", body)
                        code = f"{pre}\nconst box = document.createElement('section');\ndocument.body.appendChild(box);\n{rendered}".strip()
                        effective_context = context
                        if verdict == "safe" and effective_defense == "safe_dom_api":
                            effective_context = "html_text"
                        elif verdict == "safe" and sink in {"eval", "function"}:
                            effective_context = "js_string"
                        labels = {"verdict": verdict, "context": effective_context,
                                  "defense": effective_defense}
                        questions = copy.deepcopy(XSS_QUESTIONS_V2)
                        for qid, q in questions.items():
                            q.update(label=labels[qid], src=f"xss_v2_{qid}")
                        records.append({
                            "state": canonical_state({"language": "javascript", "code": code}),
                            "questions": questions,
                            "_meta": {"id": f"{group}/{alias}/{verdict}", "group_id": group,
                                      "template_id": group, "source": "xss_decision_v2_synthetic",
                                      "split": split, "variant": "clean", "sink_family": sink,
                                      "source_kind": source_name, "label_method": "explicit_complete_flow_or_missing_dependency",
                                      "helper": helper if paired_helper else None,
                                      "review_status": "programmatic_semantics", "browser_status": "NOT_RUN"},
                        })
    return records


def validate_structure(records: list[dict]) -> dict:
    ids = set(); groups = {}; code_splits = {}; counts = Counter()
    for r in records:
        meta = r["_meta"]; rid = meta["id"]; group = meta["group_id"]; split = meta["split"]
        if rid in ids: raise ValueError("Duplicate record ID")
        ids.add(rid)
        if group in groups and groups[group] != split: raise ValueError("Template group crosses partitions")
        groups[group] = split
        code_hash = hashlib.sha256(r["state"]["code"].encode()).hexdigest()
        if code_hash in code_splits and code_splits[code_hash] != split: raise ValueError("Code crosses partitions")
        code_splits[code_hash] = split
        for q in r["questions"].values():
            if q["label"] not in q["criteria"]: raise ValueError("Label outside criteria")
        counts[split] += 1
    return {"records": len(records), "groups": len(groups), "counts": dict(counts), "group_disjoint": True, "exact_code_disjoint": True}


def verify_browser(records: list[dict]) -> dict:
    """Check every fixture, not just a sample. Unknown cases admit both completions.

    All browser requests are intercepted. No external lab, model-generated
    payload or target traffic is used. These checks never enter model state.
    """
    from playwright.sync_api import sync_playwright
    evidence = []; conflicts = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body="<!doctype html><body></body>"))
        def execute(code, probe):
            page.goto("http://127.0.0.1:8765/", wait_until="domcontentloaded")
            page.evaluate("""value => {
                window.__xssDecisionExecuted = 0; window.name = value;
                localStorage.clear(); localStorage.setItem('message', value);
                history.replaceState({}, '', '/?q=' + encodeURIComponent(value) + '#' + encodeURIComponent(value));
            }""", probe)
            error = page.evaluate("code => { try { (0, eval)(code); return null; } catch(e) { return String(e); } }", code)
            page.wait_for_timeout(35)
            return bool(page.evaluate("window.__xssDecisionExecuted === 1")), error
        for index, r in enumerate(records):
            verdict = r["questions"]["verdict"]["label"]
            js = r["_meta"]["sink_family"] in {"eval", "function"}
            probe = "window.__xssDecisionExecuted=1" if js else '"><img src=x onerror="window.__xssDecisionExecuted=1">'
            code = r["state"]["code"]
            if verdict == "unknown":
                helper = r["_meta"]["helper"]
                identity = helper_definition(helper, r["_meta"]["sink_family"], False) + "\n"
                escape = helper_definition(helper, r["_meta"]["sink_family"], True) + "\n"
                unsafe_result, unsafe_error = execute(identity + code, probe)
                safe_result, safe_error = execute(escape + code, probe)
                ok = unsafe_result and not safe_result and not unsafe_error and not safe_error
                ev = {"unsafe_completion_executed": unsafe_result, "safe_completion_executed": safe_result,
                      "unsafe_error": unsafe_error, "safe_error": safe_error}
            else:
                executed, error = execute(code, probe)
                ok = executed == (verdict == "vulnerable") and not error
                ev = {"executed": executed, "error": error}
            status = "PASS" if ok else "CONFLICT"
            r["_meta"]["browser_status"] = status
            ev.update(id=r["_meta"]["id"], status=status, code_sha256=hashlib.sha256(code.encode()).hexdigest())
            evidence.append(ev)
            if not ok: conflicts.append(ev)
            if (index + 1) % 100 == 0: print(f"browser-checked {index + 1}/{len(records)}, conflicts={len(conflicts)}", flush=True)
        browser.close()
    return {"checked": len(evidence), "conflicts": conflicts, "evidence": evidence,
            "scope": "Controlled local JS/HTML fixtures; one context-specific execution probe. Safe labels also rely on explicit code semantics."}


def freeze(records: list[dict], out: str | Path, verification: dict | None = None) -> dict:
    root = Path(out)
    if root.exists(): raise ValueError(f"Refusing to overwrite frozen suite: {root}")
    stats = validate_structure(records)
    if verification and verification["conflicts"]: raise ValueError("Conflicting browser checks; dataset is not admitted")
    root.mkdir(parents=True)
    manifest = {"schema_version": "xss-decision-v2", "synthetic": True,
                "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "limitations": ["JavaScript/HTML fixtures only", "No independent real-codebase or live-lab success claim", "Shared sink primitives across splits; structural wrappers held out", "Browser probe absence alone is not a safety proof"],
                "stats": stats, "splits": {}, "test_read": False,
                "verification": {k: v for k, v in (verification or {"checked": 0}).items() if k != "evidence"}}
    for split in ("train", "calibration", "development", "test"):
        rows = [r for r in records if r["_meta"]["split"] == split]
        # Do NOT sort entire rows: option order stays unchanged; state is canonical.
        raw = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode()
        (root / f"{split}.jsonl").write_bytes(raw)
        manifest["splits"][split] = {"file": f"{split}.jsonl", "n": len(rows), "locked": split == "test",
                                     "sha256": hashlib.sha256(raw).hexdigest(),
                                     "labels": dict(Counter(r["questions"]["verdict"]["label"] for r in rows)),
                                     "group_ids": sorted({r["_meta"]["group_id"] for r in rows})}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if verification:
        (root / "browser_verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/decision/xss-v2-local")
    ap.add_argument("--verify-browser", action="store_true")
    args = ap.parse_args()
    if Path(args.out).exists(): raise ValueError("Choose a new version; frozen suites are immutable")
    records = fixtures(); print(json.dumps(validate_structure(records)), flush=True)
    verification = verify_browser(records) if args.verify_browser else None
    manifest = freeze(records, args.out, verification)
    print(json.dumps({"out": args.out, "stats": manifest["stats"], "browser_checked": manifest["verification"]["checked"]}, indent=2))


if __name__ == "__main__": main()
