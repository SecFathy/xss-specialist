"""Fast model-free/network-free tests for the live-assessment subsystem."""
from live.scope import Scope, Enforcer
from live.probes import plan, _signature
from live.sanitizer_id import verify_identity
from live.findings import correlate, CONFIRMED, LIKELY, NOT_VULNERABLE


def test_scope_blocks_out_of_scope_and_redirect():
    s = Scope(base_url="http://127.0.0.1:8099/", allowed_prefixes=["/"])
    assert s.in_scope("http://127.0.0.1:8099/x")[0]
    assert not s.in_scope("http://evil.example/x")[0]
    e = Enforcer(s)
    e.note_request("http://127.0.0.1:8099/a", final_url="http://evil.example/r", status=302)
    assert any("redirect_out_of_scope" in b.get("reason", "") for b in e.blocked_log)


def test_sanitizer_nearmiss_never_inherits_safety():
    assert verify_identity("DOMPurify.sanitize").status == "VERIFIED_SAFE"
    v = verify_identity("DOMPvrify.sanitize")
    assert v.status == "UNKNOWN" and v.nearest_known == "DOMPurify.sanitize"
    assert verify_identity("totallyFake").status == "UNKNOWN"


def test_probe_marker_first_and_signature():
    cand = {"url": "http://127.0.0.1/x", "param": "q", "context": "html_text", "delivery": "query"}
    m = plan(cand, "marker")
    assert len(m) == 1 and m[0].kind == "marker" and "<" not in m[0].payload
    ex = plan(cand, "exec")
    assert ex and all(e.kind == "exec" for e in ex)
    assert _signature("<img src=x onerror=1>").startswith("<img")


def test_finding_confirmed_only_from_execution():
    cand = {"url": "u", "param": "q", "context": "html_text"}
    marker_ev = {"reflected_html": True}
    # executed -> CONFIRMED
    f = correlate(cand, marker_ev, [{"executed": True, "raw_reflected": True}], None, "F1")
    assert f.status == CONFIRMED
    # raw reflected but not executed -> LIKELY (never CONFIRMED without execution)
    f2 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], None, "F2")
    assert f2.status == LIKELY
    # reflected but encoded (no raw) -> NOT_VULNERABLE
    f3 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": False}], None, "F3")
    assert f3.status == NOT_VULNERABLE


def test_verified_safe_sanitizer_downgrades_but_unknown_does_not():
    cand = {"url": "u", "param": "q", "context": "html_text"}
    marker_ev = {"reflected_html": True}
    vs = verify_identity("DOMPurify.sanitize")
    f = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], vs, "F")
    assert f.status == NOT_VULNERABLE      # verified-safe sanitizer present
    uk = verify_identity("DOMPvrify.sanitize")
    f2 = correlate(cand, marker_ev, [{"executed": False, "raw_reflected": True}], uk, "F")
    assert f2.status == LIKELY             # near-miss must NOT grant safety


def test_pilot_refuses_without_acknowledgement():
    from live.pilot import PilotAuthorization, authorize
    a = PilotAuthorization(target="http://192.0.2.9/", operator_identity="op",
                           assessment_id="x", authorization_acknowledged=False)
    try:
        authorize(a, authorized_external=True)
        assert False
    except SystemExit:
        pass


def test_pilot_refuses_external_without_flag():
    from live.pilot import PilotAuthorization, authorize
    a = PilotAuthorization(target="http://192.0.2.9/", operator_identity="op",
                           assessment_id="x", authorization_acknowledged=True)
    try:
        authorize(a, authorized_external=False)
        assert False
    except SystemExit:
        pass


def test_js_code_probe_is_nondestructive():
    from live.probes import js_code_probe
    p = js_code_probe("query")
    assert p.kind == "exec" and "window.__X" in p.payload and "<" not in p.payload


def test_classify_quoted_vs_unquoted():
    from live.pipeline import classify_context
    q = classify_context('<input value="MARK', "MARK")
    u = classify_context('<div class=MARK', "MARK")
    assert q == "html_attr" and u == "html_attr_unquoted"
