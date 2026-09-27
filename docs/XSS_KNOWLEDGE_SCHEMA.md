# XSS Knowledge Schema (Phase 1)

Machine-readable ontology in `xss_specialist/schema.py`. Controlled vocabularies:

- **families**: `reflected`, `stored`, `dom`, `mutation`, `template`, `client_injection`, `safe`
- **contexts**: `html_text`, `html_attr`, `html_attr_url`, `html_comment`, `js_string`, `js_code`, `url`, `css`, `dom_html`, `dom_attr`, `unknown`
- **roles**: `source`, `transform`, `sanitizer`, `encoder`, `decoder`, `parser`, `sink`
- **defenses**: `contextual_encoding`, `sanitization`, `csp`, `trusted_types`, `framework_escaping`, `safe_dom_api`, `input_constraint`, `architectural`, `none`
- **verdicts**: `observed`, `inferred`, `not_established`
- **verify_status**: `verified`, `conflicting`, `unverified`, `rejected`
- **origins**: `source`, `synthetic`

## Records

**KnowledgeItem** — a provenance-bearing XSS claim: id, claim, families, contexts, defenses, provenance (source/title/reference/section/date/license/origin), verify_status, confidence, volatile, tags, knowledge_version.

**XSSCase** — a code sample with labelled data-flow: id, code, language, family, vulnerable, context, flow (list of FlowNode: role/name/context/safe), existing_defense, root_cause, remediation, poc_payload, provenance, tags.

**Provenance.origin** strictly separates `source` (authoritative material) from `synthetic` (model/template generated) — never mixed unlabelled (Phase 2).

**Verdict** (`observed`/`inferred`/`not_established`) tags evidence epistemically in every analysis (Phase 11).
