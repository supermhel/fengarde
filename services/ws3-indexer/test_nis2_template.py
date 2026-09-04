"""M5 NIS2 public template layer tests: the deterministic DE/EN renderer
(nis2_template.py) plus its wiring into the report HTTP API via
?template=nis2&stage=&lang=.

Run: python services/ws3-indexer/test_nis2_template.py
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import nis2_template  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_ALERT = {
    "alert_id": "a1", "time": 1751500000000, "rule_id": "rule-1",
    "rule_title": "DB privilege escalation", "level": "critical", "score": 85,
    "sector": "bank",
}
_TRIAGE = {"status": "triaged", "note": "looked into it"}


# -- render_nis2_report: pure-function structural tests ----------------------

def test_every_stage_and_language_renders_without_crashing():
    for stage in nis2_template.STAGES:
        for lang in nis2_template.LANGUAGES:
            body = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage=stage, lang=lang)
            check(isinstance(body, str) and len(body) > 0, f"{stage}/{lang} must render a nonempty body")


def test_disclaimer_appears_at_top_and_bottom():
    for lang in nis2_template.LANGUAGES:
        body = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="notification", lang=lang)
        disclaimer = nis2_template._DISCLAIMER[lang]
        check(body.count(disclaimer) >= 2,
              f"[{lang}] the disclaimer must appear at both the top and bottom of the draft")


def test_dora_vs_nis2_scope_caveat_is_present():
    for lang in nis2_template.LANGUAGES:
        body = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="notification", lang=lang)
        check("DORA" in body, f"[{lang}] the NIS2-vs-DORA scope caveat must be present, not silently omitted")


def test_stages_are_cumulative():
    """Art. 23(4)(b): the 72h notification updates the 24h early warning's
    info, not replaces it -- later stages must be a strict superset of
    earlier stages' sections."""
    ew = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="early_warning", lang="en")
    notif = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="notification", lang="en")
    final = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="final_report", lang="en")
    check(len(notif) > len(ew), "notification must be strictly longer than early_warning")
    check(len(final) > len(notif), "final_report must be strictly longer than notification")
    check("Early-warning fields" in notif, "notification must still carry the early-warning section")
    check("Notification fields" in final, "final_report must still carry the notification section")


def test_never_fabricates_entity_facts_always_a_placeholder():
    """The one hard correctness rule for a compliance-adjacent generator:
    nothing about the REPORTING ENTITY (name, classification, competent
    authority) is knowable from an alert -- every such field must be an
    explicit placeholder, never silently blank or guessed."""
    body = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="final_report", lang="en")
    ph = nis2_template._PLACEHOLDER["en"]
    check(body.count(ph) >= 5, f"entity/significance/root-cause fields must all be placeholders, got {body.count(ph)}")


def test_invalid_stage_and_lang_fall_back_gracefully():
    body = nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="not-a-real-stage", lang="fr")
    check(isinstance(body, str) and len(body) > 0,
          "an invalid stage/lang must degrade to defaults, never raise or return empty")


def test_tolerates_a_minimal_alert_doc():
    # fail-open, same discipline as reporting.py's generic template.
    body = nis2_template.render_nis2_report({}, {}, stage="notification", lang="de")
    check(isinstance(body, str) and len(body) > 0, "a near-empty alert doc must still render, not crash")


# -- build_report: response envelope matches contracts/reporting.md ----------

def test_build_report_matches_frozen_envelope():
    report = nis2_template.build_report(_ALERT, _TRIAGE, stage="notification", lang="de")
    check(report["report_id"] == "a1:report", "report_id must follow <alert_id>:report, same as the generic backend")
    check(report["format"] == "markdown", "format must be markdown")
    check(report["status"] == "draft", "status must be draft (contracts/reporting.md hard rule)")
    check(bool(report["disclaimer"]), "disclaimer must be non-empty (hard rule)")
    check(isinstance(report["citations"], list) and len(report["citations"]) >= 1,
          "the NIS2 template must cite its public sources (Art. 23 + BSIG)")
    check(report["backend"] == "template-nis2-de", "backend must identify itself distinctly from the generic template")
    check(report["backend_degraded"] is False, "a successful NIS2 render is never 'degraded'")


def _assert_required_fields_present(schema_node: dict, doc, path: str) -> None:
    """Minimal stdlib-only stand-in for jsonschema.validate()'s required-field
    check (gap-hunt 2026-09-04: the real jsonschema library isn't a declared
    dependency anywhere in this repo -- ADR-008 already rules out pulling in
    a heavyweight schema-validation package for one test; this walks the same
    schema file's own `required`/`properties` structure instead). Not a
    general JSON-Schema validator -- just enough to prove build_report's
    envelope carries every field contracts/nis2-de-schema.json requires,
    recursing into nested `type: object` properties."""
    for key in schema_node.get("required", []):
        check(isinstance(doc, dict) and key in doc,
              f"{path}.{key} is required by contracts/nis2-de-schema.json but missing")
    for key, subschema in schema_node.get("properties", {}).items():
        if subschema.get("type") == "object" and isinstance(doc, dict) and key in doc:
            _assert_required_fields_present(subschema, doc[key], f"{path}.{key}")


def test_build_report_envelope_matches_nis2_schema():
    """R3-#42: contracts/nis2-de-schema.json requires stage/language/
    disclaimer/entity/incident in the envelope; the generator used to ship
    all of that only inside the Markdown body. Prove build_report's envelope
    carries every field the schema requires (and never fabricates entity
    facts -- every entity field stays an explicit placeholder)."""
    import json
    schema_path = (HERE.parent.parent / "contracts" / "nis2-de-schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    report = nis2_template.build_report(_ALERT, _TRIAGE,
                                        stage="notification", lang="de")
    _assert_required_fields_present(schema, report, "report")

    check(report["stage"] == "notification" and report["language"] == "de",
          "the envelope must carry the real (coerced) stage/language")
    check(report["disclaimer"], "disclaimer is required by the schema and must be present")
    ent = report["entity"]
    check(all(v == nis2_template._PLACEHOLDER["de"]
              for v in (ent["name"], ent["sector_classification"], ent["competent_authority"])),
          "entity facts must remain ANALYST placeholders, never fabricated from the alert")
    inc = report["incident"]
    check(inc["title"] == _ALERT["rule_title"] and inc["severity"] == _ALERT["level"],
          "incident title/severity come from the real alert")
    check(inc["suspected_malicious"] is None and inc["cross_border_impact"] is None,
          "the early-warning boolean judgements default to null (not yet determined), per the schema")


def test_invalid_stage_lang_coercion_is_logged_loudly():
    """R3-#43: a typo'd ?stage= / ?lang= used to silently produce the wrong
    regulatory section. Coercion to defaults must now be logged (warn), not
    silent -- while still rendering, never raising."""
    import shared.log as shared_log

    class _FakeLog:
        def __init__(self):
            self.warnings = []

        def warn(self, msg, **fields):
            self.warnings.append(msg)

    fake = _FakeLog()
    real = shared_log.get_logger
    shared_log.get_logger = lambda *a, **k: fake
    try:
        nis2_template.build_report(_ALERT, _TRIAGE, stage="not-a-stage", lang="fr")
        nis2_template.render_nis2_report(_ALERT, _TRIAGE, stage="nope", lang="xx")
        # Review-fix (2026-09-04): build_incident_report's own lang guard used
        # to coerce silently (no _warn call) unlike the three sibling guards
        # above -- assert it now logs too, same as render_incident_report.
        _fake_pkg = {"incident_id": "inc-1", "package_id": "pkg-1", "blocks": [],
                     "chain": {"block_count": 0}}
        nis2_template.build_incident_report(_fake_pkg, verified=True, lang="zz")
    finally:
        shared_log.get_logger = real

    check(any("stage" in w and "not-a-stage" in w for w in fake.warnings),
          f"a bad stage must be logged loudly, got {fake.warnings}")
    check(any("lang" in w and "fr" in w for w in fake.warnings),
          f"a bad lang must be logged loudly, got {fake.warnings}")
    check(any("stage" in w and "nope" in w for w in fake.warnings),
          "render_nis2_report must also log its stage coercion")
    check(any("lang" in w and "xx" in w for w in fake.warnings),
          "render_nis2_report must also log its lang coercion")
    check(any("build_incident_report" in w and "zz" in w for w in fake.warnings),
          f"build_incident_report must also log its lang coercion (was silent "
          f"before this fix), got {fake.warnings}")


# -- HTTP wiring: ?template=nis2&stage=&lang= on the existing report route --

def _serve(store):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _post(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode())


def test_http_report_route_selects_nis2_template_via_query_params():
    store = MemoryStore()
    store.index("alerts-2026.07.16", "a1", dict(_ALERT))
    srv, port = _serve(store)
    try:
        code, body = _post(port, "/alerts/a1/report?template=nis2&stage=final_report&lang=en")
        check(code == 200, f"the NIS2 template mode must be a normal 200, got {code}")
        check(body["backend"] == "template-nis2-de", f"backend must reflect the NIS2 renderer, got {body}")
        check("Final report" in body["body"], "the requested stage (final_report) must be reflected in the body")
        check("DORA" in body["body"], "the scope caveat must survive the HTTP round trip")
    finally:
        srv.shutdown(); srv.server_close()


def test_http_report_route_without_template_param_keeps_generic_backend():
    store = MemoryStore()
    store.index("alerts-2026.07.16", "a1", dict(_ALERT))
    srv, port = _serve(store)
    try:
        code, body = _post(port, "/alerts/a1/report")
        check(code == 200, f"the plain (no query params) route must still work, got {code}")
        check(body["backend"] == "template", f"omitting ?template= must keep the pre-existing generic backend, got {body}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_every_stage_and_language_renders_without_crashing()
    test_disclaimer_appears_at_top_and_bottom()
    test_dora_vs_nis2_scope_caveat_is_present()
    test_stages_are_cumulative()
    test_never_fabricates_entity_facts_always_a_placeholder()
    test_invalid_stage_and_lang_fall_back_gracefully()
    test_tolerates_a_minimal_alert_doc()
    test_build_report_matches_frozen_envelope()
    test_build_report_envelope_matches_nis2_schema()
    test_invalid_stage_lang_coercion_is_logged_loudly()
    test_http_report_route_selects_nis2_template_via_query_params()
    test_http_report_route_without_template_param_keeps_generic_backend()

    if FAILS:
        print(f"[FAIL] nis2 template: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M5 NIS2 template: all 3 stages x 2 languages render, disclaimer top+bottom, "
          "NIS2-vs-DORA scope caveat present, stages cumulative (Art. 23(4)(b) 'updates' "
          "semantics), entity facts always placeholders (never fabricated), invalid "
          "stage/lang degrade gracefully, matches the frozen report envelope, and the "
          "HTTP report route correctly selects the NIS2 renderer via query params while "
          "preserving the pre-existing generic-backend default")


if __name__ == "__main__":
    main()
