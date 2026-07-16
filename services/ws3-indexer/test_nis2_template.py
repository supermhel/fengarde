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
