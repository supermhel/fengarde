"""WS-3 incident-report hook tests (v0.4 Track R).

Covers: template rendering from a fixture alert, contract-schema validation
(the hard rules in contracts/reporting.md), the HTTP backend seam degrading
to the template on failure/invalid response, idempotent re-generation, and
the HTTP API (auth applied, GET/POST wiring).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import reporting  # noqa: E402
from storage.memory import MemoryStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


_ALERT = {
    "alert_id": "6f1c8a2e-test:203.0.113.5:123",
    "time": 1751500000000,
    "rule_id": "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01",
    "rule_title": "Authentication brute-force from single source",
    "level": "high",
    "score": 70,
    "sector": "common",
    "src_endpoint": {"ip": "203.0.113.5"},
    "actor": {"user": {"name": "root"}},
    "event_ids": ["evt-1"],
}


def test_template_backend_renders_and_validates():
    os.environ.pop("REPORT_BACKEND", None)
    os.environ.pop("ARGUS_SEC_REPORT_URL", None)
    report = reporting.generate_report(_ALERT, {"status": "new", "note": ""})
    check(report["status"] == "draft", "template report must be status=draft")
    check(bool(report["disclaimer"]), "template report must carry a disclaimer")
    check(report["backend"] == "template", "default backend must be template")
    check(report["citations"] == [], "template backend must have empty citations")
    check("brute-force" in report["body"], "body should reference the rule title")
    check(reporting._validate_backend_response(report), "own output must pass its own validator")


def test_validator_rejects_non_draft_status():
    bad = {"status": "final", "disclaimer": "x", "body": "y", "citations": []}
    check(not reporting._validate_backend_response(bad),
          "status != draft must be rejected (contract hard rule)")


def test_validator_rejects_missing_disclaimer():
    bad = {"status": "draft", "disclaimer": "", "body": "y", "citations": []}
    check(not reporting._validate_backend_response(bad),
          "empty disclaimer must be rejected (contract hard rule)")


def test_validator_accepts_missing_citations_as_additive():
    ok = {"status": "draft", "disclaimer": "x", "body": "y"}
    check(reporting._validate_backend_response(ok),
          "citations must be optional -- additive-field discipline (C3)")


def test_http_backend_degrades_to_template_on_bad_response():
    os.environ["REPORT_BACKEND"] = "http"
    os.environ["ARGUS_SEC_REPORT_URL"] = "http://127.0.0.1:1/does-not-exist"
    try:
        report = reporting.generate_report(_ALERT, {"status": "new", "note": ""})
        check(report["backend"] == "template", "connection failure must fall back to template")
        check(report["backend_degraded"] is True, "fallback must flag backend_degraded")
        check(report["status"] == "draft", "fallback report must still be draft")
    finally:
        os.environ.pop("REPORT_BACKEND", None)
        os.environ.pop("ARGUS_SEC_REPORT_URL", None)


def _serve(store):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _post(port, path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                  method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_api_generate_store_and_fetch():
    os.environ.pop("REPORT_BACKEND", None)
    store = MemoryStore()
    store.index("alerts-2026.07.10", _ALERT["alert_id"], dict(_ALERT))
    srv, port = _serve(store)
    try:
        code, report1 = _post(port, f"/alerts/{_ALERT['alert_id']}/report")
        check(code == 200, f"POST report should be 200, got {code}")
        check(report1["status"] == "draft", "generated report must be draft")

        code, fetched = _get(port, f"/alerts/{_ALERT['alert_id']}/report")
        check(code == 200, f"GET report should be 200 after generation, got {code}")
        check(fetched["report_id"] == report1["report_id"], "GET must return the stored report")

        # idempotent re-generation: same report_id, still a valid draft
        code, report2 = _post(port, f"/alerts/{_ALERT['alert_id']}/report")
        check(code == 200 and report2["report_id"] == report1["report_id"],
              "re-generation must be idempotent on report_id")
    finally:
        srv.shutdown(); srv.server_close()


def test_api_report_not_found_for_missing_alert():
    store = MemoryStore()
    srv, port = _serve(store)
    try:
        code, _ = _get(port, "/alerts/does-not-exist/report")
        check(code == 404, f"GET report for unknown alert should be 404, got {code}")
        code, _ = _post(port, "/alerts/does-not-exist/report")
        check(code == 404, f"POST report for unknown alert should be 404, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_api_report_requires_auth_when_key_set():
    os.environ["ARGUS_API_KEY"] = "s3cr3t"
    try:
        store = MemoryStore()
        store.index("alerts-2026.07.10", _ALERT["alert_id"], dict(_ALERT))
        srv, port = _serve(store)
        try:
            code, _ = _post(port, f"/alerts/{_ALERT['alert_id']}/report")
            check(code == 401, f"missing key should be 401, got {code}")
        finally:
            srv.shutdown(); srv.server_close()
    finally:
        os.environ.pop("ARGUS_API_KEY", None)


def main():
    test_template_backend_renders_and_validates()
    test_validator_rejects_non_draft_status()
    test_validator_rejects_missing_disclaimer()
    test_validator_accepts_missing_citations_as_additive()
    test_http_backend_degrades_to_template_on_bad_response()
    test_api_generate_store_and_fetch()
    test_api_report_not_found_for_missing_alert()
    test_api_report_requires_auth_when_key_set()
    if FAILS:
        print(f"[FAIL] ws3 reporting: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 reporting hook: template backend, contract validation, "
          "HTTP fallback, API wiring + auth")


if __name__ == "__main__":
    main()
