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
from shared.users import UserStore  # noqa: E402
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
    os.environ.pop("FENGARDE_SEC_REPORT_URL", None)
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
    os.environ["FENGARDE_SEC_REPORT_URL"] = "http://127.0.0.1:1/does-not-exist"
    try:
        report = reporting.generate_report(_ALERT, {"status": "new", "note": ""})
        check(report["backend"] == "template", "connection failure must fall back to template")
        check(report["backend_degraded"] is True, "fallback must flag backend_degraded")
        check(report["status"] == "draft", "fallback report must still be draft")
    finally:
        os.environ.pop("REPORT_BACKEND", None)
        os.environ.pop("FENGARDE_SEC_REPORT_URL", None)


def _serve(store, users_db=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users_db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _login(port, username, password):
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/login", data=body,
                                  method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.headers.get("Set-Cookie").split(";")[0]


def _get_with_cookie(port, path, cookie):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


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


def test_api_report_malformed_content_length_is_400():
    store = MemoryStore()
    store.index("alerts-2026.07.10", _ALERT["alert_id"], dict(_ALERT))
    srv, port = _serve(store)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/alerts/{_ALERT['alert_id']}/report",
            data=b"{}", method="POST",
            headers={"Content-Type": "application/json"})
        req.add_unredirected_header("Content-Length", "abc")
        try:
            urllib.request.urlopen(req, timeout=5)
            check(False, "malformed Content-Length should not return 2xx")
        except urllib.error.HTTPError as e:
            check(e.code == 400, f"malformed Content-Length should be 400, got {e.code}")
        except OSError:
            # some client stacks abort locally on a bogus CL header -- the
            # server-side contract (reject, don't mis-drain) is what matters;
            # exercise it with a raw socket instead.
            import socket
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(b"POST /alerts/x/report HTTP/1.1\r\n"
                          b"Host: t\r\nContent-Length: abc\r\n\r\n")
                data = s.recv(1024).decode(errors="replace")
            check(" 400 " in data, f"raw request with bad CL should get 400, got {data[:60]!r}")
    finally:
        srv.shutdown(); srv.server_close()


def test_api_report_requires_auth_when_key_set():
    os.environ["FENGARDE_API_KEY"] = "s3cr3t"
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
        os.environ.pop("FENGARDE_API_KEY", None)


def test_api_report_missing_alert_doc_fails_closed_for_non_admin():
    """F2 regression (adversarial repo-wide bug hunt, 2026-07-16): the
    report GET tenant gate only ran `if found_alert is not None`. Reports
    (reports-*) and alerts (alerts-{tenant}-*) have independent retention,
    and a report document carries no tenant_id of its own -- so once the
    backing alert doc ages out or is deleted, the gate was skipped entirely
    and ANY logged-in caller (any tenant) could read the report. A
    non-admin must now get 404 when the alert can't be found to verify
    tenancy against; admin (whose role already grants cross-tenant
    visibility) and RBAC-off must be unaffected."""
    store = MemoryStore()
    # A report with NO backing alert doc -- simulates the alert having
    # aged out of its own, independent retention window.
    report_id = "ghost-alert:report"
    store.index("reports-2026.07.10", report_id, {
        "report_id": report_id, "alert_id": "ghost-alert", "format": "markdown",
        "body": "sensitive globex incident details", "status": "draft",
        "disclaimer": "DRAFT", "generated_at": 0, "backend": "template",
        "backend_degraded": False, "citations": [],
    })

    users = UserStore(":memory:")
    users.create_user("acme_analyst", "pw1", role="analyst", tenant_id="acme")
    users.create_user("admin_user", "pw2", role="admin", tenant_id="default")
    srv, port = _serve(store, users_db=users)
    try:
        cookie = _login(port, "acme_analyst", "pw1")
        code, _ = _get_with_cookie(port, "/alerts/ghost-alert/report", cookie)
        check(code == 404,
              f"a non-admin must be denied when the backing alert doc can't be found "
              f"to verify tenancy, got {code}")

        admin_cookie = _login(port, "admin_user", "pw2")
        code2, body2 = _get_with_cookie(port, "/alerts/ghost-alert/report", admin_cookie)
        check(code2 == 200 and body2.get("report_id") == report_id,
              f"admin must still be able to read a report with no backing alert doc, got {code2}")
    finally:
        srv.shutdown(); srv.server_close()

    # RBAC entirely off (the pre-M4.2 default) must be completely unaffected.
    store2 = MemoryStore()
    store2.index("reports-2026.07.10", report_id, {
        "report_id": report_id, "alert_id": "ghost-alert", "format": "markdown",
        "body": "x", "status": "draft", "disclaimer": "DRAFT", "generated_at": 0,
        "backend": "template", "backend_degraded": False, "citations": [],
    })
    srv2, port2 = _serve(store2)
    try:
        code3, body3 = _get(port2, "/alerts/ghost-alert/report")
        check(code3 == 200 and body3.get("report_id") == report_id,
              f"RBAC-off must be unaffected by this fix, got {code3}")
    finally:
        srv2.shutdown(); srv2.server_close()


def main():
    test_template_backend_renders_and_validates()
    test_validator_rejects_non_draft_status()
    test_validator_rejects_missing_disclaimer()
    test_validator_accepts_missing_citations_as_additive()
    test_http_backend_degrades_to_template_on_bad_response()
    test_api_generate_store_and_fetch()
    test_api_report_not_found_for_missing_alert()
    test_api_report_malformed_content_length_is_400()
    test_api_report_requires_auth_when_key_set()
    test_api_report_missing_alert_doc_fails_closed_for_non_admin()
    if FAILS:
        print(f"[FAIL] ws3 reporting: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-3 reporting hook: template backend, contract validation, "
          "HTTP fallback, API wiring + auth")


if __name__ == "__main__":
    main()
