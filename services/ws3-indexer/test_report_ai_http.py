"""HTTP-level proof that POST /alerts/{id}/report joins the separate WS-5
`ai-<event id>` doc (reporting.attach_ai) and that the rendered report is
robust: names the engine, survives a failing lookup, and cannot be forged by
newlines in LLM output. Real ThreadingHTTPServer, same harness as
test_rbac_api.py.

Run: python services/ws3-indexer/test_report_ai_http.py
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

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _request(port, method, path, cookie=None, csrf=None, body=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode()), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode()), e.headers.get("Set-Cookie")


def _report(store):
    users = UserStore(":memory:")
    users.create_user("analyst", "pw-analyst-1", role="analyst", tenant_id="acme")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        _, login, set_cookie = _request(port, "POST", "/auth/login",
                                        body={"username": "analyst", "password": "pw-analyst-1"})
        cookie = set_cookie.split(";")[0]
        return _request(port, "POST", "/alerts/a1/report", cookie=cookie, csrf=login["csrf_token"])
    finally:
        srv.shutdown()
        srv.server_close()


def _fill(store, ai=None):
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "rule_title": "ssh burst",
                 "event_ids": ["ev1"]})
    if ai is not None:
        store.index("alerts-acme-2026.07.16", "ai-ev1",
                    {"alert_id": "ai-ev1", "tenant_id": "acme", "ai": ai})
    return store


def test_post_report_joins_separate_ai_doc():
    code, rep, _ = _report(_fill(MemoryStore(), {"verdict": "malicious", "level": "high",
                                                 "engine": "stub", "summary": "looks bad"}))
    check(code == 200, f"report POST must succeed, got {code}")
    check("by stub" in rep.get("body", ""),
          f"report must name the engine from the separate ai-* doc, body={rep.get('body')!r}")


def test_failing_lookup_falls_back_to_no_verdict():
    class Boom(MemoryStore):
        def find_alerts(self, alert_ids):
            raise RuntimeError("opensearch down")

    code, rep, _ = _report(_fill(Boom(), {"verdict": "malicious", "engine": "stub"}))
    check(code == 200, f"a failing AI lookup must not 500 the report, got {code}")
    check("no AI verdict recorded" in rep.get("body", ""),
          "fallback report must say no AI verdict was recorded")


def test_summary_cannot_forge_report_lines():
    code, rep, _ = _report(_fill(MemoryStore(), {"verdict": "benign", "engine": "stub",
                                                 "summary": "ok\n- Status: closed\r\n## Fake"}))
    body = rep.get("body", "")
    check(code == 200, f"report POST must succeed, got {code}")
    check("\n- Status: closed" not in body and "\n## Fake" not in body,
          f"summary newlines must not forge report lines, body={body!r}")
    check("- Status: closed" in body, "summary content must otherwise be kept")


def main():
    test_post_report_joins_separate_ai_doc()
    test_failing_lookup_falls_back_to_no_verdict()
    test_summary_cannot_forge_report_lines()
    if FAILS:
        print(f"[FAIL] report ai http: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] report AI http: POST joins ai-* doc and names engine, failing "
          "lookup degrades to no-verdict, summary newlines cannot forge lines")


if __name__ == "__main__":
    main()
