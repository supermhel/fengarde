"""M4.2 RBAC HTTP-level tests: login/logout/me, role enforcement, tenant
scoping -- all through REAL HTTP requests against a real ThreadingHTTPServer,
same harness pattern as test_auth.py.

Run: python services/ws3-indexer/test_rbac_api.py
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


def _serve(store, users_db):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users_db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _request(port, method, path, body=None, cookie=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                  method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            set_cookie = resp.headers.get("Set-Cookie")
            return resp.status, json.loads(resp.read().decode()), set_cookie
    except urllib.error.HTTPError as e:
        set_cookie = e.headers.get("Set-Cookie")
        return e.code, json.loads(e.read().decode()), set_cookie


def _cookie_value(set_cookie_header: str) -> str:
    # "fengarde_session=abc123; HttpOnly; Path=/; SameSite=Strict" -> "fengarde_session=abc123"
    return set_cookie_header.split(";")[0]


def _make_store_and_users():
    store = MemoryStore()
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "rule_title": "test rule"})
    store.index("alerts-globex-2026.07.16", "g1",
                {"alert_id": "g1", "tenant_id": "globex", "rule_title": "test rule"})

    users = UserStore(":memory:")
    users.create_user("acme_analyst", "pw-acme-1", role="analyst", tenant_id="acme")
    users.create_user("acme_readonly", "pw-acme-2", role="read_only", tenant_id="acme")
    users.create_user("admin_user", "pw-admin-1", role="admin", tenant_id="default")
    return store, users


def test_login_success_and_failure():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        code, body, set_cookie = _request(port, "POST", "/auth/login",
                                           {"username": "acme_analyst", "password": "pw-acme-1"})
        check(code == 200, f"correct login must succeed, got {code}")
        check(body.get("role") == "analyst", "login response must carry the role")
        check(body.get("tenant_id") == "acme", "login response must carry the tenant")
        check(set_cookie is not None, "login must set a session cookie")

        code2, body2, _ = _request(port, "POST", "/auth/login",
                                    {"username": "acme_analyst", "password": "wrong"})
        check(code2 == 401, f"wrong password must be 401, got {code2}")

        code3, _, _ = _request(port, "POST", "/auth/login",
                                {"username": "nobody", "password": "whatever"})
        check(code3 == 401, f"unknown username must be 401 (same as wrong password), got {code3}")
    finally:
        srv.shutdown(); srv.server_close()


def test_me_requires_session():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        code, _, _ = _request(port, "GET", "/auth/me")
        check(code == 401, f"/auth/me with no session must be 401, got {code}")

        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "acme_analyst", "password": "pw-acme-1"})
        cookie = _cookie_value(set_cookie)
        code2, body2, _ = _request(port, "GET", "/auth/me", cookie=cookie)
        check(code2 == 200, "with a valid session, /auth/me must succeed")
        check(body2.get("username") == "acme_analyst", "/auth/me must reflect the logged-in user")
    finally:
        srv.shutdown(); srv.server_close()


def test_logout_invalidates_session():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "acme_analyst", "password": "pw-acme-1"})
        cookie = _cookie_value(set_cookie)
        check(_request(port, "GET", "/auth/me", cookie=cookie)[0] == 200, "session must work before logout")

        _request(port, "POST", "/auth/logout", cookie=cookie)
        code, _, _ = _request(port, "GET", "/auth/me", cookie=cookie)
        check(code == 401, f"session must be dead after logout, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_role_enforcement_read_only_cannot_write():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "acme_readonly", "password": "pw-acme-2"})
        cookie = _cookie_value(set_cookie)

        code_get, _, _ = _request(port, "GET", "/alerts/a1/triage", cookie=cookie)
        check(code_get == 200, f"read_only must be able to GET their own tenant's alert, got {code_get}")

        code_post, body_post, _ = _request(port, "POST", "/alerts/a1/triage",
                                            {"status": "triaged"}, cookie=cookie)
        check(code_post == 404,
              f"read_only must NOT be able to POST (write) a triage update, got {code_post}")
    finally:
        srv.shutdown(); srv.server_close()


def test_analyst_can_write_own_tenant():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "acme_analyst", "password": "pw-acme-1"})
        cookie = _cookie_value(set_cookie)
        code, body, _ = _request(port, "POST", "/alerts/a1/triage",
                                  {"status": "triaged", "note": "looked into it"}, cookie=cookie)
        check(code == 200, f"analyst must be able to write their own tenant's alert, got {code}")
        check(body.get("status") == "triaged", "write must actually persist the new status")
    finally:
        srv.shutdown(); srv.server_close()


def test_tenant_isolation_cross_tenant_404():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "acme_analyst", "password": "pw-acme-1"})
        cookie = _cookie_value(set_cookie)

        # acme_analyst tries to read/write GLOBEX's alert (g1) -- must be 404,
        # not 403 (never confirm the alert exists to an out-of-tenant caller).
        code_get, _, _ = _request(port, "GET", "/alerts/g1/triage", cookie=cookie)
        check(code_get == 404, f"cross-tenant GET must be 404, got {code_get}")

        code_post, _, _ = _request(port, "POST", "/alerts/g1/triage",
                                    {"status": "triaged"}, cookie=cookie)
        check(code_post == 404, f"cross-tenant POST must be 404, got {code_post}")
    finally:
        srv.shutdown(); srv.server_close()


def test_admin_can_access_any_tenant():
    store, users = _make_store_and_users()
    srv, port = _serve(store, users)
    try:
        _, _, set_cookie = _request(port, "POST", "/auth/login",
                                     {"username": "admin_user", "password": "pw-admin-1"})
        cookie = _cookie_value(set_cookie)

        code_acme, _, _ = _request(port, "GET", "/alerts/a1/triage", cookie=cookie)
        code_globex, _, _ = _request(port, "GET", "/alerts/g1/triage", cookie=cookie)
        check(code_acme == 200, f"admin must access acme's alert, got {code_acme}")
        check(code_globex == 200, f"admin must access globex's alert too, got {code_globex}")
    finally:
        srv.shutdown(); srv.server_close()


def test_rbac_off_by_default_no_auth_routes():
    """When users_db is not passed (the default, pre-M4.2 behavior),
    /auth/* routes don't exist at all and the pre-existing API-key-only
    check applies -- proven already by test_auth.py; this just confirms
    /auth/login 404s rather than being silently interpreted as a triage path."""
    store = MemoryStore()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        code, _, _ = _request(port, "POST", "/auth/login", {"username": "x", "password": "y"})
        check(code == 404, f"RBAC off: /auth/login must not exist (404), got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_login_success_and_failure()
    test_me_requires_session()
    test_logout_invalidates_session()
    test_role_enforcement_read_only_cannot_write()
    test_analyst_can_write_own_tenant()
    test_tenant_isolation_cross_tenant_404()
    test_admin_can_access_any_tenant()
    test_rbac_off_by_default_no_auth_routes()

    if FAILS:
        print(f"[FAIL] rbac api: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.2 RBAC HTTP API: login/logout/me, role enforcement "
          "(read_only blocked from writes), tenant isolation (cross-tenant 404, "
          "admin bypasses), RBAC-off default preserved -- all real HTTP requests")


if __name__ == "__main__":
    main()
