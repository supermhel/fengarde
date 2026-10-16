"""Admin console routes (admin_api.py): users, webhooks, rule on/off.

Real HTTP against a real ThreadingHTTPServer, same harness as test_rbac_api.py.
Never writes the real contracts/tenants or reads the real contracts/webhooks:
rules_view.TENANTS_DIR and webhooks.WEBHOOKS_DIR are pointed at temp dirs.

Run: python services/ws3-indexer/test_admin_api.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import rules_view  # noqa: E402
import triage_api  # noqa: E402
import webhooks  # noqa: E402

FAILS: list[str] = []
REAL_TENANTS_DIR = rules_view.TENANTS_DIR
REAL_TENANTS_BEFORE = sorted(p.name for p in REAL_TENANTS_DIR.glob("*")) if REAL_TENANTS_DIR.is_dir() else []
rules_view.TENANTS_DIR = Path(tempfile.mkdtemp()) / "tenants"

ADMIN_PW = "admin-password-1"
ANALYST_PW = "analyst-password-1"
READONLY_PW = "readonly-password-1"


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _Audit:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, event, actor, tenant_id=None, detail=None):
        self.entries.append({"event": event, "actor": actor, "tenant_id": tenant_id, "detail": detail})

    def recent(self, limit=None):
        return list(self.entries)


def _setup():
    users = UserStore(":memory:")
    users.create_user("root", ADMIN_PW, role="admin", tenant_id="default")
    users.create_user("ana", ANALYST_PW, role="analyst", tenant_id="acme")
    users.create_user("reader", READONLY_PW, role="read_only", tenant_id="acme")
    audit = _Audit()
    srv = ThreadingHTTPServer(("127.0.0.1", 0),
                              triage_api.make_handler(MemoryStore(), users_db=users, audit_log=audit))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], users, audit


def _request(port, method, path, body=None, cookie=None, csrf=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        return e.code, json.loads(raw), raw


def _login(port, username, password):
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/login", data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            return resp.headers["Set-Cookie"].split(";")[0], body["csrf_token"]
    except urllib.error.HTTPError as e:
        return None, e.code


def test_users_list_admin_only_and_never_leaks_secrets():
    srv, port, users, _ = _setup()
    try:
        users.provision_totp("root")  # a real totp_secret in the row
        ck, cs = _login(port, "root", ADMIN_PW)
        code, body, raw = _request(port, "GET", "/users", cookie=ck)
        check(code == 200 and body.get("count") == 3, f"admin GET /users must 200 with 3 users, got {code} {body}")
        for u in body.get("users", []):
            check(set(u) == {"username", "role", "tenant_id", "created_at", "last_login_at", "mfa_active", "disabled"},
                  f"user view must be the explicit allowlist, got keys {sorted(u)}")
        check("password_hash" not in raw and "totp_secret" not in raw and "scrypt$" not in raw,
              "GET /users must never carry password_hash / totp_secret / a hash")
        for name, pw in (("ana", ANALYST_PW), ("reader", READONLY_PW)):
            c2, _ = _login(port, name, pw)
            code, _, _ = _request(port, "GET", "/users", cookie=c2)
            check(code == 404, f"{name} GET /users must 404 (existing non-admin posture), got {code}")
        code, _, _ = _request(port, "GET", "/users")
        check(code == 401, f"GET /users with no session must 401, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_create_user_validation_csrf_audit():
    srv, port, _, audit = _setup()
    try:
        ck, cs = _login(port, "root", ADMIN_PW)
        new = {"username": "bob", "password": "bob-password-12", "role": "analyst", "tenant_id": "acme"}
        code, _, _ = _request(port, "POST", "/users", new, cookie=ck)
        check(code == 403, f"POST /users without X-CSRF-Token must 403, got {code}")
        for bad, why in (({**new, "password": "short"}, "short password"),
                         ({**new, "role": "root"}, "unknown role"),
                         ({**new, "is_admin": True}, "unknown field"),
                         ({**new, "username": "../x"}, "bad username"),
                         ({**new, "tenant_id": "a/b"}, "bad tenant")):
            code, body, _ = _request(port, "POST", "/users", bad, cookie=ck, csrf=cs)
            check(code == 400, f"POST /users with {why} must 400, got {code} {body}")
        code, body, raw = _request(port, "POST", "/users", new, cookie=ck, csrf=cs)
        check(code == 201 and body.get("username") == "bob" and body.get("role") == "analyst"
              and body.get("tenant_id") == "acme", f"valid POST /users must 201, got {code} {body}")
        check("bob-password-12" not in raw and "scrypt$" not in raw, "create response must not echo the password/hash")
        code, _, _ = _request(port, "POST", "/users", new, cookie=ck, csrf=cs)
        check(code == 409, f"duplicate username must 409, got {code}")
        bc, _ = _login(port, "bob", "bob-password-12")
        check(bc is not None, "a created user must be able to log in")
        ev = [e for e in audit.entries if e["event"] == "user_create"]
        check(len(ev) == 1 and ev[0]["actor"] == "root" and ev[0]["detail"]["username"] == "bob",
              f"exactly one user_create audit entry by root expected, got {ev}")
        check("bob-password-12" not in json.dumps(audit.entries), "audit must never contain a password")
        ac, acs = _login(port, "ana", ANALYST_PW)
        code, _, _ = _request(port, "POST", "/users", {**new, "username": "eve"}, cookie=ac, csrf=acs)
        check(code == 404, f"analyst POST /users must 404, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_update_user_role_password_disable_and_session_revocation():
    srv, port, _, audit = _setup()
    try:
        ck, cs = _login(port, "root", ADMIN_PW)
        ana_ck, _ = _login(port, "ana", ANALYST_PW)
        code, _, _ = _request(port, "PATCH", "/users/ana", {"role": "read_only"}, cookie=ck)
        check(code == 403, f"PATCH without X-CSRF-Token must 403, got {code}")
        code, body, _ = _request(port, "PATCH", "/users/ana", {"role": "read_only"}, cookie=ck, csrf=cs)
        check(code == 200 and body.get("role") == "read_only", f"role change must 200, got {code} {body}")
        code, _, _ = _request(port, "GET", "/auth/me", cookie=ana_ck)
        check(code == 401, f"a re-roled user's existing session must stop working, got {code}")

        code, body, raw = _request(port, "PATCH", "/users/ana", {"password": "new-ana-password"}, cookie=ck, csrf=cs)
        check(code == 200 and "new-ana-password" not in raw, f"password reset must 200 without echo, got {code}")
        check(_login(port, "ana", ANALYST_PW)[0] is None, "old password must stop working after reset")
        ana_ck, _ = _login(port, "ana", "new-ana-password")
        check(ana_ck is not None, "new password must work after reset")

        code, body, _ = _request(port, "PATCH", "/users/ana", {"disabled": True}, cookie=ck, csrf=cs)
        check(code == 200 and body.get("disabled") is True, f"disable must 200, got {code} {body}")
        code, _, _ = _request(port, "GET", "/auth/me", cookie=ana_ck)
        check(code == 401, f"a disabled user's existing session must stop working, got {code}")
        check(_login(port, "ana", "new-ana-password")[0] is None, "a disabled user must fail login")
        code, _, _ = _request(port, "PATCH", "/users/ana", {"disabled": False}, cookie=ck, csrf=cs)
        check(code == 200 and _login(port, "ana", "new-ana-password")[0] is not None,
              "re-enabling must restore login")

        for bad, why in (({"disabled": "yes"}, "non-bool disabled"), ({"password": "x"}, "short password"),
                         ({"role": "god"}, "bad role"), ({"tenant_id": "x"}, "unknown field"), ({}, "empty body")):
            code, _, _ = _request(port, "PATCH", "/users/ana", bad, cookie=ck, csrf=cs)
            check(code == 400, f"PATCH with {why} must 400, got {code}")
        code, _, _ = _request(port, "PATCH", "/users/nobody", {"role": "analyst"}, cookie=ck, csrf=cs)
        check(code == 404, f"PATCH unknown user must 404, got {code}")

        upd = [e for e in audit.entries if e["event"] == "user_update"]
        check(any(e["detail"]["changed"] == ["password"] for e in upd), f"password reset must audit changed=[password]: {upd}")
        check("new-ana-password" not in json.dumps(audit.entries), "audit must never contain a password")

        rc, rcs = _login(port, "reader", READONLY_PW)
        code, _, _ = _request(port, "PATCH", "/users/ana", {"role": "admin"}, cookie=rc, csrf=rcs)
        check(code == 404, f"read_only PATCH /users must 404, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_last_admin_guard():
    srv, port, _, _ = _setup()
    try:
        ck, cs = _login(port, "root", ADMIN_PW)
        for change in ({"role": "analyst"}, {"disabled": True}):
            code, body, _ = _request(port, "PATCH", "/users/root", change, cookie=ck, csrf=cs)
            check(code == 409, f"demoting/disabling the last active admin ({change}) must 409, got {code} {body}")
        _request(port, "POST", "/users", {"username": "root2", "password": "root2-password-1", "role": "admin"},
                 cookie=ck, csrf=cs)
        code, _, _ = _request(port, "PATCH", "/users/root2", {"disabled": True}, cookie=ck, csrf=cs)
        check(code == 200, f"disabling a second admin must be allowed, got {code}")
        code, _, _ = _request(port, "PATCH", "/users/root", {"role": "analyst"}, cookie=ck, csrf=cs)
        check(code == 409, f"a disabled admin must not count toward the guard, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_webhooks_redacted():
    tmp = Path(tempfile.mkdtemp())
    (tmp / "msp.yml").write_text(yaml.safe_dump({
        "id": "msp", "url": "https://user:TOKPW@hooks.example.com:8443/hook/SECRETPATH?token=SECRETQ",
        "secret_env": "FG_TEST_WEBHOOK_SECRET", "tenant_id": "acme", "min_score": 60}), encoding="utf-8")
    old_dir, old_unsafe = webhooks.WEBHOOKS_DIR, webhooks.is_unsafe_target_url
    webhooks.WEBHOOKS_DIR = tmp
    webhooks.is_unsafe_target_url = lambda url: False  # no DNS in tests
    os.environ["FG_TEST_WEBHOOK_SECRET"] = "HMACVALUE"
    srv, port, _, _ = _setup()
    try:
        ck, _ = _login(port, "root", ADMIN_PW)
        code, body, raw = _request(port, "GET", "/webhooks", cookie=ck)
        hooks = body.get("webhooks", [])
        check(code == 200 and len(hooks) == 1, f"admin GET /webhooks must list 1 config, got {code} {body}")
        if hooks:
            h = hooks[0]
            check(h["host"] == "hooks.example.com" and h["min_score"] == 60 and h["tenant_id"] == "acme"
                  and h["enabled"] is True, f"webhook view wrong: {h}")
        for secret in ("TOKPW", "SECRETPATH", "SECRETQ", "HMACVALUE", "8443", "user:"):
            check(secret not in raw, f"GET /webhooks leaked {secret!r}")
        ac, _ = _login(port, "ana", ANALYST_PW)
        code, _, _ = _request(port, "GET", "/webhooks", cookie=ac)
        check(code == 404, f"analyst GET /webhooks must 404, got {code}")
        os.environ.pop("FG_TEST_WEBHOOK_SECRET")
        _, body, _ = _request(port, "GET", "/webhooks", cookie=ck)
        check(body["webhooks"][0]["enabled"] is False, "unset secret env -> enabled false (deliveries skipped)")
    finally:
        srv.shutdown(); srv.server_close()
        webhooks.WEBHOOKS_DIR, webhooks.is_unsafe_target_url = old_dir, old_unsafe
        os.environ.pop("FG_TEST_WEBHOOK_SECRET", None)


def test_rule_toggle_writes_tenant_file():
    rule_id = rules_view.list_rule_summaries(None)[0]["id"]
    srv, port, _, audit = _setup()
    try:
        ck, cs = _login(port, "root", ADMIN_PW)
        path = f"/rules/{rule_id}/enabled"
        code, _, _ = _request(port, "PUT", path, {"enabled": False}, cookie=ck)
        check(code == 403, f"PUT without X-CSRF-Token must 403, got {code}")
        code, body, _ = _request(port, "PUT", path, {"enabled": False}, cookie=ck, csrf=cs)
        check(code == 200 and body == {"id": rule_id, "tenant_id": "default", "enabled": False},
              f"admin disable must 200 for the session tenant, got {code} {body}")
        written = yaml.safe_load((rules_view.TENANTS_DIR / "default.yml").read_text(encoding="utf-8"))
        check(written.get("disabled_rules") == [rule_id], f"default.yml must list the rule, got {written}")
        _, body, _ = _request(port, "GET", "/rules?tenant_id=default", cookie=ck)
        state = {r["id"]: r["enabled"] for r in body["rules"]}
        check(state.get(rule_id) is False, "GET /rules must report the rule disabled for that tenant")
        code, _, _ = _request(port, "PUT", path, {"enabled": True}, cookie=ck, csrf=cs)
        written = yaml.safe_load((rules_view.TENANTS_DIR / "default.yml").read_text(encoding="utf-8"))
        check(code == 200 and written.get("disabled_rules") == [], f"re-enable must empty the list, got {written}")
        code, _, _ = _request(port, "PUT", f"/api/v1{path}", {"enabled": False, "tenant_id": "acme"}, cookie=ck, csrf=cs)
        check(code == 200 and (rules_view.TENANTS_DIR / "acme.yml").exists(),
              "admin may target another tenant (and /api/v1 alias routes)")
        for bad, why in (({"enabled": "no"}, "non-bool"), ({}, "missing enabled"),
                         ({"enabled": True, "x": 1}, "unknown field"), ({"enabled": True, "tenant_id": "../x"}, "bad tenant")):
            code, _, _ = _request(port, "PUT", path, bad, cookie=ck, csrf=cs)
            check(code == 400, f"PUT with {why} must 400, got {code}")
        code, _, _ = _request(port, "PUT", "/rules/not-a-rule/enabled", {"enabled": False}, cookie=ck, csrf=cs)
        check(code == 404, f"unknown rule must 404, got {code}")
        ev = [e for e in audit.entries if e["event"] == "rule_toggle"]
        check(len(ev) == 3 and ev[0]["detail"] == {"rule_id": rule_id, "enabled": False, "tenant_id": "default"},
              f"rule_toggle audit entries wrong: {ev}")
        ac, acs = _login(port, "ana", ANALYST_PW)
        code, _, _ = _request(port, "PUT", path, {"enabled": False}, cookie=ac, csrf=acs)
        check(code == 404, f"analyst PUT must 404, got {code}")
    finally:
        srv.shutdown(); srv.server_close()


def test_rbac_off_admin_routes_unroutable():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(MemoryStore()))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        for method, path in (("GET", "/users"), ("GET", "/webhooks"), ("POST", "/users"),
                             ("PATCH", "/users/root"), ("PUT", "/rules/x/enabled")):
            code, body, _ = _request(port, method, path, {} if method != "GET" else None)
            check(code == 404 and body.get("error") == "no such path",
                  f"RBAC off: {method} {path} must be unroutable, got {code} {body}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_users_list_admin_only_and_never_leaks_secrets()
    test_create_user_validation_csrf_audit()
    test_update_user_role_password_disable_and_session_revocation()
    test_last_admin_guard()
    test_webhooks_redacted()
    test_rule_toggle_writes_tenant_file()
    test_rbac_off_admin_routes_unroutable()
    after = sorted(p.name for p in REAL_TENANTS_DIR.glob("*")) if REAL_TENANTS_DIR.is_dir() else []
    check(after == REAL_TENANTS_BEFORE, f"the real contracts/tenants must be untouched: {REAL_TENANTS_BEFORE} -> {after}")
    if FAILS:
        print(f"[FAIL] admin api: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] admin API: users list/create/update admin-only (analyst/read_only 404, no session 401), "
          "CSRF on POST/PATCH/PUT, password policy + never returned/audited, disable/re-role revoke live "
          "sessions, last-active-admin guard 409, webhook list redacted to host, rule toggle writes the "
          "tenant file (temp dir) + audits, all unroutable with RBAC off -- real HTTP")


if __name__ == "__main__":
    main()
