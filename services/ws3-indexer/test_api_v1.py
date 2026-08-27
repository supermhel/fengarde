"""M4.3 versioned REST API tests: GET /alerts, /events, /rules (+ /api/v1/*
aliases), real HTTP requests -- same harness pattern as test_rbac_api.py.

Run: python services/ws3-indexer/test_api_v1.py
"""
from __future__ import annotations

import json
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CONTRACT_PATH = HERE.parent.parent / "contracts" / "triage-api.yaml"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _serve(store, users_db=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), triage_api.make_handler(store, users_db=users_db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _post(port, path, body=None, cookie=None, csrf=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRF-Token"] = csrf
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body or {}).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _login_with_csrf(port, username, password):
    """Like _login(), but also returns the csrf_token from the response
    body (needed for state-changing POSTs once RBAC is on)."""
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/login", data=body,
                                  method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        set_cookie = resp.headers.get("Set-Cookie").split(";")[0]
        payload = json.loads(resp.read().decode())
        return set_cookie, payload["csrf_token"]


def _login(port, username, password):
    body = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/auth/login", data=body,
                                  method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        set_cookie = resp.headers.get("Set-Cookie")
        return set_cookie.split(";")[0]


def _seed_store():
    store = MemoryStore()
    now = int(time.time() * 1000)
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "time": now, "rule_title": "r1",
                 "actor": {"user": {"name": "jdoe"}}, "src_endpoint": {"ip": "203.0.113.5"}})
    store.index("alerts-acme-2026.07.16", "a2",
                {"alert_id": "a2", "tenant_id": "acme", "time": now - 1000, "rule_title": "r2",
                 "triage": {"status": "closed"},
                 "actor": {"user": {"name": "jdoe"}}, "src_endpoint": {"ip": "198.51.100.9"}})
    store.index("alerts-globex-2026.07.16", "g1",
                {"alert_id": "g1", "tenant_id": "globex", "time": now, "rule_title": "r3",
                 "actor": {"user": {"name": "asmith"}}, "src_endpoint": {"ip": "203.0.113.5"}})
    store.index("events-common-acme-2026.07.16", "e1",
                {"siem": {"ingest_id": "e1", "tenant": "acme", "sector": "common"}, "time": now})
    store.index("events-common-globex-2026.07.16", "e2",
                {"siem": {"ingest_id": "e2", "tenant": "globex", "sector": "common"}, "time": now})
    return store


def test_list_alerts_no_rbac_sees_everything():
    store = _seed_store()
    srv, port = _serve(store)
    try:
        code, body = _get(port, "/alerts")
        check(code == 200, f"GET /alerts must succeed, got {code}")
        check(body["count"] == 3, f"RBAC off: must see all 3 alerts across tenants, got {body['count']}")

        code2, body2 = _get(port, "/api/v1/alerts")
        check(code2 == 200 and body2["count"] == 3, "/api/v1/alerts alias must behave identically")
    finally:
        srv.shutdown(); srv.server_close()


def test_list_alerts_filters():
    store = _seed_store()
    srv, port = _serve(store)
    try:
        code, body = _get(port, "/alerts?tenant_id=acme")
        check(code == 200 and body["count"] == 2, f"tenant_id filter must scope to acme's 2 alerts, got {body}")

        code2, body2 = _get(port, "/alerts?tenant_id=acme&status=closed")
        check(code2 == 200 and body2["count"] == 1, f"status filter must narrow to 1, got {body2}")
        check(body2["alerts"][0]["alert_id"] == "a2", "status=closed must return a2")

        code3, body3 = _get(port, "/alerts?limit=1")
        check(code3 == 200 and body3["count"] == 1, "limit must cap the result count")

        code4, _ = _get(port, "/alerts?status=not-a-real-status")
        check(code4 == 400, f"an invalid status must be a 400, got {code4}")

        code5, _ = _get(port, "/alerts?limit=abc")
        check(code5 == 400, f"a non-integer limit must be a 400, got {code5}")
    finally:
        srv.shutdown(); srv.server_close()


def test_list_alerts_actor_src_ip_filters():
    """Design-C (2026-07-29 audit): manual cross-alert correlation -- pull
    every alert for one actor or source IP across tenants/time, the scoped
    substitute for a full correlation engine (see SSOT.md)."""
    store = _seed_store()
    srv, port = _serve(store)
    try:
        code, body = _get(port, "/alerts?actor=jdoe")
        check(code == 200 and body["count"] == 2,
              f"actor=jdoe must return both of jdoe's alerts (a1, a2), got {body}")
        check({a["alert_id"] for a in body["alerts"]} == {"a1", "a2"},
              f"actor filter returned the wrong alerts: {body['alerts']}")

        code2, body2 = _get(port, "/alerts?src_ip=203.0.113.5")
        check(code2 == 200 and body2["count"] == 2,
              f"src_ip=203.0.113.5 must return a1 AND g1 (crosses tenants -- "
              f"this is a manual correlation query, not tenant-scoped by "
              f"itself), got {body2}")
        check({a["alert_id"] for a in body2["alerts"]} == {"a1", "g1"},
              f"src_ip filter returned the wrong alerts: {body2['alerts']}")

        code3, body3 = _get(port, "/alerts?actor=jdoe&status=closed")
        check(code3 == 200 and body3["count"] == 1 and body3["alerts"][0]["alert_id"] == "a2",
              f"actor+status must compose (AND), got {body3}")

        code4, body4 = _get(port, "/alerts?actor=nobody-such-user")
        check(code4 == 200 and body4["count"] == 0,
              f"an actor with no alerts must return an empty list, not an error, got {body4}")
    finally:
        srv.shutdown(); srv.server_close()


def test_list_events_filters():
    store = _seed_store()
    srv, port = _serve(store)
    try:
        code, body = _get(port, "/events")
        check(code == 200 and body["count"] == 2, f"RBAC off: must see both tenants' events, got {body}")

        code2, body2 = _get(port, "/events?tenant_id=acme")
        check(code2 == 200 and body2["count"] == 1, f"tenant_id filter must scope to acme's event, got {body2}")

        code3, body3 = _get(port, "/events?family=common")
        check(code3 == 200 and body3["count"] == 2, "family=common must match both (only family present)")

        code4, _ = _get(port, "/events?family=not-a-real-family")
        check(code4 == 400, f"an invalid family must be a 400, got {code4}")
    finally:
        srv.shutdown(); srv.server_close()


def test_list_rules_reads_real_contract_files():
    store = _seed_store()
    srv, port = _serve(store)
    try:
        code, body = _get(port, "/rules")
        check(code == 200, f"GET /rules must succeed, got {code}")
        check(body["count"] > 0, "must list at least one real rule from contracts/rules/*.yml")
        sample = body["rules"][0]
        check(set(sample) == {"id", "title", "level", "sector", "score_weight",
                               "stateful", "mitre", "enabled"},
              f"a rule summary must never leak the raw `condition` field, got keys {set(sample)}")
    finally:
        srv.shutdown(); srv.server_close()


def test_rbac_non_admin_tenant_forced_not_requested():
    store = _seed_store()
    users = UserStore(":memory:")
    users.create_user("acme_analyst", "pw1", role="analyst", tenant_id="acme")
    users.create_user("admin_user", "pw2", role="admin", tenant_id="default")
    srv, port = _serve(store, users_db=users)
    try:
        cookie = _login(port, "acme_analyst", "pw1")

        # Even asking for globex explicitly, a non-admin must only ever see
        # their OWN tenant -- the query param is silently overridden, not
        # honored and not errored (a list endpoint has no single resource
        # to 404 on).
        code, body = _get(port, "/alerts?tenant_id=globex", cookie=cookie)
        check(code == 200, f"scoped list must still succeed, got {code}")
        check(body["count"] == 2 and all(a["tenant_id"] == "acme" for a in body["alerts"]),
              f"a non-admin's tenant_id request must be overridden by their session tenant, got {body}")

        admin_cookie = _login(port, "admin_user", "pw2")
        code2, body2 = _get(port, "/alerts?tenant_id=globex", cookie=admin_cookie)
        check(code2 == 200 and body2["count"] == 1 and body2["alerts"][0]["tenant_id"] == "globex",
              f"an admin's explicit tenant_id request must be honored, got {body2}")

        code3, _ = _get(port, "/alerts")  # no session cookie at all
        check(code3 == 401, f"GET /alerts with no session (RBAC on) must be 401, got {code3}")
    finally:
        srv.shutdown(); srv.server_close()


def test_openapi_spec_get_paths_are_actually_wired():
    """Not a full OpenAPI validator (no new dependency for that) -- just
    proves every GET path documented in contracts/triage-api.yaml actually
    routes to a live handler (no 404 "no such path" / no 500) against a
    real server, so the spec can't silently drift from the code."""
    spec = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    # /auth/me is deliberately excluded: its very existence is conditional on
    # RBAC being enabled (proven separately by test_rbac_api.py's
    # test_rbac_off_by_default_no_auth_routes / test_me_requires_session) --
    # a 404 for it against an RBAC-off server is correct, not spec/code drift.
    get_paths = [p for p, ops in spec["paths"].items() if "get" in ops and "auth/me" not in p]
    check(len(get_paths) >= 6, "sanity: the spec should document several GET paths")

    store = _seed_store()
    srv, port = _serve(store)
    try:
        for path in get_paths:
            concrete = re.sub(r"\{alert_id\}", "a1", path)
            code, body = _get(port, concrete)
            check(code != 500, f"spec path {path} (-> {concrete}) must not 500")
            # "no such path" is the specific marker this codebase's dispatcher
            # sends for an UNROUTED path (see _route_get/_route_post) -- a
            # business-logic 404 ("report not found", "not logged in") is a
            # legitimate response and NOT what this test is checking for.
            check(body.get("error") != "no such path",
                  f"spec path {path} (-> {concrete}) is not actually routed -- spec/code drift")
    finally:
        srv.shutdown(); srv.server_close()


def test_openapi_spec_mfa_and_audit_routes_are_wired():
    """The spec-vs-code drift that a GET-only check misses by construction:
    /auth/mfa/enable, /auth/mfa/verify and /audit were added to the code
    (E3/E1) and to the ws3 INTERFACE but absent from triage-api.yaml, and the
    old check (GET paths only) never caught it. Prove the spec now documents
    them AND that each maps to a real route (not "no such path"). The routes
    need RBAC on for auth, so they're exercised RBAC-off: the dispatcher must
    ROUTE them (return 401/403, not "no such path").

    Gap-hunt finding (2026-08-23): this test's docstring always claimed the
    "maps to a real route" half, but the body only ever checked the spec
    dict against itself -- it never started a server or made a request, so
    it could never have caught a route that's documented but not actually
    wired (or vice versa). It now does both, mirroring
    test_openapi_spec_get_paths_are_actually_wired's live-request pattern.
    """
    spec = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    for path, method in (
        ("/api/v1/auth/mfa/enable", "post"),
        ("/api/v1/auth/mfa/verify", "post"),
        ("/api/v1/audit", "get"),
    ):
        check(path in spec["paths"] and method in spec["paths"][path],
              f"spec must document {method.upper()} {path} -- the E3/E1 routes "
              f"existed in code but were absent from the spec")

    # MFA routes only exist behind `if rbac_enabled and path == ...` in
    # do_POST -- with RBAC off they are correctly, intentionally
    # unreachable (a 404 there is right, not a bug), so proving they're
    # ACTUALLY wired needs a real RBAC session, not RBAC-off. And with RBAC
    # on, do_POST's CSRF gate fires for EVERY POST path before any routing
    # decision -- a bogus path would ALSO 403 there, so testing "not 404"
    # from an unauthenticated/no-CSRF request wouldn't discriminate a real
    # route from a fake one. A valid session + CSRF token clears that gate
    # and reaches each route's own body, which fails on a MISSING PASSWORD
    # (401 "reauthentication required") -- distinct from the "no such path"
    # a genuinely unrouted path produces even with the same valid session.
    users = UserStore(":memory:")
    users.create_user("alice", "pw-alice-1", role="analyst")
    store = _seed_store()
    srv, port = _serve(store, users_db=users)
    try:
        cookie, csrf = _login_with_csrf(port, "alice", "pw-alice-1")

        for path in ("/api/v1/auth/mfa/enable", "/api/v1/auth/mfa/verify"):
            code, body = _post(port, path, body={}, cookie=cookie, csrf=csrf)
            check(code == 401 and body.get("error") == "reauthentication required",
                  f"POST {path} (RBAC on, valid session, no password) must reach the "
                  f"real handler's own reauth gate, not 'no such path' -- got {code} {body}")

        # A genuinely unrouted path, same valid session+CSRF, to prove the
        # contrast above is real and not just "anything with a session
        # returns non-404" -- this one line proving the discriminator.
        code, body = _post(port, "/totally/fake/path", body={}, cookie=cookie, csrf=csrf)
        check(code == 404 and body.get("error") == "no such path",
              f"an actually-unrouted path must still 404, got {code} {body}")

        # /audit's _require_role("admin") returns the RBAC-off sentinel
        # (True) unconditionally when RBAC is disabled -- so a plain
        # RBAC-off server (unlike the MFA routes above) reaches the real
        # handler directly and returns 200 with the (empty) audit trail.
        plain_store = _seed_store()
        plain_srv, plain_port = _serve(plain_store)
        try:
            code, body = _get(plain_port, "/audit")
            check(code == 200 and "entries" in body,
                  f"GET /audit (RBAC off) must route to the real handler, got {code} {body}")
        finally:
            plain_srv.shutdown(); plain_srv.server_close()
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_list_alerts_no_rbac_sees_everything()
    test_list_alerts_filters()
    test_list_alerts_actor_src_ip_filters()
    test_list_events_filters()
    test_list_rules_reads_real_contract_files()
    test_rbac_non_admin_tenant_forced_not_requested()
    test_openapi_spec_get_paths_are_actually_wired()
    test_openapi_spec_mfa_and_audit_routes_are_wired()

    if FAILS:
        print(f"[FAIL] api v1: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.3 versioned REST API: GET /alerts, /events, /rules (+ /api/v1/* aliases) -- "
          "filtering, limit clamping, non-admin tenant scoping forced not merely checked, "
          "rule summaries never leak the raw `condition` -- all real HTTP requests")


if __name__ == "__main__":
    main()
