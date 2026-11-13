"""Tenant/role scoping for the dashboard's former OpenSearch-direct routes
(WP-6.2, follow-up to PR #165) -- GET /dashboard/{alerts,events,ai-triage}
and GET /auth/check-admin, all through REAL HTTP against a real
ThreadingHTTPServer (same harness as test_rbac_api.py).

Run: python services/ws3-indexer/test_dashboard_scope.py
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

from storage.memory import MemoryStore  # noqa: E402
from shared.users import UserStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []
KEY = "s3cr3t-dash-scope"
ROUTES = ("/dashboard/alerts", "/dashboard/events", "/dashboard/ai-triage")


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _req(port, path, cookie=None, key=None, method="GET", body=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if key:
        headers["X-Api-Key"] = key
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                               method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode()), resp.headers.get("Set-Cookie")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}"), e.headers.get("Set-Cookie")


def _login(port, user, pw):
    code, _, sc = _req(port, "/auth/login", method="POST", body={"username": user, "password": pw})
    assert code == 200, f"login {user} -> {code}"
    return sc.split(";")[0]


def _store():
    s = MemoryStore()
    for t, base in (("acme", 1000), ("globex", 2000)):
        s.index(f"alerts-{t}-2026.11.01", f"{t}-a1",
                {"alert_id": f"{t}-a1", "tenant_id": t, "rule_title": f"{t} rule", "time": base})
        s.index(f"alerts-{t}-2026.11.01", f"ai-{t}-1",
                {"alert_id": f"ai-{t}-1", "tenant_id": t, "time": base + 1})
        s.index(f"events-common-{t}", f"{t}-e1",
                {"event_id": f"{t}-e1", "siem": {"tenant": t}, "time": base})
    # a pre-multitenancy doc with no tenant at all lands in tenant "default"
    s.index("alerts-2026.11.01", "d-a1", {"alert_id": "d-a1", "rule_title": "dflt", "time": 3000})
    return s


def _users():
    u = UserStore(":memory:")
    u.create_user("acme_analyst", "pw-acme-1", role="analyst", tenant_id="acme")
    u.create_user("globex_ro", "pw-globex-1", role="read_only", tenant_id="globex")
    u.create_user("admin_user", "pw-admin-1", role="admin", tenant_id="default")
    return u


class _Server:
    def __init__(self, rbac: bool, key: str | None):
        os.environ.pop("FENGARDE_API_KEY", None)
        if key:
            os.environ["FENGARDE_API_KEY"] = key
        self.store = _store()
        users = _users() if rbac else None
        self.srv = ThreadingHTTPServer(
            ("127.0.0.1", 0), triage_api.make_handler(self.store, users_db=users))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()
        os.environ.pop("FENGARDE_API_KEY", None)


def _tenants(body):
    """Tenant of every hit in an OpenSearch-shaped body (events carry it under siem.tenant)."""
    out = set()
    for h in body.get("hits", {}).get("hits", []):
        s = h["_source"]
        out.add(s.get("tenant_id") or (s.get("siem") or {}).get("tenant") or "default")
    return out


def test_scoping_per_session():
    with _Server(rbac=True, key=None) as s:
        acme = _login(s.port, "acme_analyst", "pw-acme-1")
        globex = _login(s.port, "globex_ro", "pw-globex-1")
        admin = _login(s.port, "admin_user", "pw-admin-1")
        for route in ROUTES:
            admin_want = {"acme", "globex", "default"} if route == "/dashboard/alerts" \
                else {"acme", "globex"}
            for who, cookie, want in (("acme", acme, {"acme"}), ("globex", globex, {"globex"}),
                                      ("admin", admin, admin_want)):
                code, body, _ = _req(s.port, route, cookie=cookie)
                check(code == 200, f"{route} {who} -> {code}")
                if code == 200:
                    check(_tenants(body) == want, f"{route} {who} saw {_tenants(body)}, want {want}")
            # non-admin tenant_id param can NOT widen scope
            _, body, _ = _req(s.port, route + "?tenant_id=globex", cookie=acme)
            check(_tenants(body) == {"acme"}, f"{route} acme + tenant_id=globex widened to {_tenants(body)}")
            _, body, _ = _req(s.port, route + "?tenant_id=acme", cookie=globex)
            check(_tenants(body) == {"globex"}, f"{route} globex + tenant_id=acme widened to {_tenants(body)}")
            # admin may narrow
            _, body, _ = _req(s.port, route + "?tenant_id=acme", cookie=admin)
            check(_tenants(body) == {"acme"}, f"{route} admin narrowing failed: {_tenants(body)}")


def test_anonymous_401_rbac_on():
    for key in (None, KEY):
        with _Server(rbac=True, key=key) as s:
            for route in ROUTES + ("/auth/check-admin",):
                code, _, _ = _req(s.port, route)
                check(code == 401, f"anonymous {route} (rbac on, key={'set' if key else 'unset'}) -> {code}")
                code, _, _ = _req(s.port, route, cookie="fengarde_session=bogus")
                check(code == 401, f"bogus-cookie {route} (key={'set' if key else 'unset'}) -> {code}")


def test_machine_key_sees_all_tenants():
    with _Server(rbac=True, key=KEY) as s:
        for route in ROUTES:
            code, body, _ = _req(s.port, route, key=KEY)
            check(code == 200, f"{route} key -> {code}")
            if code == 200:
                check({"acme", "globex"} <= _tenants(body), f"{route} key saw only {_tenants(body)}")
            code, _, _ = _req(s.port, route, key="wrong")
            check(code == 401, f"{route} wrong key -> {code}")


def test_rbac_off_modes():
    with _Server(rbac=False, key=None) as s:  # zero-config demo stays open
        for route in ROUTES:
            code, body, _ = _req(s.port, route)
            check(code == 200 and {"acme", "globex"} <= _tenants(body),
                  f"{route} demo mode (rbac off, no key) -> {code}")
    with _Server(rbac=False, key=KEY) as s:
        for route in ROUTES:
            check(_req(s.port, route)[0] == 401, f"{route} rbac off + key set, anonymous not 401")
            code, body, _ = _req(s.port, route, key=KEY)
            check(code == 200 and {"acme", "globex"} <= _tenants(body), f"{route} rbac off + key -> {code}")


def test_response_shape_and_query_semantics():
    with _Server(rbac=True, key=KEY) as s:
        for route in ROUTES:
            _, body, _ = _req(s.port, route, key=KEY)
            check(set(body) == {"hits"} and set(body.get("hits", {})) == {"hits"},
                  f"{route} body keys {sorted(body)} are not the OpenSearch shape")
            check(all(set(h) == {"_source"} for h in body.get("hits", {}).get("hits", [])),
                  f"{route} hit keys")
        # alerts: only rule alerts (no ai- docs), newest first; ai-triage: only ai- docs
        _, a, _ = _req(s.port, "/dashboard/alerts", key=KEY)
        ids = [h["_source"]["alert_id"] for h in a["hits"]["hits"]]
        check(ids == ["d-a1", "globex-a1", "acme-a1"], f"alerts ids/order {ids}")
        _, t, _ = _req(s.port, "/dashboard/ai-triage", key=KEY)
        tids = sorted(h["_source"]["alert_id"] for h in t["hits"]["hits"])
        check(tids == ["ai-acme-1", "ai-globex-1"], f"ai-triage ids {tids}")
        # gte is inclusive; invalid/negative/huge fall back to 0 (nginx-map parity)
        _, a, _ = _req(s.port, "/dashboard/alerts?gte=2000", key=KEY)
        check([h["_source"]["alert_id"] for h in a["hits"]["hits"]] == ["d-a1", "globex-a1"], "gte=2000")
        _, e, _ = _req(s.port, "/dashboard/events?gte=2000", key=KEY)
        check([h["_source"]["event_id"] for h in e["hits"]["hits"]] == ["globex-e1"], "events gte=2000")
        for bad in ("abc", "-5", "1.5", "9" * 40, ""):
            code, a, _ = _req(s.port, f"/dashboard/alerts?gte={bad}", key=KEY)
            check(code == 200 and len(a["hits"]["hits"]) == 3, f"gte={bad!r} -> {code}")
        # caps: 50 alerts / 100 events / 200 ai docs
        for i in range(260):
            s.store.index("alerts-acme-2026.11.02", f"x{i}",
                          {"alert_id": f"x{i}", "tenant_id": "acme", "rule_title": "r", "time": 5000 + i})
            s.store.index("alerts-acme-2026.11.02", f"ai-x{i}",
                          {"alert_id": f"ai-x{i}", "tenant_id": "acme", "time": 5000 + i})
            s.store.index("events-common-acme", f"ex{i}",
                          {"event_id": f"ex{i}", "siem": {"tenant": "acme"}, "time": 5000 + i})
        for route, n in (("/dashboard/alerts", 50), ("/dashboard/events", 100),
                         ("/dashboard/ai-triage", 200)):
            _, b, _ = _req(s.port, route, key=KEY)
            check(len(b["hits"]["hits"]) == n, f"{route} cap {len(b['hits']['hits'])} != {n}")


def test_check_admin():
    with _Server(rbac=True, key=KEY) as s:
        check(_req(s.port, "/auth/check-admin")[0] == 401, "check-admin anonymous")
        check(_req(s.port, "/auth/check-admin", key="wrong")[0] == 401, "check-admin wrong key")
        check(_req(s.port, "/auth/check-admin", key=KEY)[0] == 200, "check-admin key")
        for user, pw in (("acme_analyst", "pw-acme-1"), ("globex_ro", "pw-globex-1")):
            c = _login(s.port, user, pw)
            check(_req(s.port, "/auth/check-admin", cookie=c)[0] == 403, f"check-admin {user} must be 403")
            check(_req(s.port, "/auth/check", cookie=c)[0] == 200, f"/auth/check unchanged for {user}")
        c = _login(s.port, "admin_user", "pw-admin-1")
        check(_req(s.port, "/auth/check-admin", cookie=c)[0] == 200, "check-admin admin")
    with _Server(rbac=True, key=None) as s:  # sessions-only: anonymous never 200
        check(_req(s.port, "/auth/check-admin")[0] == 401, "check-admin anonymous (key unset, rbac on)")
    with _Server(rbac=False, key=None) as s:  # auth fully disabled stays open
        check(_req(s.port, "/auth/check-admin")[0] == 200, "check-admin fully disabled")
    with _Server(rbac=False, key=KEY) as s:
        check(_req(s.port, "/auth/check-admin")[0] == 401, "check-admin rbac off, key set, anonymous")
        check(_req(s.port, "/auth/check-admin", key=KEY)[0] == 200, "check-admin rbac off + key")


def main():
    test_scoping_per_session()
    test_anonymous_401_rbac_on()
    test_machine_key_sees_all_tenants()
    test_rbac_off_modes()
    test_response_shape_and_query_semantics()
    test_check_admin()
    if FAILS:
        print(f"[FAIL] dashboard tenant scope: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] dashboard tenant scope: /dashboard/{alerts,events,ai-triage} scoped per session "
          "tenant (admin/key see all, tenant_id cannot widen), anonymous 401, OpenSearch-shaped "
          "bodies, /auth/check-admin role gate -- all real HTTP requests")


if __name__ == "__main__":
    main()
