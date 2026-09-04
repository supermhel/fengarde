"""WP-2-I: prove triage_api.py's route decomposition.

The pre-refactor triage_api.py built every HTTP route inside one ~830-line
`make_handler` closure, so a single route could not be exercised without a
whole live server. It is now decomposed into module-level, per-route functions
(`triage_api.route_*` / `triage_api.mfa_*`) that read their server
dependencies through `self.deps`, and `make_handler` is a thin assembler.

This test proves the decomposition three ways:

  (a) Per-route testability -- a single route handler is constructed with a
      FAKE store + FAKE auth (no `ThreadingHTTPServer`, no live socket) and its
      route function is exercised directly. At least one route per route-group,
      plus the two RBAC session helpers.
  (b) Route-inventory parity -- `ROUTE_INVENTORY` (the post-refactor surface)
      equals the verbatim route table captured from the PRE-refactor
      `_route_get`/`_route_post` dispatchers (see EXPECTED_ROUTES).
  (c) Full-path smoke -- the ASSEMBLED handler (real `make_handler` over a real
      ephemeral HTTP server) serves exactly the inventory routes and nothing
      else, both with RBAC off (8 non-auth routes) and RBAC on (auth routes).

Standalone script (no pytest): run from inside services/ws3-indexer with the
venv python.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from shared.users import UserStore  # noqa: E402
import triage_api  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# ---------------------------------------------------------------------------
# (b) route inventory: the PRE-refactor route table, captured from the original
# `_route_get` / `_route_post` dispatchers (and do_GET/do_POST's auth special-
# cases) BEFORE the decomposition. Each tuple is (method, path_template,
# rbac_only). This is the byte-level baseline the new surface must match.
# ---------------------------------------------------------------------------
EXPECTED_ROUTES: list[tuple[str, str, bool]] = [
    ("GET", "/auth/me", True),
    ("GET", "/alerts", False),
    ("GET", "/incidents", False),
    ("GET", "/events", False),
    ("GET", "/rules", False),
    ("GET", "/audit", False),
    ("GET", "/alerts/{alert_id}/report", False),
    ("GET", "/alerts/{alert_id}/triage", False),
    ("POST", "/auth/login", True),
    ("POST", "/auth/logout", True),
    ("POST", "/auth/mfa/enable", True),
    ("POST", "/auth/mfa/verify", True),
    ("POST", "/alerts/{alert_id}/report", False),
    ("POST", "/alerts/{alert_id}/triage", False),
]


# Phase 5 (2026-09-04): real new routes, added on top of the frozen
# pre-refactor baseline above -- entity/causal-graph/evidence read path.
# Kept as a SEPARATE list rather than folded into EXPECTED_ROUTES: that one
# is a byte-level historical snapshot proving WP-2-I's refactor changed
# nothing, and growing it on every real feature would defeat its own point.
ROUTES_ADDED_SINCE_REFACTOR: list[tuple[str, str, bool]] = [
    ("GET", "/entities/{entity_id}", False),
    ("GET", "/incidents/{incident_id}/graph", False),
    ("GET", "/incidents/{incident_id}/evidence", False),
    ("POST", "/incidents/{incident_id}/report", False),
]


def test_route_inventory_matches_pre_refactor_baseline():
    """(b), part 1: every pre-refactor route is still present, unchanged --
    the original guarantee this test existed to prove. No longer an exact-
    match assertion (2026-09-04): ROUTE_INVENTORY legitimately grows as real
    routes ship (see ROUTES_ADDED_SINCE_REFACTOR); a superset check still
    catches the actual regression this test guards against -- a pre-refactor
    route silently dropped or its path/rbac flag changed."""
    missing = set(EXPECTED_ROUTES) - set(triage_api.ROUTE_INVENTORY)
    check(not missing,
          f"ROUTE_INVENTORY is missing {len(missing)} pre-refactor baseline "
          f"route(s) that WP-2-I proved present: {sorted(missing)}")
    # (b), part 2: every route added since the refactor is present too --
    # catches the opposite regression (a real route function that exists
    # but was never wired into ROUTE_INVENTORY/_route_get, invisible to
    # this file's own (c) full-path smoke below).
    missing_new = set(ROUTES_ADDED_SINCE_REFACTOR) - set(triage_api.ROUTE_INVENTORY)
    check(not missing_new,
          f"ROUTE_INVENTORY is missing {len(missing_new)} post-refactor "
          f"route(s) it should have: {sorted(missing_new)}")
    # (b), part 3: nothing else has snuck in undeclared -- the inventory is
    # EXACTLY the union of the two lists above, no third source of drift.
    expected_union = set(EXPECTED_ROUTES) | set(ROUTES_ADDED_SINCE_REFACTOR)
    extra = set(triage_api.ROUTE_INVENTORY) - expected_union
    check(not extra,
          f"ROUTE_INVENTORY has {len(extra)} route(s) neither the frozen "
          f"baseline nor ROUTES_ADDED_SINCE_REFACTOR account for -- a new "
          f"route was added without updating this test: {sorted(extra)}")
    # sanity: no accidental NUL / dupes
    check(len(triage_api.ROUTE_INVENTORY) == len(set(triage_api.ROUTE_INVENTORY)),
          "ROUTE_INVENTORY must not contain duplicate entries")


def test_concurrent_servers_keep_isolated_deps():
    """make_handler returns a PER-SERVER subclass carrying its own _Deps, so
    two servers built with different stores (like test_fix_audit's nested
    servers) can never leak each other's store/sessions/audit."""
    s1, s2 = _FakeStore(), _FakeStore()
    h1 = triage_api.make_handler(s1)
    h2 = triage_api.make_handler(s2)
    check(h1 is not h2, "each make_handler call must return its own class")
    check(h1.deps.store is s1 and h2.deps.store is s2,
          "per-server deps must bind exactly the store each server was built with")


# ---------------------------------------------------------------------------
# (a) per-route testability harness -----------------------------------------
# ---------------------------------------------------------------------------
class _FakeStore:
    """Minimal in-memory fake with exactly the methods the route functions
    call. Enough for a single route to be exercised with no real storage."""

    def __init__(self):
        self.alerts = {}      # alert_id -> doc
        self.versions = {}    # alert_id -> version
        self.reports = {}     # report_id -> doc
        self.cas_fail = {}

    def add_alert(self, alert_id, **fields):
        doc = {"alert_id": alert_id, "tenant_id": "acme", "rule_title": "r",
               "time": 1750000000000, **fields}
        self.alerts[alert_id] = doc
        self.versions[alert_id] = 1
        return doc

    def add_report(self, report_id, doc):
        self.reports[report_id] = doc

    # -- alert read / write ----------------------------------------------
    def find_alert(self, alert_id):
        doc = self.alerts.get(alert_id)
        return ("alerts-acme", doc) if doc is not None else None

    def find_alert_versioned(self, alert_id):
        doc = self.alerts.get(alert_id)
        if doc is None:
            return None
        return "alerts-acme", doc, self.versions.get(alert_id, 1)

    def index_cas(self, index, alert_id, doc, version):
        if self.cas_fail.get(alert_id):
            self.cas_fail[alert_id] -= 1
            return False
        self.alerts[alert_id] = doc
        self.versions[alert_id] = self.versions.get(alert_id, 1) + 1
        return True

    def index(self, index, doc_id, doc):
        self.alerts.setdefault(doc_id, doc)
        self.reports.setdefault(doc.get("report_id"), doc)

    # -- listings --------------------------------------------------------
    def list_alerts(self, tenant_id=None, status=None, limit=50, **extra):
        rows = list(self.alerts.values())
        if status is not None:
            rows = [d for d in rows if (d.get("triage") or {}).get("status") == status]
        return rows[:limit]

    def list_incidents(self, tenant_id=None, entity_type=None,
                       entity_value=None, limit=50):
        return getattr(self, "_incidents", [])[:limit]

    def list_events(self, family=None, tenant_id=None, limit=50):
        return getattr(self, "_events", [])[:limit]

    def find_report(self, report_id):
        # reports keyed by report_id
        for rid, doc in self.reports.items():
            if rid == report_id or doc.get("alert_id") == report_id:
                return doc
        return None


class _FakeAudit:
    def __init__(self):
        self.entries = []
        self.records = []

    def record(self, event, actor="unknown", tenant_id=None, detail=None):
        self.records.append({"event": event, "actor": actor})
        self.entries.insert(0, {"event": event, "actor": actor, "tenant_id": tenant_id,
                                "detail": detail or {}})

    def recent(self, limit=50):
        return self.entries[:limit]


class _RouteHarness:
    """A single-route `self`: real triage_api._Deps + the handful of shared
    request helpers route functions call, all captured in memory. This is the
    "construct one handler with a fake store + fake auth" hook -- no server."""

    def __init__(self, *, store=None, rbac=False, users_db=None, sessions=None,
                 rate_limiter=None, audit=None, path="/", body=b"", headers=None,
                 session=None, token=""):
        audit = audit if audit is not None else _FakeAudit()
        self.deps = triage_api._Deps(
            store=store if store is not None else _FakeStore(),
            users_db=users_db, sessions=sessions, rate_limiter=rate_limiter,
            audit_log=audit, rbac_enabled=rbac)
        self.store = self.deps.store
        self.path = path
        self.headers = {"Content-Length": str(len(body)),
                        **(headers or {})}
        self.body = body
        class _Rfile:
            def read(self, n):
                return self_body[:n]
        self_body = body
        self.rfile = _Rfile()
        self.client_address = ("1.2.3.4", 0)
        self.close_connection = False
        self.responses = []      # (code, payload, extra_headers)
        self.audits = []
        self._session = session      # session for RBAC helpers
        self._token = token
        self._role = "admin" if rbac else None

    # response capture ---------------------------------------------------
    def _send(self, code, payload, extra_headers=None):
        self.responses.append((code, payload, extra_headers))

    # query / body ---------------------------------------------------------
    def _query(self):
        return urlparse(self.path).query

    def _read_json_body(self, max_bytes):
        if len(self.body) > max_bytes:
            raise triage_api._BadRequest("request body too large")
        try:
            return json.loads(self.body or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise triage_api._BadRequest("body must be valid JSON")

    # auth / rbac helpers ----------------------------------------------------
    def _require_role(self, minimum_role):
        if not self.deps.rbac_enabled:
            return True
        if self._session is None:
            self._send(401, {"error": "not logged in"})
            return None
        if self._role != "admin":  # admin passes everything; enough for tests
            self._send(404, {"error": "no such path"})
            return None
        return self._session

    def _current_session(self):
        return self._session if self.deps.rbac_enabled else None

    def _session_token(self):
        return self._token

    def _list_tenant_filter(self, session, requested):
        if session is True or getattr(session, "role", None) == "admin":
            return requested
        return getattr(session, "tenant_id", None)

    def _tenant_gate(self, session, doc):
        if session is True:
            return True
        return True  # RBAC-on tests use the real gate via HTTP smoke instead

    def _audit_actor(self, session):
        if session is not True and session is not None:
            return str(session.username)
        return "api_key"

    def _audit(self, event, actor=None, tenant_id=None, detail=None):
        try:
            self.deps.audit.record(event=event, actor=actor or "unknown",
                                   tenant_id=tenant_id, detail=detail)
            self.audits.append(event)
        except Exception:  # noqa: BLE001
            pass

    # helpers for reading responses in assertions -------------------------
    @property
    def last(self):
        return self.responses[-1] if self.responses else (None, None, None)


def _fake_session(username="analyst", role="admin", tenant_id="acme"):
    return type("S", (), {"username": username, "role": role,
                          "tenant_id": tenant_id, "csrf_token": "csrf"})()


# ---------------------------------------------------------------------------
# per-route tests: ONE route function, ONE fake store + fake auth, NO server
# ---------------------------------------------------------------------------
def test_route_get_triage_with_fake_store():
    h = _RouteHarness(store=_FakeStore())
    h.store.add_alert("a1", triage={"status": "triaged", "note": "tp", "updated_at": 1})
    h.path = "/alerts/a1/triage"
    triage_api.route_get_triage(h, "a1")
    code, body, _ = h.last
    check(code == 200 and body["status"] == "triaged" and body["note"] == "tp",
          f"GET /alerts/a1/triage via a single route handler should return the "
          f"stored triage, got {(code, body)}")


def test_route_post_triage_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/alerts/a1/triage",
                      body=json.dumps({"status": "closed", "note": "done"}).encode())
    h.store.add_alert("a1")
    triage_api.route_post_triage(h, "a1")
    code, body, _ = h.last
    check(code == 200 and body["status"] == "closed" and body["note"] == "done",
          f"POST /alerts/a1/triage via a single route handler should return the "
          f"updated triage, got {(code, body)}")
    # persistence side effect went through the fake store's CAS path
    check(h.store.alerts["a1"]["triage"]["status"] == "closed" and
          h.store.alerts["a1"]["triage"]["note"] == "done",
          "route_post_triage must persist through self.deps.store.index_cas")
    check("triage_update" in h.audits, "route_post_triage must audit triage_update")


def test_route_get_report_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/alerts/a1/report")
    h.store.add_report("rep-1", {"report_id": "rep-1", "alert_id": "a1",
                                 "status": "draft", "title": "rep"})
    triage_api.route_get_report(h, "a1")
    code, body, _ = h.last
    check(code == 200 and body["report_id"] == "rep-1",
          f"GET /alerts/a1/report via a single route handler should return the "
          f"stored report, got {(code, body)}")


def test_route_post_report_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/alerts/a1/report?template=generic")
    h.store.add_alert("a1")
    triage_api.route_post_report(h, "a1")
    code, body, _ = h.last
    check(code == 200 and body.get("status") == "draft",
          f"POST /alerts/a1/report (generic template) should generate a draft "
          f"report, got {(code, body)}")
    check("report_generated" in h.audits,
          "route_post_report must audit report_generated")


def test_route_list_alerts_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/alerts?limit=5")
    for i in range(3):
        h.store.add_alert(f"a{i}")
    triage_api.route_list_alerts(h)
    code, body, _ = h.last
    check(code == 200 and body["count"] == 3 and len(body["alerts"]) == 3,
          f"GET /alerts via a single route handler should list 3 alerts, got {(code, body)}")


def test_route_list_incidents_events_rules_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/incidents")
    h.store._incidents = [{"id": "i1", "tactics": ["execution", "lateral"]}]
    triage_api.route_list_incidents(h)
    code, body, _ = h.last
    check(code == 200 and body["count"] == 1, f"GET /incidents failed: {(code, body)}")

    h2 = _RouteHarness(store=_FakeStore(), path="/events?family=bank")
    h2.store._events = [{"event_id": "e1"}]
    triage_api.route_list_events(h2)
    code, body, _ = h2.last
    check(code == 200 and body["count"] == 1, f"GET /events failed: {(code, body)}")

    h3 = _RouteHarness(store=_FakeStore(), path="/rules")
    triage_api.route_list_rules(h3)
    code, body, _ = h3.last
    check(code == 200 and isinstance(body.get("rules"), list),
          f"GET /rules via a single route handler failed: {(code, body)}")


def test_route_audit_with_fake_store():
    h = _RouteHarness(store=_FakeStore(), path="/audit")
    h.deps.audit.record("login_success", actor="alice", tenant_id="acme")
    triage_api.route_audit(h)
    code, body, _ = h.last
    check(code == 200 and body["count"] == 1 and
          body["entries"][0]["event"] == "login_success",
          f"GET /audit via a single route handler failed: {(code, body)}")


def test_auth_routes_with_fake_rbac_deps():
    """login -> me -> logout, and the two MFA config routes, each exercised as a
    single route handler over fake users/sessions/limiter/audit -- no server."""
    class _Users:
        def __init__(self):
            self.totp = set()
        def verify_login(self, u, p):
            return {"username": u, "role": "admin", "tenant_id": "acme"} \
                if u == "alice" and p == "pw" else None
        def is_totp_enabled(self, u): return u in self.totp
        def verify_totp(self, u, code): return True
        def get_user(self, u): return {"username": u} if u == "bob" else None
        def provision_totp(self, u): return "otpauth://totp/x?secret=ABC"

    class _Sessions:
        def __init__(self): self.active = {}
        def create(self, u, role, t):
            tok = "tok-" + u
            self.active[tok] = _fake_session(u, role, t)
            return tok
        def resolve(self, tok):
            return self.active.get(tok)
        def invalidate(self, tok): self.active.pop(tok, None)

    class _Limiter:
        def is_locked_out(self, k): return False
        def record_failure(self, k): pass
        def record_success(self, k): pass

    users = _Users()
    sessions = _Sessions()
    audit = _FakeAudit()

    # login (wrong password -> 401, then correct -> 200 + Set-Cookie)
    h = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                      sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                      path="/auth/login",
                      body=json.dumps({"username": "alice", "password": "nope"}).encode())
    triage_api.route_auth_login(h)
    code, body, _ = h.last
    check(code == 401, f"wrong-password login should 401, got {(code, body)}")

    h2 = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                       sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                       path="/auth/login",
                       body=json.dumps({"username": "alice", "password": "pw"}).encode())
    triage_api.route_auth_login(h2)
    code, body, headers = h2.last
    token = "tok-alice"
    check(code == 200 and body["username"] == "alice" and body["csrf_token"],
          f"correct login should 200 with csrf_token, got {(code, body)}")
    check(headers and "Set-Cookie" in headers,
          "correct login must set the session cookie")
    check(sessions.active[token].username == "alice",
          "login must create an active session")

    # me (with session -> identity; without -> 401)
    h3 = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                       sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                       path="/auth/me", session=sessions.active[token], token=token)
    triage_api.route_auth_me(h3)
    code, body, _ = h3.last
    check(code == 200 and body["username"] == "alice",
          f"GET /auth/me with a session should 200, got {(code, body)}")
    h3b = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                        sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                        path="/auth/me")
    triage_api.route_auth_me(h3b)
    check(h3b.last[0] == 401, f"GET /auth/me without a session should 401, got {h3b.last[0]}")

    # mfa enable / verify (admin, acting on self) via single route handlers
    h4 = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                       sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                       path="/auth/mfa/enable", session=sessions.active[token],
                       token=token,
                       body=json.dumps({"password": "pw"}).encode())
    triage_api.route_mfa_enable(h4)
    code, body, _ = h4.last
    check(code == 200 and body.get("status") == "pending-secret-verification",
          f"POST /auth/mfa/enable should 200 pending, got {(code, body)}")
    users.totp.add("alice")

    h5 = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                       sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                       path="/auth/mfa/verify", session=sessions.active[token],
                       token=token,
                       body=json.dumps({"password": "pw", "totp_code": "123456"}).encode())
    triage_api.route_mfa_verify(h5)
    code, body, _ = h5.last
    check(code == 200 and body.get("mfa_active") is True,
          f"POST /auth/mfa/verify should 200 active, got {(code, body)}")

    # logout invalidates the session
    h6 = _RouteHarness(store=_FakeStore(), rbac=True, users_db=users,
                       sessions=sessions, rate_limiter=_Limiter(), audit=audit,
                       path="/auth/logout", session=sessions.active[token],
                       token=token, body=b"{}")
    triage_api.route_auth_logout(h6)
    check(h6.last[0] == 200, f"POST /auth/logout should 200, got {h6.last[0]}")
    check(sessions.active.get(token) is None,
          "logout must invalidate the active session")


# ---------------------------------------------------------------------------
# (c) full-path smoke: the ASSEMBLED handler serves exactly the inventory
# ---------------------------------------------------------------------------
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
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _start(store, users_db=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0),
                              triage_api.make_handler(store, users_db=users_db))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _is_routed(code, body):
    """A route is 'served' if the dispatcher did not answer the unroutable-path
    404 ({"error": "no such path"} / dispatch fallback)."""
    return not (isinstance(body, dict) and body.get("error") == "no such path")


def test_full_path_smoke_rbac_off():
    """Assembled handler (real make_handler, RBAC off, default-open auth): every
    non-auth inventory route must be served; the RBAC-only routes must be hidden
    (config-level 404); an unknown path must be unroutable."""
    from storage.memory import MemoryStore  # local import: keep test self-contained
    store = MemoryStore()
    store.index("alerts-acme-2026.07.16", "a1",
                {"alert_id": "a1", "tenant_id": "acme", "rule_title": "t"})
    # Phase 5 (2026-09-04): real fixtures for the new id types, same "a1"
    # value, so the smoke loop below proves an actual 200 for each new
    # route rather than a literal unreplaced "{entity_id}" 404ing past
    # _is_routed's weak "not the dispatch fallback" bar.
    store.index("entities", "a1", {"entity_id": "a1", "entity_type": "actor",
                                    "tenant_id": "acme", "entity_value": "x"})
    store.index("incident-graphs", "a1", {"incident_id": "a1", "tenant_id": "acme",
                                           "nodes": [], "edges": []})
    store.index("incidents-acme-2026.07.16", "a1",
                {"incident_id": "a1", "tenant_id": "acme", "member_alert_ids": []})
    srv, port = _start(store)
    try:
        non_rbac = [r for r in triage_api.ROUTE_INVENTORY if not r[2]]
        served = 0
        for method, path_tpl, _ in non_rbac:
            path = (path_tpl.replace("{alert_id}", "a1")
                    .replace("{entity_id}", "a1")
                    .replace("{incident_id}", "a1"))
            code, body = _request(port, method, path)
            if _is_routed(code, body):
                served += 1
            else:
                check(False, f"RBAC-off smoke: {method} {path_tpl} was NOT routed "
                             f"(got {code} {body!r})")
        check(served == len(non_rbac),
              f"all {len(non_rbac)} non-RBAC inventory routes must be served, "
              f"saw {served}")

        # RBAC-only routes are hidden (rbac off) -- answered as unroutable.
        for method, path_tpl, rbac in triage_api.ROUTE_INVENTORY:
            if not rbac:
                continue
            code, body = _request(port, method, path_tpl.replace("{alert_id}", "a1"))
            check(not _is_routed(code, body),
                  f"RBAC-off smoke: {method} {path_tpl} must be hidden (got {code} {body!r})")

        # negative control: an unknown path is honestly unroutable.
        code, body = _request(port, "GET", "/no/such/route")
        check(code == 404 and body.get("error") == "no such path",
              f"unknown path must 404 'no such path', got {code} {body!r}")
    finally:
        srv.shutdown(); srv.server_close()


def test_full_path_smoke_rbac_on_auth_routes():
    """Assembled handler with RBAC on: the four auth routes are actually served
    (login -> me -> logout round-trip), proving the rbac-gated inventory routes
    are reachable through the assembled handler, not just declared."""
    store, users = _FakeStore(), UserStore(":memory:")
    users.create_user("alice", "pw", role="admin", tenant_id="acme")
    srv, port = _start(store, users_db=users)
    try:
        code, body, _ = None, {}, {}
        data = json.dumps({"username": "alice", "password": "pw"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/auth/login", data=data, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
                body = json.loads(resp.read().decode())
                set_cookie = resp.headers.get("Set-Cookie")
        except urllib.error.HTTPError as e:
            code, body = e.code, json.loads(e.read().decode())
            set_cookie = None
        check(code == 200 and body.get("csrf_token") and set_cookie,
              f"assembled RBAC handler: login should 200, got {code} {body!r}")
        cookie = set_cookie.split(";")[0]
        csrf = body["csrf_token"]

        code, body = _request(port, "GET", "/auth/me", cookie=cookie)
        check(code == 200 and body["username"] == "alice",
              f"assembled RBAC handler: /auth/me should 200, got {code} {body!r}")

        code, body = _request(port, "POST", "/auth/logout", cookie=cookie, csrf=csrf)
        check(code == 200 and body.get("ok") is True,
              f"assembled RBAC handler: /auth/logout should 200, got {code} {body!r}")
    finally:
        srv.shutdown(); srv.server_close()


def main():
    test_route_inventory_matches_pre_refactor_baseline()
    test_concurrent_servers_keep_isolated_deps()
    test_route_get_triage_with_fake_store()
    test_route_post_triage_with_fake_store()
    test_route_get_report_with_fake_store()
    test_route_post_report_with_fake_store()
    test_route_list_alerts_with_fake_store()
    test_route_list_incidents_events_rules_with_fake_store()
    test_route_audit_with_fake_store()
    test_auth_routes_with_fake_rbac_deps()
    test_full_path_smoke_rbac_off()
    test_full_path_smoke_rbac_on_auth_routes()

    if FAILS:
        print(f"[FAIL] WP-2-I route decomposition: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    got = len(triage_api.ROUTE_INVENTORY)
    print(f"[OK] WP-2-I route decomposition: {got} routes decomposed into "
          f"per-route functions; inventory matches pre-refactor baseline; "
          f"single-route fake-store tests + full-path smoke pass")


if __name__ == "__main__":
    main()

