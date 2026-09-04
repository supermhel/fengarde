"""WS-3 Triage HTTP API (v0.3, C1; M4.2 adds opt-in session RBAC).

The dashboard renders alert rows with no way to act on them. This is the
minimal real workflow: a status + analyst note per alert, persisted.

Endpoints:
  GET  /alerts/{alert_id}/triage        -> current triage state (default "new")
  POST /alerts/{alert_id}/triage        -> {status, note?} -> updates + returns it
  GET  /alerts/{alert_id}/report        -> existing report, if generated
  POST /alerts/{alert_id}/report        -> generate + store a draft report
  POST /auth/login   {username,password} -> session cookie + csrf_token (RBAC mode only)
  POST /auth/logout                      -> invalidate the session cookie
  GET  /auth/me                          -> current session identity + csrf_token

Every state-changing (POST) request made with an active session must echo the
session's csrf_token (from /auth/login or /auth/me) back as an `X-CSRF-Token`
header, or it's rejected 403 -- see `_check_csrf`'s docstring. A no-op when
RBAC is off or the request carries no session cookie at all.

M4.3 versioned REST API -- every route above, plus the three below, is also
reachable under an `/api/v1` prefix (e.g. `/api/v1/alerts/{id}/triage`);
both forms hit the exact same handler. The bare (unprefixed) paths are NOT
deprecated -- the dashboard's nginx proxy (services/ws7-dashboard) targets
them directly and that wiring is not being changed by this pass. `/api/v1`
is the documented, versioned surface for new integrations going forward.
See contracts/triage-api.yaml for the full OpenAPI 3.1 spec.

  GET  /alerts   ?tenant_id=&status=&limit=   -> newest-first alert list
  GET  /incidents ?tenant_id=&entity_type=&entity_value=&limit=
                                               -> newest-first (by last_seen)
                                                  correlated-incident list
                                                  (WS-8, 2026-08-18)
  GET  /events    ?family=&tenant_id=&limit=  -> newest-first event list
  GET  /rules                                 -> rule summaries (read-only;
                                                  never exposes a rule's raw
                                                  `condition` -- see
                                                  rules_view.py)

All three are bounded listing, not free-text search (no query DSL is
exposed over HTTP). RBAC (M4.2), when enabled, forces non-admin callers'
`tenant_id` to their own session tenant regardless of what a `tenant_id`
query parameter asks for -- it is silently overridden, not merely checked,
same "never let the caller widen their own scope" posture as the
per-alert 404 gate below.

Mirrors services/ws6-inventory/app.py's stdlib http.server discipline exactly
(input validation, body-size cap, clean 4xx on malformed input, handler thread
never crashes) rather than introducing a new framework/dependency.

Storage: the `triage` field is added to the EXISTING alert document (OCSF-
additive -- an old alert doc without it defaults to status "new", tolerant
reader). Uses `store.find_alert(alert_id)` (added to both MemoryStore and
OpenSearchStore) since the client only holds alert_id, not which daily index
it landed in.

RBAC (M4.2) is OPT-IN, same convention as every other auth layer in this
project (FENGARDE_API_KEY, dashboard basic-auth, Redis AUTH -- all default
off): pass `users_db=None` (the default) and behavior is EXACTLY the pre-M4.2
shared-secret-only auth, unchanged. Pass a real `UserStore` and the
triage/report endpoints require a logged-in SESSION (not the API key -- a
browser session proves more, a shared static key doesn't carry a role or
tenant) with sufficient role, scoped to the alert's own tenant (or any
tenant, for role=admin). A cross-tenant or under-privileged request gets 404
(not 403) so a request never confirms an out-of-scope alert exists.

STRUCTURE (WP-2-I, structural-only refactor -- every route's behavior is
byte-identical to the pre-refactor single 830-line `make_handler` closure):

Each HTTP route is a MODULE-LEVEL function `route_*(self)` (or `mfa_*` for
the two session helpers), where `self` is an object exposing the shared
request helpers (`_send`, `_require_role`, `_tenant_gate`, `_current_session`,
`_read_json_body`, `_audit`, ...) plus a `.deps` attribute that carries the
per-server dependency bundle (store, RBAC session machinery, audit log --
exactly what the old closure captured). `make_handler` is now only a thin
assembler: it builds that `_Deps` bundle, binds it to the module-level
`Handler` class, and returns it. `Handler` keeps only the shared request
helpers and the thin `do_GET`/`do_POST` dispatchers that decode the path and
forward to the per-route function.

The point is per-route testability: a test can build ONE route handler by
calling `make_handler(fake_store)` (or a fake `self`) and exercise a SINGLE
`route_*(self)` function directly -- no live HTTP server required -- while the
existing suite keeps proving the assembled handler via real HTTP. `ROUTE_INVENTORY`
documents the exact (method, path) surface so the pre/post route table can be
compared verbatim (see test_route_decomposition.py).
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
import time
import traceback
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_HERE = Path(__file__).resolve().parent
for _p in (str(_HERE), str(_HERE.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from shared.authz import check_api_key, warn_if_disabled  # noqa: E402
from shared.ip_utils import valid_ip  # noqa: E402
from shared.log import get_logger  # noqa: E402
from shared.rbac import role_at_least, can_access_tenant, LoginRateLimiter  # noqa: E402
from shared.sessions import SessionStore, make_session_store  # noqa: E402

_LOG = get_logger("ws3-indexer-triage")  # noqa: E402 - module-level handler logger

# local sibling modules stay imported here (not in route functions) so the
# functions below are pure and the module keeps one import site.
import reporting  # noqa: E402
import rules_view  # noqa: E402
import nis2_template  # noqa: E402
import audit  # noqa: E402
import evidence_package  # noqa: E402

_MAX_BODY_BYTES = 4096  # a triage update is a status enum + a short note.
_MAX_NOTE_CHARS = 2000
_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}
_CAS_MAX_RETRIES = 5  # optimistic-concurrency retry bound (see route_post_triage)
_SESSION_COOKIE = "fengarde_session"
_FAMILIES = {"bank", "dc", "common"}
_DEFAULT_LIST_LIMIT = 50
_MAX_LIST_LIMIT = 200

# -- FIX L4: optional per-IP token-bucket API rate limiting ------------------
# Off by default (RATE_LIMIT_REQUESTS_PER_MIN unset/0/<=0). When enabled, a
# token bucket per client IP lets `RATE_LIMIT_REQUESTS_PER_MIN` requests per
# minute through and answers 429 (with Retry-After) beyond that. In-memory
# per-process (same scope as LoginRateLimiter); sufficient as a per-instance
# guard, not a cluster-wide one.
def _rate_limit_per_min() -> int:
    raw = os.getenv("RATE_LIMIT_REQUESTS_PER_MIN", "0")
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


_RATE_LIMIT = _rate_limit_per_min()
_rate_buckets: dict[str, "_TokenBucket"] = {}
_rate_lock = threading.Lock()
_rate_calls = 0
_RATE_SWEEP_EVERY = 256  # mirrors shared/rbac.py::LoginRateLimiter's periodic sweep
_RATE_STALE_S = 600  # 10 idle minutes fully refills any bucket -- safe to drop


class _TokenBucket:
    """Leaky/token bucket: `capacity` tokens, refilled at tokens/sec."""

    __slots__ = ("capacity", "tokens", "refill_per_s", "updated")

    def __init__(self, capacity: float, refill_per_s: float):
        self.capacity = max(capacity, 1.0)
        self.tokens = self.capacity
        self.refill_per_s = refill_per_s
        self.updated = time.time()

    def allow(self) -> bool:
        now = time.time()
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.updated) * self.refill_per_s)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


def _rate_limit_allowed(ip: str) -> bool:
    """True if `ip` may proceed. Always True when rate limiting is off."""
    global _rate_calls
    if _RATE_LIMIT <= 0:
        return True
    refill_per_s = _RATE_LIMIT / 60.0
    with _rate_lock:
        bucket = _rate_buckets.get(ip)
        if bucket is None:
            bucket = _TokenBucket(float(_RATE_LIMIT), refill_per_s)
            _rate_buckets[ip] = bucket
        result = bucket.allow()
        _rate_calls += 1
        if _rate_calls % _RATE_SWEEP_EVERY == 0:
            now = time.time()
            stale = [k for k, b in _rate_buckets.items() if now - b.updated > _RATE_STALE_S]
            for k in stale:
                _rate_buckets.pop(k, None)
        return result


def _strip_api_v1(path: str) -> str:
    """`/api/v1/x` and `/x` route identically -- `/api/v1` is the documented
    versioned surface, the bare path is the pre-existing one the dashboard's
    nginx proxy already targets. Only a path exactly `/api/v1` or starting
    `/api/v1/` is affected; `/api/v1foo` is left alone (not a prefix)."""
    if path == "/api/v1":
        return "/"
    if path.startswith("/api/v1/"):
        return path[len("/api/v1"):]
    return path


class _BadRequest(Exception):
    """Malformed client input; mapped to a 400 by the dispatcher."""


def _parse_limit(raw: list[str] | None) -> int:
    if not raw:
        return _DEFAULT_LIST_LIMIT
    try:
        n = int(raw[0])
    except (TypeError, ValueError):
        raise _BadRequest("limit must be an integer")
    if n < 1:
        raise _BadRequest("limit must be >= 1")
    return min(n, _MAX_LIST_LIMIT)


def _default_triage() -> dict:
    return {"status": "new", "note": "", "updated_at": None}


# ---------------------------------------------------------------------------
# ROUTE INVENTORY (WP-2-I)
#
# The authoritative (method, path, rbac_only) surface this API serves. It is
# checked against a verbatim pre-refactor baseline by test_route_decomposition
# so a decomposition can never silently add/drop a route, and the assembled
# Handler is smoke-tested to actually serve every entry (and nothing else).
# `rbac_only=True` means the route is only reachable when RBAC is enabled
# (config-level 404 otherwise, see Handler.do_GET/do_POST).
# ---------------------------------------------------------------------------
ROUTE_INVENTORY: list[tuple[str, str, bool]] = [
    ("GET", "/auth/me", True),
    ("GET", "/alerts", False),
    ("GET", "/incidents", False),
    ("GET", "/events", False),
    ("GET", "/rules", False),
    ("GET", "/audit", False),
    ("GET", "/alerts/{alert_id}/report", False),
    ("GET", "/alerts/{alert_id}/triage", False),
    ("GET", "/entities/{entity_id}", False),
    ("GET", "/incidents/{incident_id}/graph", False),
    ("GET", "/incidents/{incident_id}/evidence", False),
    ("POST", "/auth/login", True),
    ("POST", "/auth/logout", True),
    ("POST", "/auth/mfa/enable", True),
    ("POST", "/auth/mfa/verify", True),
    ("POST", "/alerts/{alert_id}/report", False),
    ("POST", "/alerts/{alert_id}/triage", False),
]


class _Deps:
    """Per-server dependency bundle, bound to `Handler` by make_handler.

    Carries exactly what the original (removed) `make_handler` closure
    captured: the store, the RBAC session machinery, the E1 audit log, and
    whether RBAC is on. Every route function reads its server dependencies
    through `self.deps`; a per-route test supplies a fake `_Deps` (or a fake
    `self`) and exercises exactly one route with no server.
    """

    __slots__ = ("store", "users_db", "sessions", "rate_limiter", "audit", "rbac_enabled")

    def __init__(self, store, users_db, sessions, rate_limiter, audit_log, rbac_enabled):
        self.store = store
        self.users_db = users_db
        self.sessions = sessions
        self.rate_limiter = rate_limiter
        self.audit = audit_log
        self.rbac_enabled = rbac_enabled


# ---------------------------------------------------------------------------
# PER-ROUTE HANDLERS
#
# One module-level function per HTTP route. Each takes `self` (a `Handler`
# instance, or a test double exposing the same helpers + `.deps`) and returns
# whatever the route responds with (usually the result of `self._send(...)`).
# They are pure of server assembly -- the whole point of the decomposition.
# ---------------------------------------------------------------------------

def route_auth_me(self):
    session = self._current_session()
    if session is None:
        return self._send(401, {"error": "not logged in"})
    # csrf_token is included here too so a page reload (JS state
    # lost, session cookie still valid) can recover it without a
    # fresh login.
    return self._send(200, {"username": session.username, "role": session.role,
                             "tenant_id": session.tenant_id, "csrf_token": session.csrf_token})


def route_get_report(self, alert_id: str):
    """GET /alerts/{id}/report -- existing draft report, if any."""
    if not alert_id:
        raise _BadRequest("alert_id required")
    session = self._require_role("read_only")
    if session is None:
        return
    report = self.deps.store.find_report(alert_id)
    if report is None:
        return self._send(404, {"error": "report not found"})
    found_alert = self.deps.store.find_alert(alert_id)
    if found_alert is not None:
        if not self._tenant_gate(session, found_alert[1]):
            return
    elif session is not True and session.role != "admin":
        # The backing alert doc is gone (aged out under independent retention,
        # or deleted) -- report docs carry no tenant_id of their own, so there
        # is no way to verify which tenant this report belongs to. A non-admin
        # caller must be denied (fail-closed), not silently let through just
        # because the alert lookup came back empty.
        return self._send(404, {"error": "report not found"})
    return self._send(200, report)


def route_get_triage(self, alert_id: str):
    """GET /alerts/{id}/triage -- current triage state (default "new")."""
    if not alert_id:
        raise _BadRequest("alert_id required")
    session = self._require_role("read_only")
    if session is None:
        return
    found = self.deps.store.find_alert(alert_id)
    if found is None:
        return self._send(404, {"error": "alert not found"})
    _, doc = found
    if not self._tenant_gate(session, doc):
        return
    return self._send(200, doc.get("triage") or _default_triage())


def route_get_entity(self, entity_id: str):
    """GET /entities/{id} -- a WS-9-resolved entity's current canonical
    state (Phase 5, 2026-09-04: the entity.updates topic existed since
    Phase 2 with no consumer or read route until this)."""
    if not entity_id:
        raise _BadRequest("entity_id required")
    session = self._require_role("read_only")
    if session is None:
        return
    found = self.deps.store.find_entity(entity_id)
    if found is None:
        return self._send(404, {"error": "entity not found"})
    _, doc = found
    if not self._tenant_gate(session, doc):
        return
    return self._send(200, doc)


def route_get_incident_graph(self, incident_id: str):
    """GET /incidents/{id}/graph -- the typed causal DAG WS-8 emitted for
    this incident (Phase 5, 2026-09-04)."""
    if not incident_id:
        raise _BadRequest("incident_id required")
    session = self._require_role("read_only")
    if session is None:
        return
    found = self.deps.store.find_incident_graph(incident_id)
    if found is None:
        return self._send(404, {"error": "incident graph not found"})
    _, doc = found
    if not self._tenant_gate(session, doc):
        return
    return self._send(200, doc)


def route_get_incident_evidence(self, incident_id: str):
    """GET /incidents/{id}/evidence -- build, hash-verify, and serve this
    incident's evidence package on demand (Phase 5, 2026-09-04).

    Built fresh from the store's own current data on every call, not
    persisted -- evidence_package.py was delivered standalone (WP-3-B) with
    no route ever calling it; this is that first consumer. NEVER serves an
    unverified/tampered chain: verify_evidence_package() runs before the
    response is sent, not after -- a verification failure here means the
    STORED source docs disagree with what a freshly-built package's own
    hash chain expects (a data-integrity problem, not normally reachable --
    test_evidence_package.py already proves a fresh build always verifies),
    and gets a 409, never a 200 with the failures silently dropped.
    """
    if not incident_id:
        raise _BadRequest("incident_id required")
    session = self._require_role("read_only")
    if session is None:
        return
    found = self.deps.store.find_incident(incident_id)
    if found is None:
        return self._send(404, {"error": "incident not found"})
    _, incident = found
    if not self._tenant_gate(session, incident):
        return

    member_ids = set(incident.get("member_alert_ids") or [])
    alerts = []
    for alert_id in member_ids:
        found_alert = self.deps.store.find_alert(alert_id)
        if found_alert is not None:
            alerts.append(found_alert[1])
    event_ids: set[str] = set()
    for alert in alerts:
        event_ids.update(str(e) for e in (alert.get("event_ids") or []))
    events = self.deps.store.find_events(event_ids) if event_ids else []
    graph_found = self.deps.store.find_incident_graph(incident_id)
    graph = graph_found[1] if graph_found is not None else None

    pkg = evidence_package.build_evidence_package(
        incident, alerts, events, graph,
        now_ms=int(time.time() * 1000), package_id_prefix="ws3-live")
    failures = evidence_package.verify_evidence_package(pkg)
    if failures:
        _LOG.error("evidence package failed verification on build",
                   incident_id=incident_id, failures=failures)
        return self._send(409, {"error": "evidence package failed verification",
                                "failures": failures})
    return self._send(200, pkg)


def route_list_alerts(self):
    session = self._require_role("read_only")
    if session is None:
        return
    q = parse_qs(self._query())
    requested_tenant = q.get("tenant_id", [None])[0]
    status = q.get("status", [None])[0]
    if status is not None and status not in _STATUSES:
        raise _BadRequest(f"status must be one of {sorted(_STATUSES)}")
    limit = _parse_limit(q.get("limit"))
    tenant_id = self._list_tenant_filter(session, requested_tenant)
    extra = {}
    actor = q.get("actor", [None])[0]
    if actor is not None:
        extra["actor"] = actor
    src_ip = q.get("src_ip", [None])[0]
    if src_ip is not None:
        extra["src_ip"] = src_ip
    alerts = self.deps.store.list_alerts(tenant_id=tenant_id, status=status,
                                         limit=limit, **extra)
    return self._send(200, {"alerts": alerts, "count": len(alerts)})


def route_list_incidents(self):
    session = self._require_role("read_only")
    if session is None:
        return
    q = parse_qs(self._query())
    requested_tenant = q.get("tenant_id", [None])[0]
    entity_type = q.get("entity_type", [None])[0]
    if entity_type is not None and entity_type not in ("actor", "ip", "device"):
        raise _BadRequest("entity_type must be one of ['actor', 'ip', 'device']")
    entity_value = q.get("entity_value", [None])[0]
    if entity_type == "ip" and entity_value is not None:
        # WS-8 stores `ip:` incidents' entity_value in canonical (lowercased,
        # de-compressed) IPv6 form (correlator.py's `_canonical_ip`); the
        # storage layer does an exact-match term/`==` lookup, so a query in
        # any other casing/compression used to silently return zero results
        # for a real matching incident (2026-09-02 review). Canonicalize the
        # query param the same way before filtering; non-IP-parseable input
        # passes through unchanged so a garbage filter still just matches
        # nothing, same as before.
        entity_value = valid_ip(entity_value) or entity_value
    limit = _parse_limit(q.get("limit"))
    tenant_id = self._list_tenant_filter(session, requested_tenant)
    incidents = self.deps.store.list_incidents(tenant_id=tenant_id,
                                               entity_type=entity_type,
                                               entity_value=entity_value, limit=limit)
    return self._send(200, {"incidents": incidents, "count": len(incidents)})


def route_list_events(self):
    session = self._require_role("read_only")
    if session is None:
        return
    q = parse_qs(self._query())
    family = q.get("family", [None])[0]
    if family is not None and family not in _FAMILIES:
        raise _BadRequest(f"family must be one of {sorted(_FAMILIES)}")
    requested_tenant = q.get("tenant_id", [None])[0]
    limit = _parse_limit(q.get("limit"))
    tenant_id = self._list_tenant_filter(session, requested_tenant)
    events = self.deps.store.list_events(family=family, tenant_id=tenant_id, limit=limit)
    return self._send(200, {"events": events, "count": len(events)})


def route_list_rules(self):
    session = self._require_role("read_only")
    if session is None:
        return
    q = parse_qs(self._query())
    requested_tenant = q.get("tenant_id", [None])[0]
    tenant_id = self._list_tenant_filter(session, requested_tenant)
    rules = rules_view.list_rule_summaries(tenant_id)
    return self._send(200, {"rules": rules, "count": len(rules)})


def route_audit(self):
    """GET /audit -- admin-only view of the recent audit trail."""
    session = self._require_role("admin")
    if session is None:
        return
    q = parse_qs(self._query())
    limit = _parse_limit(q.get("limit"))
    entries = self.deps.audit.recent(limit)
    return self._send(200, {"entries": entries, "count": len(entries)})


def route_auth_login(self):
    body = self._read_json_body(_MAX_BODY_BYTES)
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username:
        raise _BadRequest("username and password (strings) are required")

    if self.deps.rate_limiter.is_locked_out(username):
        self._audit("login_failure", actor=username,
                    detail={"reason": "locked_out", "username": username})
        return self._send(401, {"error": "invalid credentials"})

    row = self.deps.users_db.verify_login(username, password)
    if row is None:
        self.deps.rate_limiter.record_failure(username)
        self._audit("login_failure", actor=username,
                    detail={"reason": "bad_credentials", "username": username})
        return self._send(401, {"error": "invalid credentials"})
    self.deps.rate_limiter.record_success(username)

    # FENGARDE E3 MFA -- OPT-IN per user. See original in-repo comment.
    if self.deps.users_db.is_totp_enabled(username):
        totp_code = body.get("totp_code")
        if not isinstance(totp_code, str) or not self.deps.users_db.verify_totp(username, totp_code):
            self.deps.rate_limiter.record_failure(username)
            self._audit("login_failure", actor=username,
                        detail={"reason": "bad_totp", "username": username})
            return self._send(401, {"error": "invalid credentials"})

    token = self.deps.sessions.create(row["username"], row["role"], row["tenant_id"])
    csrf_token = self.deps.sessions.resolve(token).csrf_token
    cookie = SimpleCookie()
    cookie[_SESSION_COOKIE] = token
    cookie[_SESSION_COOKIE]["httponly"] = True
    cookie[_SESSION_COOKIE]["path"] = "/"
    cookie[_SESSION_COOKIE]["samesite"] = "Strict"
    set_cookie = cookie[_SESSION_COOKIE].OutputString()
    self._audit("login_success", actor=row["username"],
                tenant_id=row["tenant_id"],
                detail={"username": row["username"], "role": row["role"]})
    return self._send(200, {"username": row["username"], "role": row["role"],
                             "tenant_id": row["tenant_id"], "csrf_token": csrf_token},
                       extra_headers={"Set-Cookie": set_cookie})


def route_auth_logout(self):
    token = self._session_token()
    if token:
        self.deps.sessions.invalidate(token)
    session = self._current_session()
    if session is not None:
        self._audit("logout", actor=session.username,
                    tenant_id=session.tenant_id, detail={"username": session.username})
    cookie = SimpleCookie()
    cookie[_SESSION_COOKIE] = ""
    cookie[_SESSION_COOKIE]["path"] = "/"
    cookie[_SESSION_COOKIE]["max-age"] = 0
    return self._send(200, {"ok": True},
                       extra_headers={"Set-Cookie": cookie[_SESSION_COOKIE].OutputString()})


def mfa_target(self, session, body):
    """The username an MFA action applies to: the acting user by default, OR
    another user when an admin supplies `username` in the body."""
    target = body.get("username")
    if target is None:
        return session.username
    if session.role != "admin":
        self._send(404, {"error": "no such path"})
        return None
    if not isinstance(target, str) or not self.deps.users_db.get_user(target):
        self._send(404, {"error": "no such user"})
        return None
    return target


def mfa_reauth(self, session, body) -> bool:
    """Re-auth gate for MFA-config-changing routes (enable/verify). Requires
    the ACTING session's own current `password` in the body. See original
    in-repo comment (FENGARDE E3, 2026-08-06)."""
    assert self.deps.rate_limiter is not None
    key = f"mfa:{session.username}"
    if self.deps.rate_limiter.is_locked_out(key):
        self._audit("mfa_reauth_failure", actor=session.username,
                    tenant_id=session.tenant_id, detail={"reason": "locked_out"})
        self._send(401, {"error": "reauthentication required"})
        return False
    password = body.get("password")
    if (not isinstance(password, str)
            or self.deps.users_db.verify_login(session.username, password) is None):
        self.deps.rate_limiter.record_failure(key)
        self._audit("mfa_reauth_failure", actor=session.username,
                    tenant_id=session.tenant_id, detail={"reason": "bad_password"})
        self._send(401, {"error": "reauthentication required"})
        return False
    self.deps.rate_limiter.record_success(key)
    return True


def route_mfa_enable(self):
    """POST /auth/mfa/enable -- opt-in MFA step one: generate a secret, store
    it (pending), and hand back the otpauth:// URI for a QR code."""
    session = self._current_session()
    if session is None:
        return self._send(401, {"error": "not logged in"})
    body = self._read_json_body(_MAX_BODY_BYTES)
    if not mfa_reauth(self, session, body):
        return
    target = mfa_target(self, session, body)
    if target is None:
        return
    try:
        uri = self.deps.users_db.provision_totp(target)
    except Exception:  # noqa: BLE001 - mfa module missing/broken
        return self._send(503, {"error": "MFA provisioning unavailable"})
    self._audit("mfa_enable", actor=session.username,
                tenant_id=session.tenant_id, detail={"target": target})
    return self._send(200, {"username": target, "otpauth_uri": uri,
                             "status": "pending-secret-verification"})


def route_mfa_verify(self):
    """POST /auth/mfa/verify -- opt-in MFA step two: activate a provisioned
    TOTP with a valid `totp_code`. Uses verify_totp (consumes the enrollment
    code = replay protection), not confirm_totp -- see in-repo comment."""
    session = self._current_session()
    if session is None:
        return self._send(401, {"error": "not logged in"})
    body = self._read_json_body(_MAX_BODY_BYTES)
    if not mfa_reauth(self, session, body):
        return
    target = mfa_target(self, session, body)
    if target is None:
        return
    code = body.get("totp_code")
    if not isinstance(code, str):
        return self._send(400, {"error": "totp_code (string) is required"})
    if not self.deps.users_db.verify_totp(target, code):
        self._audit("mfa_verify_failure", actor=session.username,
                    tenant_id=session.tenant_id, detail={"target": target})
        return self._send(401, {"error": "invalid totp code"})
    self._audit("mfa_verify_success", actor=session.username,
                tenant_id=session.tenant_id, detail={"target": target})
    return self._send(200, {"username": target, "mfa_active": True})


def route_post_report(self, report_alert_id: str):
    """POST /alerts/{id}/report -- generate + store a draft report.

    Drains any request body the client may send (this endpoint takes none) so
    the connection doesn't get reset with unread bytes still buffered; an
    unparseable/oversized Content-Length is a 400 (same as the triage route).
    """
    try:
        length = int(self.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        raise _BadRequest("invalid Content-Length")
    if length < 0:
        raise _BadRequest("invalid Content-Length")
    if length > _MAX_BODY_BYTES:
        self.close_connection = True
        raise _BadRequest("request body too large")
    elif length > 0:
        self.rfile.read(length)
    if not report_alert_id:
        raise _BadRequest("alert_id required")
    session = self._require_role("analyst")  # report generation is a write action
    if session is None:
        return
    found = self.deps.store.find_alert(report_alert_id)
    if found is None:
        return self._send(404, {"error": "alert not found"})
    _, alert_doc = found
    if not self._tenant_gate(session, alert_doc):
        return
    triage = alert_doc.get("triage") or _default_triage()
    q = parse_qs(self._query())
    template = (q.get("template", ["generic"])[0] or "generic").lower()
    if template == "nis2":
        stage = q.get("stage", ["notification"])[0]
        lang = q.get("lang", ["de"])[0]
        report = nis2_template.build_report(alert_doc, triage, stage=stage, lang=lang)
    else:
        report = reporting.generate_report(alert_doc, triage)
    report_index = reporting._report_index()
    self.deps.store.index(report_index, report["report_id"], report)
    self._audit("report_generated",
                actor=self._audit_actor(session),
                tenant_id=alert_doc.get("tenant_id"),
                detail={"alert_id": report_alert_id,
                        "report_id": report.get("report_id"),
                        "template": template})
    return self._send(200, report)


def route_post_triage(self, alert_id: str):
    """POST /alerts/{id}/triage -- partial {status?, note?} update.

    CAS-retry bounded at _CAS_MAX_RETRIES (optimistic concurrency across
    replicas; no process-wide lock -- see in-repo P2-5 comment). Preserves the
    existing note unless "note" is explicitly present (even as "").
    """
    if not alert_id:
        raise _BadRequest("alert_id required")

    session = self._require_role("analyst")  # triage status/note is a write action
    if session is None:
        return

    try:
        length = int(self.headers.get("Content-Length", 0))
    except (TypeError, ValueError):
        raise _BadRequest("invalid Content-Length")
    if length < 0:
        raise _BadRequest("invalid Content-Length")
    if length > _MAX_BODY_BYTES:
        self.close_connection = True
        raise _BadRequest("request body too large")
    try:
        body = json.loads(self.rfile.read(length) or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise _BadRequest("body must be valid JSON")
    if not isinstance(body, dict):
        raise _BadRequest("body must be a JSON object")

    status = body.get("status")
    if status is not None and status not in _STATUSES:
        raise _BadRequest(f"status must be one of {sorted(_STATUSES)}")
    note_present = "note" in body
    note = body.get("note")
    if note_present:
        if not isinstance(note, str):
            raise _BadRequest("note must be a string")
        note = note[:_MAX_NOTE_CHARS]

    for _attempt in range(_CAS_MAX_RETRIES):
        found = self.deps.store.find_alert_versioned(alert_id)
        if found is None:
            return self._send(404, {"error": "alert not found"})
        index, doc, version = found
        if not self._tenant_gate(session, doc):
            return

        triage = dict(doc.get("triage") or _default_triage())
        if status is not None:
            triage["status"] = status
        if note_present:
            triage["note"] = note
        triage["updated_at"] = int(time.time() * 1000)

        doc = dict(doc)
        doc["triage"] = triage
        if self.deps.store.index_cas(index, alert_id, doc, version):
            self._audit("triage_update",
                        actor=self._audit_actor(session),
                        tenant_id=doc.get("tenant_id"),
                        detail={"alert_id": alert_id,
                                "status": triage.get("status"),
                                "updated_at": triage.get("updated_at")})
            return self._send(200, triage)
    return self._send(409, {"error": "conflicting concurrent updates, retry"})


class _DepsAccess:
    """Descriptor giving `deps` on BOTH the instance (routes: self.deps.store)
    and the make_handler-rendered subclass (test: Handler_Class.deps.store).

    A bare @property is only invoked on INSTANCE access; `SomeClass.deps`
    returns the property object itself, breaking the route-decomposition test
    that inspects the returned handler class's `.deps.store`. This descriptor
    delegates to the class attribute `_deps` for both access modes.
    """
    __slots__ = ("_name",)

    def __set_name__(self, owner, name):
        self._name = name

    def __get__(self, obj, objtype=None):
        # Instance access (obj is the Handler instance): find `_deps` on the
        # instance OR its class/MRO (make_handler sets it as a class attribute
        # on the returned subclass). Class access (`Handler_Class.deps`, obj is
        # None -> objtype is the class) resolves the same way.
        deps = None
        if obj is not None and "_deps" in obj.__dict__:
            deps = obj.__dict__["_deps"]
        if deps is None:
            for base in objtype.__mro__:
                if "_deps" in base.__dict__:
                    deps = base.__dict__["_deps"]
                    break
        if deps is None:
            raise RuntimeError("Handler.deps accessed before make_handler bound it")
        return deps

    def __set__(self, obj, value):
        obj._deps = value


class Handler(BaseHTTPRequestHandler):
    """Thin assembled HTTP handler. Shared request helpers live here; the
    per-route logic lives in the module-level `route_*`/`mfa_*` functions.
    `.deps` (the per-server dependency bundle) is bound by make_handler, which
    returns a one-line subclass carrying this server's own `_Deps`."""

    timeout = 15

    # Set on the per-server subclass by make_handler. Declared as Optional but
    # ALWAYS present on a server built by make_handler; `deps` (the custom
    # descriptor below) narrows the type + fails loud if accessed bare.
    _deps: "_Deps | None" = None
    deps = _DepsAccess()

    # -- shared helpers (request-scoped) ------------------------------------

    def _send(self, code: int, payload, extra_headers: dict | None = None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet
        pass

    def _query(self) -> str:
        """Raw query string of the current request path (added in the WP-2-I
        decomposition so route functions share one way to read the query;
        replaces the old per-route `urlparse(self.path).query`)."""
        return urlparse(self.path).query

    def _alert_id_from_path(self, path: str, resource: str = "triage") -> str | None:
        # /alerts/{alert_id}/{resource}  (resource: "triage" | "report")
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "alerts" and parts[2] == resource:
            return parts[1]
        return None

    def _id_from_path(self, path: str, prefix: str, resource: str | None = None) -> str | None:
        """Generic sibling of _alert_id_from_path (Phase 5, 2026-09-04):
        /{prefix}/{id} when resource is None, /{prefix}/{id}/{resource}
        otherwise. Kept separate rather than generalizing
        _alert_id_from_path itself -- that one's docstring/name is
        alerts-specific and every existing call site relies on that."""
        parts = path.strip("/").split("/")
        if resource is None:
            if len(parts) == 2 and parts[0] == prefix:
                return parts[1]
            return None
        if len(parts) == 3 and parts[0] == prefix and parts[2] == resource:
            return parts[1]
        return None

    # -- M4.2 session helpers (no-ops when RBAC is off) ----------------------

    def _session_token(self) -> str:
        raw = self.headers.get("Cookie")
        if not raw:
            return ""
        jar = SimpleCookie()
        jar.load(raw)
        morsel = jar.get(_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _current_session(self):
        if not self.deps.rbac_enabled:
            return None
        token = self._session_token()
        if not token:
            return None
        try:
            return self.deps.sessions.resolve(token)
        except Exception:  # noqa: BLE001 - a session-store outage must never 500
            return None

    def _require_role(self, minimum_role: str):
        """Return the active session if it satisfies `minimum_role`, or send an
        error response and return None. When RBAC is off this ALWAYS returns a
        truthy sentinel (auth already happened via check_api_key at the call site)."""
        if not self.deps.rbac_enabled:
            return True
        session = self._current_session()
        if session is None:
            self._send(401, {"error": "not logged in"})
            return None
        if not role_at_least(session.role, minimum_role):
            self._send(404, {"error": "no such path"})
            return None
        return session

    def _tenant_gate(self, session, doc: dict) -> bool:
        """True if `session` (real Session, or True when RBAC is off) may access
        `doc`'s tenant. Sends 404 and returns False otherwise."""
        if session is True:  # RBAC off
            return True
        if can_access_tenant(session.role, session.tenant_id, doc.get("tenant_id")):
            return True
        self._send(404, {"error": "alert not found"})
        return False

    def _check_auth(self) -> bool:
        """Coarse pre-dispatch gate. `_require_role()` (session role) and
        `_tenant_gate()` (session tenant scope) do the fine-grained work
        per route; this only decides whether the caller presented SOME
        valid credential at all.

        Gap-hunt fix (2026-09-04): a valid RBAC session used to still need
        the API key header too when both FENGARDE_RBAC_DB and
        FENGARDE_API_KEY were set -- contradicting this module's own
        documented contract ("triage/report endpoints require a logged-in
        SESSION (not the API key)") and `_require_role`'s own comment
        ("when RBAC is off... auth already happened via check_api_key"),
        which only makes sense if a session is the alternative auth path
        when RBAC is ON. Untested combination (test_rbac_api never sends
        X-Api-Key) is exactly how this went unnoticed. A session with an
        insufficient role, or no session/key at all, is still rejected --
        by `_require_role`/`_tenant_gate` for the former, here for the
        latter.
        """
        if check_api_key(self.headers):
            return True
        if self.deps.rbac_enabled and self._current_session() is not None:
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def _audit_actor(self, session) -> str:
        """The actor name for an audit entry. RBAC-off (session is the True
        sentinel) means the shared API key is authenticating -- name it as a
        non-person actor; a real session uses its username."""
        if session is not True and session is not None:
            return str(session.username)
        return "api_key"

    def _audit(self, event: str, actor: str | None = None,
               tenant_id: str | None = None, detail: dict | None = None) -> None:
        """E1: fail-open audit write. Any failure inside the audit log is
        swallowed here so an audit outage can never raise into (and break) the
        login/triage/report request path."""
        try:
            self.deps.audit.record(event=event, actor=actor or "unknown",
                                   tenant_id=tenant_id, detail=detail)
        except Exception:  # noqa: BLE001 - fail-open, see audit.py docstring
            pass

    def _check_csrf(self) -> bool:
        """CSRF defense-in-depth for state-changing (POST) requests riding on
        an active browser session. A no-op when there is no active session
        (RBAC off, or the request carries no/invalid session cookie)."""
        session = self._current_session()
        if session is None:
            return True
        token = self.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, session.csrf_token):
            self._send(403, {"error": "missing or invalid CSRF token"})
            return False
        return True

    def _normalized_path(self) -> str:
        """Request path with an optional leading `/api/v1` stripped."""
        return _strip_api_v1(urlparse(self.path).path)

    def _rate_limit_ip(self) -> str:
        """Client identity for rate limiting: TCP peer, or X-Forwarded-For when
        RATE_LIMIT_TRUST_PROXY_HEADER=1 (nginx reverse-proxy topology)."""
        if os.getenv("RATE_LIMIT_TRUST_PROXY_HEADER", "").strip().lower() in ("1", "true", "yes"):
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _check_rate_limit(self) -> bool:
        """FIX L4: per-IP token-bucket guard. Sends 429 (Retry-After) and
        returns False when the caller's IP has exhausted its bucket; a no-op
        (always True) when rate limiting is disabled."""
        ip = self._rate_limit_ip()
        if _rate_limit_allowed(ip):
            return True
        body = json.dumps({"error": "rate limit exceeded"}).encode()
        self.send_response(429)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Retry-After", "60")
        self.end_headers()
        self.wfile.write(body)
        return False

    def _list_tenant_filter(self, session, requested: str | None) -> str | None:
        """The tenant_id to actually filter a list endpoint by. RBAC off
        (session is True) or role=admin: use whatever the caller asked for
        (None = every tenant). Any other role: ALWAYS the caller's own tenant,
        silently overriding a different requested value."""
        if session is True or session.role == "admin":
            return requested
        return session.tenant_id

    def _read_json_body(self, max_bytes: int) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            raise _BadRequest("invalid Content-Length")
        if length < 0:
            raise _BadRequest("invalid Content-Length")
        if length > max_bytes:
            raise _BadRequest("request body too large")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise _BadRequest("body must be valid JSON")
        if not isinstance(body, dict):
            raise _BadRequest("body must be a JSON object")
        return body

    # -- dispatchers (thin: decode path, forward to a per-route function) ---

    def do_GET(self):
        try:
            if not self._check_rate_limit():  # FIX L4 (no-op when off)
                return
            path = self._normalized_path()
            if self.deps.rbac_enabled and path == "/auth/me":
                return route_auth_me(self)
            if not self._check_auth():
                return
            self._route_get(path)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001 - never let a handler crash the thread
            _LOG.error("GET handler raised", path=self.path, error=repr(e),
                       traceback=traceback.format_exc())
            self._send(500, {"error": "internal error"})

    def _route_get(self, path: str):
        if path == "/alerts":
            return route_list_alerts(self)
        if path == "/incidents":
            return route_list_incidents(self)
        if path == "/events":
            return route_list_events(self)
        if path == "/rules":
            return route_list_rules(self)
        if path == "/audit":
            return route_audit(self)

        report_alert_id = self._alert_id_from_path(path, "report")
        if report_alert_id is not None:
            return route_get_report(self, report_alert_id)

        # Phase 5 (2026-09-04): entity/causal-graph/evidence read path.
        graph_incident_id = self._id_from_path(path, "incidents", "graph")
        if graph_incident_id is not None:
            return route_get_incident_graph(self, graph_incident_id)
        evidence_incident_id = self._id_from_path(path, "incidents", "evidence")
        if evidence_incident_id is not None:
            return route_get_incident_evidence(self, evidence_incident_id)
        entity_id = self._id_from_path(path, "entities")
        if entity_id is not None:
            return route_get_entity(self, entity_id)

        alert_id = self._alert_id_from_path(path)
        if alert_id is None:
            return self._send(404, {"error": "no such path"})
        return route_get_triage(self, alert_id)

    def do_POST(self):
        try:
            if not self._check_rate_limit():  # FIX L4 (no-op when off)
                return
            path = self._normalized_path()
            if self.deps.rbac_enabled and path == "/auth/login":
                return route_auth_login(self)
            if self.deps.rbac_enabled and not self._check_csrf():
                return
            if self.deps.rbac_enabled and path == "/auth/logout":
                return route_auth_logout(self)
            if self.deps.rbac_enabled and path == "/auth/mfa/enable":
                return route_mfa_enable(self)
            if self.deps.rbac_enabled and path == "/auth/mfa/verify":
                return route_mfa_verify(self)
            if not self._check_auth():
                return
            self._route_post(path)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001 - never let a handler crash the thread
            _LOG.error("POST handler raised", path=self.path, error=repr(e),
                       traceback=traceback.format_exc())
            self._send(500, {"error": "internal error"})

    def _route_post(self, path: str):
        # Thin dispatcher: route to a dedicated per-route handler. Each id is
        # parsed once here and passed down -- not re-parsed inside the handler.
        report_alert_id = self._alert_id_from_path(path, "report")
        if report_alert_id is not None:
            return route_post_report(self, report_alert_id)
        alert_id = self._alert_id_from_path(path)
        if alert_id is not None:
            return route_post_triage(self, alert_id)
        return self._send(404, {"error": "no such path"})


def make_handler(store, users_db=None, sessions: SessionStore | None = None,
                  rate_limiter: LoginRateLimiter | None = None,
                  audit_log: "audit.AuditLog | None" = None):
    """Returns a Handler class bound to the given store.

    WP-2-I: this is now a thin assembler -- it builds the `_Deps` bundle the
    per-route functions read through `self.deps` and returns a one-line
    per-server subclass of the module-level `Handler` carrying that bundle
    (mirroring the original per-call closure class, so two servers built with
    DIFFERENT stores stay fully isolated -- each request instance reads its
    own class's `.deps`). Callers see no change: the returned
    `BaseHTTPRequestHandler` subclass has exactly the same routes, methods,
    auth, status codes, response shapes and logging as before the refactor.

    ``users_db`` is None by default -> RBAC (M4.2) is OFF; pass a real
    ``shared.users.UserStore`` to turn on session login + role/tenant
    enforcement. ``sessions``/``rate_limiter`` default to fresh in-process
    instances when RBAC is on. ``audit_log`` defaults to the process-wide
    ``audit.default_audit()``.
    """
    rbac_enabled = users_db is not None
    if rbac_enabled:
        sessions = sessions or make_session_store()
        rate_limiter = rate_limiter or LoginRateLimiter()
    _audit = audit_log if audit_log is not None else audit.default_audit()

    class _BoundHandler(Handler):
        _deps = _Deps(store=store, users_db=users_db, sessions=sessions,
                     rate_limiter=rate_limiter, audit_log=_audit,
                     rbac_enabled=rbac_enabled)

    _BoundHandler.__name__ = "Handler"
    _BoundHandler.__qualname__ = "Handler"
    return _BoundHandler


def serve(store, host="0.0.0.0", port=8013):
    warn_if_disabled("ws3-indexer-triage")

    # M4.2 RBAC: opt-in via FENGARDE_RBAC_DB (a SQLite file path), same
    # unset-is-off convention as FENGARDE_API_KEY/dashboard basic-auth/Redis
    # AUTH. Unset -> make_handler(store) with no users_db -> byte-for-byte
    # pre-M4.2 behavior.
    import os as _os
    users_db = None
    rbac_db_path = _os.getenv("FENGARDE_RBAC_DB")
    if rbac_db_path:
        from shared.users import UserStore, ensure_first_boot_admin  # noqa: E402
        users_db = UserStore(rbac_db_path)
        # First-boot bootstrap: the admin password comes from the operator via
        # FENGARDE_ADMIN_PASSWORD -- the service never generates, logs, or
        # stores a plaintext credential (only the scrypt hash reaches disk).
        created = ensure_first_boot_admin(users_db)
        if created:
            get_logger("ws3-indexer-triage").info(
                "first-boot admin account created from "
                "FENGARDE_ADMIN_PASSWORD (unset it now -- it is no "
                "longer needed and env vars leak via inspect/exec)",
                username=created,
            )
        elif users_db.count() == 0:
            get_logger("ws3-indexer-triage").warn(
                "RBAC enabled but the user store is empty and "
                "FENGARDE_ADMIN_PASSWORD is unset -- no one can log "
                "in. Set FENGARDE_ADMIN_PASSWORD and restart to "
                "create the first admin account."
            )

    handler_cls = make_handler(store, users_db=users_db)
    srv = ThreadingHTTPServer((host, port), handler_cls)
    get_logger("ws3-indexer-triage").info(
        "listening", url=f"http://{host}:{port}",
        rbac="enabled" if users_db else "disabled",
    )
    srv.serve_forever()
