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
from shared.log import get_logger  # noqa: E402
from shared.rbac import role_at_least, can_access_tenant, LoginRateLimiter  # noqa: E402
from shared.sessions import SessionStore, make_session_store  # noqa: E402

_LOG = get_logger("ws3-indexer-triage")  # noqa: E402 - module-level handler logger
import reporting  # noqa: E402
import rules_view  # noqa: E402
import nis2_template  # noqa: E402
import audit  # noqa: E402

_MAX_BODY_BYTES = 4096  # a triage update is a status enum + a short note.
_MAX_NOTE_CHARS = 2000
_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}
_CAS_MAX_RETRIES = 5  # optimistic-concurrency retry bound (see _route_post)
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
        # `_rate_buckets` has no TTL/cap otherwise, so it grows for the
        # process lifetime -- one entry per distinct client IP ever seen.
        # Periodic sweep (mirrors shared/rbac.py::LoginRateLimiter) instead
        # of a per-call check keeps this cheap.
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


def make_handler(store, users_db=None, sessions: SessionStore | None = None,
                  rate_limiter: LoginRateLimiter | None = None,
                  audit_log: "audit.AuditLog | None" = None):
    """Returns a Handler class bound to the given store (closure, matches the
    pattern main.py already uses for the bus handler).

    ``users_db`` is None by default -> RBAC (M4.2) is OFF, the handler is
    byte-for-byte the pre-M4.2 API-key-only behavior. Pass a real
    ``shared.users.UserStore`` to turn on session login + role/tenant
    enforcement on the triage and report routes; ``sessions``/
    ``rate_limiter`` default to fresh in-process instances when RBAC is on.

    ``audit_log`` is the E1 audit store (append-only, fail-open -- see
    audit.py). Defaults to the process-wide ``audit.default_audit()``. Every
    audit write is fail-open: an audit-log outage never breaks login, triage,
    or report generation (the write is swallowed in Handler._audit).
    """
    rbac_enabled = users_db is not None
    if rbac_enabled:
        # make_session_store() honors FENGARDE_SESSION_BACKEND (memory default,
        # redis for multi-replica) and fails loud if redis is asked for but
        # unreachable -- see shared/sessions.py's module docstring.
        sessions = sessions or make_session_store()
        rate_limiter = rate_limiter or LoginRateLimiter()
    _audit = audit_log if audit_log is not None else audit.default_audit()

    class Handler(BaseHTTPRequestHandler):
        # Slowloris guard: drop a client that stalls mid-request instead of
        # pinning this connection's thread indefinitely.
        timeout = 15

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

        def _alert_id_from_path(self, path: str, resource: str = "triage") -> str | None:
            # /alerts/{alert_id}/{resource}  (resource: "triage" | "report")
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "alerts" and parts[2] == resource:
                return parts[1]
            return None

        # -- M4.2 session helpers (no-ops when RBAC is off) ------------------

        def _session_token(self) -> str:
            raw = self.headers.get("Cookie")
            if not raw:
                return ""
            jar = SimpleCookie()
            jar.load(raw)
            morsel = jar.get(_SESSION_COOKIE)
            return morsel.value if morsel else ""

        def _current_session(self):
            if not rbac_enabled:
                return None
            token = self._session_token()
            if not token:
                return None
            try:
                return sessions.resolve(token)
            except Exception:  # noqa: BLE001 - FIX (#3): a session-store outage
                # must never 500 every auth-gated request; degrade to
                # "no session" (fail-open) and let the auth gate answer 401.
                return None

        def _require_role(self, minimum_role: str):
            """Return the active session if it satisfies `minimum_role`, or
            send an error response and return None. When RBAC is off this
            ALWAYS returns a truthy sentinel (auth already happened via
            check_api_key at the call site) -- keeps one call site for both
            modes instead of branching every route."""
            if not rbac_enabled:
                return True
            session = self._current_session()
            if session is None:
                self._send(401, {"error": "not logged in"})
                return None
            if not role_at_least(session.role, minimum_role):
                # 404, not 403: don't confirm a resource's existence to a
                # caller who isn't entitled to act on it at all.
                self._send(404, {"error": "no such path"})
                return None
            return session

        def _tenant_gate(self, session, doc: dict) -> bool:
            """True if `session` (real Session, or True when RBAC is off) may
            access `doc`'s tenant. Sends 404 and returns False otherwise."""
            if session is True:  # RBAC off
                return True
            if can_access_tenant(session.role, session.tenant_id, doc.get("tenant_id")):
                return True
            self._send(404, {"error": "alert not found"})
            return False

        def _check_auth(self) -> bool:
            if check_api_key(self.headers):
                return True
            self._send(401, {"error": "unauthorized"})
            return False

        def _audit_actor(self, session) -> str:
            """The actor name for an audit entry. RBAC-off (session is the
            True sentinel) means the shared API key is authenticating -- name
            it as a non-person actor; a real session uses its username."""
            if session is not True and session is not None:
                return str(session.username)
            return "api_key"

        def _audit(self, event: str, actor: str | None = None,
                   tenant_id: str | None = None, detail: dict | None = None) -> None:
            """E1: fail-open audit write. Any failure inside the audit log is
            swallowed here so an audit outage can never raise into (and break)
            the login/triage/report request path."""
            try:
                _audit.record(event=event, actor=actor or "unknown",
                             tenant_id=tenant_id, detail=detail)
            except Exception:  # noqa: BLE001 - fail-open, see audit.py docstring
                pass

        def _check_csrf(self) -> bool:
            """CSRF defense-in-depth for state-changing (POST) requests
            riding on an active browser session. The session cookie already
            carries SameSite=Strict (services/shared's own comment on that
            cookie explains it blocks the cookie from ever being attached to
            a genuine cross-site request in a modern browser) -- this is a
            SECOND, independent layer: proving the caller can also read a
            same-origin JSON response body (where csrf_token is handed out,
            in _route_auth_login/_route_auth_me) and echo it back as a
            custom header, something a blind cross-site form/img submission
            cannot do even on a browser/proxy combination where SameSite is
            somehow not honored.

            A no-op when there is no active session (RBAC off, or the
            request carries no/an invalid session cookie) -- those requests
            get their own 401 further down the call chain; this check exists
            only to protect a request that a valid SESSION would otherwise
            let through."""
            session = self._current_session()
            if session is None:
                return True
            token = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token, session.csrf_token):
                self._send(403, {"error": "missing or invalid CSRF token"})
                return False
            return True

        def _normalized_path(self) -> str:
            """Request path with an optional leading `/api/v1` stripped --
            see _strip_api_v1's docstring for why both forms must resolve
            identically."""
            return _strip_api_v1(urlparse(self.path).path)

        def _rate_limit_ip(self) -> str:
            """Client identity for rate limiting. `client_address[0]` is the
            TCP peer -- correct for a directly-exposed instance, but behind
            the documented nginx reverse-proxy topology every real client
            collapses to nginx's own container IP, turning the per-IP limiter
            into a single limiter shared by every user. Opt-in (default off,
            matches this project's auth-is-opt-in convention): when
            RATE_LIMIT_TRUST_PROXY_HEADER=1, trust X-Forwarded-For instead --
            safe only because ws3-indexer's triage port isn't published to
            the host, so this header can only be set by nginx's own
            `proxy_set_header X-Forwarded-For $remote_addr` (which REPLACES,
            not appends to, any client-supplied value) or by another
            container on the same trusted docker network."""
            if os.getenv("RATE_LIMIT_TRUST_PROXY_HEADER", "").strip().lower() in ("1", "true", "yes"):
                xff = self.headers.get("X-Forwarded-For")
                if xff:
                    return xff.split(",")[0].strip()
            return self.client_address[0] if self.client_address else ""

        def _check_rate_limit(self) -> bool:
            """FIX L4: per-IP token-bucket guard. Sends 429 (Retry-After) and
            returns False when the caller's IP has exhausted its bucket; a
            no-op (always True) when rate limiting is disabled."""
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
            (session is True) or role=admin: use whatever the caller asked
            for (None = every tenant). Any other role: ALWAYS the caller's
            own tenant, silently overriding a different requested value --
            a list endpoint has no single resource to 404 on, so scope
            narrowing is the only enforcement available."""
            if session is True or session.role == "admin":
                return requested
            return session.tenant_id

        def do_GET(self):
            try:
                if not self._check_rate_limit():  # FIX L4 (no-op when off)
                    return
                path = self._normalized_path()
                if rbac_enabled and path == "/auth/me":
                    return self._route_auth_me()
                if not self._check_auth():
                    return
                self._route_get(path)
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 - never let a handler crash the thread
                # FIX (#3): log the real exception before answering a bare 500 --
                # an unhandled handler error is invisible to operators otherwise.
                # shared.log.Logger has no `.exception()` (stdlib-logging-only
                # method) -- use `.error()` with the traceback as a field.
                _LOG.error("GET handler raised", path=self.path, error=repr(e),
                           traceback=traceback.format_exc())
                self._send(500, {"error": "internal error"})

        def _route_auth_me(self):
            session = self._current_session()
            if session is None:
                return self._send(401, {"error": "not logged in"})
            # csrf_token is included here too so a page reload (JS state
            # lost, session cookie still valid) can recover it without a
            # fresh login.
            return self._send(200, {"username": session.username, "role": session.role,
                                     "tenant_id": session.tenant_id, "csrf_token": session.csrf_token})

        def _route_get(self, path: str):
            u = urlparse(self.path)

            if path == "/alerts":
                return self._route_list_alerts(u.query)
            if path == "/incidents":
                return self._route_list_incidents(u.query)
            if path == "/events":
                return self._route_list_events(u.query)
            if path == "/rules":
                return self._route_list_rules(u.query)
            if path == "/audit":
                return self._route_audit()

            report_alert_id = self._alert_id_from_path(path, "report")
            if report_alert_id is not None:
                if not report_alert_id:
                    raise _BadRequest("alert_id required")
                session = self._require_role("read_only")
                if session is None:
                    return
                report = store.find_report(report_alert_id)
                if report is None:
                    return self._send(404, {"error": "report not found"})
                found_alert = store.find_alert(report_alert_id)
                if found_alert is not None:
                    if not self._tenant_gate(session, found_alert[1]):
                        return
                elif session is not True and session.role != "admin":
                    # The backing alert doc is gone (aged out under
                    # independent retention, or deleted) -- report docs
                    # carry no tenant_id of their own, so there is no way
                    # to verify which tenant this report belongs to. A
                    # non-admin caller must be denied (fail-closed), not
                    # silently let through just because the alert lookup
                    # came back empty. Same 404-not-403 convention as
                    # _tenant_gate: never confirm the report exists to a
                    # caller who isn't entitled to see it.
                    return self._send(404, {"error": "report not found"})
                return self._send(200, report)

            alert_id = self._alert_id_from_path(path)
            if alert_id is None:
                return self._send(404, {"error": "no such path"})
            if not alert_id:
                raise _BadRequest("alert_id required")
            session = self._require_role("read_only")
            if session is None:
                return
            found = store.find_alert(alert_id)
            if found is None:
                return self._send(404, {"error": "alert not found"})
            _, doc = found
            if not self._tenant_gate(session, doc):
                return
            return self._send(200, doc.get("triage") or _default_triage())

        def _route_list_alerts(self, raw_query: str):
            session = self._require_role("read_only")
            if session is None:
                return
            q = parse_qs(raw_query)
            requested_tenant = q.get("tenant_id", [None])[0]
            status = q.get("status", [None])[0]
            if status is not None and status not in _STATUSES:
                raise _BadRequest(f"status must be one of {sorted(_STATUSES)}")
            limit = _parse_limit(q.get("limit"))
            tenant_id = self._list_tenant_filter(session, requested_tenant)
            # Design-C (2026-07-29 audit): manual cross-alert correlation --
            # let an analyst pull every alert for one actor/source IP across
            # time (the safe scoped improvement in place of a full
            # correlation engine, see storage/opensearch.py's list_alerts).
            # Passed conditionally, not as an always-present kwarg: a
            # third-party StorageAdapter written against the pre-Design-C
            # 3-parameter signature keeps working for every call that
            # doesn't actually ask for this filter.
            extra = {}
            actor = q.get("actor", [None])[0]
            if actor is not None:
                extra["actor"] = actor
            src_ip = q.get("src_ip", [None])[0]
            if src_ip is not None:
                extra["src_ip"] = src_ip
            alerts = store.list_alerts(tenant_id=tenant_id, status=status, limit=limit, **extra)
            return self._send(200, {"alerts": alerts, "count": len(alerts)})

        def _route_list_incidents(self, raw_query: str):
            session = self._require_role("read_only")
            if session is None:
                return
            q = parse_qs(raw_query)
            requested_tenant = q.get("tenant_id", [None])[0]
            entity_type = q.get("entity_type", [None])[0]
            if entity_type is not None and entity_type not in ("actor", "ip", "device"):
                raise _BadRequest("entity_type must be one of ['actor', 'ip', 'device']")
            entity_value = q.get("entity_value", [None])[0]
            limit = _parse_limit(q.get("limit"))
            tenant_id = self._list_tenant_filter(session, requested_tenant)
            incidents = store.list_incidents(tenant_id=tenant_id, entity_type=entity_type,
                                              entity_value=entity_value, limit=limit)
            return self._send(200, {"incidents": incidents, "count": len(incidents)})

        def _route_list_events(self, raw_query: str):
            session = self._require_role("read_only")
            if session is None:
                return
            q = parse_qs(raw_query)
            family = q.get("family", [None])[0]
            if family is not None and family not in _FAMILIES:
                raise _BadRequest(f"family must be one of {sorted(_FAMILIES)}")
            requested_tenant = q.get("tenant_id", [None])[0]
            limit = _parse_limit(q.get("limit"))
            tenant_id = self._list_tenant_filter(session, requested_tenant)
            events = store.list_events(family=family, tenant_id=tenant_id, limit=limit)
            return self._send(200, {"events": events, "count": len(events)})

        def _route_list_rules(self, raw_query: str):
            session = self._require_role("read_only")
            if session is None:
                return
            q = parse_qs(raw_query)
            requested_tenant = q.get("tenant_id", [None])[0]
            tenant_id = self._list_tenant_filter(session, requested_tenant)
            rules = rules_view.list_rule_summaries(tenant_id)
            return self._send(200, {"rules": rules, "count": len(rules)})

        def _route_audit(self):
            """E1: GET /audit -- admin-only view of the recent audit trail.
            Requires role >= admin (RBAC off -> the shared API key is treated
            as the deployment owner, so it's allowed). Non-admins are denied
            via _require_role. The log itself is already capacity-capped, so
            the `limit` param only narrows the response."""
            session = self._require_role("admin")
            if session is None:
                return
            q = parse_qs(urlparse(self.path).query)
            limit = _parse_limit(q.get("limit"))
            entries = _audit.recent(limit)
            return self._send(200, {"entries": entries, "count": len(entries)})

        def do_POST(self):
            try:
                if not self._check_rate_limit():  # FIX L4 (no-op when off)
                    return
                path = self._normalized_path()
                if rbac_enabled and path == "/auth/login":
                    return self._route_auth_login()
                if rbac_enabled and not self._check_csrf():
                    return
                if rbac_enabled and path == "/auth/logout":
                    return self._route_auth_logout()
                if rbac_enabled and path == "/auth/mfa/enable":
                    return self._route_mfa_enable()
                if rbac_enabled and path == "/auth/mfa/verify":
                    return self._route_mfa_verify()
                if not self._check_auth():
                    return
                self._route_post(path)
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001 - never let a handler crash the thread
                # FIX (#3): log the exception BEFORE answering a bare 500 --
                # an unhandled handler error is invisible to operators otherwise.
                # shared.log.Logger has no `.exception()` (stdlib-logging-only
                # method) -- use `.error()` with the traceback as a field.
                _LOG.error("POST handler raised", path=self.path, error=repr(e),
                           traceback=traceback.format_exc())
                self._send(500, {"error": "internal error"})

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

        def _route_auth_login(self):
            body = self._read_json_body(_MAX_BODY_BYTES)
            username = body.get("username")
            password = body.get("password")
            if not isinstance(username, str) or not isinstance(password, str) or not username:
                raise _BadRequest("username and password (strings) are required")

            if rate_limiter.is_locked_out(username):
                # Same response as a wrong password -- a lockout must not be
                # a distinguishable oracle for "this username exists and is
                # currently being attacked."
                self._audit("login_failure", actor=username,
                            detail={"reason": "locked_out", "username": username})
                return self._send(401, {"error": "invalid credentials"})

            row = users_db.verify_login(username, password)
            if row is None:
                rate_limiter.record_failure(username)
                self._audit("login_failure", actor=username,
                            detail={"reason": "bad_credentials", "username": username})
                return self._send(401, {"error": "invalid credentials"})
            rate_limiter.record_success(username)

            # FENGARDE E3 MFA -- OPT-IN per user. If this account has an
            # ACTIVE TOTP secret, a valid `totp_code` in the login body is
            # REQUIRED before any session is issued. Accounts that never
            # provisioned TOTP are untouched: login is byte-for-byte the
            # pre-E3 path below. A missing/invalid code fails identically to
            # a wrong password (401 "invalid credentials", plus a rate-limit
            # failure) so an attacker can't distinguish "wrong TOTP" from
            # "wrong password" -- no new oracle.
            if users_db.is_totp_enabled(username):
                totp_code = body.get("totp_code")
                if not isinstance(totp_code, str) or not users_db.verify_totp(username, totp_code):
                    rate_limiter.record_failure(username)
                    self._audit("login_failure", actor=username,
                                detail={"reason": "bad_totp", "username": username})
                    return self._send(401, {"error": "invalid credentials"})

            token = sessions.create(row["username"], row["role"], row["tenant_id"])
            csrf_token = sessions.resolve(token).csrf_token
            cookie = SimpleCookie()
            cookie[_SESSION_COOKIE] = token
            cookie[_SESSION_COOKIE]["httponly"] = True
            cookie[_SESSION_COOKIE]["path"] = "/"
            cookie[_SESSION_COOKIE]["samesite"] = "Strict"
            # `Secure` is deliberately not set: the dashboard's documented
            # deployment path (docs/deployment.md) terminates TLS at a
            # reverse proxy in FRONT of this service, which forwards
            # plaintext HTTP on the compose network -- a `Secure`-only
            # cookie would never be sent over that hop. TLS termination
            # closer to this service is the real fix, tracked as an M4
            # ops-lifecycle follow-up, not silently worked around here.
            set_cookie = cookie[_SESSION_COOKIE].OutputString()
            # csrf_token travels in the response BODY, not a cookie -- the
            # browser JS reads it here (or from /auth/me on a page reload)
            # and echoes it back as X-CSRF-Token on writes. See _check_csrf.
            self._audit("login_success", actor=row["username"],
                        tenant_id=row["tenant_id"],
                        detail={"username": row["username"], "role": row["role"]})
            return self._send(200, {"username": row["username"], "role": row["role"],
                                     "tenant_id": row["tenant_id"], "csrf_token": csrf_token},
                               extra_headers={"Set-Cookie": set_cookie})

        def _route_auth_logout(self):
            token = self._session_token()
            if token:
                sessions.invalidate(token)
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

        def _mfa_target(self, session, body):
            """The username an MFA action applies to: the acting user by
            default, OR another user when an admin supplies `username` in the
            body (admin may provision/verify MFA on behalf of an account).
            Returns None (an error already sent) if unauthorized or the
            target doesn't exist -- an admin provisioning for a nonexistent
            user is the same 404-not-confirm posture as every other RBAC
            gate."""
            target = body.get("username")
            if target is None:
                return session.username
            if session.role != "admin":
                self._send(404, {"error": "no such path"})
                return None
            if not isinstance(target, str) or not users_db.get_user(target):
                self._send(404, {"error": "no such user"})
                return None
            return target

        def _mfa_reauth(self, session, body) -> bool:
            """Re-auth gate for MFA-config-changing routes (enable/verify),
            added 2026-08-06. Requires the ACTING session's own current
            `password` in the body -- even though a valid session cookie is
            already presented. Without this, a stolen session cookie ALONE
            was enough to re-provision MFA on an account: `enable_totp`
            unconditionally resets `totp_active` to 0 (users.py), so one
            unauthenticated-beyond-the-cookie POST to /auth/mfa/enable
            silently disarmed an account's MFA, and the caller then held the
            new secret. Requiring the caller's own password closes that --
            an attacker who only has the cookie cannot pass this gate.

            Rate-limited per-username in a separate `mfa:` namespace (reuses
            the login `rate_limiter` instance, so it shares its cleanup/sweep
            machinery, but keyed apart from plain usernames so a burst of bad
            MFA re-auth attempts can't be confused with, or silently ride
            along on, ordinary login-lockout accounting) and every outcome is
            audited. Sends its own error response and returns False on
            failure; the caller just returns.
            """
            # rate_limiter is only None when rbac_enabled is False (see the
            # `rate_limiter = rate_limiter or LoginRateLimiter()` reassignment
            # above), and this method is only ever reached via /auth/mfa/*
            # routes that are themselves gated behind `rbac_enabled` in
            # do_POST -- so it is always set here. mypy can't see that
            # narrowing across this closure, hence the assert (this is the
            # only method in this class with a `-> bool` return annotation,
            # which is what makes mypy check its body at all -- see
            # --check-untyped-defs in pyproject.toml's [tool.mypy] comment).
            assert rate_limiter is not None
            key = f"mfa:{session.username}"
            if rate_limiter.is_locked_out(key):
                self._audit("mfa_reauth_failure", actor=session.username,
                            tenant_id=session.tenant_id, detail={"reason": "locked_out"})
                self._send(401, {"error": "reauthentication required"})
                return False
            password = body.get("password")
            if (not isinstance(password, str)
                    or users_db.verify_login(session.username, password) is None):
                rate_limiter.record_failure(key)
                self._audit("mfa_reauth_failure", actor=session.username,
                            tenant_id=session.tenant_id, detail={"reason": "bad_password"})
                self._send(401, {"error": "reauthentication required"})
                return False
            rate_limiter.record_success(key)
            return True

        def _route_mfa_enable(self):
            """POST /auth/mfa/enable -- opt-in MFA step one: generate a secret,
            store it (pending), and hand back the otpauth:// URI for a QR code.
            Body must carry the ACTING user's current `password` (see
            _mfa_reauth) plus an optional admin-on-behalf-of `username`."""
            session = self._current_session()
            if session is None:
                return self._send(401, {"error": "not logged in"})
            body = self._read_json_body(_MAX_BODY_BYTES)
            if not self._mfa_reauth(session, body):
                return
            target = self._mfa_target(session, body)
            if target is None:
                return
            try:
                uri = users_db.provision_totp(target)
            except Exception:  # noqa: BLE001 - mfa module missing/broken
                return self._send(503, {"error": "MFA provisioning unavailable"})
            self._audit("mfa_enable", actor=session.username,
                        tenant_id=session.tenant_id, detail={"target": target})
            return self._send(200, {"username": target, "otpauth_uri": uri,
                                     "status": "pending-secret-verification"})

        def _route_mfa_verify(self):
            """POST /auth/mfa/verify -- opt-in MFA step two. Body carries the
            ACTING user's current `password` (re-auth, see _mfa_reauth) PLUS
            the `totp_code` read from the authenticator; on success the
            secret is marked ACTIVE and future logins require the code."""
            session = self._current_session()
            if session is None:
                return self._send(401, {"error": "not logged in"})
            body = self._read_json_body(_MAX_BODY_BYTES)
            if not self._mfa_reauth(session, body):
                return
            target = self._mfa_target(session, body)
            if target is None:
                return
            code = body.get("totp_code")
            if not isinstance(code, str):
                return self._send(400, {"error": "totp_code (string) is required"})
            # Enrollment confirmation uses verify_totp (the LOGIN path), which
            # advances totp_last_counter -- deliberately: it CONSUMES the
            # enrollment code so that same code can't be replayed at /auth/login
            # (replay protection). A fresh step's code (e.g. +30s) still works,
            # proven by test_fix_mfa. confirm_totp exists for any caller that
            # must activate WITHOUT consuming -- but the HTTP route needs the
            # consume, so it uses verify_totp.
            if not users_db.verify_totp(target, code):
                self._audit("mfa_verify_failure", actor=session.username,
                            tenant_id=session.tenant_id, detail={"target": target})
                return self._send(401, {"error": "invalid totp code"})
            self._audit("mfa_verify_success", actor=session.username,
                        tenant_id=session.tenant_id, detail={"target": target})
            return self._send(200, {"username": target, "mfa_active": True})

        def _route_post(self, path: str):
            # Thin dispatcher: route to a dedicated per-route handler. Kept
            # deliberately small so a new POST route is a new method, not a
            # grown if-chain inside this one. Each id is parsed once here and
            # passed down -- not re-parsed from `path` inside the handler.
            report_alert_id = self._alert_id_from_path(path, "report")
            if report_alert_id is not None:
                return self._route_report(report_alert_id)
            alert_id = self._alert_id_from_path(path)
            if alert_id is not None:
                return self._route_triage(alert_id)
            return self._send(404, {"error": "no such path"})

        def _route_report(self, report_alert_id: str):  # POST /alerts/{id}/report
            # Drain any request body (the client may send one, even
            # though this endpoint takes none) so the connection doesn't
            # get reset with unread bytes still buffered. An unparseable
            # Content-Length is a 400 (mirrors the triage route) -- NOT
            # silently zeroed, which would leave stray body bytes in the
            # buffer and corrupt the next request on a keep-alive
            # connection.
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (TypeError, ValueError):
                raise _BadRequest("invalid Content-Length")
            if length < 0:
                raise _BadRequest("invalid Content-Length")
            if length > _MAX_BODY_BYTES:
                # FIX (#11): reject an oversized body (close connection to
                # avoid leaving unread bytes that corrupt the next request on
                # a keep-alive connection, then a 400) -- same as the triage
                # route. This endpoint takes no body, so only drain the small,
                # legitimate Content-Length case.
                self.close_connection = True
                raise _BadRequest("request body too large")
            elif length > 0:
                self.rfile.read(length)
            if not report_alert_id:
                raise _BadRequest("alert_id required")
            session = self._require_role("analyst")  # report generation is a write action
            if session is None:
                return
            found = store.find_alert(report_alert_id)
            if found is None:
                return self._send(404, {"error": "alert not found"})
            _, alert_doc = found
            if not self._tenant_gate(session, alert_doc):
                return
            triage = alert_doc.get("triage") or _default_triage()
            q = parse_qs(urlparse(self.path).query)
            template = (q.get("template", ["generic"])[0] or "generic").lower()
            if template == "nis2":
                # M5: additive rendering mode, same response envelope
                # (contracts/reporting.md's frozen schema) -- see
                # nis2_template.py's module docstring for the DRAFT/
                # NOT-LEGAL-ADVICE + NIS2-vs-DORA scope caveat.
                stage = q.get("stage", ["notification"])[0]
                lang = q.get("lang", ["de"])[0]
                report = nis2_template.build_report(alert_doc, triage, stage=stage, lang=lang)
            else:
                report = reporting.generate_report(alert_doc, triage)
            report_index = reporting._report_index()
            store.index(report_index, report["report_id"], report)
            self._audit("report_generated",
                        actor=self._audit_actor(session),
                        tenant_id=alert_doc.get("tenant_id"),
                        detail={"alert_id": report_alert_id,
                                "report_id": report.get("report_id"),
                                "template": template})
            return self._send(200, report)

        def _route_triage(self, alert_id: str):  # POST /alerts/{id}
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
                # Rejecting without reading leaves the body unread on the
                # socket -- same keep-alive corruption risk as
                # _route_report's sibling bug, closed the same way.
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
            # PARTIAL UPDATE: "note" absent from the body must PRESERVE the
            # existing note, not clear it -- symmetric with how "status" only
            # updates when provided. Distinguish "key absent" from "key present
            # with an empty string" (an analyst clearing the note on purpose is
            # a legitimate, different action from not mentioning note at all).
            note_present = "note" in body
            note = body.get("note")
            if note_present:
                if not isinstance(note, str):
                    raise _BadRequest("note must be a string")
                note = note[:_MAX_NOTE_CHARS]

            # P2-5 (2026-07-21 audit): this used to hold write_lock (a
            # process-wide lock) across the entire retry loop below,
            # including find_alert_versioned/index_cas -- both real network
            # I/O against OpenSearch (up to ~60s under a slow cluster). That
            # serialized triage writes to EVERY alert, in EVERY tenant,
            # through this one process, one at a time, for as long as the
            # slowest concurrent write's I/O took -- vastly wider than the
            # lost-update race it existed to prevent (which is only ever
            # between two writers touching the SAME alert_id).
            #
            # index_cas (optimistic concurrency) is already sufficient
            # cross-writer protection on its own: MemoryStore's version
            # counter and OpenSearch's (_seq_no, _primary_term) are each
            # checked-and-incremented atomically by the store itself, so two
            # threads racing on the same alert_id can each safely
            # find_alert_versioned/compute/index_cas with NO external lock --
            # the loser's index_cas simply returns False and it retries. The
            # lock added nothing beyond what CAS already guarantees, so it is
            # dropped rather than narrowed: there is no read-modify-write
            # section left that needs one.
            for _attempt in range(_CAS_MAX_RETRIES):
                found = store.find_alert_versioned(alert_id)
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
                if store.index_cas(index, alert_id, doc, version):
                    self._audit("triage_update",
                                actor=self._audit_actor(session),
                                tenant_id=doc.get("tenant_id"),
                                detail={"alert_id": alert_id,
                                        "status": triage.get("status"),
                                        "updated_at": triage.get("updated_at")})
                    return self._send(200, triage)
                # conflict: another writer landed between our read and
                # write -- loop re-reads the fresh doc and re-applies.
            return self._send(409, {"error": "conflicting concurrent updates, retry"})

    return Handler


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
        # First-boot bootstrap: the admin password comes from the operator
        # via FENGARDE_ADMIN_PASSWORD -- the service never generates, logs,
        # or stores a plaintext credential (only the scrypt hash reaches
        # disk). Closes CodeQL py/clear-text-logging AND
        # py/clear-text-storage at the design level: there is simply no
        # plaintext secret in this process's output or filesystem, ever.
        created = ensure_first_boot_admin(users_db)
        if created:
            get_logger("ws3-indexer-triage").info(
                "first-boot admin account created from "
                "FENGARDE_ADMIN_PASSWORD (unset it now -- it is no "
                "longer needed and env vars leak via inspect/exec)",
                username=created,
            )
        elif users_db.count() == 0:
            # RBAC is on but no account exists and no bootstrap password was
            # provided: fail-closed (nobody can log in), and say so loudly.
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
