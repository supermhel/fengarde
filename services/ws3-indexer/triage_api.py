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
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_HERE = Path(__file__).resolve().parent
for _p in (str(_HERE), str(_HERE.parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from shared.authz import check_api_key, warn_if_disabled  # noqa: E402
from shared.rbac import role_at_least, can_access_tenant, LoginRateLimiter  # noqa: E402
from shared.sessions import SessionStore  # noqa: E402
import reporting  # noqa: E402
import rules_view  # noqa: E402
import nis2_template  # noqa: E402

_MAX_BODY_BYTES = 4096  # a triage update is a status enum + a short note.
_MAX_NOTE_CHARS = 2000
_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}
_CAS_MAX_RETRIES = 5  # optimistic-concurrency retry bound (see _route_post)
_SESSION_COOKIE = "fengarde_session"
_FAMILIES = {"bank", "dc", "common"}
_DEFAULT_LIST_LIMIT = 50
_MAX_LIST_LIMIT = 200


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
                  rate_limiter: LoginRateLimiter | None = None):
    """Returns a Handler class bound to the given store (closure, matches the
    pattern main.py already uses for the bus handler).

    ``users_db`` is None by default -> RBAC (M4.2) is OFF, the handler is
    byte-for-byte the pre-M4.2 API-key-only behavior. Pass a real
    ``shared.users.UserStore`` to turn on session login + role/tenant
    enforcement on the triage and report routes; ``sessions``/
    ``rate_limiter`` default to fresh in-process instances when RBAC is on.
    """
    rbac_enabled = users_db is not None
    if rbac_enabled:
        sessions = sessions or SessionStore()
        rate_limiter = rate_limiter or LoginRateLimiter()

    # ThreadingHTTPServer runs one thread per connection. A triage update is a
    # read (find_alert) -> modify (merge triage dict) -> write (store.index)
    # sequence across several Python statements; two concurrent POSTs to the
    # SAME alert_id can interleave and silently lose one side's change (a
    # classic lost-update race -- e.g. one analyst's status change and
    # another's note both intended to persist, only the later store.index()
    # survives). Triage writes are rare and cheap, so one process-wide lock
    # serializing the read-modify-write section is the simplest correct fix;
    # it does not block concurrent GETs or POSTs to DIFFERENT alerts in any
    # way that matters at this volume.
    write_lock = threading.Lock()

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
            return sessions.resolve(self._session_token())

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
                path = self._normalized_path()
                if rbac_enabled and path == "/auth/me":
                    return self._route_auth_me()
                if not self._check_auth():
                    return
                self._route_get(path)
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
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
            if path == "/events":
                return self._route_list_events(u.query)
            if path == "/rules":
                return self._route_list_rules(u.query)

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
            alerts = store.list_alerts(tenant_id=tenant_id, status=status, limit=limit)
            return self._send(200, {"alerts": alerts, "count": len(alerts)})

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

        def do_POST(self):
            try:
                path = self._normalized_path()
                if rbac_enabled and path == "/auth/login":
                    return self._route_auth_login()
                if rbac_enabled and not self._check_csrf():
                    return
                if rbac_enabled and path == "/auth/logout":
                    return self._route_auth_logout()
                if not self._check_auth():
                    return
                self._route_post(path)
            except _BadRequest as e:
                self._send(400, {"error": str(e)})
            except Exception:  # noqa: BLE001 - never let a handler crash the thread
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
                return self._send(401, {"error": "invalid credentials"})

            row = users_db.verify_login(username, password)
            if row is None:
                rate_limiter.record_failure(username)
                return self._send(401, {"error": "invalid credentials"})
            rate_limiter.record_success(username)

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
            return self._send(200, {"username": row["username"], "role": row["role"],
                                     "tenant_id": row["tenant_id"], "csrf_token": csrf_token},
                               extra_headers={"Set-Cookie": set_cookie})

        def _route_auth_logout(self):
            token = self._session_token()
            if token:
                sessions.invalidate(token)
            cookie = SimpleCookie()
            cookie[_SESSION_COOKIE] = ""
            cookie[_SESSION_COOKIE]["path"] = "/"
            cookie[_SESSION_COOKIE]["max-age"] = 0
            return self._send(200, {"ok": True},
                               extra_headers={"Set-Cookie": cookie[_SESSION_COOKIE].OutputString()})

        def _route_post(self, path: str):
            report_alert_id = self._alert_id_from_path(path, "report")
            if report_alert_id is not None:
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
                if length > 0:
                    self.rfile.read(min(length, _MAX_BODY_BYTES))
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
                return self._send(200, report)

            alert_id = self._alert_id_from_path(path)
            if alert_id is None:
                return self._send(404, {"error": "no such path"})
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

            # Two layers of lost-update protection:
            # - write_lock serializes read-modify-write WITHIN this process
            #   (covers MemoryStore and single-replica deployments outright).
            # - index_cas (optimistic concurrency) covers writers this lock
            #   can't see -- another ws3 replica against a shared OpenSearch.
            #   A stale write comes back as a conflict; re-read and retry.
            #   Retries are bounded; exhaustion surfaces as 409 to the client
            #   (retryable), never a silently dropped update.
            with write_lock:
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
        first_boot_password = ensure_first_boot_admin(users_db)
        if first_boot_password:
            # Written exactly once, ever, for this DB -- there is no
            # admin/admin or any other default credential (PLAN_A's ask).
            # A restart against the SAME db file does not re-print this
            # (ensure_first_boot_admin is a no-op once a user exists).
            #
            # Deliberately NOT logged (CodeQL py/clear-text-logging,
            # alert #1): stdout in a container gets captured by `docker
            # logs` and typically shipped verbatim to a log aggregator/
            # SIEM with long retention -- "printed once to the console"
            # in practice means "written to persistent log storage
            # forever." Written instead to a local file next to the RBAC
            # db, chmod 0600 (owner-read-only), and only its path is
            # logged -- never the secret itself.
            cred_path = _os.path.join(_os.path.dirname(rbac_db_path) or ".",
                                       ".first-boot-admin-password")
            with open(cred_path, "w", encoding="utf-8") as f:
                f.write(first_boot_password + "\n")
            try:
                _os.chmod(cred_path, 0o600)
            except OSError:
                pass  # best-effort on filesystems without POSIX permissions
            print(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "warning", "service": "ws3-indexer-triage",
                "msg": "first-boot admin account created -- password written to "
                       "the file below (owner-read-only), read it and delete it; "
                       "it will not be written again",
                "username": "admin", "password_file": cred_path,
            }), flush=True)

    handler_cls = make_handler(store, users_db=users_db)
    srv = ThreadingHTTPServer((host, port), handler_cls)
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "level": "info", "service": "ws3-indexer-triage",
                      "msg": "listening", "url": f"http://{host}:{port}",
                      "rbac": "enabled" if users_db else "disabled"}), flush=True)
    srv.serve_forever()
