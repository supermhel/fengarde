"""WS-6 Inventory HTTP API (Contract C).

Implements the OpenAPI paths from contracts/inventory-api.yaml. The handler logic
lives here on a stdlib http.server so it runs with zero dependencies (the contract
test exercises it live). For production, the same `InventoryStore` is trivially
wrapped by FastAPI + uvicorn (see requirements.txt); routing is identical.

Endpoints:
  GET  /assets                 list/search (ip, mac, sector, status, limit)
  GET  /assets/resolve         ?ip=&at=  -> historically-correct asset
  GET  /assets/{mac}           one asset by MAC
  POST /assets/upsert          upsert from an Observation
  GET  /keys                   key metadata (id/tenant/scope/source/created/last_used,
                                NEVER key material) -- tenant-narrowed like every GET above
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from store import InventoryStore, InvalidTenantId  # noqa: E402
from keystore import (  # noqa: E402
    SCOPE_READ_ONLY, TenantKeyStore, ensure_legacy_keys_migrated,
    warn_if_legacy_env_now_ignored, warn_missing_pepper,
)
from authz import require_auth_or_die, warn_if_disabled  # noqa: E402

STORE = InventoryStore(os.getenv("INVENTORY_DB", ":memory:"))
# Same file as STORE by default (one DB to back up), separate connection --
# TenantKeyStore owns its own table/schema, see keystore.py.
KEYSTORE = TenantKeyStore(os.getenv("INVENTORY_KEYSTORE_DB", os.getenv("INVENTORY_DB", ":memory:")))
MIGRATED_TENANTS = ensure_legacy_keys_migrated(KEYSTORE)

# Bounds on client-controlled inputs. `limit` is clamped so a hostile/typo value
# can't ask SQLite for an unbounded scan; the POST body is capped so an oversized
# upload can't be buffered into memory (a naive rfile.read(Content-Length) would).
_MAX_LIMIT = 1000
_DEFAULT_LIMIT = 50
_MAX_BODY_BYTES = 1_048_576  # 1 MiB — an Observation is a few hundred bytes.

# Gap-hunt #3 (2026-08-26): a failed API-key attempt previously produced ZERO
# telemetry and was never rate-limited -- a brute-force/probe could run forever
# unseen and with no cost. Now every failure is (1) counted on a monotonic
# slow-fail counter (observable via auth_fail_total(), which app.py's __main__
# feeds into the bus consumer's /metrics), (2) logged as a structured JSON line
# (this HTTP surface deliberately avoids `shared`, so print() is the same
# channel serve()'s startup lines already use), and (3) rate-limited per IP:
# more than _AUTH_FAIL_LIMIT failures within _AUTH_FAIL_WINDOW_S -> 429.
_AUTH_FAIL_WINDOW_S = 60
_AUTH_FAIL_LIMIT = 25
# R2-#4: auth is OPT-IN -- an empty keystore = the zero-infra/quickstart
# default where every request is allowed. But that "auth is disabled" state
# must only exist if auth was NEVER enabled: once a key has ever been observed
# (provisioned) or seeded at boot, revoking the LAST key must NOT reopen the
# service. `_AUTH_WAS_ENABLED` is a write-once-to-True latch (benign value
# race under the threaded server: any thread setting it True is correct). It
# is only reset by tests so each test gets a fresh, empty keystore.
_AUTH_WAS_ENABLED = False
# NEW-hunt read-plane #4: `_auth_fail_by_ip` buckets are otherwise pruned only
# on the NEXT failure from the SAME IP, so a "deceased" IP's bucket (and its
# now-empty/lingering list) stays in the dict for the process lifetime --
# unbounded growth, one entry per distinct failing IP ever seen. Periodic
# sweep, mirroring ws3-indexer/triage_api.py::_rate_buckets: every
# _AUTH_FAIL_SWEEP_EVERY-th failure, drop any bucket whose last entry is
# longer than _AUTH_FAIL_STALE_S old (default: 5 windows).
_AUTH_FAIL_SWEEP_EVERY = 256
_AUTH_FAIL_STALE_S = 5 * _AUTH_FAIL_WINDOW_S
_auth_fail_lock = threading.Lock()
_auth_fail_total = 0
_auth_fail_calls = 0
_auth_fail_by_ip: dict[str, list[float]] = {}


def auth_fail_total() -> int:
    """Monotonic count of failed API-key authentications since boot -- the
    slow-fail signal for a brute-force/probe. Merged into the bus consumer's
    /metrics ``extra`` when BUS_BACKEND wiring is present (gap-hunt #8)."""
    return _auth_fail_total


def _log_http_line(level: str, msg: str, **fields) -> None:
    """Structured JSON log line to stdout (flush=True) -- the HTTP surface's
    `shared`-free counterpart to shared.log. Only genuine failures/errors use
    this; the per-request noise stays muted by the no-op log_message."""
    print(json.dumps({"level": level, "service": "ws6-inventory",
                      "msg": msg, **fields}, default=str), flush=True)


class _BadRequest(Exception):
    """Raised on malformed client input; mapped to a 400 by the dispatcher."""


def _parse_limit(raw) -> int:
    """Coerce ?limit= to an int in [1, _MAX_LIMIT]. Raises _BadRequest on garbage."""
    if raw is None:
        return _DEFAULT_LIMIT
    try:
        n = int(raw)
    except (TypeError, ValueError):
        raise _BadRequest("limit must be an integer")
    if n < 1:
        raise _BadRequest("limit must be >= 1")
    return min(n, _MAX_LIMIT)


class Handler(BaseHTTPRequestHandler):
    # Slowloris guard: drop a client that stalls mid-request instead of pinning
    # this connection's thread indefinitely.
    timeout = 15

    def _send(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet
        pass

    def _check_auth(self):
        """Returns (True, bound_tenant, scope) on success, or sends 401 and
        returns (False, None, None). An empty keystore means auth is fully
        disabled -- the zero-infra/quickstart default, unchanged since
        before F1. Otherwise every request must present a key that
        verifies against KEYSTORE (hashed at rest, see keystore.py).
        bound_tenant is None for the '*' admin key (unrestricted, this
        request's own ?tenant_id= trusted as-is) or a specific tenant_id
        for a tenant-scoped key -- every tenant_id this request touches
        must then be forced to it, regardless of what the caller asked
        for. scope is SCOPE_READ_ONLY/SCOPE_READ_WRITE -- do_POST rejects
        a read-only key before it can write anything.

        R2-#4: the "auth disabled" case is pinned to auth NEVER having
        been enabled. `KEYSTORE.count()==0` at request time alone must not
        reopen an already-armed service -- we keep a `_AUTH_WAS_ENABLED`
        latch (set when any key is observed, or at boot by serve() when the
        keystore is pre-seeded). Revoking the last key mid-session therefore
        leaves auth ON: every request needs a key (and none verifies),
        instead of silently serving unauthenticated traffic again."""
        global _AUTH_WAS_ENABLED
        if KEYSTORE.count() > 0:
            _AUTH_WAS_ENABLED = True
        if KEYSTORE.count() == 0 and not _AUTH_WAS_ENABLED:
            return True, None, None
        ok, bound, scope = KEYSTORE.verify(self.headers.get("X-Api-Key", ""))
        if not ok:
            if self._note_auth_failure():
                return False, None, None  # 429 already sent
            self._send(401, {"error": "unauthorized"})
            return False, None, None
        return True, bound, scope

    def _note_auth_failure(self) -> bool:
        """Gap-hunt #3: record + log + rate-limit a failed API-key attempt.
        Returns True when the per-IP budget is exhausted and a 429 has
        already been sent (caller must NOT also send 401). NEW-hunt
        read-plane #4: also runs a periodic sweep over `_auth_fail_by_ip`
        so a "deceased" IP's bucket is dropped instead of lingering for the
        process lifetime (see the module-level constants above)."""
        ip = self.client_address[0] if self.client_address else "?"
        now = time.time()
        with _auth_fail_lock:
            global _auth_fail_total, _auth_fail_calls
            _auth_fail_total += 1
            _auth_fail_calls += 1
            window = [t for t in _auth_fail_by_ip.get(ip, [])
                      if now - t < _AUTH_FAIL_WINDOW_S]
            window.append(now)
            _auth_fail_by_ip[ip] = window
            if _auth_fail_calls % _AUTH_FAIL_SWEEP_EVERY == 0:
                stale = [k for k, w in _auth_fail_by_ip.items()
                         if not w or now - w[-1] >= _AUTH_FAIL_STALE_S]
                for k in stale:
                    _auth_fail_by_ip.pop(k, None)
            total, in_window = _auth_fail_total, len(window)
        _log_http_line("warning", "failed API-key authentication",
                       client_ip=ip, method=self.command, path=self.path,
                       auth_fail_total=total, auth_fail_in_window=in_window)
        if in_window > _AUTH_FAIL_LIMIT:
            self._send(429, {"error": "too many failed auth attempts, try again later"})
            return True
        return False

    def do_GET(self):
        # Any malformed input (bad ?at=, bad ?limit=) becomes a clean 4xx/5xx JSON
        # response instead of an unhandled exception that drops the connection and
        # leaks a stack trace to the client.
        try:
            ok, bound_tenant, _scope = self._check_auth()
            if not ok:
                return
            self._route_get(bound_tenant)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except InvalidTenantId as e:
            self._send(400, {"error": str(e)})
        except Exception:  # noqa: BLE001 - never let a handler crash the thread
            # Gap-hunt #2 (2026-08-26): this catch-all returned a bare 500 with
            # ZERO logging (log_message is a no-op), so a real backend break
            # was invisible. Log the traceback before answering; the log line
            # carries path/method so the failing request is identifiable.
            _log_http_line("error", "unhandled exception in request",
                           method="GET", path=self.path,
                           traceback=traceback.format_exc())
            self._send(500, {"error": "internal error"})

    def _route_get(self, bound_tenant: str | None = None):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        # F1 (2026-07-29 audit): every read is scoped to ?tenant_id=, defaulting
        # to "default" -- the pre-fix, single-tenant behavior -- when absent,
        # so an existing caller (WS-2 enrichment, WS-7 dashboard) that never
        # sends tenant_id keeps seeing exactly what it saw before this fix.
        # F1 follow-up (2026-07-30): a per-tenant-key caller (bound_tenant is
        # not None) has ITS OWN tenant_id forced here, silently overriding
        # whatever ?tenant_id= it asked for -- same convention as WS-3's
        # triage_api.py::_list_tenant_filter (scope narrowing, never a
        # rejection that would confirm/deny another tenant's existence).
        tenant_id = bound_tenant if bound_tenant is not None else q.get("tenant_id")
        if u.path == "/assets/resolve":
            if "ip" not in q or "at" not in q:
                return self._send(400, {"error": "ip and at required"})
            try:
                asset = STORE.resolve(q["ip"], q["at"], tenant_id=tenant_id)
            except InvalidTenantId:
                raise  # let do_GET's own handler report the real (tenant) problem
            except ValueError:
                # datetime.fromisoformat() on a malformed `at` -> 400, not a 500.
                raise _BadRequest("at must be an ISO-8601 timestamp")
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        if u.path == "/assets":
            return self._send(200, STORE.list(
                ip=q.get("ip"), mac=q.get("mac"), sector=q.get("sector"),
                status=q.get("status"), limit=_parse_limit(q.get("limit")),
                tenant_id=tenant_id))
        if u.path == "/keys":
            # 2026-08-20: key metadata (never key material -- see keystore.py::
            # list_keys) had zero HTTP route, CLI-only via manage_keys.py. Same
            # tenant-narrowing convention as every other GET here: the '*' admin
            # key (bound_tenant is None) or auth-disabled (KEYSTORE empty) sees
            # every tenant's keys; a tenant-scoped key sees only its own.
            return self._send(200, {"keys": KEYSTORE.list_keys(tenant_id=bound_tenant)})
        if u.path.startswith("/assets/"):
            # unquote: a raw path segment is never URL-decoded by urlparse
            # -- without this, a %-encoded MAC (e.g. "%3A" for ":") never
            # matches the decoded value stored by upsert(), silently
            # always 404ing instead of finding the real (tenant-scoped)
            # asset.
            mac = unquote(u.path[len("/assets/"):])
            asset = STORE.get(mac, tenant_id=tenant_id)
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        return self._send(404, {"error": "no such path"})

    def do_POST(self):
        try:
            ok, bound_tenant, scope = self._check_auth()
            if not ok:
                return
            if scope == SCOPE_READ_ONLY:
                self._send(403, {"error": "this key is read-only"})
                return
            self._route_post(bound_tenant)
        except _BadRequest as e:
            self._send(400, {"error": str(e)})
        except InvalidTenantId as e:
            self._send(400, {"error": str(e)})
        except Exception:  # noqa: BLE001 - never let a handler crash the thread
            # Gap-hunt #2: same as do_GET -- log the traceback, then 500.
            _log_http_line("error", "unhandled exception in request",
                           method="POST", path=self.path,
                           traceback=traceback.format_exc())
            self._send(500, {"error": "internal error"})

    def _route_post(self, bound_tenant: str | None = None):
        u = urlparse(self.path)
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
        if u.path == "/assets/upsert":
            # F1 follow-up: a per-tenant-key caller (bound_tenant is not
            # None) has its own tenant_id forced into the body, silently
            # overriding whatever tenant_id it tried to upsert as -- a
            # scoped key must not be able to WRITE into another tenant's
            # inventory any more than it can read one.
            if bound_tenant is not None:
                body = {**body, "tenant_id": bound_tenant}
            try:
                asset, is_new_device = STORE.upsert_with_diff(body)
            except ValueError as e:
                # Gap-hunt #5/#7: invalid observation input -- non-ISO
                # seen_at, oversized/malformed mac/hostname/protocol,
                # invalid tenant_id (IS-A ValueError) -- is the CALLER'S
                # fault: a clean 400 naming the reason, never a 500.
                raise _BadRequest(str(e))
            if not asset:
                return self._send(400, {"error": "mac required"})
            # M7 Track Y: an alertable first-ever sighting for this tenant.
            # Additive field -- existing callers that ignore it are unaffected.
            # This is the SIGNAL on this response; the durable new-device
            # notification is published to `raw.events` by `bus_consumer.py`
            # (which consumes `assets.updates` and republishes in the shape
            # the `inventory_diff` parser expects) when `BUS_BACKEND` wiring is
            # present -- see SSOT.md's M7 Track Y rows for the transport path.
            return self._send(200, {**asset, "new_device": is_new_device})
        return self._send(404, {"error": "no such path"})


def serve(host="0.0.0.0", port=8000):
    global _AUTH_WAS_ENABLED
    require_auth_or_die("ws6-inventory", KEYSTORE)
    warn_if_disabled("ws6-inventory", KEYSTORE)
    warn_missing_pepper()
    if KEYSTORE.count() > 0:
        # R2-#4: a service booting with provisioned keys is and remains
        # auth-enabled -- even if the last key is later revoked.
        _AUTH_WAS_ENABLED = True
    if not MIGRATED_TENANTS and KEYSTORE.count() > 0:
        # Nothing migrated on THIS boot, yet the keystore is non-empty --
        # it was already seeded by an earlier boot. If a legacy env var is
        # still set, editing it now does nothing; say so.
        warn_if_legacy_env_now_ignored()
    srv = ThreadingHTTPServer((host, port), Handler)
    # ws6's HTTP surface deliberately avoids `shared` even though the image
    # bundles it now (M7 Track Y follow-up, for bus_consumer.py's opt-in use)
    # -- emit a structured JSON log line inline rather than importing
    # shared.log, so this path stays independent of that dependency.
    import json as _json
    import time as _time
    if MIGRATED_TENANTS:
        # Never the key values -- see keystore.py::ensure_legacy_keys_migrated.
        print(_json.dumps({"level": "info", "service": "ws6-inventory",
                           "msg": "migrated legacy API key(s) into the hashed keystore",
                           "tenants": MIGRATED_TENANTS}), flush=True)
    print(_json.dumps({"ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                       "level": "info", "service": "ws6-inventory",
                       "msg": "listening", "url": f"http://{host}:{port}"}), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    # M7 Track Y follow-up: opt-in bus consumer, mirrors ws3-indexer's
    # triage_api/webhook thread pattern (services/ws3-indexer/main.py) -- HTTP
    # stays the main thread, the bus consumer runs alongside it on a daemon
    # thread. Gated on BUS_BACKEND (unset in the zero-infra Docker build,
    # which never installs `shared`/redis at all) so importing this module
    # never requires them; `shared` is only imported inside this branch.
    if os.getenv("BUS_BACKEND"):
        import threading
        from bus_consumer import run_forever
        # Gap-hunt #8: wire the consumer's health port (default
        # INVENTORY_BUS_HEALTH_PORT, 8006) so runner.serve's per-topic
        # acked/failed/deadlettered counters are actually readable, and feed
        # the auth-failure slow-fail counter (gap-hunt #3) into /metrics.
        threading.Thread(
            target=run_forever, args=(STORE,),
            kwargs={"health_port": int(os.getenv("INVENTORY_BUS_HEALTH_PORT", "8006")),
                    "metrics_provider": lambda: {"ws6_inventory.auth_fail_total": auth_fail_total()}},
            daemon=True,
        ).start()
    serve(port=int(os.getenv("PORT", "8000")))
